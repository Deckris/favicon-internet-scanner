"""Versioned favicon observations; asset similarity is never a phishing verdict.

Schema 1 mislabeled dHash as ``phash_hex``. Schema 2 stores actual dHash and
DCT pHash per raster representation. Regenerate old records from raw assets;
never relabel the old value as pHash. No vendor coverage is implied by a digest.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import struct
import subprocess
import sys
import warnings
from dataclasses import asdict, dataclass
from importlib.metadata import version
from pathlib import Path

import imagehash
import mmh3
from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from PIL import IcoImagePlugin, Image, UnidentifiedImageError

MAX_BYTES = 5 * 1024 * 1024
MAX_PIXELS = 1_048_576          # real favicons are at most 512x512; larger images are a memory/CPU risk
MAX_REPRESENTATIONS = 64
RENDER_TIMEOUT = 5
RECIPE = "rgba8-native-size-zero-transparent-rgb;rgb-white-black;hash64-v2"


class ObservationError(ValueError):
    """A recorded acquisition/decode outcome, not an absent favicon."""


@dataclass(frozen=True)
class FaviconFingerprint:
    schema_version: int
    size_bytes: int
    content_sha256: str
    mmh3_hash: int
    md5_hex: str
    image_ok: bool
    decode_status: str
    representations: list[dict]
    errors: list[dict]
    algorithms: dict

    def as_dict(self) -> dict:
        return asdict(self)


def shodan_mmh3(data: bytes) -> int:
    """Signed x86 32-bit MurmurHash3, seed 0, wrapped base64 + final newline."""
    return mmh3.hash(base64.encodebytes(data))


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _check_size(width: int, height: int) -> None:
    if width <= 0 or height <= 0 or (width * height) > MAX_PIXELS:
        raise ObservationError("pixel_limit")


def _canonical_rgba(image: Image.Image) -> Image.Image:
    _check_size(*image.size)
    rgba = image.convert("RGBA")
    r, g, b, a = rgba.split()
    zero_alpha = a.point(lambda p: 255 if p == 0 else 0)
    zero_rgb = Image.new("L", rgba.size, 0)
    r.paste(zero_rgb, mask=zero_alpha)
    g.paste(zero_rgb, mask=zero_alpha)
    b.paste(zero_rgb, mask=zero_alpha)
    return Image.merge("RGBA", (r, g, b, a))


def _composite(rgba: Image.Image, color: tuple[int, int, int]) -> Image.Image:
    background = Image.new("RGB", rgba.size, color)
    background.paste(rgba, mask=rgba.split()[3])
    return background


def _represent(image: Image.Image, meta: dict) -> list[dict]:
    rgba = _canonical_rgba(image)
    white = _composite(rgba, (255, 255, 255))
    black = _composite(rgba, (0, 0, 0))
    pixel_sha256 = hashlib.sha256(rgba.tobytes()).hexdigest()
    dhash = str(imagehash.dhash(rgba, hash_size=8))
    phash = str(imagehash.phash(rgba, hash_size=8))
    return [{
        **meta,
        "width": rgba.width,
        "height": rgba.height,
        "pixel_sha256": pixel_sha256,
        "dhash_hex": dhash,
        "phash_hex": phash,
        "composites": {
            "white": {
                "pixel_sha256": hashlib.sha256(white.tobytes()).hexdigest(),
                "dhash_hex": str(imagehash.dhash(white, hash_size=8)),
                "phash_hex": str(imagehash.phash(white, hash_size=8)),
            },
            "black": {
                "pixel_sha256": hashlib.sha256(black.tobytes()).hexdigest(),
                "dhash_hex": str(imagehash.dhash(black, hash_size=8)),
                "phash_hex": str(imagehash.phash(black, hash_size=8)),
            },
        },
    }]


def _unpack_ico(data: bytes) -> list[tuple[int, Image.Image | bytes | None]]:
    """Return ICO frames in file-directory order.

    A frame payload is either PNG-compressed or a bare DIB. A bare DIB carries no
    BMP file header and stores a doubled height for its AND mask, so it cannot be
    opened as a standalone image; those frames are decoded through Pillow's ICO
    plugin, which reassembles the header. The plugin sorts its own entries, so each
    directory entry claims its slot by size and colour depth rather than by position,
    and frame_index stays reproducible.
    """
    if len(data) < 6:
        raise ObservationError("decode_failure")
    reserved, kind, count = struct.unpack_from("<HHH", data, 0)
    if reserved != 0 or kind != 1 or count <= 0:
        raise ObservationError("decode_failure")
    if count > MAX_REPRESENTATIONS:
        raise ObservationError("representation_limit")
    directory: list[tuple[int, bytes, tuple[int, int], int]] = []
    header_len = 6 + count * 16
    for i in range(count):
        offset = 6 + i * 16
        if offset + 16 > len(data):
            raise ObservationError("decode_failure")
        w_b, h_b, _colors, _res, _planes, bpp, size, img_offset = struct.unpack_from("<BBBBHHII", data, offset)
        if img_offset < header_len or img_offset + size > len(data) or size > MAX_BYTES:
            raise ObservationError("decode_failure")
        directory.append((i, data[img_offset:img_offset + size], (w_b or 256, h_b or 256), bpp))

    entries: list[tuple[int, Image.Image | bytes | None]] = []
    plugin: IcoImagePlugin.IcoFile | None = None
    by_dim: dict[tuple[int, int], list[int]] = {}
    by_depth: dict[tuple[tuple[int, int], int], list[int]] = {}
    for index, payload, dim, bpp in directory:
        if payload.startswith(b"\x89PNG\r\n\x1a\n"):
            entries.append((index, payload))
            continue
        if plugin is None:
            try:
                plugin = IcoImagePlugin.IcoFile(io.BytesIO(data))
            except (OSError, ValueError, SyntaxError, struct.error) as exc:
                raise ObservationError("decode_failure") from exc
            for slot in range(plugin.nb_items):
                entry = plugin.entry[slot]
                slot_dim = tuple(entry.dim)
                by_dim.setdefault(slot_dim, []).append(slot)
                by_depth.setdefault((slot_dim, getattr(entry, "bpp", 0) or 0), []).append(slot)
        slot = _take_ico_slot(by_depth, by_dim, dim, bpp)
        if slot is None:
            # Directory advertises a frame the plugin will not surface; the caller
            # records this as a per-frame decode_failure rather than losing the file.
            entries.append((index, None))
            continue
        try:
            entries.append((index, plugin.frame(slot)))
        except (OSError, ValueError, SyntaxError, struct.error):
            entries.append((index, None))
    return entries


def _take_ico_slot(
    by_depth: dict[tuple[tuple[int, int], int], list[int]],
    by_dim: dict[tuple[int, int], list[int]],
    dim: tuple[int, int],
    bpp: int,
) -> int | None:
    """Claim the plugin slot for one directory entry.

    Matching on size alone would let two frames of identical dimensions but
    different colour depth be assigned to each other's directory entries, so the
    colour depth is preferred and size is only the fallback. A slot claimed through
    either index is withdrawn from both so no frame is emitted twice.
    """
    for bucket in (by_depth.get((dim, bpp)), by_dim.get(dim)):
        if not bucket:
            continue
        slot = bucket.pop(0)
        for other in (by_depth.get((dim, bpp)), by_dim.get(dim)):
            if other is not None and slot in other:
                other.remove(slot)
        return slot
    return None


def _svg_document(data: bytes) -> tuple[str, list[tuple[int, int]]]:
    if len(data) > MAX_BYTES:
        raise ObservationError("size_limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("utf-16")
        except UnicodeDecodeError as exc:
            raise ObservationError("decode_failure") from exc
    try:
        root = ElementTree.fromstring(text, forbid_dtd=True, forbid_entities=True)
    except (ElementTree.ParseError, DefusedXmlException) as exc:
        raise ObservationError("decode_failure") from exc
    tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag
    if tag.lower() != "svg":
        raise ObservationError("decode_failure")
    for elem in root.iter():
        t = elem.tag.split("}")[-1].lower() if "}" in elem.tag else elem.tag.lower()
        if t in {"script", "foreignobject", "iframe"}:
            raise ObservationError("unsafe_svg")
        for key, value in elem.attrib.items():
            if key.lower().startswith("on") or (key.lower().endswith("href") and not value.startswith("#") and not value.startswith("data:image/")):
                raise ObservationError("unsafe_svg")
    sizes: set[tuple[int, int]] = set()
    vb = root.attrib.get("viewBox") or root.attrib.get("viewbox")
    if vb:
        parts = [p for p in re.split(r"[\s,]+", vb.strip()) if p]
        if len(parts) == 4:
            try:
                w, h = int(float(parts[2])), int(float(parts[3]))
                if 0 < w <= 1024 and 0 < h <= 1024:
                    sizes.add((w, h))
            except ValueError:
                pass
    try:
        w_attr = int(float(re.sub(r"[^\d.]", "", root.attrib.get("width", ""))))
        h_attr = int(float(re.sub(r"[^\d.]", "", root.attrib.get("height", ""))))
        if 0 < w_attr <= 1024 and 0 < h_attr <= 1024:
            sizes.add((w_attr, h_attr))
    except ValueError:
        pass
    sizes.update({(32, 32), (64, 64)})
    return text, sorted(sizes)


def _render_svg(text: str, sizes: list[tuple[int, int]]) -> list[Image.Image]:
    helper = Path(__file__).with_name("svg_renderer.py")
    try:
        proc = subprocess.run(
            [sys.executable, str(helper), json.dumps(sizes)],
            input=text.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=RENDER_TIMEOUT,
            check=True,
        )
        rendered = json.loads(proc.stdout.decode("ascii"))
        return [Image.open(io.BytesIO(base64.b64decode(chunk))) for chunk in rendered]
    except (subprocess.SubprocessError, json.JSONDecodeError, UnidentifiedImageError, OSError) as exc:
        raise ObservationError("render_failure") from exc


def fingerprint(data: bytes) -> FaviconFingerprint:
    algorithms = {
        "recipe": RECIPE,
        "imagehash_version": version("imagehash"),
        "pillow_version": version("pillow"),
        "dhash": "imagehash.dhash(hash_size=8)",
        "phash": "imagehash.phash(hash_size=8)",
        "mmh3": "mmh3.hash(base64.encodebytes(bytes))",
        "md5": "hashlib.md5(bytes).hexdigest()",
    }
    if not data:
        return FaviconFingerprint(
            schema_version=2, size_bytes=0, content_sha256=hashlib.sha256(b"").hexdigest(),
            mmh3_hash=shodan_mmh3(b""), md5_hex=md5_hex(b""), image_ok=False,
            decode_status="empty", representations=[], errors=[{"frame_index": None, "status": "empty"}],
            algorithms=algorithms,
        )
    if len(data) > MAX_BYTES:
        return FaviconFingerprint(
            schema_version=2, size_bytes=len(data), content_sha256=hashlib.sha256(data).hexdigest(),
            mmh3_hash=shodan_mmh3(data), md5_hex=md5_hex(data), image_ok=False,
            decode_status="size_limit", representations=[], errors=[{"frame_index": None, "status": "size_limit"}],
            algorithms=algorithms,
        )
    representations: list[dict] = []
    errors: list[dict] = []
    status = "ok"
    try:
        if data.startswith(b"\x00\x00\x01\x00"):
            inputs = _unpack_ico(data)
            kind = "ico"
        elif re.search(br"<(?:[\w.-]+:)?svg(?:\s|>)", data[:4096], re.I):
            sanitized, sizes = _svg_document(data)
            inputs = list(enumerate(_render_svg(sanitized, sizes)))
            kind = "svg"
        else:
            inputs, kind = [(0, data)], "raster"
        for index, source in inputs:
            try:
                if source is None:
                    raise ObservationError("decode_failure")
                with warnings.catch_warnings():
                    warnings.simplefilter("error", Image.DecompressionBombWarning)
                    image = source if isinstance(source, Image.Image) else Image.open(io.BytesIO(source))
                    with image:
                        _check_size(*image.size)
                        image.seek(0)
                        representations.extend(_represent(image, {
                            "frame_index": index, "asset_format": kind if kind != "raster" else image.format,
                            "animation_policy": "first-frame" if kind == "raster" else "not-applicable",
                        }))
            except (Image.DecompressionBombWarning, Image.DecompressionBombError):
                errors.append({"frame_index": index, "status": "pixel_limit"})
            except (OSError, ValueError, SyntaxError) as exc:
                errors.append({"frame_index": index, "status": str(exc) if isinstance(exc, ObservationError) else "decode_failure"})
        if errors:
            status = "partial" if representations else errors[0]["status"]
    except ObservationError as exc:
        status = str(exc)
        errors.append({"frame_index": None, "status": status})
    return FaviconFingerprint(
        schema_version=2, size_bytes=len(data), content_sha256=hashlib.sha256(data).hexdigest(),
        mmh3_hash=shodan_mmh3(data), md5_hex=md5_hex(data), image_ok=bool(representations),
        decode_status=status, representations=representations, errors=errors, algorithms=algorithms,
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python pipeline/favicon_hash.py <local-favicon-file>")
    with open(sys.argv[1], "rb") as handle:
        blob = handle.read(MAX_BYTES + 1)
    print(json.dumps(fingerprint(blob).as_dict(), indent=2))
