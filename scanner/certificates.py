"""TLS certificate parsing into the shared ``CertificateInfo`` record.

Not an external provider: this module turns raw DER bytes captured during a
handshake (direct-IP or hostname-aware) into the fields the hostname-evidence
union and oracle need. Malformed DER never raises past the scanner boundary
when callers use ``parse_der_safe``.
"""
from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

from scanner.models import CertificateInfo

_MAX_LABEL = 63
_MAX_NAME = 253


class CertificateParseError(ValueError):
    """DER could not be parsed into a certificate. Callers record, never crash."""


def _to_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_hostname(name: str | None) -> str | None:
    """Lower-case, strip trailing dot, IDNA-encode; ``None`` if not a hostname."""
    if name is None:
        return None
    candidate = name.strip()
    if not candidate or len(candidate) > 1024:       # far beyond any DNS name; bounds the work a hostile certificate can cause
        return None
    if candidate.endswith("."):
        candidate = candidate[:-1]
    if not candidate:
        return None
    try:
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        pass
    candidate = candidate.lower()
    if candidate.startswith("*."):
        wildcard_rest = candidate[2:]
        if not wildcard_rest or "*" in wildcard_rest:     # only a single leading "*." is a wildcard; "*.*." recursion is a DoS shape
            return None
        rest = normalize_hostname(wildcard_rest)
        if rest is None:
            return None
        return f"*.{rest}"
    labels = candidate.split(".")
    if len(labels) < 1 or any(label == "" for label in labels):
        return None
    encoded_labels: list[str] = []
    for label in labels:
        try:
            encoded = label.encode("idna") if not label.isascii() else label.encode("ascii")
        except UnicodeError:
            return None
        encoded_str = encoded.decode("ascii")
        if not encoded_str or len(encoded_str) > _MAX_LABEL:
            return None
        if not all(ch.isalnum() or ch in "-_" for ch in encoded_str):
            return None
        if encoded_str.startswith("-") or encoded_str.endswith("-"):
            return None
        encoded_labels.append(encoded_str)
    result = ".".join(encoded_labels)
    if len(result) > _MAX_NAME:
        return None
    if "." not in result:
        return None
    return result


def _dedupe_preserve(names: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return tuple(out)


def _public_key_info(cert: x509.Certificate) -> tuple[str | None, int | None]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.key_size
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 448
    return key.__class__.__name__, None


def _verify_self_signed(cert: x509.Certificate) -> bool:
    if cert.issuer != cert.subject:
        return False
    public_key = cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes)
        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
        else:
            return True  # issuer == subject but unknown key type; trust the name match only
        return True
    except InvalidSignature:
        return False
    except Exception:
        return True  # cannot verify (e.g. unsupported padding); fall back to name-match self-signed


def _match_hostname(sni: str, san_dns: tuple[str, ...], cn: str | None) -> bool:
    candidates = san_dns if san_dns else ((cn,) if cn else ())
    for candidate in candidates:
        if candidate is None:
            continue
        if candidate.startswith("*."):
            zone = candidate[2:]
            sni_labels = sni.split(".")
            if len(sni_labels) < 2:
                continue
            if ".".join(sni_labels[1:]) == zone:
                return True
            continue
        if candidate == sni:
            return True
    return False


def parse_der(
    der: bytes,
    *,
    handshake_mode: str,
    sni_sent: str | None,
    observed_at: datetime,
    chain: list[bytes] = (),
    target_ip: str = "",
    port: int = 0,
) -> CertificateInfo:
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:  # cryptography raises various ValueError/TypeError subclasses
        raise CertificateParseError(f"malformed DER: {exc}") from exc

    sha256 = hashlib.sha256(der).hexdigest()

    try:
        cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        raw_cn = cn_attr[0].value if cn_attr else None
    except Exception:
        raw_cn = None
    subject_cn = normalize_hostname(raw_cn) if isinstance(raw_cn, str) else None
    if subject_cn is not None and subject_cn.startswith("*."):
        subject_cn = None  # CN wildcards are not meaningful hostnames here

    san_dns_raw: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns_raw = list(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        san_dns_raw = []

    san_normalized: list[str] = []
    for raw in san_dns_raw:
        normalized = normalize_hostname(raw)
        if normalized is not None:
            san_normalized.append(normalized)
    san_dns = _dedupe_preserve(san_normalized)

    try:
        issuer = cert.issuer.rfc4514_string()
    except Exception:
        issuer = None
    try:
        serial = format(cert.serial_number, "x")
    except Exception:
        serial = None

    try:
        not_before = _to_iso(cert.not_valid_before_utc)
        not_after = _to_iso(cert.not_valid_after_utc)
    except AttributeError:  # older cryptography without *_utc
        not_before = _to_iso(cert.not_valid_before)
        not_after = _to_iso(cert.not_valid_after)

    try:
        sig_alg = cert.signature_algorithm_oid._name
    except Exception:
        sig_alg = None
    pubkey_alg, pubkey_bits = _public_key_info(cert)

    chain_sha256 = tuple(hashlib.sha256(link).hexdigest() for link in chain)

    self_signed = _verify_self_signed(cert)

    observed = observed_at if observed_at.tzinfo else observed_at.replace(tzinfo=timezone.utc)
    not_before_dt = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after_dt = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    expired = observed > not_after_dt
    not_yet_valid = observed < not_before_dt

    hostname_matches: bool | None = None
    if sni_sent is not None:
        sni_norm = normalize_hostname(sni_sent)
        hostname_matches = bool(sni_norm) and _match_hostname(sni_norm, san_dns, subject_cn)

    return CertificateInfo(
        sha256=sha256,
        subject_cn=subject_cn,
        san_dns=san_dns,
        issuer=issuer,
        serial=serial,
        not_before=not_before,
        not_after=not_after,
        signature_algorithm=sig_alg,
        public_key_algorithm=pubkey_alg,
        public_key_bits=pubkey_bits,
        chain_sha256=chain_sha256,
        handshake_mode=handshake_mode,  # type: ignore[arg-type]
        sni_sent=sni_sent,
        self_signed=self_signed,
        expired_at_observation=expired,
        not_yet_valid_at_observation=not_yet_valid,
        hostname_matches=hostname_matches,
        target_ip=target_ip,
        port=port,
    )


def parse_der_safe(
    der: bytes,
    *,
    handshake_mode: str,
    sni_sent: str | None,
    observed_at: datetime,
    chain: list[bytes] = (),
    target_ip: str = "",
    port: int = 0,
) -> CertificateInfo | None:
    try:
        return parse_der(
            der,
            handshake_mode=handshake_mode,
            sni_sent=sni_sent,
            observed_at=observed_at,
            chain=chain,
            target_ip=target_ip,
            port=port,
        )
    except CertificateParseError:
        return None


def certificate_names(cert: CertificateInfo) -> list[tuple[str, str, bool]]:
    """Evidence names from a parsed certificate: (name, source, wildcard)."""
    names: list[tuple[str, str, bool]] = []
    seen: set[tuple[str, str]] = set()
    for san in cert.san_dns:
        wildcard = san.startswith("*.")
        name = san[2:] if wildcard else san
        key = (name, "certificate_san")
        if name and key not in seen:
            seen.add(key)
            names.append((name, "certificate_san", wildcard))
    if cert.subject_cn and not cert.subject_cn.startswith("*."):
        key = (cert.subject_cn, "certificate_cn")
        if key not in seen:
            seen.add(key)
            names.append((cert.subject_cn, "certificate_cn", False))
    return names
