"""Offline IP-to-ASN context with a cloud/CDN/hosting flag.

The origin AS comes from a RouteViews prefix-to-AS snapshot read through ``pyasn``. The flag comes
from a short, curated list of ASNs (``cloud_cdn_asns.csv``). Both are context for attribution
checks, not ownership evidence: a name and an icon that disagree are expected behind a CDN or on a
shared platform, and an address outside the list is not shown to be dedicated infrastructure.
"""
from __future__ import annotations

import csv
import gzip
from pathlib import Path
from typing import Any


CLOUD_CDN_CSV = Path(__file__).with_name("cloud_cdn_asns.csv")

ASN_FIELDS = ("asn", "asn_prefix", "cloud_cdn_flag", "cloud_cdn_class")


def convert_pfx2as(sources: list[Path], dest: Path) -> dict[str, int]:
    """Write a pyasn ``prefix/length<TAB>asn`` table from CAIDA/RouteViews ``pfx2as`` files.

    Multi-origin prefixes (``A_B``) and AS sets (``A,B``) keep the first origin; the table cannot hold
    more than one, so the number of such prefixes is returned for the run manifest.
    """
    counts = {"prefixes": 0, "multi_origin": 0, "invalid": 0}
    with dest.open("w", encoding="ascii", newline="\n") as out:
        for source in sources:
            opener = gzip.open if source.suffix == ".gz" else open
            with opener(source, "rt", encoding="ascii") as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) != 3:
                        counts["invalid"] += 1
                        continue
                    prefix, length, origin = parts
                    first = origin.replace(",", "_").split("_")[0].strip("{}")
                    if not first.isdigit():
                        counts["invalid"] += 1
                        continue
                    if first != origin:
                        counts["multi_origin"] += 1
                    out.write(f"{prefix}/{length}\t{first}\n")
                    counts["prefixes"] += 1
    return counts


def load_cloud_cdn(path: Path = CLOUD_CDN_CSV) -> dict[int, str]:
    with path.open(encoding="utf-8", newline="") as handle:
        return {int(row["asn"]): row["class"] for row in csv.DictReader(handle)}


class AsnContext:
    def __init__(self, ipasn_file: str | Path, cloud_cdn_csv: str | Path = CLOUD_CDN_CSV) -> None:
        import pyasn          # optional dependency: only needed when an ASN table is configured

        self._db = pyasn.pyasn(str(ipasn_file))
        self._cloud_cdn = load_cloud_cdn(Path(cloud_cdn_csv))

    def lookup(self, ip: str) -> dict[str, Any]:
        """ASN, matching prefix and cloud/CDN flag for one address; all null fields when no route is known."""
        try:
            asn, prefix = self._db.lookup(ip)
        except ValueError:
            asn, prefix = None, None
        klass = self._cloud_cdn.get(asn) if asn is not None else None
        flag = None if asn is None else klass is not None
        return {"asn": asn, "asn_prefix": prefix, "cloud_cdn_flag": flag, "cloud_cdn_class": klass}


def empty_fields() -> dict[str, Any]:
    return {"asn": None, "asn_prefix": None, "cloud_cdn_flag": None, "cloud_cdn_class": None}
