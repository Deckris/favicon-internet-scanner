"""scanner run configuration and the authorization gate.

The configuration is strict: unknown keys, placeholder values and anything the
approval record does not cover are refused before any packet is sent. The
approval record uses the repository's machine-readable format
(``pipeline.config_schema``); two operations are required:

* ``hostname_resolution`` -- ZMap/ZGrab2/ZDNS stages
* ``favicon_fetch`` -- only when ``favicon.enabled`` is true
* ``offhost_icon_fetch`` -- only when ``favicon.offhost_icons.enabled`` is true (contacts hosts outside the sample)

plus a ``max_sample_fraction`` key (read here, not by the shared loader).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

from pipeline.config_schema import Approval, ApprovalError, load_approval, require_operation
from scanner.internet.zmap_compat import packet_rate_args, supported

OP_RESOLUTION = "hostname_resolution"
OP_FAVICON = "favicon_fetch"
OP_OFFHOST_ICONS = "offhost_icon_fetch"
PLACEHOLDERS = ("REPLACE_ME", "CHANGEME", "TODO", "PLACEHOLDER")
HARD_MAX_PORTS = 16
# IANA special-purpose / non-global IPv4 space that is never part of a sample.
RESERVED_V4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)


class ConfigError(ValueError):
    pass


def _section(raw: dict[str, Any], name: str, allowed: set[str], required: set[str] | None = None) -> dict[str, Any]:
    section = raw.get(name)
    if not isinstance(section, dict):
        raise ConfigError(f"missing or invalid section {name!r}")
    unknown = sorted(set(section) - allowed)
    if unknown:
        raise ConfigError(f"unknown keys in {name!r}: {', '.join(unknown)}")
    missing = sorted((required if required is not None else allowed) - set(section))
    if missing:
        raise ConfigError(f"missing keys in {name!r}: {', '.join(missing)}")
    return section


def _no_placeholders(value: Any, where: str) -> None:
    if isinstance(value, str) and any(p in value for p in PLACEHOLDERS):
        raise ConfigError(f"placeholder value left in {where}")
    if isinstance(value, dict):
        for k, v in value.items():
            _no_placeholders(v, f"{where}.{k}")
    if isinstance(value, list):
        for i, v in enumerate(value):
            _no_placeholders(v, f"{where}[{i}]")


@dataclass(frozen=True)
class ScanConfig:
    run_label: str
    vantage: SimpleNamespace
    sample_fraction: float
    sample_seed: int
    measurement: SimpleNamespace
    exclusions_file: Path
    exclusions_sha256: str
    approval_file: Path
    hostname_mode: str
    hostname_suffixes: tuple[str, ...]
    dns: SimpleNamespace
    max_candidates_per_ip: int
    sni_confirm: SimpleNamespace
    favicon: SimpleNamespace
    fetch: SimpleNamespace
    transparency: SimpleNamespace
    output_dir: Path
    kill_switch_file: Path
    binaries: SimpleNamespace
    checksum: str
    approval: Approval | None = None
    shards: int = 1                            # the sample is split into this many disjoint ZMap shards (campaign mode)
    shard: int = 0                             # which shard THIS run covers
    max_listed_targets: int = 1_000_000        # above this many targets per shard the full target list is not written
    egress_check_seconds: int = 120            # re-check the public IP this often during a run (0 = off)
    min_free_mib: int = 512                    # abort when free disk falls below this
    target_ips: tuple[str, ...] = ()           # known-targets mode: probe exactly these addresses, not a random sample
    target_hostnames: tuple[str, ...] = ()     # operator-supplied names, verified like any other candidate
    tarpit: SimpleNamespace = field(default_factory=lambda: SimpleNamespace(min_open_ports=4, tiny_window_below=246))
    max_sample_fraction: float = 0.0
    approval_sha256: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


MIN_PACE_SECONDS = 15.0     # the pause an approval is assumed to require when it does not state one


def read_exclusions(path: Path) -> list[str]:
    nets: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        text = line.split("#", 1)[0].strip()
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ConfigError(f"bad exclusion entry {text!r}: {exc}") from exc
        if net.version == 4:          # the scanner is IPv4-only; IPv6 entries stay in the file and are ignored
            nets.append(str(net))
    return nets


def _float(value: Any, name: str, lo: float, hi: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be a number") from exc
    if not lo <= number <= hi:
        raise ConfigError(f"{name} must be in [{lo}, {hi}]")
    return number


def _int(value: Any, name: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{name} must be an integer")
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be in [{lo}, {hi}]")
    return value


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{name} must be true or false")
    return value


def load_config(path: Path, *, base_dir: Path | None = None, require_approval: bool = True) -> ScanConfig:
    """Load and validate a config file. ``require_approval=False`` is for offline tooling only."""
    path = Path(path)
    base = Path(base_dir) if base_dir else path.parent
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read config: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("config must be a mapping")
    top = {"run_label", "vantage", "sample", "measurement", "target_policy", "dns", "hostnames",
           "sni_confirm", "favicon", "fetch", "transparency", "output", "operations", "binaries", "tarpit"}
    unknown = sorted(set(raw) - top)
    if unknown:
        raise ConfigError(f"unknown top-level keys: {', '.join(unknown)}")
    _no_placeholders(raw, "config")

    def rel(p: str) -> Path:
        q = Path(p)
        return q if q.is_absolute() else (base / q)

    vantage = _section(raw, "vantage", {"id", "interface", "source_ipv4", "public_egress_ip", "gateway_mac",
                                        "egress_check", "egress_check_urls"},
                       {"id", "interface", "source_ipv4", "public_egress_ip"})
    egress_check = vantage.get("egress_check", "url")
    if egress_check not in ("url", "nic", "off"):
        raise ConfigError("vantage.egress_check must be url, nic or off")
    egress_urls = vantage.get("egress_check_urls") or []
    if not isinstance(egress_urls, list) or len(egress_urls) > 5 or not all(isinstance(u, str) and u.startswith("https://") for u in egress_urls):
        raise ConfigError("vantage.egress_check_urls must be a list of up to 5 https:// URLs that return the caller's IPv4 address")
    try:
        src = ipaddress.ip_address(vantage["source_ipv4"])
        egress = ipaddress.ip_address(vantage["public_egress_ip"])
    except ValueError as exc:
        raise ConfigError("vantage.source_ipv4 / public_egress_ip must be IP addresses") from exc
    if src.version != 4 or egress.version != 4:
        raise ConfigError("vantage addresses must be IPv4")
    if not egress.is_global:
        # Behind NAT (e.g. WSL2) the address the network owner sees differs from source_ipv4; the approval
        # must name that public address, so a private value here would defeat source-address ownership.
        raise ConfigError("vantage.public_egress_ip must be the public IPv4 address the Internet sees")

    if egress_check == "nic" and src != egress:
        raise ConfigError("vantage.egress_check: nic means the public address is on the interface, so source_ipv4 must equal public_egress_ip")

    sample = _section(raw, "sample", {"fraction", "seed", "target_ips", "target_hostnames", "shards"}, {"seed"})
    seed = _int(sample["seed"], "sample.seed", 0, 2**32 - 1)
    shards = _int(sample.get("shards", 1), "sample.shards", 1, 100_000)
    target_ips: tuple[str, ...] = ()
    target_hostnames: tuple[str, ...] = ()
    if ("fraction" in sample) == ("target_ips" in sample):
        raise ConfigError("sample needs exactly one of fraction (random sample) or target_ips (known targets)")
    if "target_ips" in sample:
        ips = sample["target_ips"]
        if not isinstance(ips, list) or not 1 <= len(ips) <= 64:
            raise ConfigError("sample.target_ips must be a list of 1-64 IPv4 addresses")
        parsed = []
        for item in ips:
            try:
                addr = ipaddress.ip_address(str(item))
            except ValueError as exc:
                raise ConfigError(f"sample.target_ips: {item!r} is not an IP address") from exc
            if addr.version != 4 or not addr.is_global:
                raise ConfigError(f"sample.target_ips: {item} must be a public IPv4 address")
            parsed.append(str(addr))
        if shards != 1:
            raise ConfigError("sample.shards applies to random samples, not to target_ips")
        target_ips = tuple(sorted(set(parsed)))
        names = sample.get("target_hostnames") or []
        if not isinstance(names, list) or len(names) > 20 or not all(isinstance(n, str) and n.strip() for n in names):
            raise ConfigError("sample.target_hostnames must be a list of up to 20 hostnames")
        target_hostnames = tuple(sorted({n.strip().lower() for n in names}))
        fraction = len(target_ips) / 2**32       # tiny by construction; the approval cap is still checked
    else:
        if "target_hostnames" in sample:
            raise ConfigError("sample.target_hostnames needs sample.target_ips")
        fraction = _float(sample["fraction"], "sample.fraction", 1e-9, 1.0)

    measurement_keys = {
        "ports", "zmap_rate", "zmap_max_runtime", "zmap_cooldown", "zmap_probes",
        "zgrab_connect_timeout", "zgrab_target_timeout", "zgrab_senders", "zgrab_batch_size"}
    m = _section(raw, "measurement", measurement_keys | {"zmap_version", "min_seconds_between_probes_per_ip"}, measurement_keys)
    zmap_version = str(m.get("zmap_version", "2.1.1"))
    if not supported(zmap_version):
        raise ConfigError("measurement.zmap_version must be 2.1.x or the pinned 4.4.0")
    if zmap_version == "4.4.0" and shards != 1:
        raise ConfigError("sample.shards is not supported with ZMap 4.4.0, which divides the target count across shards")
    ports = m["ports"]
    if not isinstance(ports, list) or not ports or len(ports) > HARD_MAX_PORTS:
        raise ConfigError("measurement.ports must be a non-empty list")
    ports = sorted({_int(p, "measurement.ports[]", 1, 65535) for p in ports})
    measurement = SimpleNamespace(
        ports=tuple(ports),
        zmap_version=zmap_version,
        # ZMap's -r takes an integer: "100.0" is rejected by the binary, so the rate is an int end to end.
        zmap_rate=_int(int(_float(m["zmap_rate"], "measurement.zmap_rate", 1, 100_000)), "measurement.zmap_rate", 1, 100_000),
        zmap_max_runtime=_int(m["zmap_max_runtime"], "measurement.zmap_max_runtime", 1, 7 * 24 * 3600),
        zmap_cooldown=_int(m["zmap_cooldown"], "measurement.zmap_cooldown", 1, 3600),
        zmap_probes=_int(m["zmap_probes"], "measurement.zmap_probes", 1, 5),
        zgrab_connect_timeout=_float(m["zgrab_connect_timeout"], "measurement.zgrab_connect_timeout", 0.5, 60),
        zgrab_target_timeout=_float(m["zgrab_target_timeout"], "measurement.zgrab_target_timeout", 1, 120),
        zgrab_senders=_int(m["zgrab_senders"], "measurement.zgrab_senders", 1, 1000),
        zgrab_batch_size=_int(m["zgrab_batch_size"], "measurement.zgrab_batch_size", 1, 100_000),
        # Minimum pause between any two requests to the same address. `authorize` holds it to the approval's floor.
        min_seconds_between_probes_per_ip=_float(m.get("min_seconds_between_probes_per_ip", 15),
                                                 "measurement.min_seconds_between_probes_per_ip", 0, 3600),
        zmap_seed=seed,
        zmap_max_targets=None,   # set from the sample plan at run time
    )
    try:
        packet_rate_args(zmap_version, measurement.zmap_rate, measurement.zmap_probes)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    tp = _section(raw, "target_policy", {"exclusions_file", "exclusions_sha256", "approval_file", "hostname_policy"})
    hp = tp["hostname_policy"]
    if not isinstance(hp, dict) or set(hp) - {"mode", "suffixes"} or hp.get("mode") not in ("any_public", "suffix_allowlist"):
        raise ConfigError("target_policy.hostname_policy needs mode any_public|suffix_allowlist")
    suffixes = tuple(str(s).lower() for s in (hp.get("suffixes") or []))
    if hp["mode"] == "suffix_allowlist" and not suffixes:
        raise ConfigError("suffix_allowlist requires suffixes")
    excl_file = rel(tp["exclusions_file"])
    if not excl_file.is_file():
        raise ConfigError(f"exclusions file not found: {excl_file}")
    if sha256_file(excl_file) != str(tp["exclusions_sha256"]).lower():
        raise ConfigError("exclusions file checksum does not match target_policy.exclusions_sha256")
    read_exclusions(excl_file)

    d = _section(raw, "dns", {"resolvers", "timeout", "network_timeout", "retries", "threads", "max_cnames", "canary_name"},
                 {"resolvers", "timeout", "retries", "threads", "max_cnames"})
    resolvers = d["resolvers"]
    if not isinstance(resolvers, list) or not resolvers:
        raise ConfigError("dns.resolvers must be a non-empty list")
    for r in resolvers:
        host = str(r).rsplit(":", 1)[0] if ":" in str(r) else str(r)
        try:
            ip = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ConfigError(f"dns resolver {r!r} must be an IP[:port]") from exc
        # Institutional recursive resolvers are often private; loopback/multicast/unspecified/link-local never are.
        if ip.version != 4 or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_reserved:
            raise ConfigError(f"dns resolver {r!r} must be a routable unicast IPv4 address")
    dns = SimpleNamespace(
        resolvers=tuple(str(r) for r in resolvers),
        timeout=_float(d["timeout"], "dns.timeout", 1, 120),
        network_timeout=_float(d.get("network_timeout", 5), "dns.network_timeout", 1, 60),
        retries=_int(d["retries"], "dns.retries", 0, 10),
        threads=_int(d["threads"], "dns.threads", 1, 1000),
        max_cnames=_int(d["max_cnames"], "dns.max_cnames", 1, 32),
        canary_name=str(d.get("canary_name") or "example.com"),
    )

    h = _section(raw, "hostnames", {"max_candidates_per_ip"})
    tp_raw = _section({"tarpit": raw.get("tarpit") or {}}, "tarpit", {"min_open_ports", "tiny_window_below"}, set())
    sc = _section(raw, "sni_confirm", {"enabled", "max_per_endpoint"})
    fv = _section(raw, "favicon", {"enabled", "max_hostnames_per_endpoint", "workers", "max_icons_per_page",
                                   "max_unverified_names_per_endpoint", "offhost_icons", "stage_max_seconds", "store_images"},
                  {"enabled", "max_hostnames_per_endpoint", "workers", "max_icons_per_page"})
    oh = _section({"offhost_icons": fv.get("offhost_icons") or {"enabled": False}}, "offhost_icons",
                  {"enabled", "max_total_fetches", "max_per_host", "min_interval_seconds", "max_bytes"}, {"enabled"})
    if not isinstance(oh["enabled"], bool):
        raise ConfigError("favicon.offhost_icons.enabled must be true or false")
    f = _section(raw, "fetch", {"connect_timeout", "read_timeout", "total_timeout", "max_document_bytes", "max_favicon_bytes", "max_decoded_bytes", "max_redirects", "user_agent"})
    tr = _section(raw, "transparency", {"info_url", "contact", "anonymous"}, {"info_url", "contact"})
    anonymous = tr.get("anonymous", False)
    if not isinstance(anonymous, bool):
        raise ConfigError("transparency.anonymous must be true or false")
    if anonymous:
        # Explicit opt-out of the identifiable-traffic rule: nothing identifying may then appear in the user agent.
        if "@" in f["user_agent"] or "http" in f["user_agent"].lower():
            raise ConfigError("transparency.anonymous is set but fetch.user_agent still carries a contact or URL")
    elif tr["contact"] not in f["user_agent"] and tr["info_url"] not in f["user_agent"]:
        raise ConfigError("fetch.user_agent must embed the transparency contact or info URL")
    out = _section(raw, "output", {"dir", "max_listed_targets"}, {"dir"})
    ops = _section(raw, "operations", {"kill_switch_file", "egress_check_seconds", "min_free_mib"}, {"kill_switch_file"})
    bins = _section({"binaries": raw.get("binaries") or {}}, "binaries", {"zmap", "zgrab2", "zdns"}, set())

    checksum = hashlib.sha256(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest()
    cfg = ScanConfig(
        run_label=str(raw.get("run_label") or "scanner"),
        vantage=SimpleNamespace(
            id=str(vantage["id"]), interface=str(vantage["interface"]), source_ipv4=str(src),
            public_egress_ip=str(egress),
            gateway_mac=vantage.get("gateway_mac"),
            egress_check=egress_check, egress_check_urls=tuple(egress_urls),
        ),
        sample_fraction=fraction, sample_seed=seed, measurement=measurement,
        target_ips=target_ips, target_hostnames=target_hostnames, shards=shards,
        max_listed_targets=_int(out.get("max_listed_targets", 1_000_000), "output.max_listed_targets", 0, 10**9),
        egress_check_seconds=_int(ops.get("egress_check_seconds", 120), "operations.egress_check_seconds", 0, 3600),
        min_free_mib=_int(ops.get("min_free_mib", 512), "operations.min_free_mib", 16, 10**7),
        exclusions_file=excl_file, exclusions_sha256=str(tp["exclusions_sha256"]).lower(),
        approval_file=rel(tp["approval_file"]),
        hostname_mode=hp["mode"], hostname_suffixes=suffixes, dns=dns,
        max_candidates_per_ip=_int(h["max_candidates_per_ip"], "hostnames.max_candidates_per_ip", 1, 1000),
        sni_confirm=SimpleNamespace(enabled=bool(sc["enabled"]), max_per_endpoint=_int(sc["max_per_endpoint"], "sni_confirm.max_per_endpoint", 1, 20)),
        favicon=SimpleNamespace(
            enabled=bool(fv["enabled"]), max_hostnames_per_endpoint=_int(fv["max_hostnames_per_endpoint"], "favicon.max_hostnames_per_endpoint", 0, 20),
            workers=_int(fv["workers"], "favicon.workers", 1, 64), max_icons_per_page=_int(fv["max_icons_per_page"], "favicon.max_icons_per_page", 1, 20),
            store_images=_bool(fv.get("store_images", True), "favicon.store_images"),
            stage_max_seconds=_int(fv.get("stage_max_seconds", 7200), "favicon.stage_max_seconds", 1, 86400),
            max_unverified_names_per_endpoint=_int(fv.get("max_unverified_names_per_endpoint", 0), "favicon.max_unverified_names_per_endpoint", 0, 10),
            offhost=SimpleNamespace(
                enabled=oh["enabled"],
                max_total_fetches=_int(oh.get("max_total_fetches", 500), "favicon.offhost_icons.max_total_fetches", 1, 100000),
                max_per_host=_int(oh.get("max_per_host", 3), "favicon.offhost_icons.max_per_host", 1, 100),
                min_interval_seconds=_float(oh.get("min_interval_seconds", 1.0), "favicon.offhost_icons.min_interval_seconds", 0.0, 60.0),
                max_bytes=_int(oh.get("max_bytes", 262144), "favicon.offhost_icons.max_bytes", 1024, 2 * 2**20))),
        fetch=SimpleNamespace(
            connect_timeout=_float(f["connect_timeout"], "fetch.connect_timeout", 0.5, 60),
            read_timeout=_float(f["read_timeout"], "fetch.read_timeout", 0.5, 120),
            total_timeout=_float(f["total_timeout"], "fetch.total_timeout", 1, 300),
            max_document_bytes=_int(f["max_document_bytes"], "fetch.max_document_bytes", 1024, 16 * 2**20),
            max_favicon_bytes=_int(f["max_favicon_bytes"], "fetch.max_favicon_bytes", 1024, 8 * 2**20),
            max_decoded_bytes=_int(f["max_decoded_bytes"], "fetch.max_decoded_bytes", 1024, 64 * 2**20),
            max_redirects=_int(f["max_redirects"], "fetch.max_redirects", 0, 10),
            user_agent=str(f["user_agent"]),
            retry_statuses=(429, 503), max_retries=1, retry_after_cap=2.0),
        transparency=SimpleNamespace(info_url=str(tr["info_url"]), contact=str(tr["contact"]), anonymous=anonymous),
        output_dir=rel(out["dir"]), kill_switch_file=rel(ops["kill_switch_file"]),
        binaries=SimpleNamespace(zmap=bins.get("zmap", "zmap"), zgrab2=bins.get("zgrab2", "zgrab2"), zdns=bins.get("zdns", "zdns")),
        tarpit=SimpleNamespace(min_open_ports=_int(tp_raw.get("min_open_ports", 4), "tarpit.min_open_ports", 3, 20),
                               tiny_window_below=_int(tp_raw.get("tiny_window_below", 246), "tarpit.tiny_window_below", 1, 4096)),
        checksum=checksum, raw=raw,
    )
    if require_approval:
        cfg = authorize(cfg)
    return cfg


def _read_record(path: Path) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    return json.loads(text) if Path(path).suffix.lower() == ".json" else yaml.safe_load(text)


def _normalized_approval_path(path: Path) -> Path:
    """YAML turns an unquoted ISO timestamp into a datetime, which the shared loader rejects.

    Return a path the loader can read: the original when no fix is needed, otherwise a
    normalized JSON copy next to nothing permanent (temp dir). The original file is what is
    checksummed and recorded.
    """
    try:
        data = _read_record(path)
    except (OSError, ValueError, yaml.YAMLError):
        return path          # let load_approval report the read error
    if isinstance(data, dict) and hasattr(data.get("valid_until"), "isoformat"):
        import tempfile
        data = {**data, "valid_until": data["valid_until"].isoformat()}
        tmp = Path(tempfile.mkdtemp(prefix="scanner-approval-")) / "approval.json"
        tmp.write_text(json.dumps(data, default=str), encoding="utf-8")
        return tmp
    return path


def authorize(cfg: ScanConfig) -> ScanConfig:
    """Fail closed unless the approval record covers exactly what this config will do."""
    try:
        approval = load_approval(_normalized_approval_path(cfg.approval_file))
        require_operation(approval, OP_RESOLUTION)
        if cfg.favicon.enabled:
            require_operation(approval, OP_FAVICON)
            if cfg.favicon.offhost.enabled:
                require_operation(approval, OP_OFFHOST_ICONS)
    except ApprovalError as exc:
        raise ConfigError(f"not authorized: {exc}") from exc
    if approval.exclusions_checksum.lower() != cfg.exclusions_sha256:
        raise ConfigError("not authorized: approval exclusions_checksum differs from the configured exclusions file")
    if cfg.measurement.zmap_rate > approval.max_rate_per_second:
        raise ConfigError("not authorized: zmap_rate exceeds the approval's max_rate_per_second")
    try:
        floor = float(_read_record(cfg.approval_file).get("min_seconds_between_probes_per_ip", MIN_PACE_SECONDS))
    except (TypeError, ValueError) as exc:
        raise ConfigError("not authorized: approval min_seconds_between_probes_per_ip must be a number") from exc
    if cfg.measurement.min_seconds_between_probes_per_ip < floor:
        raise ConfigError(f"not authorized: measurement.min_seconds_between_probes_per_ip is below the approved {floor:g} s")
    outside = sorted(set(cfg.measurement.ports) - set(approval.ports))
    if outside:
        raise ConfigError(f"not authorized: ports outside approval: {outside}")
    if cfg.vantage.public_egress_ip not in approval.source_addresses:
        raise ConfigError("not authorized: vantage.public_egress_ip is not an approved source address")
    if cfg.transparency.info_url.strip() != approval.transparency_url.strip()             or cfg.transparency.contact.strip() != approval.opt_out_contact.strip():
        raise ConfigError("not authorized: transparency info_url/contact differ from the approval's transparency_url/opt_out_contact")
    if not {"http", "https"} <= set(approval.protocols):
        raise ConfigError("not authorized: approval must list both http and https protocols")
    try:
        max_fraction = float(_read_record(cfg.approval_file)["max_sample_fraction"])
    except (KeyError, TypeError, ValueError, OSError, yaml.YAMLError) as exc:
        raise ConfigError("not authorized: approval record has no numeric max_sample_fraction") from exc
    if not 0 < max_fraction <= 1:
        raise ConfigError("not authorized: approval max_sample_fraction must be in (0, 1]")
    if cfg.sample_fraction > max_fraction:
        raise ConfigError("not authorized: sample.fraction exceeds the approval's max_sample_fraction")
    from dataclasses import replace
    return replace(cfg, approval=approval, max_sample_fraction=max_fraction, approval_sha256=sha256_file(cfg.approval_file))
