"""One human-edited settings file -> the config and the approval record, always consistent.

``settings.yaml`` holds everything a person decides: who to contact, which address the scanner uses, the
exclusion list, the caps and the approval details. ``apply`` turns it into ``config.yaml`` and
``approval.yaml`` and binds both to the exclusion list's checksum. The approval caps (``approval.max_*``)
are the approved values, kept separate from what a run asks for, so raising a run past them is refused.
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime
import ipaddress
import math
import re
from pathlib import Path
from typing import Any

import yaml

from scanner.internet import profile as prof

PLACEHOLDER = "REPLACE_ME"
SETTINGS_NAME, CONFIG_NAME, APPROVAL_NAME = "settings.yaml", "config.yaml", "approval.yaml"
MIN_PACE_SECONDS = 5.0                     # the shortest pause between two requests to one address that any approval may allow
ALLOWED_ADDRESSES = 3_702_258_432          # routable IPv4 after reserved space; the run recomputes the exact figure
ICON_SELECTIONS = ("first_image", "browser_models")
JAVASCRIPT_KEYS = ("enabled", "max_pages_per_shard", "page_timeout_seconds", "concurrency", "wait_ms")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

TEMPLATE = """\
# scanner settings. This is the ONE file to edit; config.yaml and approval.yaml are generated from it.
# `scanner apply` runs automatically before plan, doctor and run. Replace every REPLACE_ME.

scanner_name: {scanner_name}        # first word of the user agent
contact: {contact}                  # opt-out and abuse e-mail; someone must read it during the run
info_url: {info_url}                # public page: purpose, ports, tools, contact, how to opt out
incident_contact: {incident_contact}   # who is called if something goes wrong (default: contact)

host:
  public_ip: {public_ip}            # the address the Internet sees; must be an address your institution approved
  source_ip: {source_ip}            # leave empty if the host carries public_ip itself; behind NAT give the private address
  interface: {interface}            # network interface that owns source_ip
  egress_check: {egress_check}      # auto | nic (no outside lookup) | url (ask a public-IP service) | off
  gateway_mac: {gateway_mac}        # optional; detected when empty

scope:
  exclusions_file: {exclusions_file}   # one CIDR per line: the list from the network owner plus every opt-out
  ports: {ports}
  sample_fraction: {sample_fraction}   # share of routable IPv4; 0.000001 is a pilot of about 3,700 targets per port
  seed: {seed}
  rate_pps: {rate_pps}              # ZMap packets per second
  min_seconds_between_probes_per_ip: {pace}   # pause between any two requests to the same address
  overlap_tls_with_zmap: {overlap}   # auto | true | false. true: TLS starts while ZMap sweeps later ports (traffic = ZMap + ZGrab2)
  # max_connections_per_subnet: 4   # connections open at once to one /24 (IPv6 /48), 1 to 64; backs off on timeouts, 429 and 503
  # retry_after_max_hold_seconds: 30   # longest a network is left alone after a 429/503 with Retry-After, 0 to 900
  # subnet_wait_max_seconds: 120   # longest a request waits for room in its network before it is skipped unsent, 1 to 3600
  dns_resolver: {dns_resolver}      # resolver for PTR and name checks; a remote one sees every scanned address, a local recursive one (127.0.0.1) does not, but each authoritative server then sees queries from the scanner's address
  # Concurrency follows the cores, RAM and open-file limit of the host (see `scanner plan`). Set any of these to
  # fix it instead; a value set here always wins over the derived one, and a command-line flag wins over both.
  # zgrab_senders: 500                # connections per ZGrab2 process (1-1000)
  # zgrab_parallel_batches: 4         # ZGrab2 processes at once (1-64)
  # zgrab_batch_size: 20000           # addresses per ZGrab2 batch (1-100000)
  # dns_threads: 100                  # zdns threads (1-1000)
  # favicon_workers: 256              # favicon worker threads in all (1-8192)
  # favicon_processes: 4              # worker processes sharing the favicon requests
  # favicon_max_active_requests: 512  # favicon requests on the wire at once (1-8192)
  # favicon_stage_max_seconds: 86400  # time limit of the favicon stage (1-86400)
  try_unverified_names: false       # also request pages under certificate names that did not verify
  offhost_icons: false              # fetch icons hosted elsewhere (needs the approval to allow it); works with favicon_processes above 1
  # icon_selection: first_image       # first_image | browser_models: which declared icons are fetched; part of the config checksum
  # javascript:                       # render pages in a headless browser to find icons added by scripts; off unless enabled
  #   enabled: false
  #   max_pages_per_shard: 1000       # 1 to 10000000
  #   page_timeout_seconds: 20        # 1 to 120
  #   concurrency: auto               # 1 to 64; auto follows the cores and RAM of the host
  #   wait_ms: 1500                   # wait after load for scripts to add icons, 0 to 30000

approval:                           # copy these from the real approval; they cap what a run may ask for
  status: {approval_status}         # `blocked` until the approving authority has approved, then `approved`
  reference: {approval_reference}   # ticket or message reference of the approval
  valid_until: "{valid_until}"      # ISO 8601 with timezone, e.g. 2026-12-31T23:59:59+00:00
  max_rate_pps: {max_rate_pps}
  max_sample_fraction: {max_fraction}
  min_seconds_between_probes_per_ip: {approval_pace}   # the approved pause between requests to one address; never below 5
  data_handling: {data_handling}    # where raw output is kept, who may read it, when it is deleted

# resources:                          # optional; detected from the host when absent
#   cores: 8
#   memory_gb: 16
#   max_open_files: 65536

run:
  label: {label}
  output_dir: {output_dir}
  kill_switch_file: {kill_switch}   # `scanner stop` creates this file
  # prune_raw_keep_every: 50   # campaign: delete raw/ of each compacted shard except every 50th (0 or absent keeps all; changes the config checksum)
"""

DEFAULTS: dict[str, Any] = {
    "scanner_name": "research-scanner", "contact": PLACEHOLDER, "info_url": PLACEHOLDER, "incident_contact": '""',
    "public_ip": PLACEHOLDER, "source_ip": '""', "interface": "eth0", "egress_check": "auto", "gateway_mac": '""',
    "exclusions_file": "exclusions.txt", "ports": "[80, 443, 8080, 8090, 8443]", "sample_fraction": "0.000001",
    "seed": "4", "rate_pps": "100", "pace": "5", "overlap": "auto", "dns_resolver": PLACEHOLDER, "approval_status": "blocked",
    "approval_reference": PLACEHOLDER, "valid_until": PLACEHOLDER, "max_rate_pps": "100", "max_fraction": "0.000001", "approval_pace": "5",
    "data_handling": PLACEHOLDER, "label": "pilot", "output_dir": "runs", "kill_switch": "STOP",
}


class SettingsError(Exception):
    """Raised with a message a person can act on."""


def sha256_file(path: Path) -> str:
    with open(path, "rb") as fh:
        if hasattr(hashlib, "file_digest"):
            return hashlib.file_digest(fh, "sha256").hexdigest()
        h = hashlib.sha256()
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
        return h.hexdigest()


def write_settings(workdir: Path, answers: dict[str, Any], *, force: bool = False) -> Path:
    path = Path(workdir) / SETTINGS_NAME
    if path.exists() and not force:
        raise SettingsError(f"{path} already exists; edit it, or pass --force to overwrite it")
    values = dict(DEFAULTS)
    for key, value in answers.items():
        if value is not None:
            values[key] = value
    path.parent.mkdir(parents=True, exist_ok=True)
    text = TEMPLATE.format(**{k: _scalar(k, v) for k, v in values.items() if k in DEFAULTS})
    text = _with_profile_answers(text, answers)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def _with_profile_answers(text: str, answers: dict[str, Any]) -> str:
    """Uncomment the concurrency and resource lines that the operator gave on the command line."""
    for key in prof.OVERRIDE_KEYS:
        value = answers.get(key)
        if value is None:
            continue
        shown = str(value).lower() if isinstance(value, bool) else str(value)
        pattern = re.compile(rf"^(\s*)(?:# )?{key}: [^#\n]*?(\s*#.*)?$", re.MULTILINE)
        text = pattern.sub(lambda m: f"{m.group(1)}{key}: {shown}{m.group(2) or ''}", text, count=1)
    for key in ("cores", "memory_gb", "max_open_files"):
        value = answers.get(key)
        if value is not None:
            text = re.sub(rf"^#   {key}: .*$", f"  {key}: {value}", text, count=1, flags=re.MULTILINE)
    if any(answers.get(k) is not None for k in ("cores", "memory_gb", "max_open_files")):
        text = text.replace("# resources:", "resources:", 1)
    for key in ("icon_selection", "max_connections_per_subnet", "retry_after_max_hold_seconds", "subnet_wait_max_seconds"):
        value = answers.get(key)
        if value is not None:
            text = re.sub(rf"^(\s*)# {key}: [^#\n]*?(\s*#.*)?$", lambda m: f"{m.group(1)}{key}: {value}{m.group(2) or ''}",
                          text, count=1, flags=re.MULTILINE)
    if answers.get("offhost_icons") is not None:
        shown = str(bool(answers["offhost_icons"])).lower()
        text = re.sub(r"^(\s*)offhost_icons: \w+", lambda m: f"{m.group(1)}offhost_icons: {shown}", text, count=1, flags=re.MULTILINE)
    given = {k[len("javascript_"):]: v for k, v in answers.items() if k.startswith("javascript_") and v is not None}
    if given:
        text = text.replace("  # javascript:", "  javascript:", 1)
        for key in JAVASCRIPT_KEYS:
            shown = given.get(key)
            shown = str(shown).lower() if isinstance(shown, bool) else shown
            pattern = re.compile(rf"^  #   {key}: ([^#\n]*?)(\s*#.*)?$", re.MULTILINE)
            text = pattern.sub(lambda m: f"    {key}: {m.group(1) if shown is None else shown}{m.group(2) or ''}", text, count=1)
    return text


def _scalar(key: str, value: Any) -> str:
    """Render a command-line answer as a YAML scalar; template defaults pass through unchanged."""
    if isinstance(value, str) and (value.startswith('"') or value.startswith("[") or value == PLACEHOLDER):
        return value
    if key in {"contact", "info_url", "incident_contact", "scanner_name", "dns_resolver", "public_ip", "source_ip",
               "approval_reference", "data_handling", "gateway_mac", "exclusions_file", "label", "output_dir", "kill_switch"}:
        return yaml.safe_dump(str(value), default_flow_style=True, width=10**6).splitlines()[0]
    return str(value)


def _problems(s: dict[str, Any]) -> list[str]:
    out: list[str] = []

    def todo(name: str, value: Any) -> None:
        if value in (None, "") or str(value).strip() == PLACEHOLDER:
            out.append(f"{name} is not filled in")
    for name, value in (("contact", s.get("contact")), ("info_url", s.get("info_url")),
                        ("host.public_ip", s.get("host", {}).get("public_ip")),
                        ("scope.dns_resolver", s.get("scope", {}).get("dns_resolver")),
                        ("approval.reference", s.get("approval", {}).get("reference")),
                        ("approval.valid_until", s.get("approval", {}).get("valid_until")),
                        ("approval.data_handling", s.get("approval", {}).get("data_handling"))):
        todo(name, value)
    return out


def load_settings(workdir: Path) -> dict[str, Any]:
    path = Path(workdir) / SETTINGS_NAME
    if not path.is_file():
        raise SettingsError(f"{path} not found; create it with `scanner init`")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise SettingsError(f"{path} is not valid YAML: {exc}") from exc
    for section in ("host", "scope", "approval", "run"):
        if not isinstance(data.get(section), dict):
            raise SettingsError(f"{path}: section `{section}` is missing")
    return data


def read_exclusions(path: Path) -> list[str]:
    if not path.is_file():
        raise SettingsError(f"exclusion list {path} not found. Give the list from the network owner (`scanner init --exclusions FILE`)")
    cidrs = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        text = line.split("#", 1)[0].strip()
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise SettingsError(f"{path} line {number}: `{text}` is not an address or CIDR block") from exc
        if net.version == 4:      # the scanner is IPv4-only; IPv6 entries stay in the file and are ignored
            cidrs.append(str(net))
    return cidrs


def add_exclusions(workdir: Path, cidrs: list[str], from_file: Path | None = None) -> tuple[Path, int]:
    """Append ranges to the exclusion list (opt-outs). Returns the file and how many were new."""
    settings = load_settings(workdir)
    path = _resolve(workdir, settings["scope"]["exclusions_file"])
    wanted = list(cidrs)
    if from_file is not None:
        wanted += read_exclusions(Path(from_file))
    existing = set(read_exclusions(path)) if path.is_file() else set()
    new = []
    for c in wanted:
        try:
            norm = str(ipaddress.ip_network(c, strict=False))
        except ValueError as exc:
            raise SettingsError(f"`{c}` is not an address or CIDR block") from exc
        if norm not in existing and norm not in new:
            new.append(norm)
    if new:
        body = path.read_text(encoding="utf-8") if path.is_file() else ""
        path.write_text(body + ("" if body.endswith("\n") or not body else "\n") + "\n".join(new) + "\n", encoding="utf-8", newline="\n")
    return path, len(new)


def _resolve(workdir: Path, value: str) -> Path:
    p = Path(str(value))
    return p if p.is_absolute() else Path(workdir) / p


def _example_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "run"


def _header(source: str) -> str:
    return (f"# GENERATED from {SETTINGS_NAME} by `scanner apply`. Do not edit this file: edit {SETTINGS_NAME}.\n"
            f"# Source: {source}\n")


def resolve_resources(s: dict[str, Any], cli: dict[str, Any] | None = None) -> tuple[prof.Resources, dict[str, Any]]:
    """The host resources and the explicit overrides: command-line flags over settings.yaml over detection."""
    cli = {k: v for k, v in (cli or {}).items() if v is not None}
    section = s.get("resources") or {}
    scope = s.get("scope", {})
    if not isinstance(section, dict):
        raise SettingsError("`resources` must hold cores, memory_gb and max_open_files")
    try:
        resources = prof.detect(cli.get("cores", section.get("cores")), cli.get("memory_gb", section.get("memory_gb")),
                                cli.get("max_open_files", section.get("max_open_files")))
    except ValueError as exc:
        raise SettingsError(f"resources: {exc}") from exc
    overrides: dict[str, Any] = {}
    for key in prof.OVERRIDE_KEYS:
        value = cli.get(key, scope.get(key))
        if isinstance(value, str) and value.strip().lower() == "auto":
            value = None
        overrides[key] = value
    return resources, overrides


def _whole(value: Any, low: int, high: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def _icon_settings(scope: dict[str, Any], cli: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    """The icon selection and the JavaScript block from settings.yaml, with command-line flags over them; None when not set."""
    selection = cli.get("icon_selection", scope.get("icon_selection"))
    if selection is not None and selection not in ICON_SELECTIONS:
        raise SettingsError(f"scope.icon_selection `{selection}` must be one of {', '.join(ICON_SELECTIONS)}")
    block = scope.get("javascript")
    given = {k[len("javascript_"):]: v for k, v in cli.items() if k.startswith("javascript_") and v is not None}
    if block is None and not given:
        return selection, None
    if block is not None and not isinstance(block, dict):
        raise SettingsError("scope.javascript must hold enabled, max_pages_per_shard, page_timeout_seconds, concurrency and wait_ms")
    js = {**(block or {}), **given}
    unknown = set(js) - set(JAVASCRIPT_KEYS)
    if unknown:
        raise SettingsError(f"scope.javascript has unknown setting {', '.join(sorted(map(str, unknown)))}")
    if not isinstance(js.get("enabled", False), bool):
        raise SettingsError("scope.javascript.enabled must be true or false")
    if "max_pages_per_shard" in js and not _whole(js["max_pages_per_shard"], 1, 10**7):
        raise SettingsError("scope.javascript.max_pages_per_shard must be a whole number from 1 to 10000000")
    timeout = js.get("page_timeout_seconds")
    if "page_timeout_seconds" in js and (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 120):
        raise SettingsError("scope.javascript.page_timeout_seconds must be a number from 1 to 120")
    if isinstance(js.get("concurrency"), str) and js["concurrency"].strip().lower() == "auto":
        js["concurrency"] = None
    if js.get("concurrency") is not None and not _whole(js["concurrency"], 1, 64):
        raise SettingsError("scope.javascript.concurrency must be auto or a whole number from 1 to 64")
    if "wait_ms" in js and not _whole(js["wait_ms"], 0, 30000):
        raise SettingsError("scope.javascript.wait_ms must be a whole number from 0 to 30000")
    return selection, {"enabled": False, **{k: v for k, v in js.items() if v is not None}}


def derived_plan(s: dict[str, Any], cli: dict[str, Any] | None = None) -> tuple[prof.Resources, dict[str, Any]]:
    resources, overrides = resolve_resources(s, cli)
    try:
        plan = prof.derive(resources.cores, resources.memory_gb, resources.open_files,
                           offhost_icons=bool((cli or {}).get("offhost_icons", s.get("scope", {}).get("offhost_icons", False))),
                           overrides=overrides)
    except ValueError as exc:
        text = str(exc)
        scope = s.get("scope", {})
        given = {k: v for k, v in (cli or {}).items() if v is not None}
        for name in overrides:
            if text.startswith(name) and name in scope and name not in given:
                text = f"scope.{text}"      # the bad value is in settings.yaml: name it the way the file does
                break
        raise SettingsError(text) from exc
    return resources, plan


def apply(workdir: Path, cli: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate settings.yaml and write config.yaml and approval.yaml. Returns a summary.

    ``cli`` holds command-line overrides (cores, memory_gb, max_open_files and the concurrency settings).
    """
    workdir = Path(workdir)
    s = load_settings(workdir)
    host, scope, appr, run = s["host"], s["scope"], s["approval"], s["run"]
    problems = _problems(s)
    if problems:
        raise SettingsError("settings.yaml needs attention:\n  - " + "\n  - ".join(problems))
    contact, info = str(s["contact"]).strip(), str(s["info_url"]).strip()
    if not EMAIL.match(contact):
        raise SettingsError(f"contact `{contact}` is not an e-mail address")
    if not info.lower().startswith(("https://", "http://")):
        raise SettingsError(f"info_url `{info}` must start with https:// (or http://)")
    for name, value in (("host.public_ip", host["public_ip"]), ("host.source_ip", host.get("source_ip") or host["public_ip"])):
        try:
            address = ipaddress.IPv4Address(str(value))
        except ValueError as exc:
            raise SettingsError(f"{name} `{value}` is not an IPv4 address") from exc
        if name == "host.public_ip" and not address.is_global:
            raise SettingsError(f"host.public_ip `{value}` is not a public address; give the address the Internet sees")
    ports = scope["ports"]
    if (not isinstance(ports, list) or not ports
            or not all(isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535 for p in ports)):
        raise SettingsError("scope.ports must be a list of port numbers, e.g. [80, 443]")
    try:
        valid_until = datetime.fromisoformat(str(appr["valid_until"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise SettingsError("approval.valid_until must be an ISO 8601 time, e.g. 2026-12-31T23:59:59+00:00") from exc
    if valid_until.tzinfo is None:
        raise SettingsError("approval.valid_until needs a timezone, e.g. +00:00")
    if appr["status"] == "approved" and valid_until <= datetime.now(UTC):
        raise SettingsError(f"approval.valid_until {appr['valid_until']} has passed")
    rate, fraction = float(scope["rate_pps"]), float(scope["sample_fraction"])
    if rate > float(appr["max_rate_pps"]):
        raise SettingsError(f"scope.rate_pps {rate:g} is above the approved approval.max_rate_pps {appr['max_rate_pps']}")
    if fraction > float(appr["max_sample_fraction"]):
        raise SettingsError(f"scope.sample_fraction {fraction:g} is above the approved approval.max_sample_fraction {appr['max_sample_fraction']}")
    approved_pace, pace = float(appr.get("min_seconds_between_probes_per_ip", MIN_PACE_SECONDS)), float(scope.get("min_seconds_between_probes_per_ip", MIN_PACE_SECONDS))
    if approved_pace < MIN_PACE_SECONDS:
        raise SettingsError(f"approval.min_seconds_between_probes_per_ip {approved_pace:g} is below the minimum of {MIN_PACE_SECONDS:g} s")
    if pace < approved_pace:
        raise SettingsError(f"scope.min_seconds_between_probes_per_ip {pace:g} is below the approved {approved_pace:g} s")
    overlap = scope.get("overlap_tls_with_zmap", "auto")
    if not isinstance(overlap, bool) and str(overlap).strip().lower() != "auto":
        raise SettingsError("scope.overlap_tls_with_zmap must be auto, true or false")
    cli_flags = {k: v for k, v in (cli or {}).items() if v is not None}
    subnet_cap = cli_flags.get("max_connections_per_subnet", scope.get("max_connections_per_subnet"))
    if subnet_cap is not None and (not isinstance(subnet_cap, int) or isinstance(subnet_cap, bool) or not 1 <= subnet_cap <= 64):
        raise SettingsError("scope.max_connections_per_subnet must be a whole number from 1 to 64")
    timing = {}
    for key, lo, hi in (("retry_after_max_hold_seconds", 0, 900), ("subnet_wait_max_seconds", 1, 3600)):
        value = cli_flags.get(key, scope.get(key))
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not lo <= value <= hi:
            raise SettingsError(f"scope.{key} must be a number from {lo} to {hi}")
        timing[key] = value
    if appr["status"] not in ("blocked", "approved"):
        raise SettingsError("approval.status must be `blocked` or `approved`")
    excl_path = _resolve(workdir, scope["exclusions_file"])
    entries = read_exclusions(excl_path)
    digest = sha256_file(excl_path)

    public_ip = str(host["public_ip"])
    source_ip = str(host.get("source_ip") or public_ip)
    check = str(host.get("egress_check") or "auto")
    if check == "auto":
        check = "nic" if source_ip == public_ip else "url"
    if check not in ("nic", "url", "off"):
        raise SettingsError("host.egress_check must be auto, nic, url or off")
    offhost = cli_flags.get("offhost_icons", scope.get("offhost_icons", False))
    if not isinstance(offhost, bool):
        raise SettingsError("scope.offhost_icons must be true or false")
    icon_selection, javascript = _icon_settings(scope, cli_flags)
    resources, plan = derived_plan(s, cli)
    if not prof.fits_open_files(plan, resources.open_files):
        raise SettingsError(f"the plan needs {prof.file_demand(plan)} open descriptors but only "
                            f"{int(prof.OPEN_FILE_FRACTION * resources.open_files)} of the limit of {resources.open_files} may be used; "
                            "lower the concurrency settings or raise the open-file limit")
    overlap = plan["overlap_tls_with_zmap"]
    workers, processes = plan["favicon_workers"], plan["favicon_processes"]
    if isinstance(processes, bool) or not isinstance(processes, int) or not 1 <= processes <= 64:
        raise SettingsError(f"scope.favicon_processes `{processes}` must be a whole number from 1 to 64")
    if processes > int(workers):
        raise SettingsError(f"scope.favicon_processes `{processes}` cannot exceed scope.favicon_workers `{workers}`")
    probes = 1
    targets = ALLOWED_ADDRESSES * fraction
    runtime = int(min(7 * 24 * 3600, max(3600, math.ceil(targets * probes / rate * 1.5) + 600)))

    base = yaml.safe_load((_example_dir() / "config.example.yaml").read_text(encoding="utf-8"))
    base["run_label"] = str(run["label"])
    base["vantage"] = {"id": str(s.get("scanner_name", "scanner")), "interface": str(host["interface"]),
                       "source_ipv4": source_ip, "public_egress_ip": public_ip, "egress_check": check}
    if host.get("gateway_mac"):
        base["vantage"]["gateway_mac"] = str(host["gateway_mac"])
    base["sample"] = {"fraction": fraction, "seed": int(scope["seed"])}
    if int(scope.get("shards", 1)) > 1:
        base["sample"]["shards"] = int(scope["shards"])     # run with `campaign`: one bounded run per shard
    m = base["measurement"]
    m.update(ports=[int(p) for p in scope["ports"]], zmap_rate=int(rate), zmap_probes=probes, zmap_max_runtime=runtime,
             min_seconds_between_probes_per_ip=pace, overlap_tls_with_zmap=overlap, zgrab_senders=plan["zgrab_senders"],
             zgrab_parallel_batches=plan["zgrab_parallel_batches"], zgrab_batch_size=plan["zgrab_batch_size"])
    if subnet_cap is not None:
        m["max_connections_per_subnet"] = subnet_cap
    m.update(timing)
    base["target_policy"].update(exclusions_file=str(scope["exclusions_file"]), exclusions_sha256=digest, approval_file=APPROVAL_NAME)
    if scope.get("exclusions_overlay_file"):
        base["target_policy"]["exclusions_overlay_file"] = str(scope["exclusions_overlay_file"])
    base["dns"]["resolvers"] = [str(scope["dns_resolver"])]
    base["dns"]["threads"] = plan["dns_threads"]
    f = base["favicon"]
    f.update(workers=int(workers), processes=processes, stage_max_seconds=plan["favicon_stage_max_seconds"],
             max_active_requests=plan["favicon_max_active_requests"],
             max_unverified_names_per_endpoint=2 if scope.get("try_unverified_names") else 0)
    f["offhost_icons"] = {**f.get("offhost_icons", {}), "enabled": offhost}
    if icon_selection is not None:
        f["icon_selection"] = icon_selection
    if javascript is not None:
        f["javascript"] = javascript
    base["fetch"]["user_agent"] = f"{s.get('scanner_name', 'research-scanner')} (+{info}; contact {contact})"
    base["transparency"] = {"info_url": info, "contact": contact}
    base["output"] = {"dir": str(run["output_dir"])}
    keep_raw = run.get("prune_raw_keep_every", 0)
    if isinstance(keep_raw, bool) or not isinstance(keep_raw, int) or keep_raw < 0:
        raise SettingsError(f"run.prune_raw_keep_every `{keep_raw}` must be a whole number, 0 or more")
    if keep_raw:
        base["output"]["prune_raw_keep_every"] = keep_raw     # left out when off, so the config checksum is the one it was
    base["operations"] = {**base.get("operations", {}), "kill_switch_file": str(run["kill_switch_file"])}

    operations = ["hostname_resolution", "favicon_fetch"] + (["offhost_icon_fetch"] if offhost else [])
    approval = {
        "schema_version": 1, "status": appr["status"], "approval_reference": str(appr["reference"]), "operations": operations,
        "approved_domains": ["any"], "target_population": "Seeded random sample of routable IPv4 space, excluding the exclusions file",
        "exclusions_checksum": digest, "ports": [int(p) for p in scope["ports"]], "protocols": ["http", "https"],
        "max_rate_per_second": int(float(appr["max_rate_pps"])), "max_sample_fraction": float(appr["max_sample_fraction"]),
        "min_seconds_between_probes_per_ip": approved_pace,
        "source_addresses": [public_ip], "transparency_url": info, "opt_out_contact": contact,
        "data_handling_reference": str(appr["data_handling"]),
        "incident_contact": str(s.get("incident_contact") or contact), "valid_until": str(appr["valid_until"]),
    }
    written = []
    for name, payload in ((CONFIG_NAME, base), (APPROVAL_NAME, approval)):
        text = _header(SETTINGS_NAME) + yaml.safe_dump(payload, sort_keys=False, width=10**6)
        target = workdir / name
        if not target.exists() or target.read_text(encoding="utf-8") != text:
            target.write_text(text, encoding="utf-8", newline="\n")
            written.append(name)
    return {"written": written, "resources": _resources_dict(resources), "derived_plan": plan, "exclusions_entries": len(entries), "exclusions_sha256": digest, "egress_check": check,
            "approval_status": appr["status"], "user_agent": base["fetch"]["user_agent"]}


def _resources_dict(r: prof.Resources) -> dict[str, Any]:
    return {"cores": r.cores, "memory_gb": None if r.memory_gb is None else round(r.memory_gb, 1), "max_open_files": r.open_files}
