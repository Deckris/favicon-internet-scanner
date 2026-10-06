"""One human-edited settings file -> the config and the approval record, always consistent.

``settings.yaml`` holds everything a person decides: who to contact, which address the scanner uses, the
exclusion list, the caps and the approval details. ``apply`` turns it into ``config.yaml`` and
``approval.yaml`` and binds both to the exclusion list's checksum. The approval caps (``approval.max_*``)
are the approved values, kept separate from what a run asks for, so raising a run past them is refused.
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from pathlib import Path
from typing import Any

import yaml

PLACEHOLDER = "REPLACE_ME"
SETTINGS_NAME, CONFIG_NAME, APPROVAL_NAME = "settings.yaml", "config.yaml", "approval.yaml"
ALLOWED_ADDRESSES = 3_702_258_432          # routable IPv4 after reserved space; the run recomputes the exact figure
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
  dns_resolver: {dns_resolver}      # resolver for PTR and name checks; it sees every scanned address
  try_unverified_names: false       # also request pages under certificate names that did not verify
  offhost_icons: false              # fetch icons hosted elsewhere (needs the approval to allow it)

approval:                           # copy these from the real approval; they cap what a run may ask for
  status: {approval_status}         # `blocked` until the approving authority has approved, then `approved`
  reference: {approval_reference}   # ticket or message reference of the approval
  valid_until: "{valid_until}"      # ISO 8601 with timezone, e.g. 2026-12-31T23:59:59+00:00
  max_rate_pps: {max_rate_pps}
  max_sample_fraction: {max_fraction}
  data_handling: {data_handling}    # where raw output is kept, who may read it, when it is deleted

run:
  label: {label}
  output_dir: {output_dir}
  kill_switch_file: {kill_switch}   # `scanner stop` creates this file
"""

DEFAULTS: dict[str, Any] = {
    "scanner_name": "research-scanner", "contact": PLACEHOLDER, "info_url": PLACEHOLDER, "incident_contact": '""',
    "public_ip": PLACEHOLDER, "source_ip": '""', "interface": "eth0", "egress_check": "auto", "gateway_mac": '""',
    "exclusions_file": "exclusions.txt", "ports": "[80, 443, 8080, 8090, 8443]", "sample_fraction": "0.000001",
    "seed": "4", "rate_pps": "100", "pace": "15", "dns_resolver": PLACEHOLDER, "approval_status": "blocked",
    "approval_reference": PLACEHOLDER, "valid_until": PLACEHOLDER, "max_rate_pps": "100", "max_fraction": "0.000001",
    "data_handling": PLACEHOLDER, "label": "pilot", "output_dir": "runs", "kill_switch": "STOP",
}


class SettingsError(Exception):
    """Raised with a message a person can act on."""


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_settings(workdir: Path, answers: dict[str, Any], *, force: bool = False) -> Path:
    path = Path(workdir) / SETTINGS_NAME
    if path.exists() and not force:
        raise SettingsError(f"{path} already exists; edit it, or pass --force to overwrite it")
    values = dict(DEFAULTS)
    for key, value in answers.items():
        if value is not None:
            values[key] = value
    path.parent.mkdir(parents=True, exist_ok=True)
    text = TEMPLATE.format(**{k: _scalar(k, v) for k, v in values.items()})
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


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
            cidrs.append(str(ipaddress.ip_network(text, strict=False)))
        except ValueError as exc:
            raise SettingsError(f"{path} line {number}: `{text}` is not an address or CIDR block") from exc
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


def apply(workdir: Path) -> dict[str, Any]:
    """Validate settings.yaml and write config.yaml and approval.yaml. Returns a summary."""
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
            ipaddress.IPv4Address(str(value))
        except ValueError as exc:
            raise SettingsError(f"{name} `{value}` is not an IPv4 address") from exc
    rate, fraction = float(scope["rate_pps"]), float(scope["sample_fraction"])
    if rate > float(appr["max_rate_pps"]):
        raise SettingsError(f"scope.rate_pps {rate:g} is above the approved approval.max_rate_pps {appr['max_rate_pps']}")
    if fraction > float(appr["max_sample_fraction"]):
        raise SettingsError(f"scope.sample_fraction {fraction:g} is above the approved approval.max_sample_fraction {appr['max_sample_fraction']}")
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
    offhost = bool(scope.get("offhost_icons", False))
    pace = float(scope.get("min_seconds_between_probes_per_ip", 15))
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
    m = base["measurement"]
    m.update(ports=[int(p) for p in scope["ports"]], zmap_rate=int(rate), zmap_probes=probes, zmap_max_runtime=runtime,
             min_seconds_between_probes_per_ip=pace)
    base["target_policy"].update(exclusions_file=str(scope["exclusions_file"]), exclusions_sha256=digest, approval_file=APPROVAL_NAME)
    base["dns"]["resolvers"] = [str(scope["dns_resolver"])]
    f = base["favicon"]
    f.update(workers=64, stage_max_seconds=86400,
             max_unverified_names_per_endpoint=2 if scope.get("try_unverified_names") else 0)
    f["offhost_icons"] = {**f.get("offhost_icons", {}), "enabled": offhost}
    base["fetch"]["user_agent"] = f"{s.get('scanner_name', 'research-scanner')} (+{info}; contact {contact})"
    base["transparency"] = {"info_url": info, "contact": contact}
    base["output"] = {"dir": str(run["output_dir"])}
    base["operations"] = {**base.get("operations", {}), "kill_switch_file": str(run["kill_switch_file"])}

    operations = ["hostname_resolution", "favicon_fetch"] + (["offhost_icon_fetch"] if offhost else [])
    approval = {
        "schema_version": 1, "status": appr["status"], "approval_reference": str(appr["reference"]), "operations": operations,
        "approved_domains": ["any"], "target_population": "Seeded random sample of routable IPv4 space, excluding the exclusions file",
        "exclusions_checksum": digest, "ports": [int(p) for p in scope["ports"]], "protocols": ["http", "https"],
        "max_rate_per_second": int(float(appr["max_rate_pps"])), "max_sample_fraction": float(appr["max_sample_fraction"]),
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
    return {"written": written, "exclusions_entries": len(entries), "exclusions_sha256": digest, "egress_check": check,
            "approval_status": appr["status"], "user_agent": base["fetch"]["user_agent"]}
