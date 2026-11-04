"""Host bootstrap: the files it references exist and the resolver template carries the required settings."""
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "run" / "bootstrap-host.sh"

UNBOUND_REQUIRED = {
    "interface": "127.0.0.1", "port": "53", "do-ip6": "no", "num-threads": "8",
    "msg-cache-slabs": "8", "rrset-cache-slabs": "8", "infra-cache-slabs": "8", "key-cache-slabs": "8",
    "msg-cache-size": "1g", "rrset-cache-size": "2g", "outgoing-range": "692", "num-queries-per-thread": "346",
    "so-reuseport": "yes", "outgoing-port-permit": "60000-65535", "outgoing-port-avoid": "0-59999",
    "qname-minimisation": "yes", "use-syslog": "no", "verbosity": "0", "log-queries": "no",
    "log-replies": "no", "log-servfail": "no",
}


def unbound_settings():
    out = {}
    for line in (ROOT / "run" / "unbound" / "scanner.conf").read_text().splitlines():
        m = re.match(r"^\s+([a-z0-9-]+):\s*(.+?)\s*$", line)
        if m:
            out.setdefault(m.group(1), []).append(m.group(2))
    return out


def test_unbound_template_keys():
    got = unbound_settings()
    for key, value in UNBOUND_REQUIRED.items():
        assert got.get(key) == [value], key
    assert got["access-control"] == ["0.0.0.0/0 refuse", "127.0.0.0/8 allow"]
    text = (ROOT / "run" / "unbound" / "scanner.conf").read_text()
    assert "access-control: 0.0.0.0/0 refuse" in text and "access-control: 127.0.0.0/8 allow" in text


def test_script_references_existing_files():
    text = SCRIPT.read_text()
    assert text.startswith("#!/usr/bin/env bash\n") and "set -euo pipefail" in text
    assert b"\r" not in SCRIPT.read_bytes()
    for rel in re.findall(r'\$REPO_ROOT/(run/[A-Za-z0-9_./-]+)', text):
        assert (ROOT / rel).exists(), rel
    assert (ROOT / "run" / "setup-wsl.sh").exists()
    assert (ROOT / "run" / "systemd" / "scanner.env.example").exists()
    for flag in ("--dry-run", "--no-upgrade", "--no-unbound", "--no-systemd", "--no-sysctl", "--no-logrotate"):
        assert flag in text


def test_script_settings():
    text = SCRIPT.read_text()
    for line in ("net.ipv4.ip_local_port_range = 10000 59999", "net.ipv4.tcp_tw_reuse = 1",
                 "net.ipv4.tcp_fin_timeout = 15", 'Unattended-Upgrade::Automatic-Reboot "false";',
                 "/etc/sysctl.d/90-scanner.conf", "/etc/security/limits.d/90-scanner.conf",
                 "$OP_USER soft nofile $NOFILE", "$OP_USER hard nofile $NOFILE", "NOFILE=65536"):
        assert line in text, line
    assert "deferred due to phasing" in text and "60000-65535" in text
    # The env file is never overwritten.
    assert re.search(r'if \[ -e "\$ENV_FILE" \]', text)


def test_units_have_open_file_limit():
    for unit in (ROOT / "run" / "systemd").glob("*.service"):
        assert "LimitNOFILE=65536" in unit.read_text(), unit.name


def test_bash_syntax_if_available():
    if os.name == "nt":
        return
    try:
        r = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, OSError):
        return
    assert r.returncode == 0, r.stderr


def test_coordinator_memory_limits_are_computed_from_ram():
    text = SCRIPT.read_text()
    assert "memory_limits" in text and "* 78 / 100" in text and "* 85 / 100" in text
    assert "MemoryHigh=" in text and "MemoryMax=" in text
