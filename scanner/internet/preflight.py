"""scanner preflight: everything checkable before a single probe is sent.

Offline checks never touch the network; the DNS canary (skipped with
``offline=True``) sends one query through zdns to the configured resolvers.
Any ``fail`` blocks the run.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable

from scanner.zdns_runner import run_zdns
from scanner.internet.zmap_compat import supported, version_number

Executor = Callable[..., Any]
CAP_NET_RAW_BIT = 13


class PreflightFailed(RuntimeError):
    def __init__(self, report: dict[str, Any]) -> None:
        failed = [c["name"] for c in report["checks"] if c["status"] == "fail"]
        super().__init__(f"preflight failed: {', '.join(failed)}")
        self.report = report


def _check(name: str, ok: bool, detail: str, *, warn: bool = False) -> dict[str, str]:
    return {"name": name, "status": "pass" if ok else ("warn" if warn else "fail"), "detail": detail}


def _run(executor: Executor, cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        p = executor(cmd, capture_output=True, text=True, check=False, timeout=timeout)
        return getattr(p, "returncode", 0) or 0, ((getattr(p, "stdout", "") or "") + (getattr(p, "stderr", "") or "")).strip()
    except Exception as exc:
        return -1, f"{type(exc).__name__}: {exc}"


def detect_gateway_mac(executor: Executor) -> str | None:
    """MAC of the default gateway from the neighbour table (pinging it once if the entry is missing).

    ZMap run without -G stalls while it hunts for the gateway, so the MAC is always passed explicitly.
    """
    rc, out = _run(executor, ["ip", "-4", "route", "show", "default"])
    parts = out.split()
    if rc != 0 or "via" not in parts:
        return None
    gw = parts[parts.index("via") + 1]
    for attempt in range(2):
        rc, out = _run(executor, ["ip", "neigh", "show", gw])
        m = re.search(r"lladdr\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", out) if rc == 0 else None
        if m:
            return m.group(1).lower()
        if attempt == 0:
            _run(executor, ["ping", "-c", "1", "-W", "2", gw], timeout=10)
    return None


def _has_cap_net_raw() -> bool:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("CapEff:"):
                return bool(int(line.split()[1], 16) >> CAP_NET_RAW_BIT & 1)
    except OSError:
        pass
    return False


def _zmap_has_file_cap(path: str, executor: Executor) -> bool:
    rc, out = _run(executor, ["getcap", path])
    return rc == 0 and "cap_net_raw" in out


def running_zmap_pids(names: tuple[str, ...] = ("zmap",), proc: Path = Path("/proc")) -> list[int] | None:
    """Pids of processes whose command name is one of ``names`` (None where /proc is not available)."""
    if not proc.is_dir():
        return None
    wanted = {n[:15] for n in names}            # comm is cut at 15 characters
    me = os.getpid()
    found: list[int] = []
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) == me:
            continue
        try:
            if (entry / "comm").read_text(encoding="utf-8", errors="replace").strip() in wanted:
                found.append(int(entry.name))
        except OSError:
            continue
    return sorted(found)


def run_preflight(cfg: Any, splan: Any, *, run_dir: Path, executor: Executor = subprocess.run, offline: bool = False) -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    versions: dict[str, str] = {}

    checks.append(_check("approval_loaded", cfg.approval is not None, cfg.approval.approval_reference if cfg.approval else "no approval"))
    checks.append(_check("scanner_identifiable", not cfg.transparency.anonymous,
                         "traffic carries a contact/info URL" if not cfg.transparency.anonymous else
                         "ANONYMOUS: no contact in requests, recipients cannot opt out (accepted by the researcher; "
                         "conflicts with the project's identifiable-traffic control)", warn=True))
    if cfg.favicon.enabled:
        try:
            from scanner.internet.selftest import run_selftest
            control = run_selftest(cfg)
            checks.append(_check("favicon_positive_control", control["ok"],
                                 "; ".join(f'{c["case"]}={c["outcome"]}' for c in control["cases"]) + " (loopback only)"))
        except Exception as exc:
            checks.append(_check("favicon_positive_control", False, f"{type(exc).__name__}: {exc}"[:200]))
    try:
        mem_gib = next(int(l.split()[1]) for l in open("/proc/meminfo") if l.startswith("MemTotal")) / 2**20
        cores = os.cpu_count() or 1
        checks.append(_check("host_resources", mem_gib >= 2 and cores >= 2, f"{cores} cores, {mem_gib:.1f} GiB RAM (want >= 2 cores and 2 GiB)", warn=True))
    except (OSError, StopIteration, ValueError):
        pass
    others = running_zmap_pids(("zmap", Path(cfg.binaries.zmap).name))
    if others is not None:
        checks.append(_check("no_other_zmap", not others,
                             "no other zmap process is running" if not others else
                             f"zmap is already running on this host (pid {', '.join(map(str, others[:5]))}): a second sweep would exceed the approved "
                             "packet rate and could contact an address twice within the minimum spacing. Wait for it or stop it"))
    checks.append(_check("kill_switch_clear", not Path(cfg.kill_switch_file).exists(), f"{cfg.kill_switch_file} must not exist at start"))
    checks.append(_check("sample_nonempty", splan.allowed_addresses > 0 and splan.targets_per_port >= 1,
                         f"{splan.allowed_addresses} allowed addresses, {splan.targets_per_port} targets/port"))
    need = splan.seconds_per_port * 1.1 + cfg.measurement.zmap_cooldown
    checks.append(_check("zmap_runtime_covers_sample", cfg.measurement.zmap_max_runtime >= need,
                         f"max_runtime {cfg.measurement.zmap_max_runtime}s vs needed ~{need:.0f}s per port (truncation would give each port a different sample)"))

    for tool, binary in (("zmap", cfg.binaries.zmap), ("zgrab2", cfg.binaries.zgrab2), ("zdns", cfg.binaries.zdns)):
        path = shutil.which(binary)
        if not path:
            checks.append(_check(f"{tool}_present", False, f"{binary} not found on PATH"))
            continue
        if tool == "zgrab2":
            rc, out = _run(executor, [path, "tls", "--help"])
            ok = rc == 0
            versions[tool] = f"{path} (sha256 {_sha(path)[:16]})"
        else:
            rc, out = _run(executor, [path, "-C", "/dev/null", "--version"] if tool == "zmap" else [path, "--version"])
            ok = rc == 0 and bool(out)
            versions[tool] = out.splitlines()[0] if out else ""
        checks.append(_check(f"{tool}_present", ok, versions.get(tool) or out[:200]))
        if tool == "zmap" and ok and versions.get("zmap"):
            configured = cfg.measurement.zmap_version
            actual = version_number(versions["zmap"])
            checks.append(_check("zmap_version_supported", zmap_version_supported(versions["zmap"]) and actual == configured,
                                 f"{versions['zmap']}; configured {configured} (must match: pacing and CSV differ by release)"))
            if actual and actual.startswith("2.1."):
                checks.append(_check("zmap_legacy_clock", False,
                                     "2.1.x uses realtime for adaptive pacing; clock steps can stall it. Prefer pinned 4.4.0.", warn=True))
    info = Path(os.environ.get("SCANNER_BUILD_INFO", str(Path.home() / ".scanner" / "BUILD_INFO")))
    if info.is_file():
        versions["build_info"] = info.read_text(encoding="utf-8").strip()[:2000]
    else:
        checks.append(_check("build_info_present", False, f"{info} missing (written by setup-wsl.sh)", warn=True))

    zmap_path = shutil.which(cfg.binaries.zmap) or ""
    priv = _has_cap_net_raw() or (bool(zmap_path) and _zmap_has_file_cap(os.path.realpath(zmap_path), executor))
    checks.append(_check("raw_socket_privilege", priv, "CAP_NET_RAW via root, process capability or file capability on zmap"))

    iface, src = cfg.vantage.interface, cfg.vantage.source_ipv4
    rc, out = _run(executor, ["ip", "-4", "-o", "addr", "show", "dev", iface])
    checks.append(_check("interface_owns_source_ip", rc == 0 and re.search(rf"\b{re.escape(src)}/", out) is not None,
                         f"{iface}: {out[:160] or 'no output'}"))
    rc, out = _run(executor, ["ip", "-4", "route", "show", "default"])
    checks.append(_check("default_route", rc == 0 and iface in out, out[:160] or "no default route"))
    gateway_mac = cfg.vantage.gateway_mac or detect_gateway_mac(executor)
    checks.append(_check("gateway_mac", bool(gateway_mac),
                         f"{gateway_mac} ({'configured' if cfg.vantage.gateway_mac else 'detected'})" if gateway_mac
                         else "could not determine the default gateway MAC; set vantage.gateway_mac (ZMap stalls without -G)"))

    try:
        import resource
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        checks.append(_check("open_files_limit", soft >= 4096, f"RLIMIT_NOFILE soft={soft} (need >= 4096)"))
    except ImportError:
        checks.append(_check("open_files_limit", False, "resource module unavailable (this instrument runs on Linux)"))
    try:
        Path(cfg.output_dir).mkdir(parents=True, exist_ok=True)
        free = shutil.disk_usage(cfg.output_dir).free
        checks.append(_check("disk_space", free >= 1 << 30, f"{free // (1 << 20)} MiB free (need >= 1024)"))
    except OSError as exc:
        checks.append(_check("disk_space", False, str(exc)))

    if not offline:
        # The approval names the source address. A VPN that rotates servers silently changes it, so ask the
        # Internet what it sees and refuse to run if that is not the address the config (and approval) name.
        seen = current_egress(cfg, executor)
        how = {"url": "Internet sees", "nic": "interface carries", "off": "NOT CHECKED (vantage.egress_check: off); assumed"}[cfg.vantage.egress_check]
        checks.append(_check("egress_matches_approved_source", seen == cfg.vantage.public_egress_ip and cfg.vantage.egress_check != "off",
                             f"{how} {seen or 'nothing (lookup failed; if outbound HTTPS to the lookup services is blocked, set vantage.egress_check: nic or egress_check_urls)'}; "
                             f"config/approval name {cfg.vantage.public_egress_ip}", warn=cfg.vantage.egress_check == "off"))
        _, ans = run_zdns("A", [cfg.dns.canary_name], nameservers=list(cfg.dns.resolvers), run_dir=run_dir, threads=1,
                          timeout=cfg.dns.timeout, retries=cfg.dns.retries, binary=cfg.binaries.zdns, executor=executor)
        a = ans.get(cfg.dns.canary_name)
        ok = bool(a and a.status == "NOERROR" and any(t == "A" for t, _o, _v in a.records))
        checks.append(_check("dns_canary", ok, f"{cfg.dns.canary_name}: {a.status if a else 'no answer'} via {', '.join(cfg.dns.resolvers)}"))

    return {"ok": not any(c["status"] == "fail" for c in checks), "offline": offline, "checks": checks,
            "tool_versions": versions, "gateway_mac": gateway_mac}


DEFAULT_EGRESS_URLS = ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com")


def zmap_version_supported(version_line: str) -> bool:
    """Only releases with an explicit, tested rate/output contract are accepted."""
    number = version_number(version_line)
    return number is not None and supported(number)


def current_egress(cfg: Any, executor: Executor = subprocess.run, timeout: float = 10.0) -> str | None:
    """The public address scan traffic leaves from, according to ``vantage.egress_check``.

    url: ask an external service (first answer wins; several URLs so one blocked service is not fatal).
    nic: the host's own interface carries the public address (no NAT, no VPN): trusted while that address is still there.
    off: the operator vouches for the address; nothing is checked.
    """
    global _egress_max_stale
    mode = cfg.vantage.egress_check
    _egress_max_stale = float(getattr(cfg, "egress_check_seconds", 0) or 0)
    if mode == "off":
        return cfg.vantage.public_egress_ip
    if mode == "nic":
        rc, out = _run(executor, ["ip", "-4", "-o", "addr", "show", "dev", cfg.vantage.interface])
        owned = rc == 0 and re.search(rf"\b{re.escape(cfg.vantage.source_ipv4)}/", out) is not None
        return cfg.vantage.public_egress_ip if owned else None
    for url in cfg.vantage.egress_check_urls or DEFAULT_EGRESS_URLS:
        seen = _public_ip(url, timeout, tuple(getattr(getattr(cfg, "dns", None), "resolvers", ()) or ()))
        if seen:
            return seen
    return None


_EGRESS_DNS_TTL_MAX = 300.0
_egress_dns: dict[str, tuple[float, list[str]]] = {}
_egress_lock = threading.Lock()
_egress_worker: threading.Thread | None = None
_egress_max_stale = 0.0       # the run's egress check interval: a lookup younger than this stands in while a slow one lingers
_egress_last: tuple[float, str] | None = None      # (monotonic time, address) of the last successful lookup


def _split_nameserver(ns: str) -> tuple[str, int | None]:
    """Host and optional port of a resolver entry: ``192.0.2.1``, ``192.0.2.1:53``, ``::1``, ``[::1]:53``."""
    ns = ns.strip()
    if ns.startswith("["):
        host, _, rest = ns[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
    if ns.count(":") > 1:
        return ns, None                      # bare IPv6 address: no port can be meant
    host, _, port = ns.partition(":")
    return host, int(port) if port.isdigit() else None


def _resolve_a(host: str, resolvers: tuple[str, ...], lifetime: float) -> tuple[list[str], float]:
    """IPv4 addresses for ``host`` and the record TTL, through dnspython with a hard lifetime (glibc getaddrinfo has no timeout)."""
    import dns.resolver
    r = dns.resolver.Resolver(configure=not resolvers)
    if resolvers:
        parsed = [_split_nameserver(ns) for ns in resolvers]
        r.nameservers = [h for h, _p in parsed]
        ports = {p for _h, p in parsed if p is not None}
        if len(ports) == 1:
            r.port = ports.pop()
    r.timeout = min(lifetime, 3.0)
    r.lifetime = lifetime
    answer = r.resolve(host, "A")
    return sorted({a.address for a in answer}), float(getattr(answer.rrset, "ttl", _EGRESS_DNS_TTL_MAX))


def _egress_addresses(host: str, resolvers: tuple[str, ...], lifetime: float) -> list[str]:
    import ipaddress
    try:
        return [str(ipaddress.IPv4Address(host))]
    except ValueError:
        pass
    now = time.monotonic()
    with _egress_lock:
        hit = _egress_dns.get(host)
    if hit and hit[0] > now:
        return hit[1]
    ips, ttl = _resolve_a(host, resolvers, lifetime)
    if ips:
        with _egress_lock:
            _egress_dns[host] = (time.monotonic() + max(0.0, min(ttl, _EGRESS_DNS_TTL_MAX)), ips)
    return ips


def _fetch_text(url: str, resolvers: tuple[str, ...], timeout: float, _redirects: int = 1) -> str | None:
    """GET ``url`` over a socket to a resolved address, every step bounded by one deadline. No proxy.

    One redirect to the same host (the usual http to https upgrade) is followed; anything else is a failure.
    """
    import socket
    import ssl
    from urllib.parse import urljoin, urlsplit
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return None
    port = u.port or (443 if u.scheme == "https" else 80)
    deadline = time.monotonic() + timeout

    def left() -> float:
        return max(deadline - time.monotonic(), 0.05)

    addresses = _egress_addresses(u.hostname, resolvers, timeout / 2)[:3]
    for ip in addresses:
        if time.monotonic() >= deadline:
            break
        try:
            sock = socket.create_connection((ip, port), timeout=left())
            try:
                if u.scheme == "https":
                    sock = ssl.create_default_context().wrap_socket(sock, server_hostname=u.hostname)
                path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                sock.settimeout(left())
                req = (f"GET {path} HTTP/1.0\r\nHost: {u.netloc}\r\nUser-Agent: scanner-egress-check\r\n"
                       f"Accept: text/plain\r\nConnection: close\r\n\r\n")
                sock.sendall(req.encode("ascii"))
                raw = b""
                while len(raw) < 4096:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("egress lookup deadline")
                    sock.settimeout(left())
                    block = sock.recv(1024)
                    if not block:
                        break
                    raw += block
            finally:
                sock.close()
        except Exception:
            continue
        head, sep, body = raw.partition(b"\r\n\r\n")
        status = head.split(b" ", 2)[1:2]
        if sep and status == [b"200"]:
            return body[:64].decode("ascii", "replace").strip()
        if sep and status and status[0] in (b"301", b"302", b"307", b"308") and _redirects > 0:
            for line in head.split(b"\r\n")[1:]:
                name, _, value = line.partition(b":")
                if name.strip().lower() == b"location":
                    target = urlsplit(urljoin(url, value.decode("ascii", "replace").strip()))
                    if target.scheme in ("http", "https") and (target.hostname or "").lower() == u.hostname.lower():
                        return _fetch_text(target.geturl(), resolvers, max(deadline - time.monotonic(), 0.05), _redirects - 1)
                    break
        return None
    if addresses and u.hostname in _egress_dns:      # every cached address failed: look the name up afresh next time
        with _egress_lock:
            _egress_dns.pop(u.hostname, None)
    return None


def _public_ip(url: str = "https://api.ipify.org", timeout: float = 10.0, resolvers: tuple[str, ...] = (),
               max_stale: float | None = None) -> str | None:
    """The public IPv4 address this machine appears from, or None if it cannot be determined.

    Names are resolved with dnspython under an explicit lifetime and the connection goes to the literal address,
    so nothing here can block on glibc's resolver. At most one check thread exists; while an older one is still
    running the answer is the last good one if that is younger than ``max_stale`` seconds, otherwise None.
    """
    import ipaddress
    global _egress_worker, _egress_last
    found: list[str] = []

    def work() -> None:
        global _egress_last
        try:
            text = _fetch_text(url, resolvers, timeout)
            if text:
                found.append(str(ipaddress.IPv4Address(text)))
                _egress_last = (time.monotonic(), found[0])
        except Exception:
            pass

    with _egress_lock:
        if _egress_worker is not None and _egress_worker.is_alive():
            last = _egress_last
            limit = _egress_max_stale if max_stale is None else max_stale
            if last and limit > 0 and time.monotonic() - last[0] < limit:
                return last[1]
            return None
        t = _egress_worker = threading.Thread(target=work, daemon=True)
        t.start()
    t.join(timeout + 2)
    return found[0] if found else None


def _sha(path: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()
