"""scanner orchestrator: IP -> ZMap -> ZGrab2 (TLS first) -> PTR/cert names -> ZDNS -> SNI confirm -> favicon.

Each stage is failure-isolated: an exception or tool failure is recorded under
``stage_errors`` and the run continues with whatever the stage managed to
produce, so one bad host or one bad stage never discards the rest of the run.
The manifest is written even when the run ends early (kill switch, error).
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

from scanner.internet import candidates as cand
from scanner.internet import enrich
from scanner.internet import favicon as fav
from scanner.internet import icon_store
from scanner.internet import pacing
from scanner.internet import population as pop
from scanner.internet import preflight as pre
from scanner.internet import tls as tlsmod
from scanner.internet.config import ConfigError, ScanConfig, read_exclusions, sha256_file
from scanner.internet.runner import ManagedExecutor
from scanner.models import ToolJob, write_jsonl
from scanner.safety import HostnamePolicyInput, ProductionPolicyInput, TargetPolicy
from scanner.zdns_runner import ptr_names, resolve, run_zdns
from scanner.zgrab_runner import ZGrabTarget, run_zgrab_batches
from scanner.zmap_runner import run_zmap

Executor = Callable[..., Any]
SCHEMA_VERSION = 1
INSTRUMENT_VERSION = "scanner.1"
WEB_PROTOCOLS = ("https", "http")
# TLS outcomes after which a plain-HTTP probe is still worth sending: the port did not prove it speaks TLS.
HTTP_FALLBACK = frozenset({tlsmod.NOT_TLS, tlsmod.CLOSED, tlsmod.RESET, tlsmod.TIMEOUT, tlsmod.OTHER})
# TLS outcomes that prove the port speaks TLS even though no handshake completed without SNI.
TLS_PROVEN = frozenset({tlsmod.ALERT_UNRECOGNIZED_NAME, tlsmod.ALERT_OTHER, tlsmod.VERSION, tlsmod.NO_CIPHER})
# DNS outcomes that say nothing about the mapping (maps_to_scanned_ip is then null, not false).
DNS_UNKNOWN = frozenset({"tool_error", "timeout", "servfail", "cname_loop", "too_many_cnames"})


def confirm_token(cfg: ScanConfig, splan: pop.SamplePlan) -> str:
    """Token ``plan`` prints and ``run`` must be given: ties a run to a reviewed plan."""
    blob = f"{cfg.checksum}|{cfg.approval_sha256}|{splan.total_targets or splan.targets_per_port}|{splan.shards}|{list(splan.ports)}|{splan.rate}"
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


def build_policy(cfg: ScanConfig) -> tuple[TargetPolicy, pop.SamplePlan, list[str]]:
    exclusions = read_exclusions(cfg.exclusions_file)
    if cfg.target_ips:                      # known targets: the population IS the listed addresses
        population = [f"{ip}/32" for ip in cfg.target_ips]
        allowed = pop.allowed_addresses(population, exclusions)
        splan = pop.SamplePlan(tuple(population), allowed, cfg.sample_fraction, allowed, tuple(cfg.measurement.ports),
                               cfg.measurement.zmap_rate, cfg.measurement.zmap_probes, 1, 0, allowed)
    else:
        population = pop.population_cidrs()
        splan = pop.plan(population, exclusions, fraction=cfg.sample_fraction, ports=cfg.measurement.ports,
                         rate=cfg.measurement.zmap_rate, probes=cfg.measurement.zmap_probes, shards=cfg.shards, shard=cfg.shard)
    policy = TargetPolicy.production(ProductionPolicyInput(
        approval_reference=cfg.approval.approval_reference if cfg.approval else "unapproved",
        population=tuple(population),
        hostname_policy=HostnamePolicyInput(cfg.hostname_mode, cfg.hostname_suffixes),
        exclusions=tuple(exclusions),
    ))
    return policy, splan, exclusions


def _scrub(value: Any) -> Any:
    """Replace lone surrogates (they cannot be encoded as UTF-8) so one hostile string cannot lose a whole output file."""
    if isinstance(value, str):
        return value.encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, (list, tuple)):
        return [_scrub(v) for v in value]
    if isinstance(value, dict):
        return {_scrub(k): _scrub(v) for k, v in value.items()}
    return value


def _jsonable(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, SimpleNamespace):
        return vars(value)
    return value


class _Stages:
    """Stage runner: failure isolation plus the stop conditions (kill switch, interrupt, approval expiry)."""

    def __init__(self, cfg: ScanConfig, run_dir: Path | None = None, guards: bool = False) -> None:
        self.cfg = cfg
        self.run_dir = run_dir
        self.guards = guards                 # live checks that touch the network (public IP); off for offline runs
        self.label = f"shard {cfg.shard + 1}/{cfg.shards}" if cfg.shards > 1 else "run"
        now = time.monotonic()
        self._next_egress = now + cfg.egress_check_seconds
        self._next_disk = now
        self._egress_unknown = 0
        self._guard_lock = threading.Lock()      # one lookup at a time, whichever thread polls first
        self.timings: dict[str, float] = {}
        self.errors: dict[str, str] = {}
        self.skipped: list[str] = []
        self.interrupted = False
        self.reason: str | None = None

    def killed(self) -> bool:
        if self.reason:
            return True
        if self.interrupted:
            self.reason = "interrupt"
        elif Path(self.cfg.kill_switch_file).exists():
            self.reason = "kill_switch"
        elif self.cfg.approval is not None and datetime.now(UTC) >= self.cfg.approval.valid_until:
            self.reason = "approval_expired"
        else:
            self.reason = self._guard_reason()
        return self.reason is not None

    def _guard_reason(self) -> str | None:
        """Conditions that must stop a long run: low disk, and a public IP that is no longer the approved source."""
        if not self._guard_lock.acquire(blocking=False):
            return None
        try:
            return self._guard_reason_locked()
        finally:
            self._guard_lock.release()

    def _guard_reason_locked(self) -> str | None:
        now = time.monotonic()
        if self.run_dir is not None and now >= self._next_disk:
            self._next_disk = now + 15
            try:
                if shutil.disk_usage(self.run_dir).free < self.cfg.min_free_mib << 20:
                    return "disk_low"
            except OSError:
                pass
        if self.guards and self.cfg.egress_check_seconds and now >= self._next_egress:
            self._next_egress = now + self.cfg.egress_check_seconds
            seen = pre.current_egress(self.cfg, timeout=6.0)
            if seen is None:
                self._egress_unknown += 1
                if self._egress_unknown >= 3:        # a single failed lookup is tolerated; three in a row is not
                    return "egress_unknown"
            else:
                self._egress_unknown = 0
                if seen != self.cfg.vantage.public_egress_ip:
                    return "egress_changed"
        return None

    def run(self, name: str, fn: Callable[[], Any], default: Any) -> Any:
        if self.killed():
            self.skipped.append(name)
            return default
        t = time.monotonic()
        print(f"[scanner {self.label}] {name}: start", file=sys.stderr, flush=True)
        try:
            return fn()
        except KeyboardInterrupt as exc:      # Ctrl-C, SIGTERM or SIGHUP (mapped to KeyboardInterrupt)
            self.interrupted = True
            self.errors[name] = f"interrupted: {exc}"[:200]
            return default
        except Exception as exc:
            self.errors[name] = f"{type(exc).__name__}: {exc}"[:500] + " | " + traceback.format_exc().splitlines()[-3].strip()[:200]
            return default
        finally:
            self.timings[name] = round(time.monotonic() - t, 3)
            print(f"[scanner {self.label}] {name}: {self.timings[name]} s", file=sys.stderr, flush=True)


def _install_signal_handlers() -> Callable[[], None]:
    """SIGTERM/SIGHUP behave like Ctrl-C so tools are killed and the manifest is still written."""
    if threading.current_thread() is not threading.main_thread():
        return lambda: None
    previous = {}

    def handler(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")
    for sig in (signal.SIGTERM, getattr(signal, "SIGHUP", None)):
        if sig is None:
            continue
        if sig == getattr(signal, "SIGHUP", None) and signal.getsignal(sig) == signal.SIG_IGN:
            continue                      # started under nohup: the operator asked us to survive a hangup
        try:
            previous[sig] = signal.signal(sig, handler)
        except (ValueError, OSError):
            pass

    def restore() -> None:
        for sig, h in previous.items():
            try:
                signal.signal(sig, h)
            except (ValueError, OSError):
                pass
    return restore


def run(
    cfg: ScanConfig,
    *,
    run_id: str | None = None,
    executor: Executor | None = None,
    fetcher: Any = None,
    skip_preflight: bool = False,
    offline_preflight: bool = False,
) -> Path:
    if cfg.approval is None:
        raise ConfigError("run requires an authorized config (approval not loaded)")
    started = datetime.now(UTC)
    wall = time.monotonic()
    policy, splan, exclusions = build_policy(cfg)
    shard_tag = f"-s{cfg.shard:03d}of{cfg.shards:03d}" if cfg.shards > 1 else ""
    run_id = run_id or f"scanner-{cfg.run_label}{shard_tag}-{started.strftime('%Y%m%dT%H%M%SZ')}"
    run_dir = Path(cfg.output_dir) / run_id
    if (run_dir / "manifest.json").exists():
        raise ConfigError(f"run directory {run_dir} already holds a run; refusing to mix two runs in one directory")
    for sub in ("raw", "normalized", "report"):
        (run_dir / sub).mkdir(parents=True, exist_ok=True)
    (run_dir / "config.snapshot.json").write_text(json.dumps(cfg.raw, indent=2, sort_keys=True, default=str), encoding="utf-8")

    st = _Stages(cfg, run_dir, guards=not offline_preflight)
    executor = executor or ManagedExecutor(cfg, run_dir, st.killed)
    restore_signals = _install_signal_handlers()
    jobs: list[ToolJob] = []
    counts: dict[str, Any] = {}
    try:
        report = pre.run_preflight(cfg, splan, run_dir=run_dir, executor=executor, offline=offline_preflight)
        (run_dir / "preflight.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        if not report["ok"] and not skip_preflight:
            raise pre.PreflightFailed(report)
        return _run_stages(cfg, st, policy, splan, exclusions, run_dir, executor, fetcher, jobs, counts, report,
                           started, wall, run_id)
    finally:
        restore_signals()


def _run_stages(cfg, st, policy, splan, exclusions, run_dir, executor, fetcher, jobs, counts, report, started, wall, run_id) -> Path:
    from scanner.internet.zmap_compat import output_args, packet_rate_args
    killed = st.killed
    pace = cfg.measurement.min_seconds_between_probes_per_ip
    gap = pacing.Gap(pace, killed)             # pause between steps that contact targets
    pacer = pacing.IpPacer(pace, killed)       # pause between HTTP requests to one address
    gateway_mac = cfg.vantage.gateway_mac or report.get("gateway_mac")
    # Stub manifest before the first probe: if the process is killed hard (OOM, WSL shutdown) the run still
    # leaves evidence of what was started and the run-once guard still sees it.
    (run_dir / "manifest.json").write_text(json.dumps({
        "schema_version": SCHEMA_VERSION, "experiment": "scanner", "run_id": run_id, "status": "started",
        "complete": False, "started_at": started.isoformat(), "config_checksum": cfg.checksum,
        "shard": {"index": cfg.shard, "of": cfg.shards},
        "approval_reference": cfg.approval.approval_reference if cfg.approval else None,
    }, indent=2), encoding="utf-8")
    mview = SimpleNamespace(**{**vars(cfg.measurement), "zmap_max_targets": splan.targets_per_port, "zmap_output_fields": "saddr,window,ttl",
                                                    "zmap_shards": cfg.shards, "zmap_shard": cfg.shard,
                                                    # one sender thread is plenty (and ZMap's default of one per core burns ~12 cores)
                                                    "zmap_sender_threads": 1,
                                                    "zmap_rate": packet_rate_args(cfg.measurement.zmap_version,
                                                        cfg.measurement.zmap_rate, cfg.measurement.zmap_probes),
                                                    "zmap_extra_args": output_args(cfg.measurement.zmap_version)})
    cfgview = SimpleNamespace(vantage=cfg.vantage, measurement=mview, fetch=cfg.fetch)

    # ---- Stage 0: the complete list of sampled targets (ZMap --dryrun prints targets, sends nothing) --
    sample_ips: list[str] = []

    def sample_stage() -> None:
        if splan.targets_per_port > cfg.max_listed_targets:
            counts["sample_listing"] = ("skipped: more than output.max_listed_targets targets in this shard; "
                                        "the seed, shard and fraction in the manifest regenerate the list")
            return
        raw = run_dir / "raw" / "zmap"
        raw.mkdir(parents=True, exist_ok=True)
        allow, block = raw / "sample-allowlist.txt", raw / "sample-blocklist.txt"
        allow.write_text("".join(f"{c}\n" for c in policy.target_cidrs()), encoding="utf-8")
        block.write_text("".join(f"{c}\n" for c in policy.exclusion_cidrs()), encoding="utf-8")
        cmd = ["zmap", "-C", "/dev/null", "-T", "1", "-p", str(cfg.measurement.ports[0]), "-w", str(allow), "-b", str(block),
               "-i", cfg.vantage.interface, "-S", cfg.vantage.source_ipv4, "-r", "100000", "--cooldown-time", "1",
               "--max-runtime", "600", "-O", "csv", "-f", "saddr", "-o", str(raw / "sample-dryrun.csv"),
               "-P", "1", "-n", str(splan.targets_per_port), "--seed", str(cfg.measurement.zmap_seed), "--dryrun"]
        cmd += output_args(cfg.measurement.zmap_version)
        if cfg.shards > 1:
            cmd += ["--shards", str(cfg.shards), "--shard", str(cfg.shard)]
        if gateway_mac:
            cmd += ["-G", gateway_mac]
        res = executor(cmd, capture_output=True, text=True, check=False)
        text = (getattr(res, "stdout", "") or "") + (getattr(res, "stderr", "") or "")
        found = sorted(set(re.findall(r"daddr: (\d+\.\d+\.\d+\.\d+)", text)), key=lambda x: tuple(int(o) for o in x.split(".")))
        sample_ips.extend(ip for ip in found if policy.check_ip(ip, stage="zmap", context="sample_list") is None)
        expected = splan.targets_per_port
        if st.guards and not expected * 0.99 <= len(sample_ips) <= expected * 1.0001 + 1:
            # Live runs only: a dry run that does not reproduce the plan means -n / --shards / the allowlist is not
            # doing what we think, so nothing is scanned. (The dry run sends nothing.)
            st.reason = "sample_list_mismatch"
            st.errors["sample_list"] = f"dry run listed {len(sample_ips)} targets, the plan expects {expected}"
        (run_dir / "scanned_ips.txt").write_text("".join(f"{ip}\n" for ip in sample_ips), encoding="utf-8")

    st.run("sample_list", sample_stage, None)
    counts["sample_listed"] = len(sample_ips)

    # ---- Stage 1: ZMap L4 discovery (same seed -> same sample on every port) ----------------
    l4: dict[int, list[str]] = {}
    synack: dict[tuple[str, int], dict[str, int | None]] = {}      # SYN-ACK window and TTL, free from the same probes

    def zmap_stage() -> None:
        for port in cfg.measurement.ports:
            if killed():
                st.skipped.append(f"zmap:{port}")
                continue
            # Every port probes the same seeded sample, so a pause between port runs keeps one address's SYNs apart.
            if not gap.wait():
                st.skipped.append(f"zmap:{port}")
                continue
            try:
                job, res = run_zmap(cfgview, policy, port, run_dir, executor=executor, gateway_mac=gateway_mac)
            except Exception as exc:
                st.errors[f"zmap:{port}"] = f"{type(exc).__name__}: {exc}"[:500]
                gap.mark()
                continue
            gap.mark()
            jobs.append(job)
            if job.error:
                st.errors[f"zmap:{port}"] = job.error[:500]
            l4[port] = sorted({r.target_ip for r in res})
            try:
                for ip_, fields in enrich.parse_synack_csv((run_dir / job.raw_path).read_text(encoding="utf-8", errors="replace")).items():
                    synack[(ip_, port)] = fields
            except OSError:
                pass

    st.run("zmap", zmap_stage, None)
    gap.mark()
    endpoints = sorted({(ip, port) for port, ips in l4.items() for ip in ips}, key=lambda e: (e[0], e[1]))
    counts["l4_per_port"] = {str(p): len(l4.get(p, [])) for p in cfg.measurement.ports}
    counts["l4_endpoints"] = len(endpoints)
    counts["l4_unique_ips"] = len({ip for ip, _ in endpoints})
    counts["sample_targets_per_port"] = splan.targets_per_port

    # ---- Stage 2: TLS first, direct IP (no SNI) ---------------------------------------------
    tls_direct: dict[tuple[str, int], tlsmod.TlsResult] = {}

    def tls_stage() -> None:
        def one(batch):
            return tlsmod.run_tls_batches(batch, mode="direct_ip", cfg=cfgview, policy=policy, run_dir=run_dir,
                                          binary=cfg.binaries.zgrab2, executor=executor)
        for j, res in pacing.paced_rounds([(ip, port, None) for ip, port in endpoints], lambda t: t[0], gap, one):
            jobs.extend(j)
            for r in res:
                if r.ip:
                    tls_direct[(r.ip, r.port)] = r

    st.run("tls_direct", tls_stage, None)

    # ---- Stage 3: plain HTTP only where TLS did not prove the port speaks TLS ---------------
    http_res: dict[tuple[str, int], Any] = {}

    def http_stage() -> None:
        targets = [ZGrabTarget(ip, None, port) for ip, port in endpoints
                   if (r := tls_direct.get((ip, port))) is not None and r.outcome in HTTP_FALLBACK]
        def one(batch):
            return run_zgrab_batches(batch, scheme="http", mode="direct_ip", cfg=cfgview, policy=policy,
                                     run_dir=run_dir, executor=executor)
        for j, res in pacing.paced_rounds(targets, lambda t: t.ip, gap, one):
            jobs.extend(j)
            for r in res:
                if r.target_ip:
                    http_res[(r.target_ip, r.port)] = r

    st.run("http_direct", http_stage, None)

    sni_res: dict[tuple[str, int, str], tlsmod.TlsResult] = {}
    sni_ok_endpoints: set[tuple[str, int]] = set()

    def protocol_of(ep: tuple[str, int]) -> str:
        t = tls_direct.get(ep)
        if t is None:
            return "not_attempted"
        if t.ok or ep in sni_ok_endpoints:
            return "https"                       # a TLS session was established (bare IP, or with SNI)
        if t.outcome in TLS_PROVEN:
            return "tls_unestablished"           # speaks TLS but wants a name we do not (yet) have
        h = http_res.get(ep)
        if h is not None and h.http_status is not None:
            return "http"
        return "tcp_only"

    # ---- Stage 4: PTR via ZDNS for every responsive IP --------------------------------------
    ptr_by_ip: dict[str, list[str]] = {}
    ptr_status: dict[str, str] = {}
    dns_kw = dict(nameservers=list(cfg.dns.resolvers), run_dir=run_dir, threads=cfg.dns.threads, timeout=cfg.dns.timeout,
                  retries=cfg.dns.retries, network_timeout=cfg.dns.network_timeout, binary=cfg.binaries.zdns, executor=executor)

    def ptr_stage() -> None:
        ips = sorted({ip for ip, _ in endpoints})
        j, ans = run_zdns("PTR", ips, **dns_kw)
        jobs.extend(j)
        for ip in ips:
            a = ans.get(ip)
            ptr_by_ip[ip] = ptr_names(a)
            ptr_status[ip] = a.status if a else "NO_OUTPUT"

    st.run("ptr", ptr_stage, None)

    # ---- Stage 5: hostname candidates = PTR U cert SAN/CN ----------------------------------
    names_by_ep: dict[tuple[str, int], cand.EndpointNames] = {}

    def cand_stage() -> None:
        for ep in endpoints:
            t = tls_direct.get(ep)
            names_by_ep[ep] = cand.build_endpoint_names(
                ptr_by_ip.get(ep[0], []), t.certificate if t else None, policy, max_candidates=cfg.max_candidates_per_ip,
                operator_names=cfg.target_hostnames)

    st.run("candidates", cand_stage, None)
    for ep in endpoints:       # endpoints must always have an entry, even if the stage failed
        names_by_ep.setdefault(ep, cand.EndpointNames())

    # ---- Stage 6: forward verification via ZDNS (A + AAAA, CNAME chains) -------------------
    resolutions: dict[str, Any] = {}

    def dns_stage() -> None:
        names = sorted({n for e in names_by_ep.values() for n in e.names})
        if not names:
            return
        ja, a_ans = run_zdns("A", names, **dns_kw)
        jobs.extend(ja)
        jb, aaaa_ans = run_zdns("AAAA", names, **dns_kw)
        jobs.extend(jb)
        for n in names:
            resolutions[n] = resolve(n, a_ans.get(n), aaaa_ans.get(n), max_cnames=cfg.dns.max_cnames)
        share = enrich.dns_unknown_share([r.status for r in resolutions.values()])
        counts["dns_unknown_share"] = round(share, 4)
        if len(names) >= 20 and share > 0.10:
            # Rate limiting or an unhealthy resolver would otherwise quietly turn real names into "unverified".
            st.errors["dns_degraded"] = f"{share:.0%} of {len(names)} forward lookups got no usable answer (servfail/timeout/tool error)"

    st.run("dns_forward", dns_stage, None)

    def dns_status(ip: str, host: str) -> str:
        return cand.judge_dns(resolutions.get(host), ip)

    def verified_names(ep: tuple[str, int]) -> list[str]:
        """Verified names for an endpoint, best-corroborated first: several sources, then PTR, then alphabetical."""
        names = names_by_ep[ep].names
        ok = [h for h in names if dns_status(ep[0], h) in cand.VERIFIED]
        return sorted(ok, key=lambda h: (-len(names[h]), cand.SRC_PTR not in names[h], h))

    # ---- Stage 7: optional SNI confirmation (batched, verified names only) -----------------
    sni_skipped: dict[tuple[str, int, str], str] = {}

    def sni_stage() -> None:
        targets: list[tuple[str, int, str | None]] = []
        for ep in endpoints:
            t = tls_direct.get(ep)
            for i, h in enumerate(verified_names(ep)):
                if not cfg.sni_confirm.enabled:
                    sni_skipped[(ep[0], ep[1], h)] = "disabled"
                elif t is None or t.outcome in (tlsmod.NOT_TLS, tlsmod.CONNECT_TIMEOUT):
                    sni_skipped[(ep[0], ep[1], h)] = "port_not_tls"
                elif i >= cfg.sni_confirm.max_per_endpoint:
                    sni_skipped[(ep[0], ep[1], h)] = "cap"
                else:
                    targets.append((ep[0], ep[1], h))
        if not targets:
            return
        def one(batch):
            return tlsmod.run_tls_batches(batch, mode="hostname_aware", cfg=cfgview, policy=policy, run_dir=run_dir,
                                          binary=cfg.binaries.zgrab2, executor=executor)
        for j, res in pacing.paced_rounds(targets, lambda t: t[0], gap, one):
            jobs.extend(j)
            for r in res:
                if r.ip and r.sni:
                    sni_res[(r.ip, r.port, r.sni)] = r
                    if r.ok:
                        sni_ok_endpoints.add((r.ip, r.port))

    st.run("sni_confirm", sni_stage, None)

    # ---- Stage 8: favicon acquisition (HTTP and HTTPS), bounded, sample-and-port-confined ---
    fav_res: dict[tuple[str, int, str | None], dict[str, Any]] = {}
    offhost_log: list[dict[str, Any]] = []

    def unverified_names(ep: tuple[str, int]) -> list[str]:
        """Candidate names that did NOT verify, best-corroborated first. Used only as Host/SNI on the scanned IP."""
        names = names_by_ep[ep].names
        bad = [h for h in names if dns_status(ep[0], h) not in cand.VERIFIED]
        return sorted(bad, key=lambda h: (-len(names[h]), cand.SRC_PTR not in names[h], h))

    def favicon_stage() -> None:
        if not cfg.favicon.enabled:
            return
        fjobs: list[dict[str, Any]] = []
        for ep in endpoints:
            proto = protocol_of(ep)
            # A bare-IP request only makes sense where a bare-IP session works; a host that answered
            # only with SNI would just fail (and record a misleading direct-IP failure).
            if proto == "http" or (proto == "https" and tls_direct[ep].ok):
                fjobs.append({"scheme": proto, "ip": ep[0], "port": ep[1], "hostname": None})
            for h in verified_names(ep)[: cfg.favicon.max_hostnames_per_endpoint]:
                sni = sni_res.get((ep[0], ep[1], h))
                if proto == "http":
                    scheme = "http"
                elif proto == "https" and (tls_direct[ep].ok or (sni is not None and sni.ok)):
                    scheme = "https"
                else:
                    continue
                fjobs.append({"scheme": scheme, "ip": ep[0], "port": ep[1], "hostname": h})
            # Unverified names: same scanned ip:port, just a different Host/SNI. Recorded as unverified in the rows.
            if proto in ("http", "https", "tls_unestablished"):
                for h in unverified_names(ep)[: cfg.favicon.max_unverified_names_per_endpoint]:
                    fjobs.append({"scheme": "http" if proto == "http" else "https", "ip": ep[0], "port": ep[1], "hostname": h})
                    counts["favicon_jobs_unverified_names"] = counts.get("favicon_jobs_unverified_names", 0) + 1
        if not fjobs or not gap.wait():
            return
        fp = fav.fetch_policy(cfg, [j["ip"] for j in fjobs])
        f = fetcher or fav.make_fetcher(cfg, fp, fav.RedirectResolver(cfg.dns.resolvers, cfg.dns.timeout),
                                        {(j["ip"], j["port"]) for j in fjobs}, exclusions=exclusions, killed=killed,
                                        state_path=Path(cfg.output_dir) / f"campaign-{cfg.checksum[:12]}" / "offhost_state.json", pacer=pacer)
        deadline = time.monotonic() + cfg.favicon.stage_max_seconds
        store = icon_store.IconStore(run_dir / "favicons") if cfg.favicon.store_images else None

        def stop() -> bool:
            return killed() or time.monotonic() > deadline
        try:
            for rec in fav.run_favicon_stage(f, fjobs, workers=cfg.favicon.workers, max_icons=cfg.favicon.max_icons_per_page, killed=stop,
                                            icon_store=store):
                fav_res[(rec["ip"], rec["port"], rec.get("hostname"))] = rec
            skipped = sum(1 for r in fav_res.values() if r.get("favicon_outcome") == "skipped_kill_switch")
            if time.monotonic() > deadline and skipped:
                st.errors["favicon_deadline"] = f"stage cap of {cfg.favicon.stage_max_seconds} s reached; {skipped} of {len(fjobs)} lookups skipped"
        finally:
            if store is not None:
                counts["favicon_images_stored"] = len(store)
                counts["favicon_images_indexed"] = store.write_index(list(fav_res.values()))
            getattr(getattr(f, "offhost", None), "save_state", lambda: None)()
            third_party = getattr(getattr(f, "offhost", None), "log", None)
            if third_party:
                offhost_log.extend(third_party)
                sent = [e for e in third_party if not e["cached"] and e["outcome"] != "policy_refused"]
                counts["offhost_icon_requests"] = len(sent)
                counts["offhost_icon_logged"] = len(third_party)
                counts["offhost_icon_refused"] = sum(1 for e in third_party if e["outcome"] == "policy_refused")

    st.run("favicon", favicon_stage, None)

    # ---- Records (never allowed to prevent the manifest from being written) ----------------
    tool_errors = [j.job_id for j in jobs if j.error]      # tools that crashed or exited non-zero
    incomplete = bool(st.errors or st.skipped or tool_errors)
    try:
        rows, ep_rows = _build_rows(cfg, endpoints, tls_direct, http_res, protocol_of, ptr_by_ip, ptr_status,
                                    names_by_ep, resolutions, dns_status, sni_res, sni_skipped, fav_res, incomplete, synack)
    except Exception as exc:
        st.errors["records"] = f"{type(exc).__name__}: {exc}"[:500]
        rows, ep_rows = [], []
    rows, ep_rows = _scrub(rows), _scrub(ep_rows)
    normalized = run_dir / "normalized"
    checksums: dict[str, str] = {}
    try:
        _write_ip_results(run_dir / "ip_results.csv", sample_ips, ep_rows, rows)
    except Exception as exc:
        st.errors["ip_results"] = f"{type(exc).__name__}: {exc}"[:500]
    try:
        checksums["normalized/endpoints.jsonl"] = write_jsonl(normalized / "endpoints.jsonl", ep_rows)
        checksums["normalized/hostname_resolution.jsonl"] = write_jsonl(normalized / "hostname_resolution.jsonl", rows)
        checksums["normalized/tool_jobs.jsonl"] = write_jsonl(normalized / "tool_jobs.jsonl", jobs)
        if cfg.favicon.offhost.enabled:
            checksums["normalized/offhost_icon_fetches.jsonl"] = write_jsonl(normalized / "offhost_icon_fetches.jsonl", offhost_log)
        _write_csv(normalized / "hostname_resolution.csv", rows)
        checksums["normalized/hostname_resolution.csv"] = sha256_file(normalized / "hostname_resolution.csv")
        checksums["normalized/policy_refusals.jsonl"] = write_jsonl(normalized / "policy_refusals.jsonl", [r.as_dict() for r in policy.refusals])
    except Exception as exc:
        st.errors["write_outputs"] = f"{type(exc).__name__}: {exc}"[:500]
    for p in sorted(run_dir.rglob("*")):
        if p.is_file() and p.name != "manifest.json" and "report" not in p.parts:
            checksums[str(p.relative_to(run_dir)).replace("\\", "/")] = sha256_file(p)

    incomplete = bool(st.errors or st.skipped or tool_errors)      # again: the writers above may just have failed
    summary = _summarize(cfg, splan, endpoints, rows, ep_rows, counts, st, jobs)
    (run_dir / "report" / "summary.json").write_text(json.dumps(summary, indent=2, default=_jsonable), encoding="utf-8")
    (run_dir / "report" / "summary.md").write_text(_summary_md(summary), encoding="utf-8")
    checksums["report/summary.json"] = sha256_file(run_dir / "report" / "summary.json")

    finished = datetime.now(UTC)
    manifest = {
        "schema_version": SCHEMA_VERSION, "instrument_version": INSTRUMENT_VERSION, "experiment": "scanner",
        "run_id": run_id, "started_at": started.isoformat(), "finished_at": finished.isoformat(),
        "elapsed_seconds": round(time.monotonic() - wall, 3), "stage_seconds": st.timings,
        "stage_errors": st.errors, "stages_skipped": st.skipped, "abort_reason": st.reason,
        "anonymous_traffic": cfg.transparency.anonymous,
        "status": "finished", "complete": not (incomplete or st.reason or st.interrupted), "tool_job_errors": tool_errors,
        # "nothing answered" is only a finding when ZMap actually ran cleanly on every port
        "zero_responsive": counts.get("l4_endpoints", 0) == 0 and st.reason is None and not st.errors,
        "config_checksum": cfg.checksum, "approval_reference": cfg.approval.approval_reference if cfg.approval else None,
        "approval_sha256": cfg.approval_sha256, "approval_valid_until": cfg.approval.valid_until.isoformat() if cfg.approval else None,
        "exclusions_sha256": cfg.exclusions_sha256, "exclusion_count": len(exclusions),
        "shard": {"index": cfg.shard, "of": cfg.shards, "total_targets": splan.total_targets},
        "sample": {"fraction": cfg.sample_fraction, "seed": cfg.sample_seed, "target_ips": list(cfg.target_ips),
                   "target_hostnames": list(cfg.target_hostnames), "allowed_addresses": splan.allowed_addresses,
                   "targets_per_port": splan.targets_per_port, "ports": list(splan.ports), "rate_pps": splan.rate,
                   "probes": splan.probes, "population_cidrs": len(splan.population)},
        "vantage": {"id": cfg.vantage.id, "interface": cfg.vantage.interface, "source_ipv4": cfg.vantage.source_ipv4,
                    "gateway_mac": gateway_mac,
                    "public_egress_ip": cfg.vantage.public_egress_ip},
        "parameters": {"dns_resolvers": list(cfg.dns.resolvers), "dns_threads": cfg.dns.threads, "dns_timeout": cfg.dns.timeout,
                       "zmap_version": cfg.measurement.zmap_version, "zmap_cli_rate": mview.zmap_rate,
                       "zmap_sender_threads": 1,
                       "dns_network_timeout": cfg.dns.network_timeout, "dns_retries": cfg.dns.retries,
                       "zgrab_senders": cfg.measurement.zgrab_senders, "zgrab_batch_size": cfg.measurement.zgrab_batch_size,
                       "zgrab_connect_timeout": cfg.measurement.zgrab_connect_timeout, "zgrab_target_timeout": cfg.measurement.zgrab_target_timeout,
                       "max_candidates_per_ip": cfg.max_candidates_per_ip, "sni_confirm": vars(cfg.sni_confirm),
                       "favicon": vars(cfg.favicon), "fetch": vars(cfg.fetch)},
        "tools": report.get("tool_versions", {}), "stage_counts": counts, "tool_job_counts": _job_counts(jobs),
        "output_checksums": checksums, "limitations": LIMITATIONS,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, default=_jsonable), encoding="utf-8")
    return run_dir


LIMITATIONS = (
    "Single vantage, single observation window; results describe what this vantage could observe at that time.",
    "Hostname evidence is PTR plus certificate SAN/CN only; no CT, passive DNS, ASN or brand matching.",
    "A verified mapping means the name resolved to the scanned IP via the configured resolvers at query time.",
    "Wildcard certificate names are recorded as evidence but never queried.",
    "ZMap loss and rate limiting can miss responsive hosts; the sample is a seeded random subset of IPv4.",
    "Favicons are fetched only from scanned IPs and only on ports that answered the scan; other redirect targets are refused.",
    "The sample is the first N targets of ZMap's seeded permutation of the allowed space: well spread, but not documented as a simple random sample.",
    "protocol=https means a TLS handshake completed (bare IP or with SNI); it does not prove the service speaks HTTP.",
    "Approval rate limits cover ZMap packets only; ZGrab2, ZDNS and favicon concurrency are bounded by configuration, not by the approval.",
)


def _job_counts(jobs: list[ToolJob]) -> dict[str, int]:
    out: dict[str, int] = {}
    for j in jobs:
        out[j.tool] = out.get(j.tool, 0) + 1
    return out


def _cert_fields(t: tlsmod.TlsResult | None) -> dict[str, Any]:
    c = t.certificate if t else None
    return {
        "certificate_present": c is not None,
        "certificate_sha256": c.sha256 if c else None,
        "certificate_cn": c.subject_cn if c else None,
        "certificate_sans": list(c.san_dns[:50]) if c else [],
        "certificate_san_count": len(c.san_dns) if c else 0,
        "certificate_not_before": c.not_before if c else None,
        "certificate_not_after": c.not_after if c else None,
        "certificate_self_signed": c.self_signed if c else None,
        "certificate_expired": c.expired_at_observation if c else None,
        "certificate_not_yet_valid": c.not_yet_valid_at_observation if c else None,
        "certificate_parse_error": t.cert_parse_error if t else None,
    }


def _build_rows(cfg, endpoints, tls_direct, http_res, protocol_of, ptr_by_ip, ptr_status, names_by_ep,
                resolutions, dns_status, sni_res, sni_skipped, fav_res, incomplete, synack=None):
    synack = synack or {}
    rows: list[dict[str, Any]] = []
    ep_rows: list[dict[str, Any]] = []
    facts_by_ip: dict[str, list[dict[str, Any]]] = {}
    for ip_, port_ in endpoints:
        doc = fav_res.get((ip_, port_, None)) or {}
        facts_by_ip.setdefault(ip_, []).append({
            "protocol": protocol_of((ip_, port_)), "window": synack.get((ip_, port_), {}).get("window"),
            "doc_sha256": doc.get("document_body_sha256"), "doc_status": doc.get("http_status")})
    tarpit = {ip_: enrich.tarpit_assessment(f, len(cfg.measurement.ports), cfg.tarpit.min_open_ports, cfg.tarpit.tiny_window_below)
              for ip_, f in facts_by_ip.items()}
    for ep in endpoints:
        ip, port = ep
        t = tls_direct.get(ep)
        h = http_res.get(ep)
        names = names_by_ep[ep]
        direct_fav = fav_res.get((ip, port, None)) or {}
        base: dict[str, Any] = {
            "target_ip": ip, "port": port, "zmap_result": "synack",
            "protocol": protocol_of(ep), **tarpit[ip],
            "synack_window": synack.get(ep, {}).get("window"), "synack_ttl": synack.get(ep, {}).get("ttl"),
            "tls_status": "success" if t and t.ok else ("not_tls" if t and t.outcome == tlsmod.NOT_TLS else ("failed" if t else "not_attempted")),
            "tls_outcome": t.outcome if t else None,
            "tls_failure_reason": None if (t is None or t.ok) else t.error,
            "tls_version": t.tls_version if t else None, "tls_cipher": t.cipher_suite if t else None,
            **_cert_fields(t),
            "certificate_wildcards": sorted(names.wildcards),
            "http_zgrab_status": h.status if h else None, "http_status": h.http_status if h else None,
            "http_location": h.location if h else None, "http_error": h.error if h else None,
            "ptr_status": ptr_status.get(ip), "ptr_names": ptr_by_ip.get(ip, [])[:20], "ptr_name_count": len(ptr_by_ip.get(ip, [])),
            "run_incomplete": incomplete,
            "candidate_names_total": names.source_count, "candidate_names_truncated": names.truncated,
            "dropped_names": names.dropped[:50],
            "direct_favicon_outcome": direct_fav.get("favicon_outcome"), "direct_favicon_is_image": bool(direct_fav.get("favicon_is_image")),
            "direct_favicon_sha256": direct_fav.get("favicon_sha256"), "direct_favicon_file": direct_fav.get("favicon_file"),
            "direct_favicon_mmh3": direct_fav.get("favicon_mmh3"), "direct_favicon_url": direct_fav.get("favicon_url"),
            "direct_document_outcome": direct_fav.get("document_outcome"), "direct_document_status": direct_fav.get("http_status"),
            "direct_document_title": direct_fav.get("document_title"), "direct_document_body_sha256": direct_fav.get("document_body_sha256"),
            "direct_icon_declared_count": direct_fav.get("icon_declared_count"), "direct_icon_offhost_hosts": direct_fav.get("icon_offhost_hosts") or [],
            "direct_icon_embedded_images": direct_fav.get("icon_embedded_images"),
        }
        ep_rows.append({**base, "hostnames": sorted(names.names)})
        if not names.names:
            rows.append({**base, "hostname": None, "hostname_sources": [], "dns_status": None, "cname_chain": [],
                         "a_answers": [], "aaaa_answers": [], "maps_to_scanned_ip": None,
                         "sni_confirmation_attempted": False, "sni_confirmation_result": None, "sni_confirmation_outcome": None,
                         "sni_skipped_reason": None,
                         "sni_certificate_sha256": None, "sni_certificate_hostname_match": None,
                         "hostname_favicon_outcome": None, "hostname_favicon_is_image": False, "hostname_favicon_sha256": None, "hostname_favicon_file": None, "hostname_favicon_mmh3": None,
                         "hostname_favicon_url": None, "hostname_document_title": None, "hostname_icon_offhost_hosts": [],
                         "hostname_icon_embedded_images": None, "final_hostname_status": "no_hostname_evidence"})
            continue
        for host in sorted(names.names):
            res = resolutions.get(host)
            status = dns_status(ip, host)
            sources = names.names[host]
            sni = sni_res.get((ip, port, host))
            hf = fav_res.get((ip, port, host)) or {}
            rows.append({
                **base, "hostname": host, "hostname_sources": sorted(sources), "dns_status": status,
                "cname_chain": list(res.cname_chain) if res else [], "a_answers": list(res.a) if res else [],
                "aaaa_answers": list(res.aaaa) if res else [],
                "maps_to_scanned_ip": None if status in DNS_UNKNOWN else status in cand.VERIFIED,
                "sni_skipped_reason": sni_skipped.get((ip, port, host)),
                "sni_confirmation_attempted": sni is not None,
                "sni_confirmation_result": _sni_result(sni),
                "sni_confirmation_outcome": sni.outcome if sni else None,
                "sni_certificate_sha256": sni.certificate.sha256 if sni and sni.certificate else None,
                "sni_certificate_hostname_match": sni.certificate.hostname_matches if sni and sni.certificate else None,
                "hostname_favicon_outcome": hf.get("favicon_outcome"), "hostname_favicon_is_image": bool(hf.get("favicon_is_image")),
                "hostname_favicon_sha256": hf.get("favicon_sha256"), "hostname_favicon_file": hf.get("favicon_file"),
                "hostname_favicon_mmh3": hf.get("favicon_mmh3"), "hostname_favicon_url": hf.get("favicon_url"),
                "hostname_document_title": hf.get("document_title"), "hostname_icon_offhost_hosts": hf.get("icon_offhost_hosts") or [],
                "hostname_icon_embedded_images": hf.get("icon_embedded_images"),
                "final_hostname_status": cand.final_status(status, sources),
            })
    return rows, ep_rows


def _sni_result(sni: Any) -> str | None:
    """confirmed: handshake ok and the certificate covers the name; tls_ok_cert_mismatch: a default/shared cert came back."""
    if sni is None:
        return None
    if not sni.ok:
        return "failed"
    return "confirmed" if sni.certificate is not None and sni.certificate.hostname_matches else "tls_ok_cert_mismatch"


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = list(rows[0].keys())
    def cell(v: Any) -> Any:
        if isinstance(v, (list, dict, bool)):
            return json.dumps(v)
        if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", chr(9), chr(13)):
            return "'" + v        # neutralize spreadsheet formula injection from hostile certificate/PTR text
        return v

    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: cell(v) for k, v in r.items()})


def _write_ip_results(path: Path, sample_ips: list[str], ep_rows: list[dict[str, Any]], rows: list[dict[str, Any]]) -> None:
    """One row per sampled IP: did anything answer, on which ports, and what it gave us."""
    by_ip: dict[str, list[dict[str, Any]]] = {}
    for e in ep_rows:
        by_ip.setdefault(e["target_ip"], []).append(e)
    names_by_ip: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        if r["hostname"]:
            names_by_ip.setdefault(r["target_ip"], []).append(r)

    def key(ip: str) -> tuple[int, ...]:
        return tuple(int(o) for o in ip.split("."))

    out: list[dict[str, Any]] = []
    for ip in sorted(set(sample_ips) | set(by_ip), key=key):
        eps = sorted(by_ip.get(ip, []), key=lambda e: e["port"])
        hosts = names_by_ip.get(ip, [])
        verified = sorted({h["hostname"] for h in hosts if h["final_hostname_status"] == "verified"})
        other = sorted({f'{h["hostname"]}:{h["final_hostname_status"]}' for h in hosts if h["final_hostname_status"] != "verified"})
        out.append({
            "ip": ip,
            "responsive": "yes" if eps else "no",
            "open_ports": "|".join(str(e["port"]) for e in eps),
            "endpoints": "; ".join(
                f'{e["port"]}={e["protocol"]}' + (f'({e["tls_outcome"]})' if e["tls_outcome"] not in (None, "tls_success") else "")
                + (f'[http {e["http_status"]}]' if e["http_status"] else "") for e in eps),
            "ptr_names": "|".join(sorted({n for e in eps for n in e["ptr_names"]})),
            "verified_hostnames": "|".join(verified),
            "other_hostnames": "|".join(other),
            "certificate_cns": "|".join(sorted({e["certificate_cn"] for e in eps if e["certificate_cn"]})),
            "tarpit_suspect": "yes" if eps and eps[0]["tarpit_suspect"] else "no",
            "tarpit_confidence": (eps[0]["tarpit_confidence"] or "") if eps else "",
            "tarpit_signals": "|".join(eps[0]["tarpit_signals"]) if eps else "",
            "tarpit_reason": (eps[0]["tarpit_reason"] or "") if eps else "",
            "document_titles": "|".join(sorted({e["direct_document_title"] for e in eps if e["direct_document_title"]}
                                               | {h["hostname_document_title"] for h in hosts if h["hostname_document_title"]})),
            "icon_offhost_hosts": "|".join(sorted({x for e in eps for x in e["direct_icon_offhost_hosts"]}
                                                  | {x for h in hosts for x in h["hostname_icon_offhost_hosts"]})),
            # only real images: the hash of an HTML error page is not a favicon
            "favicon_sha256": "|".join(sorted({e["direct_favicon_sha256"] for e in eps if e["direct_favicon_is_image"] and e["direct_favicon_sha256"]}
                                              | {h["hostname_favicon_sha256"] for h in hosts if h["hostname_favicon_is_image"] and h["hostname_favicon_sha256"]})),
        })
    _write_csv(path, out) if out else path.write_text("ip,responsive,open_ports,endpoints,ptr_names,verified_hostnames,other_hostnames,certificate_cns,tarpit_suspect,tarpit_confidence,tarpit_signals,tarpit_reason,document_titles,icon_offhost_hosts,favicon_sha256\n", encoding="utf-8")


def _tally(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        v = str(r.get(key))
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))


def _summarize(cfg, splan, endpoints, rows, ep_rows, counts, st, jobs) -> dict[str, Any]:
    named = [r for r in rows if r["hostname"]]
    ips_verified = {r["target_ip"] for r in named if r["final_hostname_status"] == "verified"}
    both = sum(1 for r in named if {"ptr"} < set(r["hostname_sources"]) and any(s.startswith("certificate") for s in r["hostname_sources"]))
    sni_ok = {(x["target_ip"], x["port"]) for x in rows if x["sni_confirmation_outcome"] == tlsmod.OK}
    sni_needed = sum(1 for r in ep_rows if r["tls_status"] == "failed" and (r["target_ip"], r["port"]) in sni_ok)
    return {
        "counts": counts,
        "protocol_by_endpoint": _tally(ep_rows, "protocol"),
        "tls_outcome_by_endpoint": _tally(ep_rows, "tls_outcome"),
        "final_hostname_status_by_row": _tally(rows, "final_hostname_status"),
        "dns_status_by_row": _tally(named, "dns_status"),
        "ips_with_verified_hostname": len(ips_verified),
        "unique_ips": counts.get("l4_unique_ips", 0),
        "hostname_rows_with_ptr_and_certificate": both,
        "tls_failed_but_sni_handshake_ok": sni_needed,
        "sni_confirmation_by_row": _tally([r for r in named if r["sni_confirmation_attempted"]], "sni_confirmation_result"),
        "favicon_direct_by_endpoint": _tally([r for r in ep_rows if r["direct_favicon_outcome"]], "direct_favicon_outcome"),
        "favicon_hostname_by_row": _tally([r for r in named if r["hostname_favicon_outcome"]], "hostname_favicon_outcome"),
        "tarpit_suspect_ips": len({r["target_ip"] for r in ep_rows if r["tarpit_suspect"]}),
        "tarpit_ips_by_confidence": _tally(list({r["target_ip"]: r for r in ep_rows if r["tarpit_confidence"]}.values()), "tarpit_confidence"),
        "icons_declared_on_other_hosts": len({(r["target_ip"], r["port"]) for r in ep_rows if r["direct_icon_offhost_hosts"]}
                                              | {(r["target_ip"], r["port"]) for r in named if r["hostname_icon_offhost_hosts"]}),
        "wildcard_certificates": sum(1 for r in ep_rows if r["certificate_wildcards"]),
        "stage_seconds": st.timings, "stage_errors": st.errors, "stages_skipped": st.skipped,
        "tool_job_counts": _job_counts(jobs),
        "warnings": _warnings(cfg, splan, counts, st),
    }


def _warnings(cfg, splan, counts, st) -> list[str]:
    out: list[str] = []
    total = counts.get("l4_endpoints", 0)
    listed = counts.get("sample_listed", 0)
    if "sample_listing" not in counts and listed != splan.targets_per_port and not st.reason:
        out.append(f"sample list has {listed} targets but the plan expected {splan.targets_per_port}; check raw/zmap/sample-*.")
    if st.reason:
        out.append(f"run stopped early ({st.reason}); outputs are partial, see stages_skipped.")
    if total == 0 and not st.reason:
        out.append("ZERO responsive endpoints: check egress/NAT (WSL2), ZMap interface/gateway settings and raw/stderr/*zmap*.txt.")
    elif total:
        for port, n in counts.get("l4_per_port", {}).items():
            rate = n / max(1, splan.targets_per_port)
            if rate < 0.003 and int(port) in (80, 443):
                out.append(f"port {port}: hit rate {rate:.4%} is far below typical Internet rates; scan may be impaired (NAT, loss, filtering).")
    if st.errors:
        out.append(f"{len(st.errors)} stage error(s) recorded; see manifest stage_errors.")
    return out


def _summary_md(s: dict[str, Any]) -> str:
    lines = ["# scanner run summary", ""]
    for k in ("counts", "protocol_by_endpoint", "tls_outcome_by_endpoint", "final_hostname_status_by_row", "dns_status_by_row",
              "sni_confirmation_by_row", "favicon_direct_by_endpoint", "favicon_hostname_by_row", "stage_seconds", "stage_errors"):
        lines += [f"## {k}", "```", json.dumps(s.get(k), indent=2, default=_jsonable), "```", ""]
    for k in ("ips_with_verified_hostname", "unique_ips", "hostname_rows_with_ptr_and_certificate", "tls_failed_but_sni_handshake_ok", "wildcard_certificates",
              "tarpit_suspect_ips", "icons_declared_on_other_hosts"):
        lines.append(f"- {k}: {s.get(k)}")
    lines += ["", "## warnings", *(f"- {w}" for w in s.get("warnings", [])), ""]
    return "\n".join(lines)
