"""CLI: ``python -m scanner.internet {preflight|plan|run|campaign|favicon-refetch|selftest} --config FILE``.

Exit codes: 0 complete, 2 refused (config, approval, preflight, confirmation, or a prior run of this config),
3 run error, 4 run finished but found zero responsive endpoints, 5 run ended early or with stage errors
(outputs are partial and flagged).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scanner.internet import pipeline
from scanner.internet import preflight as pre
from scanner.internet.config import ConfigError, load_config


def _fmt_seconds(s: float) -> str:
    h, rem = divmod(int(s), 3600)
    return f"{h}h{rem // 60:02d}m"


def _prior_runs(cfg) -> list[str]:
    out = []
    for m in sorted(Path(cfg.output_dir).glob("*/manifest.json")) if Path(cfg.output_dir).is_dir() else []:
        try:
            data = json.loads(m.read_text(encoding="utf-8"))
            shard = data.get("shard")
            index = shard.get("index", 0) if isinstance(shard, dict) else 0
            if data.get("config_checksum") == cfg.checksum and index == cfg.shard:
                out.append(m.parent.name)
        except (OSError, ValueError):
            continue
    return out


PILOT_MAX_TARGETS_PER_PORT = 5000


def _anonymous_refusal(cfg, args) -> str | None:
    if cfg.transparency.anonymous:
        return ("this config has no contact and no information page, so recipients could not identify the scanner "
                "or opt out. Set `contact` and `info_url` in settings.yaml (then run `scanner apply`)")
    return None


def _pilot_refusal(cfg, splan, args) -> str | None:
    """A large sample must follow a completed small one: scale up in steps, not in one go."""
    if args.skip_pilot_check or cfg.target_ips or splan.targets_per_port <= PILOT_MAX_TARGETS_PER_PORT:
        return None
    out = Path(cfg.output_dir)
    for m in sorted(out.glob("*/manifest.json")) if out.is_dir() else []:
        try:
            data = json.loads(m.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        sample = data.get("sample") or {}
        if data.get("complete") and 0 < sample.get("targets_per_port", 0) <= PILOT_MAX_TARGETS_PER_PORT:
            return None
    return (f"this run has {splan.targets_per_port} targets per port and no completed pilot of at most "
            f"{PILOT_MAX_TARGETS_PER_PORT} targets per port exists in {out}. Run a small pilot first "
            "(sample.fraction about 1e-6), check its manifest and report, or pass --skip-pilot-check on purpose")


SETTINGS_COMMANDS = ("init", "apply", "exclusions")


def _settings_command(args) -> int:
    import shutil

    from scanner.internet import settings as st
    workdir = args.workdir
    try:
        if args.command == "init":
            answers = {
                "contact": args.contact, "info_url": args.info_url, "incident_contact": args.incident_contact,
                "public_ip": args.egress_ip, "source_ip": args.source_ip, "interface": args.interface,
                "dns_resolver": args.resolver, "label": args.label,
            }
            if args.exclusions:
                workdir.mkdir(parents=True, exist_ok=True)
                target = workdir / "exclusions.txt"
                if Path(args.exclusions).resolve() != target.resolve():
                    shutil.copyfile(args.exclusions, target)
            path = st.write_settings(workdir, answers, force=args.force)
            print(f"wrote {path}\nEdit it (every REPLACE_ME), then run: scanner apply")
            if not args.exclusions and not (workdir / "exclusions.txt").exists():
                print("Also put the exclusion list from the network owner at "
                      f"{workdir / 'exclusions.txt'} (or run `scanner init --force --exclusions FILE`).")
            return 0
        if args.command == "apply":
            result = st.apply(workdir)
            print(json.dumps(result, indent=2))
            print("config.yaml and approval.yaml are up to date" if not result["written"]
                  else "wrote " + ", ".join(result["written"]))
            return 0
        path, added = st.add_exclusions(workdir, args.add or [], args.from_file)
        print(f"{added} new range(s) added to {path}. Run `scanner apply` so the checksum follows.")
        return 0
    except st.SettingsError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="scanner.internet")
    ap.add_argument("command", choices=("preflight", "plan", "run", "campaign", "favicon-refetch", "selftest") + SETTINGS_COMMANDS)
    ap.add_argument("--config", type=Path)
    ap.add_argument("--workdir", type=Path, default=Path("."), help="init, apply, exclusions: folder holding settings.yaml")
    ap.add_argument("--contact", help="init: opt-out and abuse e-mail")
    ap.add_argument("--info-url", help="init: public information page")
    ap.add_argument("--incident-contact", help="init: who is called if something goes wrong")
    ap.add_argument("--egress-ip", help="init: the public address the scan leaves from")
    ap.add_argument("--source-ip", help="init: the host's own address, when it differs from --egress-ip (NAT)")
    ap.add_argument("--interface", help="init: network interface of the scanner host")
    ap.add_argument("--resolver", help="init: DNS resolver for PTR and name checks")
    ap.add_argument("--label", help="init: run label")
    ap.add_argument("--exclusions", type=Path, help="init: exclusion list file (copied into the work folder)")
    ap.add_argument("--force", action="store_true", help="init: overwrite an existing settings.yaml")
    ap.add_argument("--add", nargs="+", metavar="CIDR", help="exclusions: ranges to add")
    ap.add_argument("--from-file", type=Path, help="exclusions: file of ranges to add")
    ap.add_argument("--offline", action="store_true", help="preflight: skip the DNS canary (no network)")
    ap.add_argument("--confirm", help="run: confirmation token printed by `plan`")
    ap.add_argument("--run-id")
    ap.add_argument("--source-run", type=Path, help="favicon-refetch: the finished run whose favicon lookups are repeated")
    ap.add_argument("--all-jobs", action="store_true",
                    help="favicon-refetch: repeat every favicon lookup, not only those that returned an image")
    ap.add_argument("--shard", type=int, help="run: which shard of a sharded config (0-based); `campaign` runs them all")
    ap.add_argument("--skip-pilot-check", action="store_true",
                    help="run: skip the requirement that a small completed pilot precedes a larger sample")
    ap.add_argument("--allow-rerun", action="store_true",
                    help="run: permit a second run of an identical config (it re-probes the same sample)")
    args = ap.parse_args(argv)

    if args.command in SETTINGS_COMMANDS:
        return _settings_command(args)
    if args.config is None:
        ap.error("--config is required for this command")
    if args.command == "selftest":     # loopback only: needs no approval and sends nothing external
        from scanner.internet.selftest import run_selftest
        try:
            result = run_selftest(load_config(args.config, require_approval=False))
        except ConfigError as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 3
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2

    if args.command == "favicon-refetch":
        from scanner.internet import refetch
        if args.source_run is None:
            print("REFUSED: favicon-refetch needs --source-run", file=sys.stderr)
            return 2
        try:
            plan = refetch.plan(cfg, args.source_run, all_jobs=args.all_jobs)
            if args.confirm is None:
                print(json.dumps(plan, indent=2))
                print("\nNothing was sent. To run: python -m scanner.internet favicon-refetch --config <file> "
                      f"--source-run {args.source_run} {'--all-jobs ' if args.all_jobs else ''}--confirm " + plan["confirm_token"])
                return 0
            if args.confirm != plan["confirm_token"]:
                print("REFUSED: --confirm does not match the token printed for this exact source run and job list", file=sys.stderr)
                return 2
            refusal = _anonymous_refusal(cfg, args)
            if refusal:
                print(f"REFUSED: {refusal}", file=sys.stderr)
                return 2
            run_dir = refetch.run_refetch(cfg, args.source_run, all_jobs=args.all_jobs, run_id=args.run_id)
        except (ConfigError, pre.PreflightFailed) as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 2
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        print(f"done: {run_dir}")
        print(json.dumps(manifest["summary"], indent=2))
        if not manifest.get("complete"):
            print(f"WARNING: re-fetch incomplete (abort_reason={manifest.get('abort_reason')}, errors={manifest.get('stage_errors')})",
                  file=sys.stderr)
            return 5
        return 0

    policy, splan, exclusions = pipeline.build_policy(cfg)
    token = pipeline.confirm_token(cfg, splan)

    if args.command == "plan":
        print(json.dumps({
            "approval_reference": cfg.approval.approval_reference,
            "approval_valid_until": cfg.approval.valid_until.isoformat(),
            "allowed_addresses": splan.allowed_addresses,
            "sample_fraction": splan.fraction,
            "approved_max_sample_fraction": cfg.max_sample_fraction,
            "targets_per_port": splan.targets_per_port,
            "shards": splan.shards,
            "targets_total_per_port": splan.total_targets,
            "ports": list(splan.ports),
            "zmap_rate_pps": splan.rate,
            "zmap_probes": splan.probes,
            "estimated_zmap_time_per_port": _fmt_seconds(splan.seconds_per_port),
            "estimated_zmap_time_per_shard": _fmt_seconds(splan.seconds_per_port * len(splan.ports)),
            "estimated_zmap_time_total": _fmt_seconds(splan.seconds_per_port * len(splan.ports) * splan.shards),
            "exclusion_entries": len(exclusions),
            "dns_resolvers": list(cfg.dns.resolvers),
            "favicon_enabled": cfg.favicon.enabled,
            "sni_confirm_enabled": cfg.sni_confirm.enabled,
            "output_dir": str(cfg.output_dir),
            "confirm_token": token,
        }, indent=2))
        verb = "campaign" if splan.shards > 1 else "run"
        print(f"\nNothing was sent. To run: python -m scanner.internet {verb} --config <file> --confirm " + token)
        return 0

    if args.command == "preflight":
        Path(cfg.output_dir).mkdir(parents=True, exist_ok=True)
        report = pre.run_preflight(cfg, splan, run_dir=Path(cfg.output_dir), offline=args.offline)
        print(json.dumps(report, indent=2, default=str))
        return 0 if report["ok"] else 2

    if args.confirm != token:
        print("REFUSED: run requires --confirm with the token printed by `plan` for this exact config", file=sys.stderr)
        return 2
    for refusal in (_anonymous_refusal(cfg, args), _pilot_refusal(cfg, splan, args)):
        if refusal:
            print(f"REFUSED: {refusal}", file=sys.stderr)
            return 2
    if args.command == "campaign":
        if cfg.shards < 2 or cfg.target_ips:
            print("REFUSED: campaign needs a random sample split into 2 or more shards (sample.shards)", file=sys.stderr)
            return 2
        from scanner.internet.campaign import CampaignLocked, run_campaign
        try:
            result = run_campaign(cfg)
        except (CampaignLocked, ValueError) as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(result, indent=2, default=str))
        if result["complete"]:
            return 0
        return {"preflight_failed": 2, "zero_responsive": 4}.get((result["stopped"] or {}).get("reason"), 5)
    if cfg.shards > 1:
        if args.shard is None or not 0 <= args.shard < cfg.shards:
            print(f"REFUSED: this config has {cfg.shards} shards; use `campaign`, or `run --shard N` with 0 <= N < {cfg.shards}", file=sys.stderr)
            return 2
        from dataclasses import replace
        cfg = replace(cfg, shard=args.shard)
    elif args.shard not in (None, 0):
        print("REFUSED: --shard needs a sharded config", file=sys.stderr)
        return 2
    prior = _prior_runs(cfg)
    if prior and not args.allow_rerun:
        print(f"REFUSED: this exact config already ran ({prior[0]}). A rerun re-probes the same hosts; "
              "pass --allow-rerun only if that is intended.", file=sys.stderr)
        return 2
    try:
        run_dir = pipeline.run(cfg, run_id=args.run_id)
    except pre.PreflightFailed as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:   # pragma: no cover - last-resort report
        print(f"RUN ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    print(f"done: {run_dir}  (elapsed {manifest['elapsed_seconds']} s)")
    if manifest.get("stage_errors") or not manifest.get("complete"):
        print(f"WARNING: run incomplete (abort_reason={manifest.get('abort_reason')}, "
              f"errors={manifest.get('stage_errors')}). Outputs are partial; see raw/stderr/.", file=sys.stderr)
        return 5
    if manifest.get("zero_responsive"):
        print("WARNING: zero responsive endpoints although every tool ran cleanly. Treat as an egress/NAT problem, "
              "not as an empty Internet (see report/summary.md and raw/stderr/). Typical causes: a host firewall or "
              "rp_filter dropping the SYN-ACK replies (check `sysctl net.ipv4.conf.all.rp_filter`, `iptables -S`, `nft list ruleset`), "
              "a wrong gateway MAC or interface, or upstream filtering of scan traffic.", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
