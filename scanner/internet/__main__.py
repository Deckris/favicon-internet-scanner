"""CLI: ``python -m scanner.internet {preflight|plan|run|campaign|favicon-refetch|selftest} --config FILE``
and ``python -m scanner.internet export-csv RUN_DIR [--out FILE]``.

Exit codes: 0 complete, 2 refused (config, approval, preflight, confirmation, or a prior run of this config),
3 run error, 4 run finished but found zero responsive endpoints, 5 run ended early or with stage errors
(outputs are partial and flagged), 6 campaign stopped before a shard for lack of free disk (resume with the same command).
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

# Exit codes of an incomplete campaign, by the reason it stopped. Every reason that is not listed (crashed,
# stage_errors, kill_switch, stalled, egress_changed, ...) is a stop that needs a look: exit 5, the same as an
# incomplete `run`. `stalled` is listed on purpose: a shard made no progress for operations.stall_minutes.
EXIT_STOPPED = 5
# `disk` is a stop between shards for lack of free space (operations.min_free_gb_between_shards): free space, run again.
EXIT_DISK = 6
CAMPAIGN_EXIT = {"preflight_failed": 2, "zero_responsive": 4, "drain": 0, "stalled": EXIT_STOPPED, "disk": EXIT_DISK}


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


def _favicon_stage(args, cfg) -> int:
    """Run the favicon stage of a network-only shard (this host's copy or the original) and finish the shard."""
    if args.run_dir is None:
        print("REFUSED: favicon-stage needs RUN_DIR", file=sys.stderr)
        return 2
    from scanner.internet import split
    problems = split.verify_export(args.run_dir)
    if problems:
        print("REFUSED: the exported run does not match its checksums: " + "; ".join(problems[:5]), file=sys.stderr)
        return 2
    token = pipeline.confirm_token(cfg, pipeline.build_policy(cfg)[1])
    if args.confirm != token:
        print("REFUSED: favicon-stage requires --confirm with the token printed by `plan` for this config", file=sys.stderr)
        return 2
    refusal = _anonymous_refusal(cfg, args)
    if refusal:
        print(f"REFUSED: {refusal}", file=sys.stderr)
        return 2
    try:
        run_dir = pipeline.run_favicon_only(cfg, args.run_dir)
    except (ConfigError, pre.PreflightFailed) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:   # pragma: no cover - last-resort report
        print(f"RUN ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    print(f"done: {run_dir}  (elapsed {manifest['elapsed_seconds']} s)")
    if not manifest.get("complete"):
        print(f"WARNING: favicon stage incomplete (abort_reason={manifest.get('abort_reason')}, errors={manifest.get('stage_errors')}). "
              "The shard stays network-only; run favicon-stage again to continue.", file=sys.stderr)
        return 5
    try:
        from scanner.internet import campaign
        campaign.record_finished_shard(cfg, run_dir)
    except Exception as exc:
        print(f"note: the campaign state was not updated ({exc}); a repeated campaign adopts the finished run", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="scanner.internet")
    ap.add_argument("command", choices=("preflight", "plan", "run", "campaign", "favicon-refetch", "selftest", "export-csv", "compact", "prune-raw",
                                    "favicon-stage", "export-network", "import-favicons", "export-shard") + SETTINGS_COMMANDS)
    ap.add_argument("run_dir", nargs="?", type=Path, help="export-csv, compact, prune-raw, export-shard: the finished run; "
                    "favicon-stage, export-network, import-favicons: a network-only run")
    ap.add_argument("dest", nargs="?", type=Path, help="export-network: new directory for the copy; import-favicons: the favicon run "
                    "to take the outputs from; export-shard: directory to copy the run into")
    ap.add_argument("--out", type=Path, help="export-csv: output file (default: normalized/hostname_resolution.csv in the run)")
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
    ap.add_argument("--pipeline", type=int, choices=(1, 2), default=1,
                    help="campaign: 2 runs the next shard's network stages while the previous shard works through its favicon stage")
    ap.add_argument("--allow-rerun", action="store_true",
                    help="run: permit a second run of an identical config (it re-probes the same sample)")

    # campaign: which shards this invocation covers (several hosts can share one campaign definition)
    ap.add_argument("--shards-from", type=int, default=0, metavar="N",
                    help="campaign: first shard to run, 0-based, inclusive (default 0)")
    ap.add_argument("--shards-to", type=int, default=None, metavar="N",
                    help="campaign: end of the shard range, exclusive (default: all shards). "
                         "`--shards-from 0 --shards-to 50` runs shards 0 to 49, `--shards-from 50` the rest")

    # network-only shards and the favicon stage on a second machine
    ap.add_argument("--stop-after-network", action="store_true",
                    help="run, campaign: stop after the network stages and keep work/facts.sqlite (state network_done); "
                         "finish with favicon-stage, here or on another machine")

    # export of finished shards to another disk
    ap.add_argument("--remove-source", action="store_true",
                    help="export-shard: after every check passed, remove the exported files from the source (a stub stays)")
    ap.add_argument("--archive-to", type=Path, metavar="DIR",
                    help="campaign: when the output disk runs low, export finished shards to DIR (verified before any removal)")
    ap.add_argument("--archive-remove-source", action="store_true",
                    help="campaign: with --archive-to, remove the exported files from the output disk once verified")
    ap.add_argument("--archive-when-free-gb-below", type=float, default=None, metavar="GB",
                    help="campaign: with --archive-to, export when less than this is free (default: less than a shard start needs)")
    args = ap.parse_args(argv)

    if args.command in SETTINGS_COMMANDS:
        return _settings_command(args)
    if args.command == "export-csv":
        if args.run_dir is None:
            ap.error("export-csv needs RUN_DIR")
        from scanner.internet import outputs
        print(outputs.export_csv(args.run_dir, args.out))
        return 0
    if args.command == "compact":
        if args.run_dir is None:
            ap.error("compact needs RUN_DIR")
        from scanner.internet import outputs
        result = outputs.compact_run(args.run_dir)
        print(json.dumps(result, indent=2))
        if result["status"] in ("skipped", "unavailable") or result.get("failed"):
            print(f"REFUSED: nothing was compacted ({result.get('reason') or result.get('failed') or 'zstandard is not installed'})", file=sys.stderr)
            return 2
        return 0
    if args.command == "prune-raw":
        if args.run_dir is None:
            ap.error("prune-raw needs RUN_DIR")
        from scanner.internet import outputs
        result = outputs.prune_raw(args.run_dir)
        print(json.dumps(result, indent=2))
        if result["status"] in ("refused", "failed"):
            print(f"REFUSED: raw/ was not removed ({result['reason']})", file=sys.stderr)
            return 2
        return 0
    if args.command == "export-network":
        if args.run_dir is None or args.dest is None:
            ap.error("export-network needs RUN_DIR and OUT_DIR")
        from scanner.internet import split
        try:
            record = split.export_network(args.run_dir, args.dest)
        except ConfigError as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({**record, "files": sorted(record["files"])}, indent=2))
        return 0
    if args.command == "import-favicons":
        if args.run_dir is None or args.dest is None:
            ap.error("import-favicons needs RUN_DIR and the favicon run directory")
        from scanner.internet import split
        try:
            record = split.import_favicons(args.run_dir, args.dest)
        except ConfigError as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({"imported_files": len(record["files"]), "run_id": record["run_id"]}, indent=2))
        print(f"\nFinish the shard without sending anything: python -m scanner.internet favicon-stage {args.run_dir} --config <file>")
        return 0
    if args.command == "export-shard":
        if args.run_dir is None or args.dest is None:
            ap.error("export-shard needs RUN_DIR and DEST")
        from scanner.internet import archive
        try:
            result = archive.export_shard(args.run_dir, args.dest, remove_source=args.remove_source, log=print)
        except archive.ArchiveRefused as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({k: v for k, v in result.items() if k != "problems"}, indent=2))
        if args.config is not None:
            try:
                from scanner.internet import campaign
                if not campaign.record_archived(load_config(args.config), args.run_dir, result):
                    print("note: the campaign state does not list this run; it was not updated", file=sys.stderr)
            except (ConfigError, ValueError, RuntimeError) as exc:
                print(f"note: the campaign state was not updated ({exc})", file=sys.stderr)
        return 0
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

    if args.command == "favicon-stage":
        return _favicon_stage(args, cfg)
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
        (Path(cfg.output_dir) / "doctor").mkdir(parents=True, exist_ok=True)
        report = pre.run_preflight(cfg, splan, run_dir=Path(cfg.output_dir) / "doctor", offline=args.offline)
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
            span = {"shards_from": args.shards_from, "shards_to": args.shards_to}
            if args.stop_after_network:
                span["network_only"] = True
            if args.archive_to is not None:
                from scanner.internet.campaign import ArchivePolicy
                span["archive"] = ArchivePolicy(args.archive_to, args.archive_remove_source, args.archive_when_free_gb_below)
            result = (run_campaign(cfg, pipeline_depth=args.pipeline, config_path=args.config, **span) if args.pipeline > 1
                      else run_campaign(cfg, **span))
        except (CampaignLocked, ValueError) as exc:
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(result, indent=2, default=str))
        if result["complete"] or (args.stop_after_network and result.get("network_complete") and not result["stopped"]):
            return 0
        stopped = result["stopped"] or {}
        if stopped.get("reason") == "disk":
            print(f"WARNING: campaign stopped for lack of disk space: {stopped.get('detail')}", file=sys.stderr)
        return CAMPAIGN_EXIT.get(stopped.get("reason"), EXIT_STOPPED)
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
        run_dir = pipeline.run(cfg, run_id=args.run_id, **({"network_only": True} if args.stop_after_network else {}))
    except pre.PreflightFailed as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:   # pragma: no cover - last-resort report
        print(f"RUN ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    print(f"done: {run_dir}  (elapsed {manifest['elapsed_seconds']} s)")
    if manifest.get("network_done"):
        print(f"network stages finished; favicon stage still to run: python -m scanner.internet favicon-stage {run_dir} --config <file> --confirm <token>")
        return 0
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
