"""Run offline tests and preserve measured wall-clock time and output.

This runs synthetic/loopback tests and optional ZMap --dryrun tests only.
It does not run the scanner CLI or perform public-target validation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--suite", choices=("scanner", "repository"), default="scanner")
    args = ap.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    files = sorted((root / "tests").glob("test_*.py")) if args.suite == "scanner" else [root / "tests"]
    cmd = [sys.executable, "-m", "pytest", *[str(p) for p in files], "-q", "-p", "no:cacheprovider",
           "--durations=5", f"--junitxml={output / 'tests.xml'}"]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    with (output / "tests.log").open("w") as log:
        proc = subprocess.Popen(cmd, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            log.write(line)
            log.flush()
            print(line, end="", flush=True)
        code = proc.wait()
    record = {"mode": "offline-tests", "suite": args.suite, "started_at": started_at,
              "elapsed_seconds": round(time.monotonic() - started, 3), "command": cmd, "exit_code": code,
              "checksums": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir() if p.is_file()}}
    (output / "manifest.json").write_text(json.dumps(record, indent=2))
    print(f"Measured test wall-clock: {record['elapsed_seconds']} s; artifacts: {output}", flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
