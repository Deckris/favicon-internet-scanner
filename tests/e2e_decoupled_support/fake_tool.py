"""Executable body of the fake zmap / zgrab2 / zdns used by the decoupled end-to-end test.

Every invocation appends one line per event to the shared log (E2E_LOG) with a single O_APPEND write, so concurrent
processes never need a lock. The answers come from tests.helpers.FakeTools over the scenario in ``scenario``.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path


def log(*fields) -> None:
    line = " ".join(str(f) for f in fields) + "\n"
    fd = os.open(os.environ["E2E_LOG"], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, line.encode("ascii"))
    finally:
        os.close(fd)


def parent_stage() -> str:
    try:
        parts = Path(f"/proc/{os.getppid()}/cmdline").read_bytes().split(b"\0")
        return parts[parts.index(b"--stage") + 1].decode()
    except (OSError, ValueError, IndexError):
        return "?"


def alive(pid: int) -> bool:
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def arg(cmd: list[str], flag: str, default: str | None = None) -> str | None:
    return cmd[cmd.index(flag) + 1] if flag in cmd else default


def zmap(cmd: list[str]) -> int:
    from tests.e2e_decoupled_support import scenario
    if "--version" in cmd:
        print("zmap 2.1.1")
        return 0
    shard = int(arg(cmd, "--shard", "0")) if "--shards" in cmd else None
    tools = scenario.build_tools(shard)
    if "--dryrun" in cmd:
        log("DRYRUN", os.getpid(), time.time(), parent_stage(), shard)
        res = tools(["zmap", *cmd[1:]])
        sys.stderr.write(res.stderr)
        return res.returncode
    port = int(arg(cmd, "-p"))
    out = arg(cmd, "-o")
    me = os.getpid()
    log("ZMAP_START", me, time.time(), port, out, parent_stage())
    others = set()
    for line in Path(os.environ["E2E_LOG"]).read_text().splitlines():
        f = line.split()
        if f and f[0] == "ZMAP_START" and int(f[1]) != me:
            others.add(int(f[1]))
        elif f and f[0] == "ZMAP_END":
            others.discard(int(f[1]))
    for pid in sorted(others):
        if alive(pid):
            log("ZMAP_OVERLAP", me, pid, time.time())
    time.sleep(float(os.environ.get("E2E_ZMAP_SECONDS", "1.0")))
    res = tools(["zmap", *cmd[1:]])
    log("ZMAP_END", me, time.time(), port, out, res.returncode)
    sys.stderr.write(res.stderr)
    return res.returncode


def zgrab2(cmd: list[str]) -> int:
    from tests.e2e_decoupled_support import scenario
    if "--help" in cmd:
        return 0
    stdin = sys.stdin.read()
    tools = scenario.build_tools(None)
    stage = parent_stage()
    hold = float(os.environ.get("E2E_CONNECT_SECONDS", "0.4"))

    def one(ip: str, port: str) -> None:
        log("CONNECT_START", ip, port, os.getpid(), time.time(), stage)
        time.sleep(hold)
        log("CONNECT_END", ip, port, os.getpid(), time.time(), stage)
    threads = []
    for row in stdin.splitlines():
        f = (row.split(",") + ["", "", "", ""])[:4]
        t = threading.Thread(target=one, args=(f[0], f[3]))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    res = tools(cmd, input=stdin)
    sys.stdout.write(res.stdout)
    return res.returncode


def zdns(cmd: list[str]) -> int:
    from tests.e2e_decoupled_support import scenario
    if "--version" in cmd:
        print("zdns 1.0")
        return 0
    res = scenario.build_tools(None)(cmd, input=sys.stdin.read())
    sys.stdout.write(res.stdout)
    return res.returncode


def main(tool: str) -> None:
    sys.exit({"zmap": zmap, "zgrab2": zgrab2, "zdns": zdns}[tool]([tool, *sys.argv[1:]]))
