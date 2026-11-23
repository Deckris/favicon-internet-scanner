"""Helpers shared by the limiter tests: a stand-in daemon with fault knobs, the old code for mixed-version runs, the lean daemon
as a process, and a per-test deadline."""
import importlib
import os
import random
import signal
import socket
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path

import pytest

from scanner.internet import limiterd
from scanner.internet.limiterclient import LimiterClient
from scanner.internet.limiterd import LimiterCore
from tests.test_limiterd import ROOT, SLOW, until

FULL = os.environ.get("LIMITER_FAULTS_FULL") == "1"
TEST_DEADLINE = 600 if FULL else 170


@pytest.fixture(autouse=True)
def deadline(request):
    """A test that hangs fails after ``TEST_DEADLINE`` seconds, with where it was, instead of holding up the run."""
    def fire(signum, frame):
        raise TimeoutError(f"{request.node.name} ran past {TEST_DEADLINE} s")
    previous = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, TEST_DEADLINE)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class Server:
    """The daemon's rules behind a plain threaded socket server, with knobs for the faults a test needs."""

    def __init__(self, path, cap=4, gap=0.4, **core_kw):
        self.path = str(path)
        core_kw.setdefault("grace", 30.0)
        self.core = LimiterCore(cap, gap, **core_kw)
        self.lock = threading.Lock()
        self.seen: list[tuple[float, str, dict]] = []        # (time, op, request)
        self.delay: dict[str, float] = {}                    # op -> seconds before the reply
        self.drain: tuple[int, float] | None = None          # (bytes, pause): read a request body this slowly
        self.cut_on: dict[str, int] = {}                     # op -> the n-th request of it ends the connection unanswered
        self.mute = threading.Event()                        # read requests, answer none
        self.lose_reply = None                               # (op, request) -> True: act on the request, then drop the connection
        self._counts: dict[str, int] = {}
        self._srv: socket.socket | None = None
        self._conns: list[socket.socket] = []
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self):
        self._stop.clear()
        if os.path.exists(self.path):
            os.unlink(self.path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.path)
        srv.listen(512)
        srv.settimeout(0.05)
        self._srv = srv
        t = threading.Thread(target=self._accept, args=(srv,), daemon=True)
        t.start()
        self._threads.append(t)
        return self

    def stop(self):
        self._stop.set()
        if self._srv is not None:
            self._srv.close()
            self._srv = None
        for c in list(self._conns):
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            c.close()
        self._conns.clear()
        for t in self._threads:
            t.join(2)
        self._threads.clear()
        try:
            os.unlink(self.path)
        except OSError:
            pass

    def _accept(self, srv):
        while not self._stop.is_set():
            try:
                c, _ = srv.accept()
            except OSError:
                if srv.fileno() < 0:
                    return
                continue
            self._conns.append(c)
            t = threading.Thread(target=self._serve, args=(c,), daemon=True)
            t.start()
            self._threads.append(t)

    def _read(self, c, n, slow=False):
        buf = bytearray()
        while len(buf) < n:
            want = n - len(buf)
            if slow and self.drain:
                want = min(want, self.drain[0])
            chunk = c.recv(want)
            if not chunk:
                raise ConnectionError("closed")
            buf += chunk
            if slow and self.drain:
                time.sleep(self.drain[1])
        return bytes(buf)

    def _serve(self, c):
        with self.lock:
            conn = self.core.open()
        try:
            while not self._stop.is_set():
                n = limiterd.unpack_length(self._read(c, 4))
                req = limiterd.decode_frame(self._read(c, n, slow=True))
                op = req.get("op")
                with self.lock:
                    self.seen.append((time.monotonic(), op, req))
                    self._counts[op] = self._counts.get(op, 0) + 1
                    nth = self._counts[op]
                if self.cut_on.get(op) == nth:
                    c.shutdown(socket.SHUT_RDWR)
                    return
                while self.mute.is_set() and not self._stop.is_set():
                    time.sleep(0.02)
                time.sleep(self.delay.get(op, 0.0))
                with self.lock:
                    reply = self.core.handle(conn, req)
                if self.lose_reply is not None and self.lose_reply(op, req):
                    c.shutdown(socket.SHUT_RDWR)
                    return
                c.sendall(limiterd.pack_frame(reply))
                if reply.get("close"):
                    return
        except (OSError, ValueError):
            pass
        finally:
            with self.lock:
                self.core.close(conn)

    def ops(self, op):
        with self.lock:
            return [(t, r) for t, o, r in self.seen if o == op]

    def events(self):
        return [e for _, r in self.ops("observe") for e in r.get("events", [])]


@pytest.fixture
def server(tmp_path):
    made = []

    def make(**kw):
        s = Server(tmp_path / f"s{len(made)}.sock", **kw).start()
        made.append(s)
        return s
    yield make
    for s in made:
        s.stop()


class Jitter(random.Random):
    """The client's source of jitter, a callable giving a float in [0, 1): seeded, or pinned so the factor is ``fixed``."""

    def __init__(self, fixed=None, seed=7):
        super().__init__(seed)
        self.fixed = fixed

    def random(self):
        return self.fixed - 0.5 if self.fixed is not None else super().random()

    def __call__(self):
        return self.random()


def make_client(path, cap=4, gap=0.4, **kw):
    kw.setdefault("retry_after", 0.05)
    return LimiterClient(str(path), cap, gap, **kw)




@pytest.fixture(scope="module")
def old_tree(tmp_path_factory):
    """A pristine checkout of the main branch: from LIMITER_OLD_TREE, else from ``git archive``. When neither is available
    the tests that need it are skipped, and the reason says so in the ``-rs`` summary."""
    given = os.environ.get("LIMITER_OLD_TREE")
    tree = None
    if given:
        if not (Path(given) / "scanner" / "internet" / "limiterd.py").is_file():
            pytest.skip(f"LIMITER_OLD_TREE={given} holds no scanner checkout: the mixed-version and reference tests did NOT run")
        tree = Path(given)
    elif (ROOT / ".git").exists():
        dest = tmp_path_factory.mktemp("old-tree")
        tar = dest / "tree.tar"
        try:
            with open(tar, "wb") as fh:
                subprocess.run(["git", "-C", str(ROOT), "archive", "main", "scanner"], stdout=fh, check=True, timeout=60,
                               stderr=subprocess.DEVNULL)
            with tarfile.open(tar) as t:
                t.extractall(dest)
            tree = dest
        except (OSError, subprocess.CalledProcessError, tarfile.TarError):
            pytest.skip("git cannot read the main branch here: the mixed-version and reference tests did NOT run "
                        "(set LIMITER_OLD_TREE to a directory with a pristine main checkout)")
    else:
        pytest.skip("no pristine main checkout: set LIMITER_OLD_TREE; the mixed-version and reference tests did NOT run")
    source = (tree / "scanner" / "internet" / "limiterd.py").read_text()
    assert "HEARTBEAT_EVERY" not in source, f"{tree} is not the old code"
    return tree


def old_env(tree):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = str(tree)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run_old(tree, script, *args, timeout=SLOW):
    out = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv.pop(1)); exec(sys.argv.pop(1))",
                          str(tree), script, *args], cwd=tree, capture_output=True, text=True, timeout=timeout,
                         env={**old_env(tree), "PYTHONPATH": str(tree)})
    assert out.returncode == 0, out.stderr
    return out.stdout


@pytest.fixture(scope="module")
def reference(old_tree, tmp_path_factory):
    """The old ``limiterd`` and ``pacing`` as a package of their own, so the reference shares no code with the current ones."""
    dest = tmp_path_factory.mktemp("reference")
    pkg = dest / "limiter_reference_pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    src = old_tree / "scanner" / "internet"
    (pkg / "pacing.py").write_text((src / "pacing.py").read_text())
    text = (src / "limiterd.py").read_text()
    text = text.replace("from scanner.internet import pacing", "from limiter_reference_pkg import pacing")
    text = text.replace("from scanner.internet.pacing import", "from limiter_reference_pkg.pacing import")
    assert "scanner." not in " ".join(l for l in text.splitlines() if l.startswith(("from ", "import ")))
    (pkg / "limiterd.py").write_text(text)
    sys.path.insert(0, str(dest))
    try:
        module = importlib.import_module("limiter_reference_pkg.limiterd")
        from scanner.internet import pacing as current
        assert module.pacing is not current and module.SubnetLimiter is not current.SubnetLimiter
        yield module
    finally:
        sys.path.remove(str(dest))
        for name in [n for n in sys.modules if n.startswith("limiter_reference_pkg")]:
            del sys.modules[name]


# the lean daemon as a process, and raw frames

def raw_hello(path, cap=4, gap=0.4, client=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(path)
    msg = {"op": "hello", "protocol": limiterd.PROTOCOL, "cap": cap, "gap": gap}
    if client:
        msg["client"] = client
    s.sendall(limiterd.pack_frame(msg))
    assert recv_reply(s)["ok"]
    return s


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def recv_reply(s):
    return limiterd.decode_frame(recv_exact(s, limiterd.unpack_length(recv_exact(s, 4))))



def start_lean(tmp_path, *flags, env=None, entry=("-m", "scanner.internet.limiterd"), name="lean.sock", cwd=ROOT, limits=(4, 0.4)):
    path = tmp_path / name
    err = open(tmp_path / f"{name}.err", "wb")
    proc = subprocess.Popen([sys.executable, *entry, "--socket", str(path), "--startup-hold-seconds", "0", "--min-seconds-between-probes", "0.4",
                             "--bucket-seconds", "0.05", *flags], cwd=cwd, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", **(env or {})},
                            stdout=subprocess.DEVNULL, stderr=err)
    probe = LimiterClient(str(path), *limits, retry_after=0.05)
    try:
        until(lambda: proc.poll() is None and path.exists() and probe.ping(), "the daemon to come up")
    except AssertionError:
        proc.kill()
        raise AssertionError((tmp_path / f"{name}.err").read_text(errors="replace"))
    return proc, str(path), probe


def stop(proc, probe=None):
    if probe is not None:
        probe.close()
    proc.send_signal(signal.SIGTERM)
    return proc.wait(SLOW)


