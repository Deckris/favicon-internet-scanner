"""Loaded by every Python process of the end-to-end test (through PYTHONPATH): the host checks that cannot pass on a test
machine are answered, and the favicon fetcher is replaced by one that records its contacts. Inert unless E2E_LOG is set."""
import os

if os.environ.get("E2E_LOG"):
    import time

    def _install() -> None:
        from scanner.internet import favicon as fav
        from scanner.internet import preflight as pre
        from tests.e2e_decoupled_support.fake_tool import log
        from tests.helpers import FakeFetcher

        real_preflight = pre.run_preflight

        def preflight(*a, **kw):
            report = real_preflight(*a, **kw)
            report["ok"] = True
            return report
        pre.run_preflight = preflight

        class Fetcher(FakeFetcher):
            def __init__(self, pacer):
                super().__init__()
                self.pacer = pacer

            def fetch(self, url, *, connect_ip, kind, context=""):
                if not self.pacer.wait(connect_ip):
                    raise RuntimeError("stopped")
                try:
                    log("CONNECT_START", connect_ip, 0, os.getpid(), time.monotonic(), "favicon")
                    time.sleep(float(os.environ.get("E2E_CONNECT_SECONDS", "0.4")) / 2)
                    log("CONNECT_END", connect_ip, 0, os.getpid(), time.monotonic(), "favicon")
                    return super().fetch(url, connect_ip=connect_ip, kind=kind, context=context)
                finally:
                    self.pacer.done(connect_ip)

        fav.make_fetcher = lambda cfg, policy, resolver, endpoints, *, pacer=None, **kw: Fetcher(pacer)

    try:
        _install()
    except Exception as exc:        # never break interpreter start-up
        import sys
        print(f"e2e sitecustomize: {exc!r}", file=sys.stderr)
