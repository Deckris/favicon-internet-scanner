"""How a caller refused by the limiter waits before it asks again."""
from __future__ import annotations

from scanner.internet import pacing
from scanner.internet.limiterclient import LimiterClient
from scanner.internet.pacing import IpPacer, WAIT_BUSY, WAIT_OK, refusal_delay


class Clock:
    def __init__(self):
        self.t = 100.0
        self.naps = []

    def now(self):
        return self.t

    def sleep(self, s):
        self.naps.append(s)
        self.t += s


class FakeLimiter:
    """Refuses until ``open_at`` (on the fake clock) and counts the claims; hands out ``hint`` with each refusal."""

    def __init__(self, clock, hint=None, open_at=float("inf")):
        self.clock, self.hint, self.open_at = clock, hint, open_at
        self.calls = []

    def key_of(self, ip):
        return ip.rsplit(".", 1)[0]

    def release(self, counts, ips=None):
        pass

    def observe_outcome(self, *a, **k):
        pass

    def wait_hint(self):
        return self.hint

    def try_acquire(self, counts, ticket=None, ips=None, exclusive=False):
        self.calls.append(self.clock.t)
        return self.clock.t >= self.open_at


def pacer_for(limiter, clock, max_wait):
    return IpPacer(0, now=clock.now, sleep=clock.sleep, limiter=limiter, max_wait=max_wait)


def test_a_refusal_with_a_hint_is_waited_out_in_full():
    clock = Clock()
    lim = FakeLimiter(clock, hint=2.0, open_at=clock.t + 2.0)
    assert pacer_for(lim, clock, 60).admit("10.0.0.1") == WAIT_OK
    assert len(lim.calls) == 2
    assert lim.calls[1] - lim.calls[0] >= 2.0


def test_no_two_claims_are_closer_than_the_hint_or_the_old_poll():
    clock = Clock()
    lim = FakeLimiter(clock, hint=3.0)
    assert pacer_for(lim, clock, 30).admit("10.0.0.1") == WAIT_BUSY
    gaps = [b - a for a, b in zip(lim.calls, lim.calls[1:])]
    assert len(gaps) > 3 and all(g >= 3.0 for g in gaps[:-1])      # the last look is cut short at max_wait
    lim = FakeLimiter(clock, hint=None)
    assert pacer_for(lim, clock, 30).admit("10.0.0.1") == WAIT_BUSY
    gaps = [b - a for a, b in zip(lim.calls, lim.calls[1:])]
    assert all(g >= pacing._LIMIT_POLL for g in gaps[:-1])


def test_a_blocked_caller_asks_far_less_often_than_a_fixed_poll():
    horizon, threads = 60.0, 40
    clock = Clock()
    lim = FakeLimiter(clock, hint=pacing._LIMIT_POLL)      # what the daemon says for a full network
    assert pacer_for(lim, clock, horizon).admit("10.0.0.1") == WAIT_BUSY
    new_calls = len(lim.calls) * threads
    old_calls = int(horizon / pacing._LIMIT_POLL) * threads
    assert new_calls <= old_calls * 0.5, (new_calls, old_calls)


def test_the_hint_is_clamped_and_never_shortens_the_wait():
    assert refusal_delay(None, 1, rand=lambda: 0.0) == pacing._LIMIT_POLL
    assert refusal_delay(0.01, 1, rand=lambda: 0.0) == pacing._LIMIT_POLL
    assert refusal_delay(2.0, 1, rand=lambda: 0.0) == 2.0
    assert refusal_delay(1e9, 1, rand=lambda: 0.0) == pacing._LIMIT_HINT_MAX
    assert refusal_delay(float("nan"), 1, rand=lambda: 0.0) == pacing._LIMIT_POLL
    assert refusal_delay(0.0, 50, rand=lambda: 1.0) <= pacing._LIMIT_POLL_CAP * (1 + pacing._LIMIT_JITTER)
    assert all(refusal_delay(h, n) >= max(h, pacing._LIMIT_POLL) for h in (0.0, 0.5, 2.0) for n in (1, 3, 9))


def test_the_pause_per_address_still_holds_with_a_limiter():
    clock = Clock()
    lim = FakeLimiter(clock, open_at=0.0)
    p = IpPacer(5.0, now=clock.now, sleep=clock.sleep, limiter=lim)
    stamps = []
    for _ in range(3):
        assert p.admit("10.0.0.1") == WAIT_OK
        stamps.append(clock.t)
        p.done("10.0.0.1")
    assert all(b - a >= 5.0 - 1e-6 for a, b in zip(stamps, stamps[1:]))


def test_the_client_hands_back_the_daemon_hint(tmp_path):
    client = LimiterClient(str(tmp_path / "x.sock"), 4, 5.0)
    reply = {"ok": True, "granted": False, "reason": "gap", "wait": 2.0}
    client._call = lambda message, strict=False, on_ok=None: reply
    assert client.try_acquire({"10.0.0": 1}, ips=["10.0.0.1"]) is False
    assert client.wait_hint() == 2.0
    reply = {"ok": True, "granted": False, "reason": "full"}
    client.try_acquire({"10.0.0": 1}, ips=["10.0.0.1"])
    assert client.wait_hint() is None
    reply = {"ok": True, "granted": True}
    assert client.try_acquire({"10.0.0": 1}, ips=["10.0.0.1"]) is True
    assert client.wait_hint() is None


def test_an_unreachable_daemon_gives_the_retry_delay_as_hint(tmp_path):
    client = LimiterClient(str(tmp_path / "absent.sock"), 4, 5.0, connect_timeout=0.1, retry_after=3.0)
    assert client.try_acquire({"10.0.0": 1}, ips=["10.0.0.1"]) is False
    assert 0 < client.wait_hint() <= 3.0
