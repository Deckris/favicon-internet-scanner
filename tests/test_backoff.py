"""Per-network back-off: halving, recovery over time, Retry-After, and that errors never raise the limit."""
from scanner.internet.pacing import BackoffState, SubnetLimiter


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def test_three_timeouts_halve_and_never_go_below_one():
    b = BackoffState(8, settle=0)
    for _ in range(3):
        b.timed_out(0)
    assert b.limit(0) == 4
    for _ in range(6):
        b.timed_out(1)
    assert b.limit(1) == 1
    b.throttled(2)
    assert b.limit(2) == 1


def test_a_reply_clears_the_timeout_streak():
    b = BackoffState(8)
    b.timed_out(0)
    b.timed_out(0)
    b.answered(0)
    b.timed_out(0)
    assert b.limit(0) == 8


def test_throttle_halves_at_once_and_recovery_is_additive_over_quiet_periods():
    b = BackoffState(8, recover_after=60)
    b.throttled(0)
    assert b.limit(0) == 4
    assert b.limit(59) == 4
    assert b.limit(60) == 5
    assert b.limit(185) == 7
    assert b.limit(10_000) == 8
    assert b.idle(10_000)


def test_bad_news_inside_the_settle_window_does_not_halve_twice():
    b = BackoffState(8, settle=10)
    b.throttled(0)
    b.throttled(5)
    assert b.limit(5) == 4
    b.throttled(11)
    assert b.limit(11) == 2


def test_errors_and_replies_never_raise_the_limit():
    b = BackoffState(8, recover_after=60)
    b.throttled(0)
    for t in range(1, 50):
        b.answered(t)
        b.timed_out(t)
    assert b.limit(50) <= 4


def test_retry_after_holds_the_network_and_is_capped():
    c = Clock()
    lim = SubnetLimiter(4, now=c, max_hold=100)
    lim.observe("10.0.0.1", http_status=429, retry_after=30)
    assert not lim.try_acquire({"10.0.0": 1})
    c.t += 29
    assert not lim.try_acquire({"10.0.0": 1})
    c.t += 2
    assert lim.try_acquire({"10.0.0": 1})
    lim.release({"10.0.0": 1})
    lim.observe("10.0.0.1", http_status=503, retry_after=10_000)
    c.t += 99
    assert not lim.try_acquire({"10.0.0": 1})
    c.t += 2
    assert lim.try_acquire({"10.0.0": 1})


def test_limiter_lowers_the_cap_of_the_struggling_network_only():
    c = Clock()
    lim = SubnetLimiter(4, now=c, recover_after=60)
    lim.observe("10.0.0.1", http_status=503)
    assert lim.limit_for("10.0.0.9") == 2
    assert lim.limit_for("10.0.1.9") == 4
    assert lim.try_acquire({"10.0.0": 2})
    assert not lim.try_acquire({"10.0.0": 1})
    lim.release({"10.0.0": 2})
    c.t += 120
    assert lim.limit_for("10.0.0.9") == 4


def test_timeouts_reported_by_zgrab_status_back_off():
    class R:
        def __init__(self, ip, status):
            self.ip, self.zgrab_status = ip, status

    lim = SubnetLimiter(4, now=Clock(), settle=0)
    lim.observe_results([R("1.2.3.4", "connection-timeout"), R("1.2.3.5", "io-timeout"), R("1.2.3.6", "connection-timeout")])
    assert lim.limit_for("1.2.3.7") == 2
    lim.observe_results([R("5.6.7.8", "success")])
    assert lim.tracked()[1] == 1               # a healthy network gets no record


def test_recovered_networks_are_dropped_from_memory():
    c = Clock()
    lim = SubnetLimiter(4, now=c, recover_after=10)
    for i in range(200):
        lim.observe(f"10.{i}.0.1", http_status=429)
    assert lim.tracked()[1] == 200
    c.t += 100
    lim.sweep()
    assert lim.tracked() == (0, 0)
