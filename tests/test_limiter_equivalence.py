"""The daemon's handlers against the code they replaced: the reference (the pristine main branch, loaded as a package of its
own) and the current ``LimiterCore`` receive the same transcript of random operations and must give identical replies and
identical state after every step.

The default run is 10^5 operations; ``LIMITER_FAULTS_FULL=1`` makes it 10^6. Test addresses are the documentation ranges
only, plus strings that are not addresses at all.
"""
import itertools
import random
import time

import pytest

from scanner.internet import limiterd, pacing
from scanner.internet.pacing import network_key, quick_key
from tests.limiter_support import FULL, deadline, old_tree, reference  # noqa: F401
from tests.test_limiterd import Clock, unix_only

pytestmark = unix_only

OPERATIONS = 1_000_000 if FULL else 100_000
NETS = ("192.0.2", "198.51.100", "203.0.113")
HOT = [f"{net}.{i}" for net in NETS for i in range(1, 11)]
V6 = ["2001:db8::1", "2001:db8::2", "2001:db8:0:1::5", "2001:db8:1::1", "2001:DB8::1", "2001:db8::1%eth0", "2001:db8:0:0:0:0:0:1",
      "::ffff:192.0.2.7", "::ffff:192.0.2.8", "::FFFF:198.51.100.3", "::ffff:c000:209", "::ffff:192.0.2.9%lo", "::1", "::"]
ODD = ["", ".", "..", "a", "abc", "203.0.113", "203.0.113.4.5", "192.0.2", "192.0.2.", ".5", "host.example.test", "198.51.100.300",
       "2001:db8::zz", ":::", "::ffff:", "::ffff:zzz", "203.0.113.4:80", "[2001:db8::1]", "192.0.2.1%eth0", " 192.0.2.4", "192.0.2.4 ",
       "é.x", "1:2", "a:b:c:d:e:f:1:2:3"]
EVERY = [f"{net}.{i}" for net in NETS for i in range(1, 255)]
POOL = HOT * 4 + EVERY[:60] + V6 + ODD
VARIANTS = [
    # cap, gap, bucket, grace, ttl, max_hold, startup_hold, share of the operations
    dict(cap=3, gap=2.0, bucket=0.5, grace=5.0, ttl=30.0, hold=20.0, startup=0.0, share=0.3),
    dict(cap=12, gap=1.0, bucket=0.25, grace=5.0, ttl=30.0, hold=20.0, startup=0.0, share=0.15),
    dict(cap=1, gap=1.0, bucket=1.0, grace=0.0, ttl=20.0, hold=5.0, startup=0.0, share=0.1),
    dict(cap=400, gap=0.6, bucket=0.05, grace=3.0, ttl=60.0, hold=60.0, startup=0.0, share=0.2),
    dict(cap=5, gap=0.0, bucket=0.5, grace=5.0, ttl=30.0, hold=20.0, startup=0.0, share=0.1),
    dict(cap=2, gap=3.0, bucket=0.25, grace=8.0, ttl=15.0, hold=10.0, startup=4.0, share=0.15),
]


def pick(rng):
    roll = rng.random()
    if roll < 0.7:
        return rng.choice(HOT)
    if roll < 0.82:
        return rng.choice(EVERY)
    if roll < 0.9:
        return rng.choice(V6)
    return rng.choice(ODD)


def addresses(rng, low=1, high=8):
    ips = [pick(rng) for _ in range(rng.choice((1, 1, 2, 3, 5, 8)) if (low, high) == (1, 8) else rng.randint(low, high))]
    if rng.random() < 0.15:
        ips += rng.sample(ips, min(len(ips), 3))             # duplicates inside one request
    return ips


TICKETS = (None,) * 7 + (1, 2, 3, 4, "t", 1.5, True, 0)


def request(rng, clients, conn, calm):
    kind = rng.random()
    ticket = rng.choice(TICKETS)
    if kind < 0.30:
        ips = addresses(rng) if rng.random() > 0.04 else [pick(rng) for _ in range(rng.randint(60, 300))]
        req = {"op": "claim", "ips": ips, "partial": rng.random() < 0.6, "exclusive": rng.random() < 0.5, "ticket": ticket}
        if rng.random() < 0.02:
            req["ips"] = rng.choice((ips + [5], "192.0.2.1", [], None, [None]))
        if rng.random() < 0.05:
            for field in ("partial", "exclusive"):
                req[field] = rng.choice((0, 1, "", "x", None, [], [0]))
        if rng.random() < 0.02:
            req["ticket"] = [1]
        return req
    if kind < 0.38:
        counts = {rng.choice(NETS): rng.randint(-1, 3) for _ in range(rng.randint(0, 3))}
        if rng.random() < 0.05:
            counts = rng.choice((None, [], {"192.0.2": "x"}, {"192.0.2": 2.7}, {"x": "3"}, "no"))
        return {"op": "claim", "counts": counts, "ticket": ticket}
    if kind < 0.56 and conn.hello and rng.random() < 0.55:       # a client gives back what it holds
        counts = {k: rng.randint(1, n) for k, n in conn.counts.items() if rng.random() < 0.7}
        if rng.random() < 0.1:
            counts[rng.choice(NETS)] = 5
        return {"op": "release", "counts": counts, "ips": [ip for ip in conn.ips if rng.random() < 0.7]}
    if kind < 0.56:
        counts = {rng.choice(NETS): rng.randint(-1, 3) for _ in range(rng.randint(0, 3))}
        req = {"op": "release", "counts": counts, "ips": addresses(rng, 0, 6) if rng.random() < 0.7 else []}
        if rng.random() < 0.03:
            req = {"op": "release", "counts": rng.choice((None, [], {"a": "x"})), "ips": rng.choice((None, [1], "x", []))}
        return req
    if kind < 0.64:
        return {"op": "withdraw", "ticket": rng.choice(TICKETS)}
    if kind < 0.80:
        return observe(rng, calm)
    if kind < 0.86:
        return {"op": "query", "ip": pick(rng) if rng.random() < 0.95 else rng.choice((None, 5, ""))}
    if kind < 0.89:
        return {"op": "ping"}
    if kind < 0.93:
        return {"op": "stats"}
    if kind < 0.955:
        return {"op": "goodbye"}
    if kind < 0.97:
        return {"op": rng.choice(("nope", None, 3, "Claim", "hello"))}
    if kind < 0.985:
        return hello(rng, clients)
    return {"op": "claim", "ips": addresses(rng, 1, 4), "partial": True, "ticket": rng.choice((1, 2))}


def event(rng):
    ev = {"ip": pick(rng)}
    if rng.random() < 0.3:
        ev["timeout"] = rng.choice((True, True, True, 1, "yes", False, 0, "", None))
    if rng.random() < 0.3:
        ev["http_status"] = rng.choice((200, 200, 404, 429, 429, 503, 429.0, "429", True, [429], None, 0))
    if rng.random() < 0.25:
        ev["retry_after"] = rng.choice((None, 0, 1.0, 5.0, 90, "2", float("inf"), float("nan"), -3, 1e9))
    if rng.random() < 0.02:
        ev["ip"] = rng.choice((5, None, 1.5, True))
    return ev


BAD_EVENTS = [{"timeout": True}, "x", 5, None, {"ip": "192.0.2.1", "retry_after": "soon"}, {"ip": "192.0.2.2", "retry_after": [1]},
              {"ip": "192.0.2.3", "retry_after": {}}, [], {"ip": []}]


def observe(rng, calm=False):
    roll = rng.random()
    if roll < 0.06:
        events = rng.choice((None, [], "x", {"ip": "192.0.2.1"}, 5, False))
    else:
        count = rng.choice((1, 1, 2, 3, 5, 8, 40))
        if calm or rng.random() < 0.75:                         # mostly answers, as in a scan
            events = [{"ip": pick(rng), "http_status": 200} if calm or rng.random() < 0.97 else event(rng) for _ in range(count)]
        else:
            events = [event(rng) for _ in range(count)]
        if rng.random() < 0.12:                                 # one failure among answers: the first record, or one more
            bad = {"ip": pick(rng), **rng.choice(({"timeout": True}, {"http_status": 429}, {"http_status": 503, "retry_after": 2},
                                                  {"http_status": 429, "retry_after": 1e9}, {"http_status": 503.0}))}
            events.insert(rng.randrange(len(events) + 1), bad)
        if rng.random() < 0.07:
            for _ in range(rng.choice((1, 1, 2))):
                events.insert(rng.randrange(len(events) + 1), rng.choice(BAD_EVENTS))
    return {"op": "observe", "events": events}


def hello(rng, clients):
    req = {"op": "hello", "protocol": 1, "cap": 1000, "gap": 0.0, "client": rng.choice(clients)}
    if rng.random() < 0.3:
        req["held"] = {rng.choice(NETS): rng.randint(-1, 2) for _ in range(rng.randint(0, 2))}
    if rng.random() < 0.3:
        req["busy"] = addresses(rng, 0, 3)
    if rng.random() < 0.4:
        req["recent"] = {pick(rng): rng.uniform(-1, 6) for _ in range(rng.randint(0, 4))}
    roll = rng.random() * 3
    if roll < 0.03:
        req["protocol"] = 2
    elif roll < 0.06:
        req["cap"] = 1
    elif roll < 0.09:
        req["gap"] = 1e9
    elif roll < 0.12:
        req["client"] = 7
    elif roll < 0.15:
        req["busy"] = "x"
    elif roll < 0.17:
        del req["cap"]
    return req


# the two sides

def run(side, conn, req):
    try:
        return ("reply", side.handle(conn, req))
    except Exception as exc:                                    # anything the handler lets through must be the same too
        return ("raised", type(exc).__name__, str(exc))


class Side:
    def __init__(self, module, params):
        self.clock = Clock()
        self.core = module.LimiterCore(params["cap"], params["gap"], now=self.clock, bucket=params["bucket"], grace=params["grace"],
                                       lease_ttl=params["ttl"], startup_hold=params["startup"], max_hold=params["hold"])
        self.conns = {}
        self.module = module

    def connect(self, slot, req):
        conn = self.core.open()
        self.conns[slot] = conn
        return run(self.core, conn, req)


def ledger(core, new):
    """The ledger as address -> end of its pause, plus its buckets as (index, addresses)."""
    contacts = core.contacts
    buckets = [(index, sorted(members)) for index, members in contacts._buckets]
    seen = {}
    for index, members in contacts._buckets:
        for ip in members:
            seen[ip] = contacts._expiry(index)
    if new:
        assert {ip: contacts._expiry(index) for ip, index in contacts._last.items()} == seen
        assert len(contacts) == len(seen)
        assert all(len(set(members)) == len(members) for _i, members in contacts._buckets)
    else:
        assert len(contacts) == sum(len(members) for _i, members in contacts._buckets)
    return seen, buckets, contacts.gap, contacts.width, len(seen)


def conn_state(c):
    return (c.id, list(c.counts.items()), set(c.ips), list(c.tickets.items()), c.last_seen, c.hello, c.expired, c.client, c.closed,
            c.linger_until)


def state(side, new):
    core = side.core
    lim = core.limiter
    return (list(lim._active.items()), [(k, dict(vars(v))) for k, v in lim._states.items()], list(lim._waiting.items()),
            lim._tickets, lim._releases, list(core._busy.items()), dict(core.stats), core._next_conn, [conn_state(c) for c in core._conns.values()], list(side.conns),
            ledger(core, new))


def same_reply(a, b, op):
    if a[0] != "reply" or b[0] != "reply" or op != "stats":
        return a == b
    ref, new = a[1], b[1]
    drop = {"ledger_addresses", "rss_kb"}
    return {k: v for k, v in ref.items() if k not in drop} == {k: new[k] for k in ref if k not in drop} and set(ref) <= set(new)


def differential(ref_module, new_module, operations, seed, params):
    rng = random.Random(seed)
    ref, new = Side(ref_module, params), Side(new_module, params)
    clients = [f"k{i}" for i in range(14)]
    slots = 6
    serial = itertools.count()

    def reconnect(slot, step):
        req = hello(rng, clients) if rng.random() < 0.5 else {"op": "hello", "protocol": 1, "cap": 1000, "gap": 0.0,
                                                               "client": rng.choice(clients + [f"n{next(serial)}"])}
        a, b = ref.connect(slot, req), new.connect(slot, req)
        assert a == b, (step, req, a, b)
        if a[0] != "reply" or not a[1].get("ok"):
            for side in (ref, new):
                side.core.close(side.conns[slot])
            good = {"op": "hello", "protocol": 1, "cap": 1000, "gap": 0.0, "client": f"n{next(serial)}"}
            assert ref.connect(slot, good) == new.connect(slot, good)

    for s in range(slots):
        reconnect(s, -1)
    ref.clock.t = new.clock.t = 1000.0
    calm = False
    for step in range(operations):
        if step % 2500 == 0:                    # a quiet stretch: every record recovers, then only answers arrive
            calm = (step // 2500) % 2 == 1
            if calm:
                ref.clock.t += 400.0
                new.clock.t += 400.0
                ref.core.sweep()
                new.core.sweep()
        roll = rng.random()
        if roll < 0.22:
            dt = rng.choice((0.0, 0.0, 0.01, 0.05, 0.3, 0.7, 1.1, 2.5))
            if rng.random() < 0.06:
                dt = rng.choice((-0.2, -0.7, -2.0, -45.0, 12.0, 45.0, 200.0))
            ref.clock.t += dt
            new.clock.t += dt
            if rng.random() < 0.5:
                ref.core.sweep()
                new.core.sweep()
        elif roll < 0.245:
            slot = rng.randrange(slots)
            for side in (ref, new):
                side.core.close(side.conns[slot])
            reconnect(slot, step)
        else:
            slot = rng.randrange(slots)
            req = request(rng, clients, ref.conns[slot], calm)
            a, b = run(ref.core, ref.conns[slot], req), run(new.core, new.conns[slot], req)
            op = req["op"] if isinstance(req, dict) else None
            assert same_reply(a, b, op), (step, req if op != "claim" or len(req.get("ips") or ()) < 20 else "big claim", a, b)
            if isinstance(a[1], dict) and a[1].get("close"):
                for side in (ref, new):
                    side.core.close(side.conns[slot])
                reconnect(slot, step)
        sa, sb = state(ref, False), state(new, True)
        assert sa == sb, (step, [(i, x, y) for i, (x, y) in enumerate(zip(sa, sb)) if x != y])
        if step % 8 == 0:
            now = ref.clock.t
            assert [ref.core.contacts.due_in(ip, now) for ip in POOL] == [new.core.contacts.due_in(ip, now) for ip in POOL]
            assert ref.core.snapshot().keys() <= new.core.snapshot().keys()
    assert ref.core.limiter.tracked() == new.core.limiter.tracked()


def test_the_daemon_core_answers_like_the_reference_over_a_long_transcript(reference):
    began = time.monotonic()
    done = 0
    for i, variant in enumerate(VARIANTS):
        count = int(OPERATIONS * variant["share"])
        done += count
        differential(reference, limiterd, count, 101 + i, variant)
    print(f"equivalence run: {done} operations in {time.monotonic() - began:.1f} s")
    assert done >= OPERATIONS * 0.99


# the parts on their own

def test_the_quick_key_is_the_network_key_for_every_input():
    rng = random.Random(5)
    alphabet = "0123456789.:abcdefABCDEF%/[]ghz -é"
    samples = list(POOL) + EVERY
    for _ in range(200_000):
        n = rng.randint(0, 40)
        samples.append("".join(rng.choice(alphabet) for _ in range(n)))
    for _ in range(50_000):
        a, b, c, d = (rng.randint(0, 300) for _ in range(4))
        samples += [f"{a}.{b}.{c}.{d}", f"::ffff:{a}.{b}.{c}.{d}", f"{a:x}:{b:x}:{c:x}::{d:x}", f"{a}.{b}.{c}", f"{a}.{b}.{c}.{d}%{a}"]
    for ip in samples:
        assert quick_key(ip) == network_key(ip), ip


def test_the_ledger_matches_the_reference_over_random_operations(reference):
    rng = random.Random(8)
    for gap, width in ((2.0, 0.5), (0.7, 0.1), (5.0, 1.0), (0.0, 1.0), (1.0, 0.001)):
        ref, new = reference.ContactBuckets(gap, width), limiterd.ContactBuckets(gap, width)
        now = 5000.0
        for step in range(OPERATIONS // 10):
            roll = rng.random()
            if roll < 0.15:
                now += rng.choice((0.0, 0.01, 0.2, 0.7, 3.0)) if rng.random() > 0.08 else rng.choice((-0.3, -1.5, -10.0))
            elif roll < 0.55:
                ips = [rng.choice(POOL) for _ in range(rng.choice((1, 1, 3, 10)))]
                for ip in ips:
                    ref.add(ip, now)
                if rng.random() < 0.5:
                    for ip in ips:
                        new.add(ip, now)
                else:
                    new.add_many(ips, now)
            elif roll < 0.62:
                ref.prune(now)
                new.prune(now)
            else:
                probe = rng.choice(POOL)
                assert ref.due_in(probe, now) == new.due_in(probe, now), (step, probe)
                group, busy = [probe, rng.choice(POOL), probe], ({probe} if rng.random() < 0.1 else set())
                assert new.waits(group, now, busy, 0.25) == [0.25 if ip in busy else ref.due_in(ip, now) for ip in group]
            if step % 5 == 0:
                assert ref.buckets == new.buckets
                assert ledger_of(ref, False) == ledger_of(new, True), step
        assert [ref.due_in(ip, now) for ip in POOL] == [new.due_in(ip, now) for ip in POOL]


def ledger_of(buckets, new):
    seen = {}
    for index, members in buckets._buckets:
        for ip in members:
            seen[ip] = buckets._expiry(index)
    if new:
        assert {ip: buckets._expiry(i) for ip, i in buckets._last.items()} == seen
    return seen, [(index, sorted(members)) for index, members in buckets._buckets]


def test_the_keyed_partial_claim_matches_try_acquire_some(reference):
    rng = random.Random(9)
    for cap in (1, 2, 5, 50):
        clock_a, clock_b = Clock(), Clock()
        ref = reference.SubnetLimiter(cap, now=clock_a, max_hold=30.0)
        new = pacing.SubnetLimiter(cap, now=clock_b, max_hold=30.0)
        tickets = []
        for step in range(OPERATIONS // 20):
            roll = rng.random()
            if roll < 0.35:
                ips = addresses(rng, 1, 10)
                ticket = rng.choice(tickets) if tickets and rng.random() < 0.6 else None
                got = ref.try_acquire_some(ips, ticket)
                keys = [quick_key(ip) for ip in ips]
                again, counts = new.try_acquire_some_keyed(ips, keys, ticket)
                assert got == again and counts == ref.counts(got) and list(counts) == list(ref.counts(got)), (step, ips)
            elif roll < 0.45:
                tickets.append(ref.ticket())
                assert new.ticket() == tickets[-1]
            elif roll < 0.52 and tickets:
                t = rng.choice(tickets)
                ref.withdraw(t)
                new.withdraw(t)
            elif roll < 0.7:
                counts = {rng.choice(NETS): rng.randint(1, 3)}
                ticket = rng.choice(tickets) if tickets and rng.random() < 0.5 else None
                assert ref.try_acquire(counts, ticket) == new.try_acquire(counts, ticket)
            elif roll < 0.82:
                key = rng.choice(NETS)
                held = ref._active.get(key, 0)
                if held:
                    ref.release({key: 1})
                    new.release({key: 1})
            elif roll < 0.92:
                kw = dict(timeout=rng.random() < 0.5, http_status=rng.choice((None, 429, 503)), retry_after=rng.choice((None, 3.0)))
                ip = pick(rng)
                ref.observe(ip, **kw)
                new.observe(ip, **kw)
            else:
                dt = rng.choice((0.1, 1.0, 20.0, 130.0))
                clock_a.t += dt
                clock_b.t += dt
                ref.sweep()
                new.sweep()
            assert ref._active == new._active and list(ref._waiting.items()) == list(new._waiting.items())
            assert {k: vars(v) for k, v in ref._states.items()} == {k: vars(v) for k, v in new._states.items()}


def test_observe_with_and_without_a_back_off_record_matches_the_reference_on_a_fixed_script(reference):
    params = VARIANTS[0]
    ref, new = Side(reference, params), Side(limiterd, params)
    hello_req = {"op": "hello", "protocol": 1, "cap": 1000, "gap": 0.0, "client": "a"}
    assert ref.connect(0, hello_req) == new.connect(0, hello_req)
    ok = [{"ip": f"{NETS[0]}.{i}", "http_status": 200} for i in range(1, 30)]
    steps = [ok, ok, [{"ip": "192.0.2.1", "timeout": True}] * 2, ok, [{"ip": "192.0.2.1", "timeout": True}] * 3, ok,
             ok + [{"timeout": True}] + [{"ip": "198.51.100.1", "timeout": True}] * 3,
             [{"ip": "192.0.2.2", "timeout": True}, {"ip": "192.0.2.2"}, {"ip": "192.0.2.2", "timeout": True}, {"ip": "192.0.2.2"}],
             [{"ip": "203.0.113.5", "http_status": 429, "retry_after": 3}] + ok]
    for i, events in enumerate(steps):
        req = {"op": "observe", "events": events}
        assert run(ref.core, ref.conns[0], req) == run(new.core, new.conns[0], req), i
        assert state(ref, False) == state(new, True), i
        for side in (ref, new):
            side.clock.t += 7
