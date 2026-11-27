"""Deterministic, stdlib-only fuzz harness for the rdv/1 decoder and the UPnP/SSDP validators.

Why this exists: the rendezvous's frame decoder consumes attacker-controlled
bytes from unauthenticated peers, and the SSDP/LOCATION validators consume
attacker-controlled packets. The unit and black-box suites cover hand-picked
adversarial inputs; this harness explores *generated* ones (grammar-aware
templates mutated at the value level, byte-level mutations, depth bombs and
raw garbage) and checks security invariants instead of crash-only hunting.

Scope (deliberate): pure call paths only.
    - ``RendezvousHandler.handle()``: frame parse + authorization + routing; the
      QUIC transport framing itself is bounded by construction (8 KiB cap,
      bounded pending buffer) and stays covered by the loopback tests.
    - ``upnp``: ``_parse_ssdp_response`` / ``is_private_http_location`` /
      ``is_lan_unicast_address`` / ``_control_url_on_base`` and the full
      reply-to-fetch gate of ``_first_igd_location``.
    - ``tokens``: ``is_valid_bucket_token`` / ``verify_bucket_token`` /
      ``derive_bucket_token`` on arbitrary text.

A coverage-guided driver (``fuzz/fuzz_guided.py``, arc feedback through
``coverage.py``) builds on the same generators and invariants; libFuzzer
(``clang -fsanitize=fuzzer``) remains the hard requirement for the future C port. The generators here are
fully deterministic (``random.Random(seed)``) so findings are reproducible; the
same targets run briefly inside ``tests/test_fuzz_harness.py``.

Standalone run (longer than the CI burst):
    .venv/bin/python fuzz/fuzz_boot.py --seconds 60
    .venv/bin/python fuzz/fuzz_boot.py --iterations 50000 --seed 12345

A finding prints the reproducing input (repr) and exits 1.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from hsync_rendezvous import upnp
from hsync_rendezvous.handler import RendezvousHandler
from hsync_rendezvous.tokens import derive_bucket_token, is_valid_bucket_token, verify_bucket_token

__all__ = [
    "PEER_IP",
    "PEER_PORT",
    "PROBE_CID",
    "PROBE_FP",
    "Finding",
    "assert_reply",
    "depth_bombs",
    "frame_batch",
    "fresh_handler",
    "generate_input",
    "handle_one",
    "mutate_bytes",
    "random_lines",
    "raw_garbage",
    "render",
    "reset_leak_trackers",
    "run_fuzz",
    "seed_corpus",
    "seen_buckets",
    "seen_cids",
    "template_mutations",
    "token_for",
    "track_accepts",
]

# Documentation-range peer (never a real routable address).
PEER_IP = "203.0.113.9"
PEER_PORT = 51000

# Probe constants shared with the CI burst test (tests/test_fuzz_harness.py).
PROBE_CID = "A1b2C3d4E5f6G7h8I9j0K"
PROBE_FP = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"

_KEY_SHARED = b"kshared"
_KEY_PRIVATE = b"kpriv"

_BASE_URL = "http://192.168.1.1:5000/rootDesc.xml"


class Finding(AssertionError):
    """A fuzz iteration violated an invariant (carries the reproducing input)."""


def _check(condition: bool, message: str, raw: Any) -> None:
    if not condition:
        raise Finding(f"{message} — input={render(raw)}")


def render(raw: Any) -> str:
    """Bounded repr of a fuzz input, for findings and CI failure messages."""
    return repr(raw[:200] if isinstance(raw, (bytes, str)) else raw)


def token_for(key: bytes, bucket: str) -> str:
    """Derived bucket token for probe/harness frames (see ``tokens.py``)."""
    return derive_bucket_token(key, bucket)


def templates() -> dict[str, dict]:
    """In-spec frames used as the grammar-aware seed corpus."""
    return {
        "register": {
            "protocol_version": "rdv/1",
            "type": "register",
            "cid": PROBE_CID,
            "bucket": "shared",
            "group": "home",
            "cert_fp": PROBE_FP,
            "version": "1.0.0",
            "endpoints": [{"proto": "tcp", "host": "198.51.100.7", "port": 443}],
            "connected": 5,
        },
        "refresh": {
            "protocol_version": "rdv/1",
            "type": "refresh",
            "cid": PROBE_CID,
            "bucket": "shared",
            "group": "home",
            "connected": 7,
        },
        "leave": {
            "protocol_version": "rdv/1",
            "type": "leave",
            "cid": PROBE_CID,
            "bucket": "shared",
        },
        "query": {
            "protocol_version": "rdv/1",
            "type": "query",
            "bucket": "shared",
            "group": "home",
            "limit": 20,
        },
    }


# Edge values the wire models must accept, reject or bound — a checklist the
# generator shoots at whichever field it wants to mutate.
_EDGE_VALUE_POOL: list[Any] = [
    None,
    "",
    " ",
    "0",
    0,
    -1,
    1,
    0.5,
    2**53,
    2**53 + 1,
    10**30,
    float("inf"),
    True,
    False,
    "0" * 64,  # well-formed token, wrong value
    "0" * 63,  # wrong length
    "0" * 65,
    "Z" * 64,  # not hex
    "0" * 64 + "\n",  # trailing newline must fail the token fullmatch
    "a" * 63,  # bucket name at max length
    "a" * 64,  # bucket name over max length
    "has space",
    "-lead",
    "dot.name",
    "..",
    "/",
    "\u0000control\u0000",
    "😀",
    [{"proto": "tcp", "host": "198.51.100.7", "port": 443}],  # list where scalar expected
    {"proto": "tcp", "host": "198.51.100.7", "port": 443},  # dict where list expected
    1e999,  # JSON Infinity literal
    "1e999",
]

_EXTRA_KEYS = ("file_search", "evil", "bucket_token_dup", "type", "__proto__")


def seed_corpus() -> list[bytes]:
    """Spec fixtures + rendered templates, as byte-mutation starting points."""
    corpus: list[bytes] = []
    for name in (
        "rendezvous-register.json",
        "rendezvous-query.json",
        "rendezvous-ack.json",
        "rendezvous-response.json",
    ):
        path = Path(__file__).resolve().parents[2] / "fixtures" / name
        corpus.append(path.read_bytes())
    for frame in templates().values():
        corpus.append(json.dumps(frame).encode("utf-8"))
    return corpus


def mutate_bytes(rng: random.Random, raw: bytes) -> bytes:
    """Apply 1–10 random byte-level mutations (bit flips, edits, chunking)."""
    out = bytearray(raw)
    for _ in range(rng.randint(1, 10)):
        if not out:
            break
        op = rng.randrange(6)
        if op == 0:  # bit flip
            i = rng.randrange(len(out))
            out[i] ^= 1 << rng.randrange(8)
        elif op == 1:  # substitution
            i = rng.randrange(len(out))
            out[i] = rng.randrange(256)
        elif op == 2:  # insertion
            out.insert(rng.randrange(len(out) + 1), rng.randrange(256))
        elif op == 3 and len(out) > 4:  # deletion
            del out[rng.randrange(len(out))]
        elif op == 4 and len(out) > 8:  # duplicated chunk
            i = rng.randrange(len(out) - 4)
            j = rng.randrange(i + 1, len(out))
            out += out[i:j]
        else:  # truncation
            del out[rng.randrange(len(out)) :]
    return bytes(out)


def template_mutations(rng: random.Random) -> Iterator[bytes]:
    """Grammar-aware frames: templates with edge-value field mutations."""
    t = templates()
    valid_token = token_for(_KEY_SHARED, "shared")
    private_token = token_for(_KEY_PRIVATE, "private")
    while True:
        name = rng.choice(tuple(t))
        frame = dict(t[name])
        for _ in range(rng.randint(0, 3)):
            field = rng.choice(tuple(frame))
            frame[field] = rng.choice(_EDGE_VALUE_POOL)
        if rng.random() < 0.35:
            frame["bucket_token"] = rng.choice(
                [valid_token, private_token, None, "0" * 64, "z" * 64, "0" * 63]
            )
        if rng.random() < 0.2:
            frame[rng.choice(_EXTRA_KEYS)] = rng.choice(_EDGE_VALUE_POOL)
        # Valid deep forms often enough that accept paths stay exercised.
        if rng.random() < 0.4 and isinstance(frame.get("endpoints", []), list):
            frame["endpoints"] = [
                {"proto": "tcp", "host": "198.51.100.7", "port": 443}
                for _ in range(rng.choice([1, 2, 16]))
            ]
        yield json.dumps(frame).encode("utf-8") + b"\n"


def depth_bombs(rng: random.Random) -> Iterator[bytes]:
    """Deeply nested JSON at sizes inside the 8 KiB frame cap."""
    while True:
        depth = rng.choice([5, 32, 128, 512, 1500, 4000])
        raw = ('{"a":' * depth) + "1" + ("}" * depth)
        yield raw.encode("utf-8")[:8192]


def random_lines(rng: random.Random) -> Iterator[bytes]:
    """JSON-ish ASCII lines (with control characters and escapes)."""
    alphabet = 'abc123{}":,[] \t\r\n\\"'
    while True:
        n = rng.randint(0, 300)
        yield "".join(rng.choice(alphabet) for _ in range(n)).encode("utf-8")


def raw_garbage(rng: random.Random) -> Iterator[bytes]:
    """Uniform random bytes at the sizes a real attacker would send."""
    while True:
        n = rng.choice([0, 1, 16, 4096, 8192])
        yield bytes(rng.randrange(256) for _ in range(n))


def frame_batch(rng: random.Random, single: bytes, corpus: list[bytes]) -> bytes:
    """Wrap ``single`` into a pipelined batch with probability 1/4."""
    if rng.random() < 0.25 and corpus:
        parts = [single] + [rng.choice(corpus) for _ in range(rng.randint(1, 4))]
        rng.shuffle(parts)
        return b"\n".join(parts) + b"\n"
    return single


def generate_input(rng: random.Random, corpus: list[bytes]) -> list[bytes]:
    """One fuzzed input: a single frame or a pipelined batch (probabilistic).

    The static-policy mix used by :func:`run_fuzz`; the coverage-guided driver
    (``fuzz/fuzz_guided.py``) composes the same primitives with its own weights.
    """
    pick = rng.random()
    if pick < 0.30:
        single = next(template_mutations(rng))
    elif pick < 0.55:
        single = mutate_bytes(rng, rng.choice(corpus)) + b"\n"
    elif pick < 0.70:
        single = next(depth_bombs(rng))
    elif pick < 0.85:
        single = next(random_lines(rng))
    else:
        single = next(raw_garbage(rng))
    return [frame_batch(rng, single, corpus)]


# Leak-oracle bookkeeping: what THIS fuzz window successfully registered. The
# reply invariants assert that relayed peers can only come from this set, so a
# model bug that leaks unregistered (or foreign-bucket) peers fires a Finding.
seen_cids: set[str] = set()
seen_buckets: set[str] = set()


def reset_leak_trackers() -> None:
    seen_cids.clear()
    seen_buckets.clear()


def track_accepts(raw: bytes, out: Any) -> None:
    """Track what this fuzz session successfully registered (for leak asserts).

    Only self-generated, parseable register frames can be attributed; byte-
    mutated inputs are best-effort (skipped when they do not parse).
    """
    if isinstance(out, bytes):
        try:
            reply = json.loads(out)
        except ValueError:
            return
        if reply.get("type") != "ack" or reply.get("error") is not None:
            return
    try:
        frame = json.loads(raw)
    except ValueError:
        return
    if not (isinstance(frame, dict) and frame.get("type") == "register"):
        return
    cid, bucket = frame.get("cid"), frame.get("bucket")
    if isinstance(cid, str) and isinstance(bucket, str):
        seen_cids.add(cid)
        seen_buckets.add(bucket)


def fresh_handler() -> RendezvousHandler:
    """Isolated handler per fuzz window (per-IP budgets reset, RAM-only state)."""
    reset_leak_trackers()
    return RendezvousHandler(
        protected_buckets=("shared", "private"),
        group_keys={
            "shared": SecretStr(_KEY_SHARED.decode("utf-8")),
            "private": SecretStr(_KEY_PRIVATE.decode("utf-8")),
        },
    )


def handle_one(handler: RendezvousHandler, raw: bytes) -> bytes | None:
    """Run one fuzzed frame through the handler under the fuzz invariants.

    The invariants (never raises; reply shaped; no cross-record/cross-bucket
    leak) are the security oracle shared by the static run_fuzz targets and the
    coverage-guided driver.
    """
    try:
        out = handler.handle(raw, peer_ip=PEER_IP, peer_port=PEER_PORT)
    except Exception as exc:
        raise Finding(f"handle raised {type(exc).__name__}: {exc} — input={render(raw)}") from exc
    track_accepts(raw, out)
    assert_reply(raw, out)
    return out


def assert_reply(raw: bytes, out: bytes | None) -> None:
    """Reply invariants, independent of how the input was generated."""
    if out is None:
        return
    try:
        frame = json.loads(out)
    except ValueError as exc:
        raise Finding(f"reply is not JSON: {exc} — input={render(raw)}") from None
    if not isinstance(frame, dict):
        raise Finding(f"reply is not an object — input={render(raw)} output={render(out)}")
    kind = frame.get("type")
    _check(kind in ("ack", "response"), f"reply type {kind!r}", raw)
    error = frame.get("error")
    _check(
        error in (None, "token_required", "rate_limited", "overloaded"),
        f"reply error {error!r} outside the documented domain",
        raw,
    )
    if error in ("rate_limited", "overloaded"):
        retry = frame.get("retry_after")
        _check(isinstance(retry, int) and retry >= 1, f"retry_after {retry!r}", raw)
    if kind == "response":
        peers = frame.get("peers")
        _check(isinstance(peers, list), f"peers {peers!r} not a list", raw)
        count = frame.get("count")
        _check(isinstance(count, int) and 0 <= count <= 50, f"count {count!r}", raw)
        if isinstance(peers, list):
            _check(len(peers) <= 50, f"relay sample {len(peers)} over the limit", raw)
            for peer in peers:
                _check(isinstance(peer, dict), "peer entry not an object", raw)
                cid, bucket = peer.get("cid"), peer.get("bucket")
                _check(
                    isinstance(cid, str) and re.fullmatch(r"[A-Za-z0-9]{21}", cid),
                    f"peer cid {cid!r}",
                    raw,
                )
                _check(isinstance(bucket, str), f"peer bucket {bucket!r}", raw)
                _check(cid in seen_cids, f"cross-record leak: relayed cid {cid!r}", raw)
                _check(bucket in seen_buckets, f"cross-bucket leak: relayed bucket {bucket!r}", raw)


def _fuzz_tokens(rng: random.Random) -> None:
    """Token helpers: pure, boolean-domain, never raising on arbitrary text."""
    text = next(random_lines(rng)).decode("utf-8", errors="replace")
    expected = "ab" * 32
    ok = is_valid_bucket_token(text)
    _check(isinstance(ok, bool), "is_valid_bucket_token domain", text)
    result = verify_bucket_token(expected, text)
    _check(isinstance(result, bool), "verify_bucket_token domain", text)
    _check(verify_bucket_token(expected, expected) is True, "self-verify must be true", expected)
    _check(len(derive_bucket_token(b"seed", text)) == 64, "derived token shape", text)
    if ok and not result:
        # A grammar-valid token that is itself the expectation must verify.
        _check(verify_bucket_token(text, text) is True, "valid token self-verify", text)


_SSDP_TEXTS = (
    "http://192.168.1.1:5000/rootDesc.xml",
    "http://10.0.0.2/desc",
    "http://[fd00::7]:5000/d",
    "https://192.168.1.1/desc.xml",
    "file:///etc/passwd",
    "ftp://192.168.1.1/desc.xml",
    "http://router.lan/rootDesc.xml",
    "http://203.0.113.9/rootDesc.xml",
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://user:password@192.168.1.1/desc.xml",
    "http://192.168.1.1:70000/desc.xml",
    "",
    "   http://192.168.1.1/x   ",
)

_SSDP_SOURCES = (
    "192.168.1.7",
    "10.1.2.3",
    "172.16.5.5",
    "fd00::7",
    "8.8.8.8",
    "203.0.113.9",
    "2001:db8::1",
    "169.254.169.254",
    "fe80::1",
    "127.0.0.1",
    "::1",
    "not-an-address",
    "",
)


class _SeedSock:
    """Fake SSDP datagram socket: one preloaded reply, immediate timeout after."""

    def __init__(self, reply: bytes, source: tuple[str, int]) -> None:
        self._reply = reply
        self._source = source
        self._drained = False

    def settimeout(self, _value: float) -> None:
        pass

    def sendto(self, _data: bytes, _addr: object) -> None:
        pass

    def recvfrom(self, _size: int) -> tuple[bytes, tuple[str, int]]:
        if self._drained:
            raise TimeoutError("drained")
        self._drained = True  # one reply only, then the read times out
        return self._reply, self._source

    def getsockname(self) -> tuple[str, int]:
        return ("192.168.1.10", 0)


def _fuzz_ssdp(rng: random.Random) -> None:
    """SSDP/UPnP validators are pure and the reply-to-fetch gate holds."""
    from urllib.parse import urlsplit

    location = rng.choice(_SSDP_TEXTS)
    if rng.random() < 0.3:
        location = next(random_lines(rng)).decode("utf-8", errors="replace")
    source_ip = rng.choice(_SSDP_SOURCES)

    ok = upnp.is_private_http_location(location)
    _check(isinstance(ok, bool), "is_private_http_location domain", location)
    # Half the time make the reply come from the host it names: the gate only
    # fetches when the LOCATION host equals the reply source, so this exercises
    # the positive fetch path instead of only the mismatching rejections.
    if ok and rng.random() < 0.5:
        source_ip = urlsplit(location).hostname or source_ip
    lan_src = upnp.is_lan_unicast_address(source_ip)
    _check(isinstance(lan_src, bool), "is_lan_unicast_address domain", source_ip)
    control = upnp._control_url_on_base(_BASE_URL, location)
    if control is not None:
        out_parts, base_parts = urlsplit(control), urlsplit(_BASE_URL)
        _check(
            out_parts.hostname == base_parts.hostname and out_parts.scheme == base_parts.scheme,
            f"controlURL escaped the IGD host: {control!r}",
            location,
        )
        _check(upnp.is_private_http_location(control), "resolved controlURL invalid", location)

    if ok and lan_src is False:
        return  # exercised the rejections; nothing more to assert for these

    reply = (
        b"HTTP/1.1 200 OK\r\nLOCATION: "
        + location.encode("utf-8", errors="replace")
        + b"\r\nST: x\r\n\r\n"
    )
    fetched: list[str] = []
    original = upnp._igd_service_from_location
    upnp._igd_service_from_location = lambda _loc, _local: fetched.append(_loc)  # type: ignore[assignment]
    try:
        result = upnp._first_igd_location(_SeedSock(reply, (source_ip, 1900)), 0.5, "192.168.1.10")
    finally:
        upnp._igd_service_from_location = original
    _check(result is None, "the fake fetch never yields a service", reply)
    if fetched:
        _check(
            lan_src and upnp.is_private_http_location(fetched[0]),
            f"fetch happened for source={source_ip!r} location={fetched[0]!r}",
            reply,
        )
    elif ok and upnp._location_host_matches_source(location, source_ip):
        _check(False, "valid LAN reply did not reach the fetch", reply)


def _fuzz_handle_step(rng: random.Random, handler: RendezvousHandler, corpus: list[bytes]) -> None:
    for raw in generate_input(rng, corpus):
        handle_one(handler, raw)


_TARGETS = ("handle", "ssdp", "token")


def run_fuzz(
    *,
    iterations_per_target: int | None = None,
    seconds: float = 0.0,
    seed: int = 0,
    targets: tuple[str, ...] = _TARGETS,
    handler: RendezvousHandler | None = None,
) -> dict[str, int]:
    """Run the fuzz targets; returns per-target iteration counts (raises a
    ``Finding`` on the first violated invariant — reproducible via ``seed``).
    """
    unknown = [t for t in targets if t not in _TARGETS]
    if unknown:
        raise ValueError(f"unknown targets: {unknown}")
    rng = random.Random(seed)
    counts = dict.fromkeys(targets, 0)
    deadline = (time.monotonic() + seconds) if seconds > 0 else None
    if iterations_per_target is None and deadline is None:
        iterations_per_target = 10000  # never an unbounded run by accident

    corpus = seed_corpus()
    if "handle" in targets and handler is None:
        handler = fresh_handler()

    while any(
        t for t in targets if not _budget_done(counts[t], iterations_per_target, deadline, t)
    ):
        for target in targets:
            if _budget_done(counts[target], iterations_per_target, deadline, target):
                continue
            try:
                if target == "handle":
                    _fuzz_handle_step(rng, handler, corpus)  # type: ignore[arg-type]
                    counts[target] += 1
                    if counts[target] % 250 == 0:
                        # fresh budgets/records/reset leak trackers: the accept
                        # paths stay exercised over long runs.
                        handler = fresh_handler()
                elif target == "ssdp":
                    _fuzz_ssdp(rng)
                    counts[target] += 1
                else:
                    _fuzz_tokens(rng)
                    counts[target] += 1
            except Finding:
                print(
                    f"FINDING seed={seed} target={target} iteration={counts[target]}",
                    file=sys.stderr,
                )
                raise
    return counts


def _budget_done(count: int, iterations: int | None, deadline: float | None, target: str) -> bool:
    if deadline is not None and time.monotonic() >= deadline:
        return True
    return iterations is not None and count >= iterations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--iterations", type=int, default=0, help="iterations per target (0 = default)"
    )
    parser.add_argument(
        "--seconds", type=float, default=0.0, help="wall-time budget (default: off)"
    )
    parser.add_argument("--seed", type=int, default=0, help="deterministic seed (default 0)")
    parser.add_argument(
        "--target", choices=_TARGETS, default=None, help="single target (default: all)"
    )
    args = parser.parse_args(argv)
    # An explicit --seconds run is time-capped only; the default 10000 applies
    # when neither budget is given (never unbounded by accident).
    iterations = args.iterations if args.iterations > 0 else None
    if iterations is None and args.seconds <= 0:
        iterations = 10000
    targets = (args.target,) if args.target else _TARGETS
    begin = time.monotonic()
    try:
        counts = run_fuzz(
            iterations_per_target=iterations,
            seconds=args.seconds,
            seed=args.seed,
            targets=targets,
        )
    except Finding as exc:
        print(f"fuzz: FINDING after {time.monotonic() - begin:.1f}s", file=sys.stderr)
        print(f"fuzz: {exc}", file=sys.stderr)
        return 1
    took = time.monotonic() - begin
    summary = " ".join(f"{t}={counts[t]}" for t in targets)
    print(f"fuzz: clean ({summary}, seed={args.seed}, {took:.1f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
