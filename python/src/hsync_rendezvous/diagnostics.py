"""Diagnostics for the rendezvous node: an always-on operational channel plus the
opt-in peer-aware debug stream.

The node is **no-log by design**: nothing peer-related is ever written to disk;
without ``--debug`` no peer data leaves memory at all.

``warn_event`` / ``error_event`` — **node health, always emitted** on stderr.
They accept only the non-identifying field allow-list :data:`_PUBLIC_FIELDS`, so
a peer-identifying key raises instead of rendering: the default run stays
peer-free **by construction**.

``debug_log`` / ``debug_event`` — the opt-in full operation log
(``--debug`` / ``HSYNC_RENDEZVOUS_DEBUG=1``), announced once on the always-on
channel when enabled. It **includes peer identity** (CID, bucket, IP, port) and
exists only on stderr: the process never writes it to disk.

A stderr that disappears (the terminal that carried it was closed, a pipe whose
reader died) disables both channels permanently instead of raising: diagnostics
are best-effort and must never take the node down.

Line format (``timestamp - source[pid] level: message``) for both channels::

    2026-09-30T10:30:45.123Z - hsync-rendezvous[1234] debug: register ack cid=… bucket=shared
    2026-09-30T10:30:45.200Z - hsync-rendezvous[1234] warn: upnp no igd on lan port=443

The timestamp is the UTC ISO-8601 SSOT (:func:`hsync_common.time_utils.utc_now_iso`)
so the stream stays correlatable with the ``hsync-client``/``hsync-server`` logs;
the pid disambiguates instances sharing one stderr.
"""

from __future__ import annotations

import os
import sys
import time
from collections import deque

from hsync_common.time_utils import utc_now_iso

__all__ = [
    "configure_debug",
    "debug_enabled",
    "debug_event",
    "debug_log",
    "error_event",
    "warn_event",
]

# Program name of the emitted lines' identity prefix (``hsync-rendezvous[1234]``).
_LOG_IDENTITY = "hsync-rendezvous"

# Fields ``warn_event``/``error_event`` may render. Everything here describes the
# node or the host, never a peer: the always-on channel is persisted by the
# operator, so a CID, bucket, peer endpoint or peer port must not be able to
# reach it (``debug_event`` is the only peer-aware sink).
_PUBLIC_FIELDS = frozenset({"action", "exc", "path", "port", "proto", "reason", "suppressed"})

# Bound a rendered value so a malformed/attacker-influenced string cannot grow a
# line without limit (OWASP: log injection and log-flooding availability risk).
_MAX_VALUE_CHARS = 200

# Anti-flood for the always-on error channel: a repeated failure must not emit a
# line per occurrence (nor grow state without bound). Inside the window only the
# count is kept; the next emission reports it as ``suppressed=<n>``.
_DEDUP_WINDOW_SECONDS = 60.0
_DEDUP_MAX_KEYS = 64

_enabled = False
# Set once stderr is gone for good (closed terminal, dead pipe). Diagnostics are
# best-effort: after that every emission is a no-op rather than an OSError inside
# whichever task happened to log.
_sink_failed = False
# ``(event, rendered fields) -> (window start, suppressed count)``, plus the
# insertion order used to keep the mapping bounded.
_dedup: dict[tuple[str, str], tuple[float, int]] = {}
_dedup_order: deque[tuple[str, str]] = deque()


def configure_debug(enabled: bool) -> None:
    """Enable or disable the stderr debug sink (process-wide)."""
    global _enabled
    _enabled = enabled


def debug_enabled() -> bool:
    """True when the opt-in debug sink is active.

    Hot paths call this before building the expensive ``debug_event`` fields
    (f-strings, attribute lookups, the kwargs dict): Python evaluates call
    arguments eagerly, so ``debug_event(...)`` with ``--debug`` off would still
    pay for every field it then discards.
    """
    return _enabled


def _sanitize(value: object) -> str:
    """Render one line fragment (event name or field value) as log-safe text.

    Newlines, tabs and other control characters become spaces, so no fragment can
    forge a second log line (OWASP log injection); the result is truncated to
    :data:`_MAX_VALUE_CHARS`.
    """
    text = "".join(ch if ch >= " " and ch != "\x7f" else " " for ch in str(value))
    if len(text) > _MAX_VALUE_CHARS:
        text = text[:_MAX_VALUE_CHARS] + "…"
    return text


def _render(event: str, fields: dict[str, object], *, allowed: frozenset[str] | None) -> str:
    """Render ``event key=value ...`` (``None`` fields are omitted).

    Both the event name and every value go through :func:`_sanitize`, so no part
    of the line can contain a control character and forge a second line. With
    ``allowed`` set, a key outside it is a programming error and raises: the
    always-on channel fails loudly rather than leaking peer identity.
    """
    parts = [_sanitize(event)]
    for key, value in fields.items():
        if value is None:
            continue
        if allowed is not None and key not in allowed:
            raise ValueError(
                f"diagnostic field {key!r} is not allowed on the always-on channel "
                f"(allowed: {', '.join(sorted(allowed))}); peer-identifying fields "
                "belong to debug_event(), which requires --debug"
            )
        parts.append(f"{key}={_sanitize(value)}")
    return " ".join(parts)


def _emit(level: str, body: str) -> None:
    """Write one ``timestamp - source[pid] level: body`` line to stderr.

    The single emission point for every channel, so the prefix is rendered once.
    A write failure marks the sink dead for the rest of the process (see
    :data:`_sink_failed`); it is never propagated to the caller.
    The pid is resolved per line — a fork without ``exec`` would otherwise keep
    logging the parent's pid (the same reason loguru renders
    ``record["process"].id`` per record).
    """
    global _sink_failed
    if _sink_failed:
        return
    stream = sys.stderr
    if stream is None:
        _sink_failed = True
        return
    try:
        stream.write(f"{utc_now_iso()} - {_LOG_IDENTITY}[{os.getpid()}] {level}: {body}\n")
        stream.flush()
    except (OSError, ValueError):
        _sink_failed = True


def _dedup_suppressed(key: tuple[str, str]) -> int | None:
    """Throttle a repeated always-on error.

    Returns ``0`` when the line must be emitted as-is, a positive count when it
    must be emitted with ``suppressed=<n>`` (the occurrences hidden in the
    previous window) and ``None`` when this occurrence is a repeat inside the
    current window and must stay silent.
    """
    now = time.monotonic()
    entry = _dedup.get(key)
    if entry is not None and now - entry[0] < _DEDUP_WINDOW_SECONDS:
        _dedup[key] = (entry[0], entry[1] + 1)
        return None
    suppressed = entry[1] if entry is not None else 0
    _evict_dedup(now)
    _dedup[key] = (now, 0)
    _dedup_order.append(key)
    return suppressed


def _evict_dedup(now: float) -> None:
    """Bound the dedup state: drop expired windows, then the oldest keys."""
    while _dedup_order:
        key = _dedup_order[0]
        entry = _dedup.get(key)
        if entry is not None and now - entry[0] < _DEDUP_WINDOW_SECONDS:
            break
        _dedup.pop(key, None)
        _dedup_order.popleft()
    while len(_dedup_order) > _DEDUP_MAX_KEYS:
        key = _dedup_order.popleft()
        _dedup.pop(key, None)


def debug_log(message: str) -> None:
    """Emit one free-form diagnostic line (no-op unless enabled)."""
    if _enabled:
        _emit("debug", _sanitize(message))


def debug_event(event: str, **fields: object) -> None:
    """Emit one structured debug line: ``event key=value ...`` (opt-in only).

    Fields with a ``None`` value are omitted. The sink is an explicit opt-in, so
    callers may include peer-identifying fields (CID, bucket, IP, port) here — and
    only here. Names and values pass through :func:`_sanitize`.
    """
    if not _enabled:
        return
    _emit("debug", _render(event, fields, allowed=None))


def warn_event(event: str, **fields: object) -> None:
    """Emit one always-on operational warning (peer-free by construction).

    Use for node health: a capability that could not be enabled, a degraded
    mode, an operator-visible misconfiguration. ``fields`` is restricted to
    :data:`_PUBLIC_FIELDS`; passing a peer-identifying key raises ``ValueError``.
    """
    _emit("warn", _render(event, fields, allowed=_PUBLIC_FIELDS))


def error_event(event: str, **fields: object) -> None:
    """Emit one always-on operational error (peer-free by construction).

    Same field policy as :func:`warn_event`. Repeated identical errors are
    throttled (:data:`_DEDUP_WINDOW_SECONDS`) and reported as ``suppressed=<n>``
    on the next emission, so a failing path cannot flood the operator's log.
    """
    body = _render(event, fields, allowed=_PUBLIC_FIELDS)
    suppressed = _dedup_suppressed((event, body))
    if suppressed is None:
        return
    if suppressed:
        body = f"{body} suppressed={suppressed}"
    _emit("error", body)
