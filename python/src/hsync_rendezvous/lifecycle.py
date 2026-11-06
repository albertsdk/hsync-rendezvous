"""Background loops and the readiness/stats files for a running node.

The periodic duties of a listener process: TTL pruning, the service-manager
watchdog, the readiness PID file, and the STATUS/text-file metric publication.
Kept apart from the CLI command definitions so they can be exercised in
isolation.
"""

from __future__ import annotations

import asyncio
import os
import time

from hsync_common.fs import atomic_write_text

from hsync_rendezvous.binding import ReadyFileError
from hsync_rendezvous.diagnostics import warn_event
from hsync_rendezvous.guard import ConnectionGuard
from hsync_rendezvous.handler import REQUEST_PATH_PRUNE_BUDGET, RendezvousHandler
from hsync_rendezvous.stats import NodeStats
from hsync_rendezvous.systemd import notify_status, notify_watchdog

__all__ = [
    "prune_loop",
    "remove_ready_file",
    "stats_loop",
    "watchdog_loop",
    "write_ready_file",
    "write_stats_file",
]


def write_ready_file(path: str) -> None:
    """Write this process's PID to ``path`` (readiness seam, no peer data).

    Created with ``O_EXCL | O_NOFOLLOW`` so a predictable path in an
    attacker-writable directory cannot be redirected (symlink) to clobber an
    existing file under the node's privileges.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        # Actionable exit (code 4) instead of a traceback: the listener is up but
        # the operator's orchestration seam cannot be honoured.
        raise ReadyFileError(path, exc.errno) from exc
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))


def remove_ready_file(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


async def prune_loop(
    handler: RendezvousHandler, connection_guard: ConnectionGuard | None = None
) -> None:
    """Spec: prune the TTL routing table every 15 s."""
    while True:
        await asyncio.sleep(handler.prune_interval)
        # Chunked: one unbudgeted sweep over a large stale backlog would block the
        # event loop for its whole duration, so the background sweep yields
        # between bounded batches instead (the request path is bounded too). An
        # explicit ``now`` keeps each chunk record-only; the limiter-state sweep
        # runs once per tick (``prune()`` is the only path that evicts it), never
        # once per chunk.
        now = time.monotonic()
        while handler.prune(now, max_remove=REQUEST_PATH_PRUNE_BUDGET) >= REQUEST_PATH_PRUNE_BUDGET:
            await asyncio.sleep(0)
        handler.prune()
        if connection_guard is not None:
            # Same cadence as the routing sweep: forget closed-and-quiet IPs so
            # the guard map cannot grow without bound under IP churn.
            connection_guard.evict_stale()


async def watchdog_loop(interval: float) -> None:
    """Feed the service manager's watchdog at half the armed interval.

    ``interval`` is already half of ``WatchdogSec=`` (:func:`watchdog_interval`),
    so one missed ping still leaves a full period for the next one to arrive. A
    wedged event loop stops pinging and the service manager restarts the node.
    """
    while True:
        await asyncio.sleep(interval)
        notify_watchdog()


def write_stats_file(path: str, body: str) -> None:
    """Replace the stats file atomically so a scraper never reads a partial file.

    Delegates to the shared writer: a fixed temp name opened with ``O_NOFOLLOW``
    (a planted symlink cannot redirect the write) then ``os.replace``.
    """
    atomic_write_text(path, body, mode=0o644, unique_temp=False, nofollow=True)


async def stats_loop(stats: NodeStats, stats_file: str | None, interval: float) -> None:
    """Publish the aggregates on a fixed cadence: ``STATUS=`` and the text file.

    Started only when a sink exists, so a node without a service manager and
    without ``--stats-file`` never wakes up for nothing.
    """
    while True:
        await asyncio.sleep(interval)
        notify_status(stats.status_text())
        if stats_file is None:
            continue
        try:
            write_stats_file(stats_file, stats.render_prometheus())
        except OSError as exc:
            stats.stats_write_failed()
            warn_event(
                "stats file not writable",
                path=stats_file,
                reason=exc.strerror or "write failed",
            )
