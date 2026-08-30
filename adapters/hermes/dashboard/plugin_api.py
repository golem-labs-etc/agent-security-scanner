"""Dashboard routes. Mounted at /api/plugins/glance-surfaces/.

`/health` and `/stats` are cache reads and never touch the scanned tree.
`/scan` is the one endpoint that starts work, it is a POST, and it returns
immediately: the scan runs on the runner's background thread.

The pane polls `/stats`. It must never poll `/scan` on a timer -- that would be
a full disk rescan every few seconds for every open window.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

try:
    from fastapi import APIRouter
except ImportError:  # pragma: no cover - fastapi ships with the dashboard
    APIRouter = None  # type: ignore

from .. import runner
from ..categories import CATEGORIES

log = logging.getLogger("glance.hermes.dashboard")

router = APIRouter() if APIRouter is not None else None


def health_payload() -> Dict[str, Any]:
    st = runner.stats()
    return {
        "ok": True,
        "scanner_available": st["scanner_available"],
        "policy": st["policy"] or runner.SCAN_POLICY,
        "has_cache": st["scanned_at"] is not None,
        "last_error": st["last_error"],
    }


def stats_payload() -> Dict[str, Any]:
    """Counts and digest, straight off the cache.

    `categories` is served from the single exported list so the pane can build
    its colour map from it rather than keeping a second copy that drifts.
    """
    st = runner.stats()
    st["categories"] = list(CATEGORIES)
    st["agent_severities"] = list(runner.AGENT_SEVERITIES)
    return st


def scan_payload() -> Dict[str, Any]:
    started = runner.kick_scan(force=True)
    return {"started": started, "scanning": runner.stats()["scanning"]}


if router is not None:

    @router.get("/health")
    async def health() -> Dict[str, Any]:
        return health_payload()

    @router.get("/stats")
    async def stats() -> Dict[str, Any]:
        return stats_payload()

    @router.post("/scan")
    async def scan() -> Dict[str, Any]:
        """Explicit, user-initiated. Returns at once; the work is backgrounded."""
        return scan_payload()
