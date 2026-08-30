"""The only thing in this adapter that scans.

No hook ever scans. Hooks read what this has already written. That separation
is the whole performance and safety story: `pre_llm_call` runs on every turn of
every session, and anything it does is paid for on the agent's critical path.

State lives under `$HERMES_HOME/.glance/`:

    cache.json      the last completed scan, plus the digest it was taken at
    baseline.json   findings present the first time we ever looked
    scan.lock       so two sessions do not scan the same tree at once

Invalidation is by a digest of (path, mtime, size) across the inventory, not by
a time-to-live. Nothing changes between turns unless a file changes.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .discover import build_inventory, hermes_home, inventory_digest, real

# Part B passes strict. An agent consuming raw markdown never sees a code
# fence, so a directive quoted in one reaches it exactly like any other text.
SCAN_POLICY = "strict"

# Severities the agent is ever told about. `fenced_directive` is medium and so
# is correctly never in this set; `unpinned_remote_exec` is info and likewise.
AGENT_SEVERITIES = ("critical", "high")

SCANNER_BIN = os.environ.get("GLANCE_SCANNER_BIN", "glance-scanner")

_LOCK_STALE_SECONDS = 300
_SCAN_TIMEOUT_SECONDS = 180


class _State:
    """One global object. The scanned filesystem is not per-session.

    A per-session copy of this would mean one session's tool call rewriting
    another session's view of the same disk.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.cache: Optional[Dict[str, Any]] = None
        self.scanning = False
        self.dirty = False
        self.last_error: Optional[str] = None


_state = _State()


def glance_dir(home: Optional[Path] = None) -> Path:
    return (real(home) if home is not None else hermes_home()) / ".glance"


def _cache_path(home: Optional[Path] = None) -> Path:
    return glance_dir(home) / "cache.json"


def _baseline_path(home: Optional[Path] = None) -> Path:
    return glance_dir(home) / "baseline.json"


def _lock_path(home: Optional[Path] = None) -> Path:
    return glance_dir(home) / "scan.lock"


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


def _write_json_atomic(path: Path, doc: Dict[str, Any]) -> None:
    """Write via a temp file and rename, so a reader never sees a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def get_cached(home: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """The last completed scan. Never scans, never stats the scanned tree.

    Reads the cache file once, then serves an in-memory copy that the scan
    thread keeps current. This is what `pre_llm_call` calls, so it has to be
    memory-speed.
    """
    with _state.lock:
        if _state.cache is not None:
            return _state.cache
    doc = _read_json(_cache_path(home))
    with _state.lock:
        if _state.cache is None:
            _state.cache = doc
        return _state.cache


def get_baseline(home: Optional[Path] = None) -> Dict[str, Any]:
    return _read_json(_baseline_path(home)) or {}


def baseline_ids(home: Optional[Path] = None) -> set:
    return set(get_baseline(home).get("ids") or [])


def has_baseline(home: Optional[Path] = None) -> bool:
    return _baseline_path(home).exists()


# ---------------------------------------------------------------- locking

def _acquire_lock(home: Optional[Path] = None) -> bool:
    """Exclusive create. Returns False when another session holds it.

    A lock older than `_LOCK_STALE_SECONDS` is treated as abandoned, because a
    killed process leaves the file behind and the alternative is a tree that
    never scans again.
    """
    p = _lock_path(home)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps({"pid": os.getpid(), "at": time.time()}))
        return True
    except FileExistsError:
        try:
            age = time.time() - p.stat().st_mtime
        except OSError:
            return False
        if age > _LOCK_STALE_SECONDS:
            try:
                p.unlink()
            except OSError:
                return False
            return _acquire_lock(home)
        return False
    except OSError:
        return False


def _release_lock(home: Optional[Path] = None) -> None:
    try:
        _lock_path(home).unlink()
    except OSError:
        pass


# ---------------------------------------------------------------- scanning

def scanner_available() -> bool:
    return shutil.which(SCANNER_BIN) is not None


def run_scan(home: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Discover, shell out to the scanner, write the cache. Blocking.

    Called only from the background thread and from tests. A hook must never
    reach this function.
    """
    root = real(home) if home is not None else hermes_home()
    inv = build_inventory(root)
    digest = inventory_digest(inv)

    if not scanner_available():
        _state.last_error = f"{SCANNER_BIN} not found on PATH"
        return None

    fd, tmp = tempfile.mkstemp(prefix="glance-inv-", suffix=".json")
    try:
        # 0600: the inventory carries inline env values so the scanner can judge
        # their shape. It is unlinked below and never persists.
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(inv, fh)

        proc = subprocess.run(
            [SCANNER_BIN, "surfaces", "--inventory", tmp, "--json",
             "--policy", SCAN_POLICY],
            capture_output=True,
            text=True,
            timeout=_SCAN_TIMEOUT_SECONDS,
        )
        # The CLI exits 1 when it found something. That is a result, not a
        # failure; only a parse failure is a failure.
        try:
            report = json.loads(proc.stdout)
        except ValueError:
            _state.last_error = (proc.stderr or "unparseable scanner output")[:500]
            return None
    except (OSError, subprocess.SubprocessError) as exc:
        _state.last_error = str(exc)[:500]
        return None
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    cache = {
        "digest": digest,
        "scanned_at": report.get("scanned_at"),
        "policy": report.get("policy"),
        "engine_version": report.get("engine_version"),
        "counts": report.get("counts", {}),
        "warnings": report.get("warnings", []),
        "findings": report.get("findings", []),
        "total_scanned": report.get("total_scanned", 0),
    }
    _write_json_atomic(_cache_path(root), cache)

    # First look ever: record what was already here and alert on none of it.
    # A tool that is red on install teaches people to ignore it.
    if not has_baseline(root):
        _write_json_atomic(
            _baseline_path(root),
            {
                "created_at": cache["scanned_at"],
                "digest": digest,
                "ids": sorted({f["id"] for f in cache["findings"] if "id" in f}),
            },
        )

    with _state.lock:
        _state.cache = cache
        _state.last_error = None
    return cache


def _scan_worker(home: Optional[Path]) -> None:
    root = real(home) if home is not None else hermes_home()
    if not _acquire_lock(root):
        with _state.lock:
            _state.scanning = False
        return
    try:
        run_scan(root)
    except Exception as exc:  # never let a thread death be silent
        _state.last_error = str(exc)[:500]
    finally:
        _release_lock(root)
        with _state.lock:
            _state.scanning = False
            _state.dirty = False


def is_stale(home: Optional[Path] = None) -> bool:
    """Has anything on disk changed since the cached scan?"""
    with _state.lock:
        if _state.dirty:
            return True
    cache = get_cached(home)
    if cache is None:
        return True
    root = real(home) if home is not None else hermes_home()
    return cache.get("digest") != inventory_digest(build_inventory(root))


def mark_dirty() -> None:
    """A skill changed. Cheap, synchronous, and does not touch the disk."""
    with _state.lock:
        _state.dirty = True


def kick_scan(home: Optional[Path] = None, force: bool = False) -> bool:
    """Start a background scan if one is not already running.

    Returns True when a thread was started. Never blocks the caller, and never
    runs on the hook's thread.
    """
    with _state.lock:
        if _state.scanning:
            return False
        _state.scanning = True
    if not force:
        try:
            if not is_stale(home):
                with _state.lock:
                    _state.scanning = False
                return False
        except Exception:
            pass
    t = threading.Thread(
        target=_scan_worker, args=(home,), name="glance-surfaces-scan", daemon=True
    )
    t.start()
    return True


def new_findings(session_announced: set, home: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Cached findings the agent has not been told about.

    Three filters, in order: severity, baseline, already-announced. Pure
    memory; this is the read path `pre_llm_call` uses.
    """
    cache = get_cached(home)
    if not cache:
        return []
    base = baseline_ids(home)
    out = []
    for f in cache.get("findings", []):
        if f.get("severity") not in AGENT_SEVERITIES:
            continue
        fid = f.get("id")
        if not fid or fid in base or fid in session_announced:
            continue
        out.append(f)
    order = {s: i for i, s in enumerate(AGENT_SEVERITIES)}
    out.sort(key=lambda f: (order.get(f.get("severity"), 9), f.get("path", ""), f.get("line") or 0))
    return out


def stats(home: Optional[Path] = None) -> Dict[str, Any]:
    """Counts and digest for the dashboard. Cache reads only, never a scan."""
    cache = get_cached(home) or {}
    with _state.lock:
        scanning = _state.scanning
        last_error = _state.last_error
    return {
        "scanned_at": cache.get("scanned_at"),
        "digest": cache.get("digest"),
        "policy": cache.get("policy"),
        "engine_version": cache.get("engine_version"),
        "counts": cache.get("counts", {"critical": 0, "high": 0, "medium": 0, "info": 0}),
        "total_scanned": cache.get("total_scanned", 0),
        "baselined": len(baseline_ids(home)),
        "warnings": cache.get("warnings", []),
        "scanning": scanning,
        "last_error": last_error,
        "scanner_available": scanner_available(),
    }


def reset_for_tests() -> None:
    with _state.lock:
        _state.cache = None
        _state.scanning = False
        _state.dirty = False
        _state.last_error = None
