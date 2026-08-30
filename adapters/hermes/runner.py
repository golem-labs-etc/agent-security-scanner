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

import errno
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

# How much of a diagnosis we keep. Long enough for a stack-ish stderr line,
# short enough that it stays readable in a dashboard pane.
_ERR_MAX = 500
_STDOUT_SNIPPET = 160


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


# --------------------------------------------------------- error reporting
#
# There are four distinct ways a scan run fails and they need four distinct
# things done about them. Collapsing them into one message costs debugging
# time: it names one cause, and the reader spends their afternoon on it.
#
#   not on PATH        install it, or set GLANCE_SCANNER_BIN
#   spawn failure      it is there but the OS would not run it -- errno says why
#   non-zero exit      it ran and objected -- its own stderr says why
#   unparseable stdout it ran, exited 0, and printed something that is not JSON
#
# The last one is the only genuine "the parser is the problem" case, and it
# should be rare. It was previously the label on all four.

def _set_error(msg: Optional[str]) -> None:
    """Store the diagnosis under the lock that `stats` reads it under."""
    with _state.lock:
        _state.last_error = msg[:_ERR_MAX] if msg else msg


def _first_line(s: Optional[str]) -> str:
    for line in (s or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _spawn_error(exc: OSError) -> str:
    """The process never started. The errno is the entire diagnosis.

    Reached when the file passes `shutil.which` but `execve` refuses it: a
    missing interpreter in the shebang, a permission bit dropped by a package
    manager, a text file where a binary is expected. Nothing was run, so there
    is no stdout to blame.
    """
    code = errno.errorcode.get(exc.errno, "?") if exc.errno is not None else "?"
    target = getattr(exc, "filename", None) or SCANNER_BIN
    hint = {
        errno.ENOENT: "The file or its interpreter is missing; check its shebang.",
        errno.EACCES: "It is not executable; chmod +x it.",
        errno.ENOEXEC: "The OS would not execute it; check its shebang.",
        errno.EISDIR: "That path is a directory.",
    }.get(exc.errno, "")
    msg = (
        f"cannot start {SCANNER_BIN}: [errno {exc.errno} {code}] "
        f"{exc.strerror or exc} ({target})"
    )
    return msg + (f". {hint}" if hint else "")


def _output_error(proc: "subprocess.CompletedProcess") -> str:
    """stdout would not parse. Say which of the two reasons that was.

    Called only after the parse has already failed, so a findings run -- which
    exits 1 with perfectly good JSON -- never reaches here. The exit code is
    consulted after the parse, never before, or a run that found something
    would be reported as an error.
    """
    err = _first_line(proc.stderr)
    if proc.returncode != 0:
        # The common case by far. The scanner ran, rejected its input or hit an
        # error, and said so. Its own words are more useful than ours.
        return (
            f"{SCANNER_BIN} exited {proc.returncode}: "
            + (err or "no output on stderr")
        )
    out = (proc.stdout or "").strip()
    if not out:
        return (
            f"{SCANNER_BIN} exited 0 but wrote nothing to stdout"
            + (f" (stderr: {err})" if err else "")
        )
    return (
        f"{SCANNER_BIN} exited 0 and wrote output that is not JSON: {out[:_STDOUT_SNIPPET]!r}"
    )


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
        _set_error(
            f"{SCANNER_BIN} not found on PATH. Install glance-scanner, or set "
            "GLANCE_SCANNER_BIN to its full path."
        )
        return None

    fd, tmp = tempfile.mkstemp(prefix="glance-inv-", suffix=".json")
    try:
        # 0600: the inventory carries inline env values so the scanner can judge
        # their shape. It is unlinked below and never persists.
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(inv, fh)

        argv = [SCANNER_BIN, "surfaces", "--inventory", tmp, "--json",
                "--policy", SCAN_POLICY]
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=_SCAN_TIMEOUT_SECONDS,
            )
        except OSError as exc:
            # Never started. Distinct from anything the scanner could report,
            # because the scanner did not run.
            _set_error(_spawn_error(exc))
            return None
        except subprocess.TimeoutExpired:
            _set_error(
                f"{SCANNER_BIN} did not finish within {_SCAN_TIMEOUT_SECONDS}s "
                "and was killed. No result was read."
            )
            return None
        except subprocess.SubprocessError as exc:
            _set_error(f"cannot run {SCANNER_BIN}: {type(exc).__name__}: {exc}")
            return None

        # The CLI exits 1 when it found something critical or high. That is a
        # result, not a failure, so success is defined by the parse and the
        # exit code is only consulted once the parse has already failed.
        try:
            report = json.loads(proc.stdout)
        except ValueError:
            _set_error(_output_error(proc))
            return None
    except OSError as exc:
        # Writing the inventory temp file failed. Also not the scanner.
        _set_error(f"cannot write the inventory file: {exc}")
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
        _set_error(f"scan thread failed: {type(exc).__name__}: {exc}")
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
