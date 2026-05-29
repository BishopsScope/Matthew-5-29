"""
firewall_scheduler.py
=====================
Internet Connection Scheduler for Windows 11  —  v2.7
------------------------------------------------------

COMPILE:
    pyinstaller --onefile --noconsole firewall_scheduler.py
    pyinstaller --onefile firewall_scheduler.py   <- visible console for debugging

TASK SCHEDULER TRIGGERS (all three required):
    1. At system startup
    2. On event — Log: System, Source: EventLog,              Event ID: 6005
    3. On event — Log: System, Source: Microsoft-Windows-Kernel-Power, Event ID: 107

    Action        : <path to firewall_scheduler.exe>
    Run as        : SYSTEM
    Highest priv  : YES
    If running    : Stop the existing instance   (belt-and-suspenders; unreliable
                    against Fast Startup survivors — handled by v2.7 lock protocol)

TIMESHEET : C:\\Timesheet\\timesheet.txt
LOG       : C:\\Timesheet\\scheduler.log
LOCK FILE : C:\\Timesheet\\scheduler.lock   <- LockFileEx target (no meaningful content)
PID FILE  : C:\\Timesheet\\scheduler.pid    <- PID storage (never locked, always readable)
            Fallback log: %TEMP%\\firewall_scheduler.log  (if primary is unwritable)

v2.7  - Fixed two bugs in the v2.6 PID file protocol.

        BUG 1 — read failure on locked file (broken in v2.6):
        Microsoft documents (Vista+) that an exclusive LockFileEx byte-range
        lock denies other processes BOTH read and write access to the locked
        region.  v2.6 locked the entire scheduler.pid file and then expected
        losing instances to read the holder's PID from that same file.  That
        read hits ERROR_LOCK_VIOLATION; the exception is caught; _read_pid()
        returns None; taskkill is never called; the loop spins until
        MAX_ATTEMPTS and falls through into multi-instance state.

        FIX — split into two files:
          scheduler.lock  Used only for LockFileEx.  Its contents are
                          irrelevant and never read.  Opened with
                          FILE_SHARE_READ | FILE_SHARE_WRITE so every
                          instance can hold an open handle simultaneously;
                          LockFileEx arbitrates who owns the lock.
          scheduler.pid   Used only to store the holder's PID as ASCII text.
                          Never locked.  Written by the lock holder via
                          Python's open() immediately after acquiring the
                          lock.  Read by losing instances via Python's open()
                          at any time — no lock means no access violation,
                          so the read always succeeds.

        The mutual exclusion guarantee (exactly one instance holds LockFileEx
        at a time) ensures only the lock holder writes to scheduler.pid, so
        there is no write race on the PID file even though it is never locked.

        BUG 2 — MAX_ATTEMPTS fallback (removed in v2.7):
        Falling back to "proceed without the lock" after N failed attempts
        explicitly allows multi-instance execution, which is exactly what
        the protocol exists to prevent.  The loop now retries indefinitely.
        If the kill genuinely cannot land (diagnosable from repeated log
        lines), the right response is to investigate, not to silently corrupt
        state by running two concurrent scheduler instances.

v2.6  - PID file + LockFileEx single-instance enforcement (broken read path).
v2.5  - Named mutex + active kill-by-name (mutual-kill race with 3 triggers).
v2.4  - Named mutex, passive enforcement (Fast Startup survival bug).
v2.3  - Replaced MpsSvc check with BFE check.
v2.2  - 5 s poll interval.
v2.0  - _wait_for_firewall_service() polls indefinitely.
v1.9  - Service readiness gate; fixed duplicate rule creation at boot.
v1.5  - Fault-tolerant logging setup; startup banner.
v1.2  - Fixed subprocess quoting for rule names with spaces.
v1.1  - Past entries pruned from timesheet on startup and after each interval.
"""

import os
import re
import sys
import time
import ctypes
import logging
import subprocess
from ctypes import wintypes
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Directory where the script/exe is running from
BASE_DIR = Path(sys.executable).parent if getattr(sys, "frozen", False) \
    else Path(__file__).resolve().parent

TIMESHEET_PATH    = str(BASE_DIR / "timesheet.txt")
LOG_PATH          = str(BASE_DIR / "scheduler.log")
LOCK_FILE_PATH    = str(BASE_DIR / "scheduler.lock")
PID_FILE_PATH     = str(BASE_DIR / "scheduler.pid")

FALLBACK_LOG_PATH = os.path.join(
    os.environ.get("TEMP", r"C:\Windows\Temp"),
    "firewall_scheduler.log",
)

FIREWALL_RULE_NAME    = "Block All Internet"
FIREWALL_SERVICE_NAME = "BFE"                        # Base Filtering Engine

# ---------------------------------------------------------------------------
# Single-instance enforcement via split lock/PID files  (v2.7)
# ---------------------------------------------------------------------------

_IS_FROZEN = getattr(sys, "frozen", False)
_EXE_NAME  = Path(sys.executable).name if _IS_FROZEN else None

# Win32 constants (lock file only — PID file uses Python's open())
_GENERIC_READ_WRITE        = 0xC0000000
_FILE_SHARE_READ_WRITE     = 0x00000003
_OPEN_ALWAYS               = 4
_FILE_ATTRIBUTE_NORMAL     = 0x00000080
_LOCKFILE_EXCLUSIVE_LOCK   = 0x00000002
_LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
_INVALID_HANDLE_VALUE      = -1


class _OVERLAPPED(ctypes.Structure):
    """
    Win32 OVERLAPPED required by LockFileEx/UnlockFileEx.
    All fields zeroed; hEvent=NULL is valid for synchronous locking.
    c_size_t used for ULONG_PTR fields to be correct on 32-bit and 64-bit.
    """
    _fields_ = [
        ("Internal",     ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset",       wintypes.DWORD),
        ("OffsetHigh",   wintypes.DWORD),
        ("hEvent",       ctypes.c_void_p),
    ]


_k32 = ctypes.windll.kernel32
_k32.CreateFileW.restype   = ctypes.c_void_p
_k32.LockFileEx.restype    = wintypes.BOOL
_k32.UnlockFileEx.restype  = wintypes.BOOL
_k32.CloseHandle.restype   = wintypes.BOOL
_k32.GetLastError.restype  = wintypes.DWORD

# Module-level lock file handle, kept alive for process lifetime.
# The OS closes it (and releases the lock) on any kind of process
# termination — clean exit, kill, crash, or shutdown.
_lock_file_handle = None


def _open_lock_file():
    """
    Open (or create) the lock file and return a Win32 HANDLE.

    FILE_SHARE_READ | FILE_SHARE_WRITE: every instance opens this file
    simultaneously.  LockFileEx — not the share mode — controls who owns
    the exclusive lock.  The file's contents are never read or written;
    it exists solely as a synchronization target.

    Returns the handle as a Python int, or None on failure.
    """
    try:
        Path(LOCK_FILE_PATH).parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    h = _k32.CreateFileW(
        LOCK_FILE_PATH,
        _GENERIC_READ_WRITE,
        _FILE_SHARE_READ_WRITE,
        None,
        _OPEN_ALWAYS,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if h is None or h == _INVALID_HANDLE_VALUE or h == 0:
        return None
    return h


def _try_lock(h) -> bool:
    """
    Attempt to acquire an exclusive lock on the lock file immediately.
    Returns True if acquired, False if another instance currently holds it.
    Non-blocking: LOCKFILE_FAIL_IMMEDIATELY returns at once either way.
    """
    ov = _OVERLAPPED()
    return bool(_k32.LockFileEx(
        ctypes.c_void_p(h),
        wintypes.DWORD(_LOCKFILE_EXCLUSIVE_LOCK | _LOCKFILE_FAIL_IMMEDIATELY),
        wintypes.DWORD(0),
        wintypes.DWORD(0xFFFFFFFF),
        wintypes.DWORD(0xFFFFFFFF),
        ctypes.byref(ov),
    ))


def _unlock(h) -> None:
    """Release the exclusive lock on the lock file."""
    ov = _OVERLAPPED()
    _k32.UnlockFileEx(
        ctypes.c_void_p(h),
        wintypes.DWORD(0),
        wintypes.DWORD(0xFFFFFFFF),
        wintypes.DWORD(0xFFFFFFFF),
        ctypes.byref(ov),
    )


def _write_pid(pid: int) -> None:
    """
    Write PID to the PID file using Python's open().

    Called only by the lock holder, so there is no concurrent writer.
    The PID file is never LockFileEx-locked, so this open() always succeeds.
    Write 0 on clean exit so a stale PID is never acted on after our handle
    is closed but before the next instance opens the PID file.
    """
    try:
        Path(PID_FILE_PATH).parent.mkdir(parents=True, exist_ok=True)
        with open(PID_FILE_PATH, "w", encoding="ascii") as f:
            f.write(str(pid))
    except Exception as exc:
        print(f"  WARNING: Could not write PID file: {exc}")


def _read_pid():
    """
    Read the current holder's PID from the PID file.

    The PID file is NEVER locked, so this open() is always permitted
    regardless of which instance holds the lock file lock.  This is the
    core reason for separating the two files: the lock guarantees mutual
    exclusion while keeping the identity data freely readable.

    Returns the PID as int, or None if the file is absent, empty, or
    contains non-numeric data (e.g., the 0 written on clean exit).
    """
    try:
        with open(PID_FILE_PATH, "r", encoding="ascii") as f:
            raw = f.read().strip()
        pid = int(raw) if raw.isdigit() else None
        return pid if pid else None   # treat 0 as None (clean-exit sentinel)
    except Exception:
        return None


def _kill_holder(pid: int) -> None:
    """
    Kill the process identified by `pid`, only if its image name matches
    our EXE.  The dual /FI filter prevents killing an unrelated process if
    the PID was recycled between the read and the kill.

    No-op when _EXE_NAME is None (running as a .py script in dev mode).
    """
    if not _EXE_NAME:
        return
    r = subprocess.run(
        [
            "taskkill", "/F",
            "/FI", f"PID eq {pid}",
            "/FI", f"IMAGENAME eq {_EXE_NAME}",
        ],
        capture_output=True, text=True,
    )
    out = (r.stdout + r.stderr).strip()
    print(f"  taskkill PID {pid} → {out or '(no output)'}")


def _acquire_single_instance():
    """
    Become the sole running instance.  Retries indefinitely — there is no
    fallback that allows multi-instance execution.

    PROTOCOL:
      1. Open the lock file (FILE_SHARE_READ | FILE_SHARE_WRITE so all
         instances hold an open handle simultaneously).
      2. Try LockFileEx on the lock file (exclusive, fail-immediately).
      3. If acquired: write our PID to the SEPARATE PID file (never locked,
         so the write always succeeds), return the lock file handle.
      4. If not acquired: read the holder's PID from the PID file (always
         succeeds — the PID file is never locked), call taskkill, wait 1 s,
         loop back to step 2.

    WHY THE READ ALWAYS WORKS:
      The lock and the identity data are on different files.  LockFileEx on
      scheduler.lock has zero effect on open() calls targeting scheduler.pid.
      The read path cannot hit ERROR_LOCK_VIOLATION regardless of who holds
      the lock or how long they hold it.

    WHY NO MAX_ATTEMPTS / FALLBACK:
      Proceeding without the lock means allowing concurrent instances, which
      is the exact failure mode this protocol exists to prevent.  If the kill
      is not landing (visible in the log as repeated attempts), the correct
      response is to diagnose the cause, not silently corrupt state.
    """
    h = _open_lock_file()
    if h is None:
        err = _k32.GetLastError()
        print(f"WARNING: Cannot open lock file '{LOCK_FILE_PATH}' "
              f"(WinError {err}).  No single-instance protection.")
        return None

    attempt = 0
    while True:
        attempt += 1

        if _try_lock(h):
            _write_pid(os.getpid())
            print(f"  Lock acquired (attempt {attempt}).  "
                  f"PID {os.getpid()} written to '{PID_FILE_PATH}'.")
            return h

        print(f"  Attempt {attempt}: lock file held by another instance.")
        pid = _read_pid()

        if pid is not None:
            print(f"  Holder PID: {pid}.  Sending kill signal...")
            _kill_holder(pid)
        else:
            # PID file is absent, empty, or contains the clean-exit sentinel
            # (0).  The holder may have just acquired the lock and not yet
            # written its PID (tiny window), or it exited cleanly and the
            # lock was released but another instance beat us to it.  Either
            # way, wait and retry.
            print(f"  Attempt {attempt}: PID not yet available.  Waiting...")

        time.sleep(1)


def _release_single_instance(h) -> None:
    """
    Clean up on graceful exit:
      1. Zero the PID file first (still holding the lock, so no race).
      2. Release the lock.
      3. Close the handle.

    On any non-graceful exit (kill, crash, shutdown), the OS closes the
    handle and releases the lock automatically — this function need not run.
    """
    try:
        _write_pid(0)   # zero while still holding the lock
        _unlock(h)
    except Exception:
        pass
    try:
        _k32.CloseHandle(ctypes.c_void_p(h))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Fault-tolerant logging setup
# ---------------------------------------------------------------------------

def _setup_logging() -> str:
    for candidate in (LOG_PATH, FALLBACK_LOG_PATH):
        try:
            Path(candidate).parent.mkdir(parents=True, exist_ok=True)
            with open(candidate, "a", encoding="utf-8"):
                pass
            logging.basicConfig(
                filename=candidate,
                level=logging.INFO,
                format="%(asctime)s  %(levelname)-8s  %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            return candidate
        except Exception:
            continue
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return "stderr"


_active_log = _setup_logging()


def log(msg: str, level: str = "info") -> None:
    getattr(logging, level)(msg)
    print(msg)


def _exit(code: int) -> None:
    """Release the lock, flush logs, and exit."""
    global _lock_file_handle
    if _lock_file_handle is not None:
        _release_single_instance(_lock_file_handle)
        _lock_file_handle = None
    logging.shutdown()
    sys.exit(code)


# ---------------------------------------------------------------------------
# Windows Firewall service readiness check
# ---------------------------------------------------------------------------

def _wait_for_firewall_service() -> None:
    """
    Poll BFE every 5 seconds until it reaches RUNNING state.
    BFE RUNNING = FWPKCLNT.SYS (WFP kernel driver) fully loaded = safe to
    call netsh.  This is a hard service dependency, not a heuristic.
    """
    log("Waiting for Base Filtering Engine (BFE)...")
    start = time.time()
    while True:
        try:
            proc = subprocess.run(
                ["sc", "query", FIREWALL_SERVICE_NAME],
                capture_output=True, text=True, timeout=10,
            )
            if "4  RUNNING" in proc.stdout:
                log(f"  BFE is RUNNING (waited ~{time.time() - start:.0f}s).  "
                    "WFP kernel driver is ready.")
                return
        except Exception as exc:
            log(f"  sc query error (will retry): {exc}", "warning")
        time.sleep(5)


# ---------------------------------------------------------------------------
# Windows Firewall rule helpers
# ---------------------------------------------------------------------------

def _firewall_rules_exist() -> dict:
    result = {"in": False, "out": False}
    try:
        proc = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule",
             f"name={FIREWALL_RULE_NAME}", "verbose"],
            capture_output=True, text=True, timeout=20,
        )
        if "no rules match" in proc.stdout.lower():
            return result
        for line in proc.stdout.splitlines():
            s = line.strip().lower()
            if s.startswith("direction:"):
                val = s.split(":", 1)[1].strip()
                if val in ("in", "inbound"):
                    result["in"] = True
                elif val in ("out", "outbound"):
                    result["out"] = True
    except Exception as exc:
        log(f"Firewall rule lookup error: {exc}", "warning")
    return result


def _ensure_firewall_rules() -> None:
    existing = _firewall_rules_exist()
    log(f"  Rule state — inbound: {existing['in']}, outbound: {existing['out']}")

    for direction, key in [("in", "in"), ("out", "out")]:
        if existing[key]:
            log(f"  Rule already exists (dir={direction}): '{FIREWALL_RULE_NAME}'")
            continue
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={FIREWALL_RULE_NAME}",
            f"dir={direction}",
            "action=block",
            "profile=any",
            "enable=no",
            "remoteip=any",
        ]
        try:
            proc   = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            detail = (proc.stdout + proc.stderr).strip()
            if proc.returncode == 0:
                log(f"  Created rule (dir={direction}): '{FIREWALL_RULE_NAME}'")
            else:
                log(f"  Failed to create rule (dir={direction}) "
                    f"[exit {proc.returncode}]: {detail}", "warning")
        except Exception as exc:
            log(f"  Rule creation error (dir={direction}): {exc}", "error")


def _netsh_set_rule_enabled(enable: bool) -> bool:
    state = "yes" if enable else "no"
    cmd = [
        "netsh", "advfirewall", "firewall", "set", "rule",
        f"name={FIREWALL_RULE_NAME}",
        "new",
        f"enable={state}",
    ]
    try:
        proc   = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        detail = (proc.stdout + proc.stderr).strip()
        if proc.returncode == 0:
            return True
        log(f"netsh set rule [exit {proc.returncode}]: {detail}", "warning")
        return False
    except Exception as exc:
        log(f"netsh set rule exception: {exc}", "error")
        return False


def disable_internet() -> None:
    log(f">>> BLOCKING   internet  (enabling rule '{FIREWALL_RULE_NAME}')")
    ok = _netsh_set_rule_enabled(True)
    log("    Rules enabled  — internet is BLOCKED."
        if ok else "    WARNING: block command may have failed.")


def enable_internet() -> None:
    log(f">>> UNBLOCKING internet  (disabling rule '{FIREWALL_RULE_NAME}')")
    ok = _netsh_set_rule_enabled(False)
    log("    Rules disabled — internet is ALLOWED."
        if ok else "    WARNING: unblock command may have failed.")


# ---------------------------------------------------------------------------
# Time / date parsing
# ---------------------------------------------------------------------------

_LINE_RE = re.compile(
    r"(\d{1,2}/\d{1,2}/\d{4})\s+"
    r"(\d{1,2}(?::\d{2})?(?:am|pm))\s*-\s*"
    r"(\d{1,2}(?::\d{2})?(?:am|pm))",
    re.IGNORECASE,
)


def _parse_clock(token: str):
    token = token.strip().lower()
    m = re.fullmatch(r"(\d{1,2})(?::(\d{2}))?\s*(am|pm)", token)
    if not m:
        raise ValueError(f"Unrecognised time token: '{token}'")
    hour   = int(m.group(1))
    minute = int(m.group(2)) if m.group(2) else 0
    period = m.group(3)
    if period == "am":
        if hour == 12: hour = 0
    else:
        if hour != 12: hour += 12
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(f"Out-of-range time: {hour:02d}:{minute:02d}")
    return hour, minute


def _line_to_interval(line: str):
    m = _LINE_RE.search(line)
    if not m:
        return None
    try:
        base = datetime.strptime(m.group(1), "%m/%d/%Y").date()
        sh, sm = _parse_clock(m.group(2))
        eh, em = _parse_clock(m.group(3))
    except ValueError:
        return None
    s = datetime(base.year, base.month, base.day, sh, sm)
    e = datetime(base.year, base.month, base.day, eh, em)
    if e <= s:
        e += timedelta(days=1)
    return s, e


def parse_timesheet(filepath: str) -> list:
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Timesheet not found: {filepath}")
    intervals = []
    with open(filepath, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            iv = _line_to_interval(line)
            if iv is None:
                log(f"  Line {lineno}: bad format — skipped: {line!r}", "warning")
                continue
            s, e = iv
            log(f"  Loaded: {s:%m/%d/%Y %I:%M %p}  →  {e:%m/%d/%Y %I:%M %p}")
            intervals.append(iv)
    intervals.sort(key=lambda x: x[0])
    return intervals


# ---------------------------------------------------------------------------
# Pruner
# ---------------------------------------------------------------------------

def prune_past_entries() -> int:
    path = Path(TIMESHEET_PATH)
    if not path.exists():
        return 0
    now = datetime.now()
    kept, removed = [], 0
    with open(path, encoding="utf-8") as fh:
        raw_lines = fh.readlines()
    for raw in raw_lines:
        iv = _line_to_interval(raw.strip())
        if iv is not None and iv[1] <= now:
            log(f"  Pruning: {raw.strip()}")
            removed += 1
            continue
        kept.append(raw)
    while kept and kept[-1].strip() == "":
        kept.pop()
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.writelines(kept)
            if kept and not kept[-1].endswith("\n"):
                fh.write("\n")
        if removed:
            log(f"Pruned {removed} past entr{'y' if removed == 1 else 'ies'}.")
        else:
            log("No past entries to prune.")
    except Exception as exc:
        log(f"Could not write pruned timesheet: {exc}", "warning")
    return removed


# ---------------------------------------------------------------------------
# Sleep until a target datetime
# ---------------------------------------------------------------------------

def sleep_until(target_dt: datetime, label: str = "") -> None:
    remaining = (target_dt - datetime.now()).total_seconds()
    if remaining <= 0:
        log(f"    Target {target_dt:%m/%d/%Y %I:%M %p} already reached.")
        return
    log(f"    Sleeping {remaining:.0f}s until {target_dt:%m/%d/%Y %I:%M %p}"
        + (f" [{label}]" if label else "") + ")")
    time.sleep(remaining)
    leftover = (target_dt - datetime.now()).total_seconds()
    if leftover > 0:
        time.sleep(leftover)
    log(f"    Woke up — reached {target_dt:%m/%d/%Y %I:%M %p}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    global _lock_file_handle

    log("Acquiring single-instance lock...")
    _lock_file_handle = _acquire_single_instance()

    log("=" * 60)
    log("  Internet Scheduler (Firewall)  —  v2.7")
    log(f"  PID       : {os.getpid()}")
    log(f"  EXE       : {Path(sys.executable).name}")
    log(f"  User      : {os.environ.get('USERNAME', 'unknown')}")
    log(f"  Log       : {_active_log}")
    log(f"  Timesheet : {TIMESHEET_PATH}")
    log(f"  Lock file : {LOCK_FILE_PATH}")
    log(f"  PID file  : {PID_FILE_PATH}")
    log(f"  Lock held : {_lock_file_handle is not None}")
    log("=" * 60)

    if _active_log != LOG_PATH:
        log(f"  WARNING: Primary log unwritable. Using: {_active_log}", "warning")

    # 1. Wait for BFE
    _wait_for_firewall_service()

    # 2. Ensure firewall rules exist
    log(f"\nChecking firewall rules: '{FIREWALL_RULE_NAME}'")
    _ensure_firewall_rules()

    # 3. Block immediately
    disable_internet()

    # 4. Prune past timesheet entries
    log("\nPruning past entries...")
    prune_past_entries()

    # 5. Load timesheet
    try:
        log(f"\nParsing timesheet: {TIMESHEET_PATH}")
        intervals = parse_timesheet(TIMESHEET_PATH)
    except FileNotFoundError as exc:
        log(str(exc), "error")
        log("Internet remains blocked. Exiting.")
        _exit(1)
    except Exception as exc:
        log(f"Unexpected error reading timesheet: {exc}", "error")
        log("Internet remains blocked. Exiting.")
        _exit(1)

    if not intervals:
        log("No valid intervals. Internet remains blocked. Exiting.")
        _exit(0)

    log(f"\nLoaded {len(intervals)} interval(s).")

    # 6. Drop fully elapsed intervals
    now     = datetime.now()
    pending = [(s, e) for s, e in intervals if e > now]
    skipped = len(intervals) - len(pending)
    if skipped:
        log(f"Skipping {skipped} already-elapsed interval(s).")
    if not pending:
        log("All intervals elapsed. Internet remains blocked. Exiting.")
        _exit(0)

    log(f"{len(pending)} interval(s) remaining.\n")

    # 7. Main loop
    for idx, (start_dt, end_dt) in enumerate(pending, 1):
        now = datetime.now()
        log(f"--- Interval {idx}/{len(pending)}: "
            f"{start_dt:%m/%d/%Y %I:%M %p}  →  {end_dt:%m/%d/%Y %I:%M %p} ---")

        if now < start_dt:
            log("  Before interval — sleeping until start...")
            sleep_until(start_dt, "interval start")
            enable_internet()
        elif start_dt <= now < end_dt:
            log("  Inside active interval — unblocking now.")
            enable_internet()
        else:
            log("  Already elapsed — skipping.", "warning")
            continue

        sleep_until(end_dt, "interval end")
        disable_internet()

        log("\nPruning past entries after interval end...")
        prune_past_entries()

    # 8. Done
    log("\n" + "=" * 60)
    log("  All intervals complete. Internet is BLOCKED. Exiting.")
    log("=" * 60)
    _exit(0)


if __name__ == "__main__":
    main()
