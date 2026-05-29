"""
timesheet_manager_firewall.py
==============================
Timesheet Manager Utility for the Firewall Scheduler
-----------------------------------------------------
Compile with:
    pyinstaller --onefile timesheet_manager_firewall.py
    (console window is required for the interactive menu — do NOT use --noconsole)

Place alongside firewall_scheduler.exe in C:\WifiScheduler\.

This tool lets the non-admin user (once the admin grants UAC elevation via
a right-click → "Run as administrator" shortcut) edit the schedule in
C:\Timesheet\timesheet.txt and automatically restart the firewall_scheduler
task so changes take effect immediately — no reboot needed.

What it does
------------
  1. Self-elevates to Administrator via UAC if not already elevated.
  2. Presents the current schedule in a numbered list.
  3. Offers a menu:
       [A] Append new time slot(s)
       [R] Remove a specific slot by number
       [C] Clear the entire schedule
       [S] Save changes and restart the scheduler task
       [Q] Quit without saving
  4. On Save:
       a. Writes the updated timesheet.txt.
       b. Ends the scheduled task     (schtasks /end).
       c. Force-kills the EXE process (taskkill /f /im /t).
       d. Starts the scheduled task   (schtasks /run).
       e. Exits.

Timesheet format accepted
--------------------------
    M/D/YYYY HH(am/pm)-HH(am/pm)
    M/D/YYYY HH:MM(am/pm)-HH:MM(am/pm)

Examples:
    3/5/2026 10am-12pm
    3/5/2026 2pm-3pm
    3/6/2026 11:30am-1:45pm
    3/6/2026 11pm-1am         <- overnight spans are fine

Author  : (admin)
Version : 1.1
"""

import re
import sys
import ctypes
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration — keep in sync with firewall_scheduler.py
# ---------------------------------------------------------------------------

# Directory where this script/exe is running from
BASE_DIR = Path(sys.executable).parent if getattr(sys, "frozen", False) \
    else Path(__file__).resolve().parent

TIMESHEET_PATH = str(BASE_DIR / "timesheet.txt")

TASK_NAME     = "Firewall Scheduler"
SCHEDULER_EXE = "firewall_scheduler_v10.exe"

# ---------------------------------------------------------------------------
# UAC self-elevation
# ---------------------------------------------------------------------------

def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_as_admin() -> None:
    """Re-launch this script / exe as Administrator via UAC prompt."""
    executable = sys.executable
    params     = " ".join(f'"{a}"' for a in sys.argv)
    # SW_SHOWNORMAL = 1
    ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, None, 1)
    if ret <= 32:
        print("UAC elevation failed or was denied. Exiting.")
    sys.exit(0)


# ---------------------------------------------------------------------------
# Time / date parsing  (self-contained mirror of firewall_scheduler.py)
# ---------------------------------------------------------------------------

_LINE_RE = re.compile(
    r"(\d{1,2}/\d{1,2}/\d{4})"
    r"\s+"
    r"(\d{1,2}(?::\d{2})?(?:am|pm))"
    r"\s*-\s*"
    r"(\d{1,2}(?::\d{2})?(?:am|pm))",
    re.IGNORECASE,
)


def _parse_clock(token: str):
    """Parse '10am', '2pm', '11:30pm' → (hour_24, minute)."""
    token = token.strip().lower()
    m = re.fullmatch(r"(\d{1,2})(?::(\d{2}))?\s*(am|pm)", token)
    if not m:
        raise ValueError(f"Cannot parse time: '{token}'")
    hour   = int(m.group(1))
    minute = int(m.group(2)) if m.group(2) else 0
    period = m.group(3)
    if period == "am":
        if hour == 12:
            hour = 0
    else:
        if hour != 12:
            hour += 12
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(f"Out-of-range time: {hour:02d}:{minute:02d}")
    return hour, minute


def _parse_entry(raw: str) -> dict:
    """
    Parse a single text line as a time entry.
    Returns a dict with keys: original, start_dt, end_dt, display.
    Raises ValueError with a human-readable message on failure.
    """
    raw = raw.strip()
    m   = _LINE_RE.search(raw)
    if not m:
        raise ValueError(
            "Expected format like  '3/5/2026 10am-12pm'  or  '3/5/2026 2:30pm-4pm'"
        )
    try:
        base_date = datetime.strptime(m.group(1), "%m/%d/%Y").date()
        sh, sm    = _parse_clock(m.group(2))
        eh, em    = _parse_clock(m.group(3))
    except ValueError as exc:
        raise ValueError(str(exc)) from exc

    start_dt = datetime(base_date.year, base_date.month, base_date.day, sh, sm)
    end_dt   = datetime(base_date.year, base_date.month, base_date.day, eh, em)
    if end_dt <= start_dt:          # overnight span
        end_dt += timedelta(days=1)

    overnight = " (overnight)" if end_dt.date() != start_dt.date() else ""
    display   = (
        f"{start_dt:%m/%d/%Y}  "
        f"{start_dt:%I:%M %p}  →  {end_dt:%I:%M %p}{overnight}"
    )

    def _fmt_clock(dt: datetime) -> str:
        h, mi = dt.hour, dt.minute
        mins  = f":{mi:02d}" if mi else ""
        if h == 0:
            return f"12{mins}am"
        elif h < 12:
            return f"{h}{mins}am"
        elif h == 12:
            return f"12{mins}pm"
        else:
            return f"{h - 12}{mins}pm"

    canonical = f"{start_dt:%m/%d/%Y} {_fmt_clock(start_dt)}-{_fmt_clock(end_dt)}"

    return {
        "original" : canonical,
        "start_dt" : start_dt,
        "end_dt"   : end_dt,
        "display"  : display,
    }


# ---------------------------------------------------------------------------
# Timesheet I/O
# ---------------------------------------------------------------------------

def load_timesheet() -> list:
    """
    Load the timesheet.  Returns a list of entry dicts (valid entries only),
    sorted chronologically.  Comment lines and blank lines are discarded
    here; the manager rewrites the file cleanly from the parsed list on save.
    """
    path = Path(TIMESHEET_PATH)
    if not path.exists():
        return []

    entries = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                entries.append(_parse_entry(stripped))
            except ValueError:
                pass    # silently skip unrecognised lines

    entries.sort(key=lambda e: e["start_dt"])
    return entries


def save_timesheet(entries: list) -> None:
    """Write the entry list back to timesheet.txt, sorted chronologically."""
    path = Path(TIMESHEET_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for entry in sorted(entries, key=lambda e: e["start_dt"]):
            fh.write(entry["original"] + "\n")


# ---------------------------------------------------------------------------
# Task Scheduler / process control
# ---------------------------------------------------------------------------

def _run(cmd: list, label: str) -> bool:
    """Run a subprocess command, print its outcome, return True on success."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"  \u2713  {label}")
            return True
        out = (result.stdout + result.stderr).strip()
        print(f"  \u26a0  {label}  (exit {result.returncode})"
              + (f": {out}" if out else ""))
        return False
    except Exception as exc:
        print(f"  \u2717  {label} — error: {exc}")
        return False


def restart_scheduler_task() -> None:
    """
    Three-step restart:
      1. schtasks /end       — graceful task stop
      2. taskkill /f /im /t  — force-kill any orphaned process (+ children)
      3. schtasks /run       — fresh start with the updated timesheet

    Note: TASK_NAME does not need inner quotes here because schtasks /tn
    receives it as a single argv token from the subprocess list — the OS
    passes it verbatim without shell tokenisation.
    """
    print("\nRestarting scheduler task...")

    # Step 1 — graceful end
    _run(
        ["schtasks", "/end", "/tn", TASK_NAME],
        f"schtasks /end  '{TASK_NAME}'"
    )

    time.sleep(2)

    # Step 2 — force-kill process image + child processes
    _run(
        ["taskkill", "/f", "/im", SCHEDULER_EXE, "/t"],
        f"taskkill /f /im {SCHEDULER_EXE}"
    )

    time.sleep(1)

    # Step 3 — start fresh
    ok = _run(
        ["schtasks", "/run", "/tn", TASK_NAME],
        f"schtasks /run  '{TASK_NAME}'"
    )

    if ok:
        print("\n  Scheduler is running with the updated timesheet.")
    else:
        print(
            "\n  WARNING: Could not start the task automatically.\n"
            f"  Please start '{TASK_NAME}' manually from Task Scheduler."
        )


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

DIVIDER  = "-" * 60
BOLD_DIV = "=" * 60


def _print_schedule(entries: list) -> None:
    now = datetime.now()
    if not entries:
        print("  (schedule is empty)")
        return
    for i, e in enumerate(entries, 1):
        if e["end_dt"] <= now:
            status = "  [PAST]"
        elif e["start_dt"] <= now < e["end_dt"]:
            status = "  [ACTIVE NOW]"
        else:
            status = ""
        print(f"  {i:>2}.  {e['display']}{status}")


def _prompt(msg: str) -> str:
    """Prompt and return stripped input.  Never raises EOFError."""
    try:
        return input(msg).strip()
    except (EOFError, KeyboardInterrupt):
        return ""


# ---------------------------------------------------------------------------
# Main interactive loop
# ---------------------------------------------------------------------------

def main() -> None:
    # ------------------------------------------------------------------ #
    # Ensure we are running as Administrator                               #
    # ------------------------------------------------------------------ #
    if not _is_admin():
        print("Requesting administrator privileges via UAC...")
        _relaunch_as_admin()
        # _relaunch_as_admin() always calls sys.exit() — nothing runs below
        # in the non-elevated instance.

    # ------------------------------------------------------------------ #
    # Load existing schedule                                               #
    # ------------------------------------------------------------------ #
    entries  = load_timesheet()
    modified = False        # track whether the user made any changes

    while True:
        print()
        print(BOLD_DIV)
        print("  Firewall Scheduler — Timesheet Manager")
        print(BOLD_DIV)
        print(f"  Timesheet: {TIMESHEET_PATH}")
        print(DIVIDER)
        _print_schedule(entries)
        print(DIVIDER)
        print("  [A] Append new time slot(s)")
        print("  [R] Remove a slot by number")
        print("  [C] Clear the entire schedule")
        print("  [S] Save & restart the scheduler (apply changes NOW)")
        print("  [Q] Quit without saving")
        print(DIVIDER)

        choice = _prompt("  Choose an option: ").upper()

        # ---------------------------------------------------------- #
        # A — Append                                                   #
        # ---------------------------------------------------------- #
        if choice == "A":
            print()
            print("  Enter one time slot per line.")
            print("  Format:  M/D/YYYY HH(am/pm)-HH(am/pm)")
            print("  Example: 3/5/2026 10am-12pm   or   3/5/2026 2:30pm-4pm")
            print("  Leave the line blank and press Enter when done.")
            print()
            added = 0
            while True:
                raw = _prompt("  > ")
                if not raw:
                    break
                try:
                    entry = _parse_entry(raw)
                except ValueError as exc:
                    print(f"  \u2717  Invalid entry: {exc}")
                    continue

                # Warn if the slot is already in the past
                if entry["end_dt"] <= datetime.now():
                    confirm = _prompt(
                        f"  \u26a0  That slot ({entry['display']}) is already in the past.\n"
                        "     Add it anyway? [y/N]: "
                    ).lower()
                    if confirm != "y":
                        continue

                entries.append(entry)
                entries.sort(key=lambda e: e["start_dt"])
                added    += 1
                modified  = True
                print(f"  \u2713  Added: {entry['display']}")

            if added:
                print(f"\n  {added} slot(s) added.")

        # ---------------------------------------------------------- #
        # R — Remove                                                   #
        # ---------------------------------------------------------- #
        elif choice == "R":
            if not entries:
                print("\n  Schedule is empty — nothing to remove.")
                continue
            print()
            raw = _prompt(
                f"  Enter the number(s) to remove (1\u2013{len(entries)}), "
                "comma-separated, or blank to cancel: "
            )
            if not raw:
                continue

            indices_to_remove = set()
            for part in raw.split(","):
                part = part.strip()
                if not part.isdigit():
                    print(f"  \u2717  '{part}' is not a valid number \u2014 skipped.")
                    continue
                n = int(part)
                if not (1 <= n <= len(entries)):
                    print(f"  \u2717  {n} is out of range \u2014 skipped.")
                    continue
                indices_to_remove.add(n - 1)    # convert to 0-based index

            if not indices_to_remove:
                continue

            print("\n  About to remove:")
            for i in sorted(indices_to_remove):
                print(f"      {entries[i]['display']}")
            confirm = _prompt("  Confirm removal? [y/N]: ").lower()
            if confirm != "y":
                print("  Cancelled.")
                continue

            entries  = [e for i, e in enumerate(entries) if i not in indices_to_remove]
            modified = True
            print(f"  \u2713  Removed {len(indices_to_remove)} slot(s).")

        # ---------------------------------------------------------- #
        # C — Clear                                                    #
        # ---------------------------------------------------------- #
        elif choice == "C":
            if not entries:
                print("\n  Schedule is already empty.")
                continue
            confirm = _prompt(
                f"\n  This will delete ALL {len(entries)} slot(s) from the schedule.\n"
                "  Are you sure? [y/N]: "
            ).lower()
            if confirm == "y":
                entries  = []
                modified = True
                print("  \u2713  Schedule cleared.")
            else:
                print("  Cancelled.")

        # ---------------------------------------------------------- #
        # S — Save & Restart                                           #
        # ---------------------------------------------------------- #
        elif choice == "S":
            print()
            if not modified:
                confirm = _prompt(
                    "  No changes have been made since loading.\n"
                    "  Restart the scheduler anyway? [y/N]: "
                ).lower()
                if confirm != "y":
                    continue

            save_timesheet(entries)
            print(f"  \u2713  Timesheet saved to {TIMESHEET_PATH}")

            restart_scheduler_task()

            print()
            print(BOLD_DIV)
            print("  Done. Timesheet Manager exiting.")
            print(BOLD_DIV)
            _prompt("\n  Press Enter to close this window...")
            sys.exit(0)

        # ---------------------------------------------------------- #
        # Q — Quit                                                     #
        # ---------------------------------------------------------- #
        elif choice == "Q":
            if modified:
                confirm = _prompt(
                    "\n  You have unsaved changes. Quit without saving? [y/N]: "
                ).lower()
                if confirm != "y":
                    continue
            print("\n  Exiting without saving.")
            _prompt("  Press Enter to close this window...")
            sys.exit(0)

        else:
            print(f"\n  Unknown option '{choice}'. Please choose A, R, C, S, or Q.")


if __name__ == "__main__":
    main()
