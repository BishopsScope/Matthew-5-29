"""
adapter_guard_oneshot.py
------------------------
Designed to be launched by Task Scheduler on Event ID 10000
(Microsoft-Windows-NetworkProfile/Operational) and Event ID 410
(Microsoft-Windows-Kernel-PnP/Configuration) — i.e. the moment
any network adapter connects or becomes active — as well as on boot.

Execution order
---------------
  1. Read ALLOWED_ADAPTERS.txt (one adapter display-name per line).
  2. ENABLE every adapter named in that file by calling netsh directly
     (no WMI status check — netsh is a no-op if already enabled, and
     avoids the unreliable NetConnectionStatus codes for soft-disabled
     adapters).
  3. DISABLE every adapter that WMI reports as present and whose display
     name is NOT in the allowlist.  Hardware-absent/malfunction adapters
     (status 4, 5, 6) are skipped in both passes.

Allowlist source
----------------
Adapter names are read at runtime from ALLOWED_ADAPTERS.txt in the
same directory as this script / compiled EXE (one display-name per
line, blank lines and leading/trailing whitespace ignored).

Example ALLOWED_ADAPTERS.txt:
    Wi-Fi
    Ethernet

If the file is missing or empty every active adapter will be disabled
(safe-default / deny-all behaviour).  Nothing will be explicitly
enabled in that case because the allowlist is empty.

Requirements:
    pip install wmi pywin32
Compile (onedir, no console window):
    pyinstaller --onedir --noconsole adapter_guard_oneshot.py
"""

import logging
import subprocess
import sys
from pathlib import Path

import wmi

# ─────────────────────────────────────────────────────────────────────────────
#  PATHS — resolve correctly whether running as .py or compiled EXE
# ─────────────────────────────────────────────────────────────────────────────

# When frozen by PyInstaller --onedir, sys.executable is the EXE and its
# parent is the directory that also contains ALLOWED_ADAPTERS.txt.
# When running as a plain .py script, __file__ gives the same answer.
if getattr(sys, "frozen", False):
    _SCRIPT_DIR: Path = Path(sys.executable).parent
else:
    _SCRIPT_DIR = Path(__file__).parent

ALLOWED_ADAPTERS_FILE: Path = _SCRIPT_DIR / "ALLOWED_ADAPTERS.txt"
LOG_FILE: Path = Path(r"C:\ProgramData\AdapterGuard\adapter_guard.log")

# ─────────────────────────────────────────────────────────────────────────────

# WMI NetConnectionStatus values for adapters with hardware problems.
# These cannot be enabled or disabled via netsh — skip them in both passes.
#   4 = Hardware Not Present
#   5 = Hardware Disabled  (physical switch / BIOS, not netsh)
#   6 = Hardware Malfunction
_HARDWARE_SKIP_STATUSES = {4, 5, 6}


def _load_allowed_adapters() -> set[str]:
    """Read allowed adapter display-names from ALLOWED_ADAPTERS.txt.

    Returns an empty set if the file is absent or contains no non-blank lines,
    which causes all active adapters to be disabled (deny-all default).
    """
    if not ALLOWED_ADAPTERS_FILE.is_file():
        return set()
    lines = ALLOWED_ADAPTERS_FILE.read_text(encoding="utf-8").splitlines()
    return {line.strip() for line in lines if line.strip()}


def setup_logging() -> logging.Logger:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("AdapterGuard")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        fmt="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger


log = setup_logging()


def enable_adapter(name: str) -> None:
    try:
        result = subprocess.run(
            ["netsh", "interface", "set", "interface", name, "admin=enable"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            log.info("ENABLED:  %r", name)
        else:
            stderr = (result.stderr or result.stdout).strip()
            log.warning("netsh returned %d enabling %r: %s", result.returncode, name, stderr)
    except subprocess.TimeoutExpired:
        log.error("Timeout enabling %r", name)
    except Exception as exc:
        log.error("Error enabling %r: %s", name, exc)


def disable_adapter(name: str) -> None:
    try:
        result = subprocess.run(
            ["netsh", "interface", "set", "interface", name, "admin=disable"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            log.info("DISABLED: %r", name)
        else:
            stderr = (result.stderr or result.stdout).strip()
            log.warning("netsh returned %d disabling %r: %s", result.returncode, name, stderr)
    except subprocess.TimeoutExpired:
        log.error("Timeout disabling %r", name)
    except Exception as exc:
        log.error("Error disabling %r: %s", name, exc)


def main() -> None:
    allowed = _load_allowed_adapters()

    if not allowed:
        log.warning(
            "ALLOWED_ADAPTERS.txt is missing or empty — "
            "all active adapters will be disabled."
        )

    log.info(
        "AdapterGuard (one-shot) triggered. "
        "Allowlist file: %s  |  Allowed: %s",
        ALLOWED_ADAPTERS_FILE,
        sorted(allowed),
    )

    # ── Pass 1: enable every adapter named in the allowlist ──────────────────
    # We call netsh directly by name WITHOUT checking WMI status first.
    # Reason: when an adapter is soft-disabled via netsh, WMI may report its
    # NetConnectionStatus as None, 0, or another value that varies by driver
    # and Windows build — there is no single reliable "disabled" status code.
    # Calling "netsh admin=enable" on an already-enabled adapter is a no-op,
    # so this approach is both simpler and correct regardless of current state.
    log.info("── Pass 1: enabling all allowed adapters ──")
    for name in sorted(allowed):
        log.info("Ensuring enabled: %r", name)
        enable_adapter(name)

    # ── Pass 2: disable every adapter NOT in the allowlist ───────────────────
    # Query WMI fresh here so we see the updated state after Pass 1.
    # Only skip adapters with genuine hardware problems (status 4/5/6) — those
    # cannot be controlled via netsh and will just produce an error if we try.
    log.info("── Pass 2: disabling all non-allowed adapters ──")
    c = wmi.WMI()
    disabled_any = False

    for adapter in c.Win32_NetworkAdapter():
        cid = adapter.NetConnectionID   # display name shown in Network Connections
        if not cid:
            continue                    # virtual/internal adapter with no UI name; skip

        status = adapter.NetConnectionStatus
        if status in _HARDWARE_SKIP_STATUSES:
            log.debug("Hardware issue (status=%s), skipping: %r", status, cid)
            continue

        if cid not in allowed:
            log.info("Not in allowlist — disabling: %r", cid)
            disable_adapter(cid)
            disabled_any = True
        else:
            log.debug("Allowed, leaving enabled: %r", cid)

    if not disabled_any:
        log.info("No disallowed adapters found.")

    log.info("AdapterGuard (one-shot) finished.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log.critical("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)
