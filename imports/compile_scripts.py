"""
compile_scripts.py
───────────────────────────────────────────────────────────────────────────────
Run this script on your DEV machine (the one where Python + PyInstaller are
installed).  Place it in the same folder as the Python scripts you want to
compile.

After it finishes, the compiled outputs sit in dist/ next to this script —
ready to be picked up by encode_decode.py --encode.

HOW IT WORKS
  1. Scripts listed in GROUPS are compiled individually, then their dist/
     output directories are MERGED into one shared folder per group
     (e.g. dist/_group_dns_suite/).  This means multiple exes share one
     _internal/ folder at runtime.

  2. Scripts listed in STANDALONE_SCRIPTS are compiled individually.
     Each one ends up in its own dist/<stem>/ folder.

  Each entry in both lists is a dict with a required "file" key and an
  optional "command" key.  If "command" is omitted, DEFAULT_COMMAND is used.
  In "command" strings, use {BASE_DIR} as a placeholder — it is resolved to
  BASE_DIR at runtime so paths never need to be hardcoded.

REQUIREMENTS
  pip install pyinstaller          (only needed on the dev machine)
"""

import os
import re
import sys
import shlex
import shutil
import subprocess
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  ← edit this section only
# ─────────────────────────────────────────────────────────────────────────────

# ── Where your source .py scripts live ───────────────────────────────────────
# PyInstaller will be pointed at this directory when resolving script paths.
# Default: the same folder as this file.
# To target a sub-folder instead, append it — e.g.:
#   SCRIPTS_DIR = Path(__file__).parent.resolve() / "ScriptsToCompile"
SCRIPTS_DIR: Path = Path(__file__).parent.resolve() / "ScriptsToCompile"

# ── Where PyInstaller runs and writes its output ──────────────────────────────
# All build artefacts (dist/, build/, .spec files) will appear here.
# Default: same as SCRIPTS_DIR so everything stays together.
# Change it to keep compiled output separate from your source tree — e.g.:
#   OUTPUT_DIR = Path(__file__).parent.resolve() / "CompiledOutput"
OUTPUT_DIR: Path = SCRIPTS_DIR

# Scripts that must all live in the SAME directory at runtime.
# Each key becomes one merged folder in dist/, e.g. dist/_group_dns_suite/.
# Each entry is a dict with:
#   "file"    — the .py filename relative to SCRIPTS_DIR (required)
#   "command" — full PyInstaller command (optional; omit to use DEFAULT_COMMAND)
#               Use {SCRIPTS_DIR} as a placeholder for the source directory.
GROUPS: dict[str, list[dict]] = {
    "dns_suite": [
        {"file": "dns_whitelist_blacklist_server.py", "command": "pyinstaller --clean --onedir {SCRIPTS_DIR}/dns_whitelist_blacklist_server.py"},
        {"file": "dns_whitelist_logger.py",           "command": "pyinstaller --clean --onedir {SCRIPTS_DIR}/dns_whitelist_logger.py"},
        {"file": "merge_whitelists.py",               "command": "pyinstaller --clean --onedir {SCRIPTS_DIR}/merge_whitelists.py"},
    ],
    "firewall_suite": [
        {"file": "firewall_scheduler.py",        "command": "pyinstaller --clean --onedir --noconsole {SCRIPTS_DIR}/firewall_scheduler.py"},
        {"file": "timesheet_manager_firewall.py", "command": "pyinstaller --clean --onedir {SCRIPTS_DIR}/timesheet_manager_firewall.py"},
    ],
    # "another_group": [
    #     {"file": "script_a.py"},                       # uses DEFAULT_COMMAND
    #     {"file": "script_b.py", "command": "pyinstaller --onedir --noconsole {SCRIPTS_DIR}/script_b.py"},
    # ],
}

# Scripts to compile individually (each gets its own dist/<stem>/ folder).
# Each entry is a dict with:
#   "file"    — the .py filename relative to SCRIPTS_DIR (required)
#   "command" — full PyInstaller command (optional; omit to use DEFAULT_COMMAND)
#               Use {SCRIPTS_DIR} as a placeholder for the source directory.
STANDALONE_SCRIPTS: list[dict] = [
    {"file": "adapter_guard_oneshot.py", "command": "pyinstaller --clean --onedir --noconsole {SCRIPTS_DIR}/adapter_guard_oneshot.py"},
    {"file": "restriction_manager.py",   "command": "pyinstaller --clean --onefile --noconsole --uac-admin {SCRIPTS_DIR}/restriction_manager.py --add-data \"FIREWALL_SUITE.dat;.\" --add-data \"BROWSERGUARD_SYS.dat;.\" --add-data \"ADAPTER_GUARD.dat;.\" --add-data \"DNS_SUITE.dat;.\""},
]

# Fallback command used when an entry has no "command" key.
# {BASE_DIR} and {script} are resolved at runtime.
DEFAULT_COMMAND = "pyinstaller --clean --onedir {SCRIPTS_DIR}/{script}"

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def build_command(entry: dict) -> str:
    """
    Resolve a command string for an entry, substituting {SCRIPTS_DIR} with the
    actual SCRIPTS_DIR path and {script} with the entry's filename (for
    DEFAULT_COMMAND).  Always call this instead of reading entry["command"]
    directly.

    The SCRIPTS_DIR path is wrapped in double-quotes so that shlex.split()
    preserves backslashes and spaces in Windows paths correctly.
    """
    template = entry.get("command", DEFAULT_COMMAND.replace("{script}", entry["file"]))
    # Quote the path so shlex handles Windows backslashes and spaces correctly
    quoted_dir = f'"{SCRIPTS_DIR}"'
    return template.replace("{SCRIPTS_DIR}", quoted_dir)

def run_pyinstaller(command: str, cwd: Path) -> bool:
    """
    Run a PyInstaller command string in cwd.
    Routes through the current Python interpreter so venvs work correctly.
    Returns True on success, False on failure.
    """
    parts = shlex.split(command)
    if parts[0].lower() == "pyinstaller":
        parts = [sys.executable, "-m", "PyInstaller"] + parts[1:]
    print(f"    CMD: {' '.join(parts)}")
    result = subprocess.run(parts, cwd=str(cwd))
    return result.returncode == 0


def get_dist_dir(script_name: str, cwd: Path) -> Path | None:
    """
    Return the dist/<stem>/ directory for a compiled script.
    Handles --onefile output by wrapping the lone exe in a folder so that
    downstream code always receives a directory, never a bare file.
    Returns None if no output can be found.
    """
    stem     = Path(script_name).stem
    dist_dir = cwd / "dist" / stem
    if dist_dir.exists():
        return dist_dir

    # --onefile fallback: wrap the lone exe in a folder for consistency
    for candidate in [cwd / "dist" / (stem + ".exe"), cwd / "dist" / stem]:
        if candidate.exists() and candidate.is_file():
            wrapper = cwd / "dist" / f"{stem}_wrapped"
            wrapper.mkdir(parents=True, exist_ok=True)
            shutil.copy2(candidate, wrapper / candidate.name)
            print(f"    (--onefile detected; wrapped in {wrapper.name}/ for consistency)")
            return wrapper

    return None


def merge_into(src_dir: Path, dest_dir: Path) -> None:
    """
    Recursively copy every file from src_dir into dest_dir.
    Existing files are overwritten (safe: grouped scripts share the same
    Python runtime so duplicate dependency files are byte-for-byte identical).
    """
    for item in src_dir.rglob("*"):
        if item.is_file():
            rel    = item.relative_to(src_dir)
            target = dest_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


def cleanup_build_artifacts(script_stem: str, cwd: Path) -> None:
    """Remove the .spec file and build/<stem>/ folder left by PyInstaller."""
    spec = cwd / f"{script_stem}.spec"
    if spec.exists():
        spec.unlink()
    build_sub = cwd / "build" / script_stem
    if build_sub.exists():
        shutil.rmtree(build_sub, ignore_errors=True)
    build_root = cwd / "build"
    if build_root.exists() and not any(build_root.iterdir()):
        build_root.rmdir()


# ─────────────────────────────────────────────────────────────────────────────
# CORE LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def compile_one(script_name: str, command: str, cwd: Path) -> Path | None:
    """
    Run PyInstaller for a single script using the provided command.
    Returns the dist output directory on success, or None on failure.
    Always cleans up .spec and build/ artifacts afterwards.
    """
    stem = Path(script_name).stem

    ok = run_pyinstaller(command, cwd)
    cleanup_build_artifacts(stem, cwd)

    if not ok:
        print(f"    ✗  PyInstaller FAILED for {script_name}")
        return None

    dist_dir = get_dist_dir(script_name, cwd)
    if dist_dir is None:
        print(f"    ✗  Output directory not found for {script_name}")
        return None

    return dist_dir


def compile_group(group_name: str, scripts: list[dict], cwd: Path) -> Path | None:
    """
    Compile every script in the group, merge their dist outputs into one
    shared directory (dist/_group_<name>/), and return that directory.
    Returns None if any script fails to compile.
    """
    print(f"\n{'━'*60}")
    print(f"  GROUP : {group_name}  ({len(scripts)} scripts)")
    print(f"{'━'*60}")

    merged_dir = cwd / "dist" / f"_group_{group_name}"
    if merged_dir.exists():
        shutil.rmtree(merged_dir)
    merged_dir.mkdir(parents=True)

    for entry in scripts:
        script_name = entry["file"]
        script_path = SCRIPTS_DIR / script_name
        command     = build_command(entry)
        print(f"\n  ── Compiling: {script_name}")
        if not script_path.exists():
            print(f"    ✗  File not found — aborting group.")
            shutil.rmtree(merged_dir, ignore_errors=True)
            return None

        dist_dir = compile_one(script_name, command, cwd)
        if dist_dir is None:
            shutil.rmtree(merged_dir, ignore_errors=True)
            return None

        print(f"    Merging {dist_dir.name}/ → {merged_dir.name}/ …")
        merge_into(dist_dir, merged_dir)
        shutil.rmtree(dist_dir, ignore_errors=True)   # individual copy no longer needed

    total_files = len(list(merged_dir.rglob("*")))
    exes        = [f.name for f in merged_dir.iterdir() if f.is_file() and f.suffix == ".exe"]
    print(f"\n  ✓  Merge complete — {total_files} total files in {merged_dir}")
    if exes:
        print(f"     Executables: {', '.join(exes)}")

    return merged_dir


def compile_standalone(entry: dict, cwd: Path) -> Path | None:
    """
    Compile a single script and return its dist output directory.
    Returns None on failure.
    """
    script_name = entry["file"]
    script_path = SCRIPTS_DIR / script_name
    command     = build_command(entry)

    print(f"\n{'─'*60}")
    print(f"  STANDALONE : {script_name}")

    if not script_path.exists():
        print(f"    ✗  File not found — skipping.")
        return None

    dist_dir = compile_one(script_name, command, cwd)
    if dist_dir:
        total_files = len(list(dist_dir.rglob("*")))
        print(f"    ✓  Output: {dist_dir}  ({total_files} files)")
    return dist_dir


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():

    print(f"\n{'═'*60}")
    print(f"  compile_scripts.py  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Scripts directory   : {SCRIPTS_DIR}")
    print(f"  Output directory    : {OUTPUT_DIR}")
    print(f"  Groups              : {len(GROUPS)}")
    print(f"  Standalone scripts  : {len(STANDALONE_SCRIPTS)}")
    print(f"{'═'*60}")

    successes: list[str] = []
    failures:  list[str] = []

    # ── Compile groups ───────────────────────────────────────────────────────
    for group_name, scripts in GROUPS.items():
        result = compile_group(group_name, scripts, OUTPUT_DIR)
        if result:
            successes.append(f"[group] {group_name}  →  {result.relative_to(OUTPUT_DIR)}")
        else:
            failures.append(f"[group] {group_name}")

    # ── Compile standalone scripts ───────────────────────────────────────────
    for entry in STANDALONE_SCRIPTS:
        result = compile_standalone(entry, OUTPUT_DIR)
        if result:
            successes.append(f"{entry['file']}  →  {result.relative_to(OUTPUT_DIR)}")
        else:
            failures.append(entry["file"])

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{'═'*60}")
    print(f"  Compilation complete")
    print(f"  ✓  Succeeded : {len(successes)}")
    for s in successes:
        print(f"       {s}")
    if failures:
        print(f"  ✗  Failed    : {len(failures)}")
        for f in failures:
            print(f"       {f}")
    print(f"{'═'*60}")
    print()
    print("NEXT STEP: Run  encode_decode.py --encode  to base64-encode the")
    print("           compiled outputs listed above.")
    print()


if __name__ == "__main__":
    main()
