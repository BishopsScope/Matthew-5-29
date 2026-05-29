"""
encode_decode.py
───────────────────────────────────────────────────────────────────────────────
Encodes a predefined list of files/folders to individual .dat files (one per
target), or decodes those .dat files back to disk.

    python encode_decode.py --encode        # zip each TARGET → <NAME>.dat
    python encode_decode.py --decode        # read <NAME>.dat files → extract to disk

WHY .dat FILES INSTEAD OF ONE BIG TEXT FILE
─────────────────────────────────────────────
Previous versions wrote all payloads as Python string literals into a single
.txt file.  With payloads in the 10–100 MB range that caused two problems:

  • Text editors (including VS Code) load the entire file into memory and apply
    syntax highlighting — a 50 MB line of base64 inside a Python string kills
    them.
  • PyInstaller refused to compile a script that imported such a module because
    the AST for a 10 MB string literal overwhelms the compiler.

The .dat approach stores each payload as raw zip bytes in its own small binary
file.  No string literals anywhere.  Text editors never need to open the files.
PyInstaller bundles them as data assets via --add-data.

TYPICAL WORKFLOW
────────────────
  1. Build your executables with PyInstaller (--onedir recommended).
  2. Run encode_decode.py --encode
       → writes  <NAME>.dat  next to this script for every entry in TARGETS.
       → prints  the exact --add-data flags to pass to PyInstaller.
  3. Recompile restriction_manager.py with those --add-data flags.
  4. Distribute only the compiled output — the .dat files are baked in.

For un-compiled / development use, place the .dat files next to
restriction_manager.py (or next to the .exe when using --onedir).

DECODING (reconstruction / inspection)
────────────────────────────────────────
  python encode_decode.py --decode
       → reads each <NAME>.dat and extracts its contents to DECODE_OUTPUT_DIR.

TARGETS can point to:
  • A PyInstaller --onedir output folder, e.g.  "dist/_group_firewall_suite"
  • Any individual file,                        e.g.  "BrowserGuard.sys"
  • Any arbitrary folder,                       e.g.  "assets/icons"

No internet connection required.  Works on any machine with Python 3.8+.
"""

import argparse
import io
import re
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  ← edit this section only
# ─────────────────────────────────────────────────────────────────────────────

# This is the directory where this script was executed from.  All relative paths are resolved against this.
BASE_DIR: Path = Path(__file__).parent.resolve()

# ── Where encoded/decoded source files are read from ─────────────────────────
# On --encode : target paths are resolved relative to this directory.
# On --decode : .dat files are read from this directory.
# Default: the folder containing this script.
# To point at a sub-folder instead, append it — e.g.:
#   INPUT_DIR = Path(__file__).parent.resolve() / "CompiledOutput"
INPUT_DIR: Path = BASE_DIR / "ScriptsToCompile"

# ── Where output files are written to ────────────────────────────────────────
# On --encode : .dat files are written here.
# On --decode : extracted folders are written here (each target gets its own subfolder).
# Default: same as INPUT_DIR so everything stays together.
# To separate output from input — e.g.:
#   OUTPUT_DIR = Path(__file__).parent.resolve() / "EncodedPayloads"
OUTPUT_DIR: Path = INPUT_DIR

# ── Prefix substituted into "path" values that contain {DIST_SUBDIR} ─────────
# Use {DIST_SUBDIR} in any "path" entry below as a placeholder for this value.
# This lets you change the dist folder in one place without touching every entry.
# Set to "" if your paths are already fully specified or rooted under INPUT_DIR.
DIST_SUBDIR: str = "dist"

# The .sys file is a special case because it's not produced by PyInstaller and doesn't sit under the dist folder.
BROWSERGUARD_SYS_DIR: str = INPUT_DIR

# Files/folders to encode.  Each entry is a dict with:
#   "name"  — used as the output filename: <NAME>.dat  (uppercase recommended)
#   "path"  — path to the file or folder, relative to INPUT_DIR (or absolute).
#             Use {DIST_SUBDIR} as a placeholder for the dist prefix — e.g.
#             "{DIST_SUBDIR}/_group_dns_suite" resolves to "dist/_group_dns_suite".
#             Use a plain path to bypass the prefix entirely for that entry.
#
# On --encode : each path is zipped into a .dat file in OUTPUT_DIR.
# On --decode : each <NAME>.dat is read from OUTPUT_DIR and extracted to
#               OUTPUT_DIR / "extracted" / <name.lower()>/
#
# Entries whose path doesn't exist at encode-time are skipped with a warning.
TARGETS: list[dict] = [
    # PyInstaller --onedir group outputs (produced by compile_scripts.py):
    {"name": "DNS_SUITE",           "path": "{DIST_SUBDIR}/_group_dns_suite"},
    {"name": "FIREWALL_SUITE",      "path": f"{DIST_SUBDIR}/_group_firewall_suite"},
    {"name": "ADAPTER_GUARD",       "path": f"{DIST_SUBDIR}/adapter_guard_oneshot"},
    #{"name": "TIMESHEET_MANAGER",   "path": "{DIST_SUBDIR}/timesheet_manager_firewall"},
    {"name": "RESTRICTION_MANAGER", "path": f"{DIST_SUBDIR}/restriction_manager_wrapped"},

    # Single-file payloads:
    {"name": "BROWSERGUARD_SYS",    "path": f"{BROWSERGUARD_SYS_DIR}/BrowserGuard.sys"},

    # Example: include a plain file or folder alongside the compiled outputs:
    # {"name": "MY_CONFIG",         "path": "config/settings.json"},   # no prefix needed
    # {"name": "ASSETS",            "path": "assets/icons"},
]

# Directory where --decode writes extracted files.
# Each target lands in its own subfolder: <decoded_output_dir>/<name.lower()>/
DECODE_OUTPUT_DIR: Path = OUTPUT_DIR / "extracted"

# ─────────────────────────────────────────────────────────────────────────────
# SHARED UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def resolve_path(raw: str | Path) -> Path:
    # Substitute {DIST_SUBDIR} placeholder before resolving
    resolved = str(raw).replace("{DIST_SUBDIR}", DIST_SUBDIR)
    p = Path(resolved)
    return p if p.is_absolute() else INPUT_DIR / p


def make_dat_name(name: str) -> str:
    """Sanitise a string into a safe uppercase identifier (used as the .dat filename)."""
    safe = re.sub(r"[^a-zA-Z0-9]", "_", name)
    if safe and safe[0].isdigit():
        safe = "_" + safe
    return safe.upper()


def dat_path(name: str) -> Path:
    """Return the Path where a given target's .dat file is written/read."""
    return OUTPUT_DIR / f"{make_dat_name(name)}.dat"


# ─────────────────────────────────────────────────────────────────────────────
# ENCODE PATH
# ─────────────────────────────────────────────────────────────────────────────

def zip_path(source: Path) -> bytes:
    """
    Zip a file or directory into an in-memory buffer and return the raw bytes.
    Directories are stored with their top-level folder name preserved so that
    extraction recreates the same layout.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if source.is_file():
            zf.write(source, source.name)
        else:
            for item in source.rglob("*"):
                if item.is_file():
                    zf.write(item, item.relative_to(source.parent))
    return buf.getvalue()


def encode_target(target: dict) -> bool:
    """
    Zip one target and write the raw zip bytes to <NAME>.dat.
    Returns True on success, False on failure.
    """
    dat_name = make_dat_name(target["name"])
    source   = resolve_path(target["path"])
    out_file = dat_path(target["name"])

    print(f"\n{'─'*60}")
    print(f"  ▶  {dat_name}.dat  ←  {source}")

    if not source.exists():
        print(f"     ✗  Path not found — skipping.")
        return False

    raw = zip_path(source)
    zip_mb = len(raw) / (1024 * 1024)
    print(f"     Zip size : {zip_mb:.2f} MB  ({len(raw):,} bytes)")

    out_file.write_bytes(raw)
    print(f"     ✓  Written → {out_file.name}")
    return True


def run_encode() -> None:
    print(f"\n{'═'*60}")
    print(f"  encode_decode.py --encode")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Input dir   : {INPUT_DIR / DIST_SUBDIR if DIST_SUBDIR else INPUT_DIR}")
    print(f"  Output dir  : {OUTPUT_DIR}")
    print(f"  Targets     : {len(TARGETS)}")
    print(f"{'═'*60}")

    successes: list[str] = []
    failures:  list[str] = []

    for target in TARGETS:
        if encode_target(target):
            successes.append(make_dat_name(target["name"]))
        else:
            failures.append(make_dat_name(target["name"]))

    print(f"\n{'═'*60}")
    if successes:
        print(f"  ✓  Written ({len(successes)}):")
        for s in successes:
            p = dat_path(s)   # dat_path accepts the sanitised name too
            actual = OUTPUT_DIR / f"{s}.dat"
            size_mb = actual.stat().st_size / (1024 * 1024)
            print(f"       {s}.dat  ({size_mb:.2f} MB)")
    if failures:
        print(f"  ✗  Failed  ({len(failures)}): {', '.join(failures)}")

    if successes:
        # ── Print the PyInstaller --add-data flags the user needs ──────────
        print(f"\n{'─'*60}")
        print("  PyInstaller --add-data flags (copy these into your build command):")
        print()
        for s in successes:
            # Windows separator is ';', POSIX is ':'
            # We emit the Windows form because restriction_manager targets Windows.
            print(f'    --add-data "{s}.dat;."  \\')
        print()
        print("  Full example:")
        flags = " ".join(f'--add-data "{s}.dat;." \\' for s in successes)
        print(f"    pyinstaller restriction_manager.py \\")
        for s in successes:
            suffix = "" if s == successes[-1] else " \\"
            print(f'        --add-data "{s}.dat;."{suffix}')
        print()
        print("  The .dat files must sit next to restriction_manager.py when")
        print("  running un-compiled (plain .py), or be passed via --add-data")
        print("  when compiling with PyInstaller.")
    print(f"{'═'*60}\n")


# ─────────────────────────────────────────────────────────────────────────────
# DECODE PATH
# ─────────────────────────────────────────────────────────────────────────────

def extract_dat(dat_name: str, raw_bytes: bytes) -> bool:
    """
    Extract one .dat payload (raw zip bytes) to DECODE_OUTPUT_DIR/<dat_name.lower()>/.
    Returns True on success, False on failure.
    """
    dest = DECODE_OUTPUT_DIR / dat_name.lower()
    print(f"\n{'─'*60}")
    print(f"  ▶  {dat_name}.dat  →  {dest}")

    if raw_bytes[:2] != b"PK":
        print(f"     ✗  Data does not look like a zip file — skipping.")
        return False

    try:
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
            names = zf.namelist()
            print(f"     Archive contains {len(names)} file(s)")
            shown = names[:8] if len(names) > 10 else names
            for n in shown:
                print(f"       {n}")
            if len(names) > 10:
                print(f"       … and {len(names) - 8} more")

            dest.mkdir(parents=True, exist_ok=True)
            zf.extractall(dest)

        size_mb = sum(
            f.stat().st_size for f in dest.rglob("*") if f.is_file()
        ) / (1024 * 1024)
        print(f"     ✓  Extracted  ({size_mb:.1f} MB on disk)")
        return True

    except zipfile.BadZipFile as e:
        print(f"     ✗  Bad zip data: {e} — skipping.")
    except Exception as e:
        print(f"     ✗  Unexpected error: {e} — skipping.")
    return False


def run_decode() -> None:
    print(f"\n{'═'*60}")
    print(f"  encode_decode.py --decode")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Source dir  : {OUTPUT_DIR}")
    print(f"  Output dir  : {DECODE_OUTPUT_DIR}")
    print(f"{'═'*60}")

    DECODE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    successes: list[str] = []
    failures:  list[str] = []
    missing:   list[str] = []

    for target in TARGETS:
        dat_name = make_dat_name(target["name"])
        src      = OUTPUT_DIR / f"{dat_name}.dat"

        if not src.is_file():
            print(f"\n  ⚠  {dat_name}.dat not found — skipping.")
            missing.append(dat_name)
            continue

        raw = src.read_bytes()
        if extract_dat(dat_name, raw):
            successes.append(dat_name)
        else:
            failures.append(dat_name)

    print(f"\n{'═'*60}")
    if successes:
        print(f"  ✓  Extracted ({len(successes)})  →  {DECODE_OUTPUT_DIR}")
        for s in successes:
            print(f"       {s}")
    if failures:
        print(f"  ✗  Failed    ({len(failures)}): {', '.join(failures)}")
    if missing:
        print(f"  ⚠  Missing   ({len(missing)}): {', '.join(missing)}")
        print(f"     Run  encode_decode.py --encode  first to generate the .dat files.")
    print(f"{'═'*60}\n")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Encode files/folders to individual .dat files, or decode them back.\n\n"
            "  --encode   zip each TARGET  →  <NAME>.dat  (+ prints PyInstaller flags)\n"
            "  --decode   read <NAME>.dat  →  extract files to disk"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--encode", action="store_true",
                       help="Encode TARGETS to individual .dat files")
    group.add_argument("--decode", action="store_true",
                       help="Decode .dat files back to disk")
    args = parser.parse_args()

    if args.encode:
        run_encode()
    else:
        run_decode()


if __name__ == "__main__":
    main()
