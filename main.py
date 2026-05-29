"""
main.py
───────────────────────────────────────────────────────────────────────────────
Driver script that runs the full compilation pipeline end-to-end:

  1. Run compile_scripts.py      — compile all groups + standalones via PyInstaller
  2. Run encode_decode.py --encode — zip compiled outputs into .dat payload files
  3. Run PyInstaller on restriction_manager.py — bundle the .dat files into the
     final single-file executable
  4. Move restriction_manager.exe to this script's directory and clean up all
     intermediate artefacts (dist/, build/, .dat files)

By the end, the only change to the environment is a freshly built
restriction_manager.exe sitting next to this script.

USAGE
  python main.py

REQUIREMENTS
  - imports/compile_scripts.py and imports/encode_decode.py must exist
  - ScriptsToCompile/ must exist next to this script
  - PyInstaller must be installed in the active Python environment

DIRECTORY LAYOUT (relative to this script)
  main.py                        ← HERE
  imports/
    compile_scripts.py
    encode_decode.py
  ScriptsToCompile/              ← SCRIPTS_DIR / OUTPUT_DIR
    firewall_scheduler.py
    timesheet_manager_firewall.py
    restriction_manager.py
    ...

HOW THE IMPORTS ARE RUN
  compile_scripts.py and encode_decode.py use Path(__file__).parent to locate
  ScriptsToCompile/.  To make that resolve correctly without modifying those
  scripts, main.py copies them temporarily into HERE, runs them from HERE, then
  deletes the copies.  ScriptsToCompile/ therefore appears as a sibling of the
  script being executed, exactly as the scripts expect.
"""

import sys
import shutil
import subprocess
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────────────────────

HERE        = Path(__file__).parent.resolve()
IMPORTS_DIR = HERE / "imports"
SCRIPTS_DIR = HERE / "ScriptsToCompile"
OUTPUT_DIR  = SCRIPTS_DIR

# ─────────────────────────────────────────────────────────────────────────────
# SANITY CHECKS
# ─────────────────────────────────────────────────────────────────────────────

for label, path in [
    ("imports/",          IMPORTS_DIR),
    ("ScriptsToCompile/", SCRIPTS_DIR),
]:
    if not path.is_dir():
        print(f"✗  '{label}' not found (expected: {path})")
        sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def run(parts: list, cwd: Path, label: str) -> None:
    """
    Run a command (as a pre-split list) in cwd, routing 'pyinstaller' through
    the current Python interpreter so venvs work correctly.
    Accepts a list so Windows paths with backslashes/spaces are never mangled.
    Exits the whole script on non-zero return code.
    """
    parts = list(parts)
    if str(parts[0]).lower() == "pyinstaller":
        parts = [sys.executable, "-m", "PyInstaller"] + parts[1:]
    elif str(parts[0]).lower() == "python":
        parts = [sys.executable] + parts[1:]

    if not cwd.is_dir():
        print(f"\n✗  Working directory does not exist: {cwd}")
        print(f"   Cannot run step '{label}' — aborting.")
        sys.exit(1)

    print(f"\n{'─'*60}")
    print(f"  STEP : {label}")
    print(f"  CWD  : {cwd}")
    print(f"  CMD  : {subprocess.list2cmdline(parts)}")
    print(f"{'─'*60}")

    result = subprocess.run(parts, cwd=str(cwd))
    if result.returncode != 0:
        print(f"\n✗  '{label}' failed (exit code {result.returncode}) — aborting.")
        sys.exit(result.returncode)


def remove(path: Path) -> None:
    """Delete a file or directory tree, silently ignoring if it doesn't exist."""
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
        print(f"  Removed dir  : {path}")
    elif path.is_file():
        path.unlink()
        print(f"  Removed file : {path}")


def run_import_script(script_name: str, extra_args: list, label: str) -> None:
    """
    Copy an import script from IMPORTS_DIR into HERE, run it from HERE so that
    Path(__file__).parent inside the script resolves to HERE (making
    ScriptsToCompile/ visible as a sibling), then delete the temporary copy.
    """
    src  = IMPORTS_DIR / script_name
    tmp  = HERE / script_name

    shutil.copy2(src, tmp)
    try:
        run(
            parts = ["python", str(tmp)] + extra_args,
            cwd   = HERE,
            label = label,
        )
    finally:
        tmp.unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{'═'*60}")
    print(f"  main.py  —  Full compilation pipeline")
    print(f"  Driver location : {HERE}")
    print(f"  Imports dir     : {IMPORTS_DIR}")
    print(f"  Scripts dir     : {SCRIPTS_DIR}")
    print(f"  PyInstaller cwd : {OUTPUT_DIR}")
    print(f"{'═'*60}")

    # ── Step 1 : compile all scripts ─────────────────────────────────────────
    # Runs from HERE so Path(__file__).parent / "ScriptsToCompile" resolves
    # to HERE/ScriptsToCompile — which exists.
    run_import_script("compile_scripts.py", [], "compile_scripts.py")

    # ── Step 2 : encode compiled outputs to .dat files ────────────────────────
    # Same approach — runs from HERE so encode_decode.py finds dist/ under
    # HERE/ScriptsToCompile via its own Path(__file__).parent logic.
    run_import_script("encode_decode.py", ["--encode"], "encode_decode.py --encode")

    # ── Step 3 : build the final restriction_manager executable ──────────────
    # PyInstaller runs from OUTPUT_DIR so --add-data relative paths resolve to
    # the .dat files written there in Step 2.
    run(
        parts = [
            "pyinstaller", "--clean", "--onefile", "--noconsole", "--uac-admin",
            str(SCRIPTS_DIR / "restriction_manager.py"),
            "--add-data", "FIREWALL_SUITE.dat;.",
            "--add-data", "BROWSERGUARD_SYS.dat;.",
            "--add-data", "ADAPTER_GUARD.dat;.",
            "--add-data", "DNS_SUITE.dat;.",
        ],
        cwd   = OUTPUT_DIR,
        label = "PyInstaller — restriction_manager.exe",
    )

    # ── Step 4 : move the exe here and clean up ───────────────────────────────
    print(f"\n{'─'*60}")
    print(f"  STEP : Move exe + clean up")
    print(f"{'─'*60}")

    exe_src  = OUTPUT_DIR / "dist" / "restriction_manager.exe"
    exe_dest = HERE / "restriction_manager.exe"

    if not exe_src.exists():
        print(f"✗  Expected exe not found at {exe_src} — aborting clean-up.")
        sys.exit(1)

    if exe_dest.exists():
        exe_dest.unlink()
    shutil.move(str(exe_src), str(exe_dest))
    print(f"  Moved exe    : {exe_src.name}  →  {exe_dest}")

    remove(OUTPUT_DIR / "dist")
    remove(OUTPUT_DIR / "build")
    remove(OUTPUT_DIR / "restriction_manager.spec")

    for dat in OUTPUT_DIR.glob("*.dat"):
        remove(dat)

    print(f"\n{'═'*60}")
    print(f"  ✓  Pipeline complete")
    print(f"     Output : {exe_dest}")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()
