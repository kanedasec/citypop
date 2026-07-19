#!/usr/bin/env python3
# @name: Pi-Tail Monitor Mode
# @desc: Check the Pi-Tail mon0 monitor interface and enable or disable it with mon0up or mon0down only when a state change is needed.
# @category: utilities
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"action","label":"Desired monitor-mode state","type":"select","choices":[{"value":"enable","label":"Enable monitor mode"},{"value":"disable","label":"Disable monitor mode"}],"default":"enable"}]

"""Manage Kali Pi-Tail's mon0 interface through its supplied helper scripts."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


MONITOR_INTERFACE = "mon0"
HELPER_LOCATIONS = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)


def monitor_state() -> tuple[bool, str]:
    """Return whether mon0 exists as a monitor interface and a status detail."""
    if not (Path("/sys/class/net") / MONITOR_INTERFACE).exists():
        return False, "mon0 is not present"

    iw = shutil.which("iw")
    if not iw:
        return False, "mon0 exists, but iw is unavailable so its interface type cannot be verified"

    result = subprocess.run(
        [iw, "dev", MONITOR_INTERFACE, "info"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode:
        detail = result.stderr.strip() or "iw could not inspect mon0"
        return False, f"mon0 exists, but verification failed: {detail}"

    interface_type = "unknown"
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("type "):
            interface_type = stripped.split(None, 1)[1]
            break
    return interface_type == "monitor", f"mon0 exists with type {interface_type}"


def find_helper(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for directory in HELPER_LOCATIONS:
        candidate = Path(directory) / name
        if candidate.is_file() and candidate.stat().st_mode & 0o111:
            return str(candidate)
    return None


def main() -> int:
    action = sys.argv[1].lower() if len(sys.argv) > 1 else ""
    if action not in {"enable", "disable"}:
        print("Choose either enable or disable.")
        return 2

    enabled, detail = monitor_state()
    desired_enabled = action == "enable"
    print(f"Current monitor-mode state: {'enabled' if enabled else 'disabled'} ({detail}).", flush=True)

    if enabled == desired_enabled:
        print(f"Monitor mode is already {action}d; no changes were made.")
        return 0

    helper_name = "mon0up" if desired_enabled else "mon0down"
    helper = find_helper(helper_name)
    if not helper:
        print(f"Cannot {action} monitor mode: Pi-Tail helper '{helper_name}' was not found.")
        return 1

    print(f"Running {helper_name} to {action} monitor mode...", flush=True)
    try:
        result = subprocess.run(
            [helper],
            capture_output=True,
            text=True,
            timeout=90,
        )
    except subprocess.TimeoutExpired:
        print(f"{helper_name} did not finish within 90 seconds.")
        return 1

    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip())
    if result.returncode:
        print(f"{helper_name} exited with status {result.returncode}.")
        return result.returncode

    final_enabled, final_detail = monitor_state()
    if final_enabled != desired_enabled:
        print(f"The requested change could not be verified ({final_detail}).")
        return 1

    print(f"Monitor mode is now {action}d ({final_detail}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
