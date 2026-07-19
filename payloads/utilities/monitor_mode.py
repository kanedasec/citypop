#!/usr/bin/env python3
# @name: Wireless Monitor Mode
# @desc: Select a wireless interface and enable or disable monitor mode; Pi-Tail's mon0 uses mon0up/mon0down, while other interfaces are changed directly with ip and iw.
# @category: utilities
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"action","label":"Desired monitor-mode state","type":"select","choices":[{"value":"enable","label":"Enable monitor mode"},{"value":"disable","label":"Disable monitor mode"}],"default":"enable"}]

"""Manage monitor mode on Kali Pi-Tail and other wireless interfaces."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from payloads._web_input import request_input


MONITOR_INTERFACE = "mon0"
HELPER_LOCATIONS = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)


def run(command: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def wireless_interfaces() -> list[str]:
    """Return wireless interfaces known to sysfs and iw."""
    interfaces = {
        path.name
        for path in Path("/sys/class/net").glob("*")
        if (path / "wireless").exists()
    }
    iw = shutil.which("iw")
    if iw:
        result = run([iw, "dev"])
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Interface "):
                interfaces.add(stripped.split(None, 1)[1])
    return sorted(interfaces)


def choose_interface() -> str:
    interfaces = wireless_interfaces()
    # mon0 may not exist while disabled, but remains a valid Pi-Tail choice
    # because mon0up is responsible for creating it.
    choices = [{"value": MONITOR_INTERFACE, "label": "mon0 · Pi-Tail managed interface"}]
    choices.extend(
        {"value": interface, "label": f"{interface} · direct ip/iw control"}
        for interface in interfaces
        if interface != MONITOR_INTERFACE
    )
    return str(request_input("Select wireless interface", input_type="select", choices=choices))


def monitor_state(interface: str) -> tuple[bool | None, str]:
    """Return monitor state and detail; None means it could not be verified."""
    if not (Path("/sys/class/net") / interface).exists():
        if interface == MONITOR_INTERFACE:
            return False, "mon0 is not present"
        return None, f"{interface} is no longer present"

    iw = shutil.which("iw")
    if not iw:
        return None, f"{interface} exists, but iw is unavailable"

    result = run([iw, "dev", interface, "info"], 10)
    if result.returncode:
        detail = result.stderr.strip() or f"iw could not inspect {interface}"
        return None, detail

    interface_type = "unknown"
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("type "):
            interface_type = stripped.split(None, 1)[1]
            break
    if interface_type == "unknown":
        return None, f"{interface} type was not reported by iw"
    return interface_type == "monitor", f"{interface} has type {interface_type}"


def find_helper(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for directory in HELPER_LOCATIONS:
        candidate = Path(directory) / name
        if candidate.is_file() and candidate.stat().st_mode & 0o111:
            return str(candidate)
    return None


def print_result(result: subprocess.CompletedProcess[str]) -> None:
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip())


def change_pitail_monitor(action: str) -> int:
    helper_name = "mon0up" if action == "enable" else "mon0down"
    helper = find_helper(helper_name)
    if not helper:
        print(f"Cannot {action} mon0: Pi-Tail helper '{helper_name}' was not found.")
        return 1
    print(f"Running {helper_name} to {action} mon0...", flush=True)
    result = run([helper], 90)
    print_result(result)
    if result.returncode:
        print(f"{helper_name} exited with status {result.returncode}.")
    return result.returncode


def change_direct(interface: str, action: str) -> int:
    ip = shutil.which("ip")
    iw = shutil.which("iw")
    if not ip or not iw:
        missing = ", ".join(name for name, path in (("ip", ip), ("iw", iw)) if not path)
        print(f"Cannot change {interface}: missing command(s): {missing}.")
        return 1

    target_type = "monitor" if action == "enable" else "managed"
    print(
        f"Changing {interface} directly to {target_type} mode. "
        "If this interface carries the phone or Wi-Fi connection, the web session may disconnect.",
        flush=True,
    )
    down = run([ip, "link", "set", "dev", interface, "down"])
    if down.returncode:
        print_result(down)
        return down.returncode

    changed = run([iw, "dev", interface, "set", "type", target_type])
    up = run([ip, "link", "set", "dev", interface, "up"])
    if changed.returncode:
        print_result(changed)
        if up.returncode:
            print("The interface also failed to return to the up state:")
            print_result(up)
        return changed.returncode
    if up.returncode:
        print_result(up)
        return up.returncode
    return 0


def main() -> int:
    action = sys.argv[1].lower() if len(sys.argv) > 1 else ""
    if action not in {"enable", "disable"}:
        print("Choose either enable or disable.")
        return 2

    try:
        interface = choose_interface()
        enabled, detail = monitor_state(interface)
        desired_enabled = action == "enable"
        if enabled is None:
            print(f"Unable to verify the current state: {detail}.")
            return 1
        print(
            f"Current state for {interface}: monitor mode is "
            f"{'enabled' if enabled else 'disabled'} ({detail}).",
            flush=True,
        )
        if enabled == desired_enabled:
            print(f"Monitor mode is already {action}d on {interface}; no changes were made.")
            return 0

        result = (
            change_pitail_monitor(action)
            if interface == MONITOR_INTERFACE
            else change_direct(interface, action)
        )
        if result:
            return result

        final_enabled, final_detail = monitor_state(interface)
        if final_enabled != desired_enabled:
            print(f"The requested change could not be verified ({final_detail}).")
            return 1
        print(f"Monitor mode is now {action}d on {interface} ({final_detail}).")
        return 0
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"Monitor-mode operation failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
