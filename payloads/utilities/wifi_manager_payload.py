#!/usr/bin/env python3
# @name: Wi-Fi Connection Manager
# @desc: Show Wi-Fi status, scan nearby networks, connect to a selected network, or disconnect using NetworkManager or wpa_supplicant; it does not enable monitor mode.
# @category: utilities
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"action","label":"Managed Wi-Fi client action","type":"select","choices":[{"value":"status","label":"Status only — show current Wi-Fi interfaces and connections"},{"value":"scan","label":"Scan only — list nearby access points without connecting"},{"value":"connect","label":"Connect — scan, select a network, and request its credentials"},{"value":"disconnect","label":"Disconnect — select and disconnect a managed Wi-Fi interface"}],"default":"status"}]

"""Phone-friendly Wi-Fi station management for City Pop.

This workflow deliberately manages normal client connections only. Monitor-mode
and injection workflows belong to assessment payloads and normally require a
separate compatible adapter so the phone's connection to City Pop is not lost.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from payloads._web_input import request_input


def run(command: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def wireless_interfaces() -> list[str]:
    interfaces = sorted(path.name for path in Path("/sys/class/net").glob("*") if (path / "wireless").exists())
    if interfaces:
        return interfaces
    try:
        return sorted(line.split(":", 1)[0].strip() for line in Path("/proc/net/wireless").read_text().splitlines()[2:] if ":" in line)
    except OSError:
        return []


def choose_interface() -> str:
    interfaces = wireless_interfaces()
    if not interfaces:
        raise RuntimeError("No Wi-Fi interfaces were detected.")
    if len(interfaces) == 1:
        print(f"Wi-Fi interface: {interfaces[0]}", flush=True)
        return interfaces[0]
    return str(request_input("Select Wi-Fi interface", input_type="select", choices=interfaces))


def backend() -> str:
    if shutil.which("nmcli"):
        return "nmcli"
    if shutil.which("wpa_cli"):
        return "wpa_cli"
    raise RuntimeError("Neither nmcli nor wpa_cli is installed.")


def nmcli_scan(interface: str) -> list[dict[str, str]]:
    result = run(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "device", "wifi", "list", "ifname", interface, "--rescan", "yes"], 45)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "NetworkManager scan failed.")
    networks: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        fields = line.replace("\\:", "\0").split(":")
        if not fields or not fields[0]:
            continue
        networks.append({"ssid": fields[0].replace("\0", ":"), "signal": fields[1] if len(fields) > 1 else "?", "security": fields[2] if len(fields) > 2 else ""})
    return networks


def wpa_scan(interface: str) -> list[dict[str, str]]:
    run(["wpa_cli", "-i", interface, "scan"], 10)
    result = run(["wpa_cli", "-i", interface, "scan_results"], 30)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "wpa_supplicant scan failed.")
    networks: list[dict[str, str]] = []
    for line in result.stdout.splitlines()[2:]:
        fields = line.split("\t", 4)
        if len(fields) == 5 and fields[4]:
            networks.append({"ssid": fields[4], "signal": fields[2], "security": fields[3]})
    return networks


def scan(interface: str, selected_backend: str) -> list[dict[str, str]]:
    networks = nmcli_scan(interface) if selected_backend == "nmcli" else wpa_scan(interface)
    unique: dict[str, dict[str, str]] = {}
    for network in networks:
        unique.setdefault(network["ssid"], network)
    return list(unique.values())


def show_networks(networks: list[dict[str, str]]) -> None:
    if not networks:
        print("No named Wi-Fi networks were found.")
        return
    for network in networks:
        print(f"{network['ssid']} · signal {network['signal']} · {network['security'] or 'open'}")


def status(interface: str, selected_backend: str) -> int:
    if selected_backend == "nmcli":
        result = run(["nmcli", "-f", "GENERAL.STATE,GENERAL.CONNECTION,IP4.ADDRESS,IP4.GATEWAY", "device", "show", interface])
    else:
        result = run(["wpa_cli", "-i", interface, "status"])
    print(result.stdout.strip() or result.stderr.strip() or "No status returned.")
    return result.returncode


def connect(interface: str, selected_backend: str) -> int:
    networks = scan(interface, selected_backend)
    if not networks:
        print("No named Wi-Fi networks were found.")
        return 1
    ssid = str(request_input("Select Wi-Fi network", input_type="select", choices=[
        {"value": item["ssid"], "label": f"{item['ssid']} · signal {item['signal']} · {item['security'] or 'open'}"} for item in networks
    ]))
    chosen = next(item for item in networks if item["ssid"] == ssid)
    secured = bool(chosen["security"] and chosen["security"] not in {"--", "[ESS]"})
    password = str(request_input("Wi-Fi password", input_type="password")) if secured else ""
    if selected_backend == "nmcli":
        command = ["nmcli", "device", "wifi", "connect", ssid, "ifname", interface]
        if password:
            command.extend(["password", password])
        result = run(command, 60)
    else:
        added = run(["wpa_cli", "-i", interface, "add_network"])
        network_id = added.stdout.strip().splitlines()[-1] if added.stdout.strip() else ""
        if not network_id.isdigit():
            print(added.stderr.strip() or "Could not create a wpa_supplicant network profile.")
            return 1
        commands = [
            ["wpa_cli", "-i", interface, "set_network", network_id, "ssid", json.dumps(ssid)],
            ["wpa_cli", "-i", interface, "set_network", network_id, "psk", json.dumps(password)] if password else ["wpa_cli", "-i", interface, "set_network", network_id, "key_mgmt", "NONE"],
            ["wpa_cli", "-i", interface, "enable_network", network_id],
            ["wpa_cli", "-i", interface, "select_network", network_id],
            ["wpa_cli", "-i", interface, "save_config"],
        ]
        result = None
        for command in commands:
            result = run(command)
            if result.returncode or "FAIL" in result.stdout:
                break
        assert result is not None
    print(result.stdout.strip() or result.stderr.strip())
    print("The web connection may move or close if this interface carries the phone link.")
    return result.returncode or int("FAIL" in result.stdout)


def disconnect(interface: str, selected_backend: str) -> int:
    command = ["nmcli", "device", "disconnect", interface] if selected_backend == "nmcli" else ["wpa_cli", "-i", interface, "disconnect"]
    result = run(command)
    print(result.stdout.strip() or result.stderr.strip())
    print("The web connection may close if this interface carries the phone link.")
    return result.returncode


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    try:
        interface = choose_interface()
        selected_backend = backend()
        print(f"Connection backend: {selected_backend}")
        if action == "status":
            return status(interface, selected_backend)
        if action == "scan":
            show_networks(scan(interface, selected_backend))
            return 0
        if action == "connect":
            return connect(interface, selected_backend)
        if action == "disconnect":
            return disconnect(interface, selected_backend)
        print(f"Unknown action: {action}")
        return 2
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"Wi-Fi manager error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
