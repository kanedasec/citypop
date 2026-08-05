#!/usr/bin/env python3
# @name: LAN Speed Test
# @desc: Measure upload and download throughput against an authorized iperf3 server.
# @category: utilities
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"server","label":"iperf3 server","type":"text","placeholder":"192.168.1.10","required":true,"help":"Hostname, IPv4 address, or IPv6 address of a machine already running iperf3 -s."},{"name":"seconds","label":"Test duration per direction","type":"number","default":"10"},{"name":"port","label":"iperf3 server port","type":"number","default":"5201","help":"TCP listening port on the remote iperf3 server."}]

import json
import os
import re
import shutil
import socket
import subprocess
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._ufw import TemporaryUfwRules, UfwRuleError


def resolve_server(server):
    try:
        addresses = socket.getaddrinfo(server, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError(f"could not resolve iperf3 server {server}: {exc}") from exc
    usable = [entry for entry in addresses if entry[0] in (socket.AF_INET, socket.AF_INET6)]
    if not usable:
        raise RuntimeError(f"iperf3 server {server} has no IPv4 or IPv6 address")
    # Prefer IPv4 where both families exist, but support IPv6-only test hosts.
    usable.sort(key=lambda entry: entry[0] != socket.AF_INET)
    family, _socktype, _protocol, _canonname, sockaddr = usable[0]
    return sockaddr[0], family


def route_to(destination, family=socket.AF_INET):
    family_flag = "-6" if family == socket.AF_INET6 else "-4"
    result = subprocess.run(
        ["ip", "-o", family_flag, "route", "get", destination],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode:
        raise RuntimeError(
            f"no local route to {destination}: "
            f"{(result.stderr or result.stdout).strip() or 'route lookup failed'}"
        )
    fields = result.stdout.split()
    try:
        return fields[fields.index("dev") + 1], fields[fields.index("src") + 1]
    except (ValueError, IndexError) as exc:
        raise RuntimeError(f"could not determine route to {destination}") from exc


def measure(server, port, seconds, reverse, family=socket.AF_INET):
    family_flag = "-6" if family == socket.AF_INET6 else "-4"
    command = [
        "iperf3", family_flag, "-c", server, "-p", str(port),
        "--connect-timeout", "5000", "-J", "-t", str(seconds),
    ]
    if reverse:
        command.append("-R")
    result = subprocess.run(command, capture_output=True, text=True, timeout=seconds + 20)
    if result.returncode:
        detail = result.stderr.strip()
        try:
            detail = json.loads(result.stdout).get("error") or detail
        except json.JSONDecodeError:
            detail = detail or result.stdout.strip()
        raise RuntimeError(detail or f"iperf3 exited with status {result.returncode}")
    end = json.loads(result.stdout)["end"]
    block = end.get("sum_received") or end.get("sum_sent") or end.get("sum")
    return float(block["bits_per_second"]) / 1_000_000


def main() -> int:
    server = sys.argv[1] if len(sys.argv) > 1 else ""
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,253}", server) or not shutil.which("iperf3"):
        print("A valid server and the iperf3 package are required.")
        return 2
    try:
        seconds = max(1, min(int(sys.argv[2]), 120))
        port = max(1, min(int(sys.argv[3]) if len(sys.argv) > 3 else 5201, 65535))
        destination, family = resolve_server(server)
        interface, local_address = route_to(destination, family)
        target = f"[{destination}]:{port}" if family == socket.AF_INET6 else f"{destination}:{port}"
        print(
            f"iperf3 target: {target} · route: {interface} ({local_address})",
            flush=True,
        )
        with TemporaryUfwRules("lan-speed-test") as firewall:
            firewall.allow_client_service(
                interface, local_address, destination, port, "tcp",
            )
            print("Temporary scoped UFW client rules installed.", flush=True)
            print("Running download test…", flush=True)
            download = measure(destination, port, seconds, True, family)
            print("Running upload test…", flush=True)
            upload = measure(destination, port, seconds, False, family)
    except subprocess.TimeoutExpired:
        print(
            f"LAN test failed: the remote iperf3 session did not finish within "
            f"{locals().get('seconds', 10) + 20}s.",
            flush=True,
        )
        print(
            "The local route and temporary UFW rules succeeded; try another authorized "
            "iperf3 server or check whether that server permits reverse tests.",
            flush=True,
        )
        return 1
    except (IndexError, ValueError, RuntimeError, UfwRuleError, json.JSONDecodeError) as exc:
        print(f"LAN test failed: {exc}")
        if "connect" in str(exc).lower() or "route to host" in str(exc).lower():
            print(
                f"Verify the remote machine is running `iperf3 -s -p {locals().get('port', 5201)}` "
                "and permits that TCP port in its own firewall.",
                flush=True,
            )
        return 1
    print(f"Download: {download:.2f} Mbps\nUpload:   {upload:.2f} Mbps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
