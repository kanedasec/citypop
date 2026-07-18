#!/usr/bin/env python3
# @name: DHCP Snoop
# @desc: Passive DHCP snooping for network reconnaissance.
# @category: network
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- DHCP Snoop
=================================
Author: 7h30th3r0n3

Passive DHCP snooping for network reconnaissance.
Sniffs DHCP Discover/Offer/Request/ACK packets to map clients,
hostnames, MAC addresses, lease info, and DHCP server details.

Flow:
  1) Sniff UDP 67/68 (DHCP) packets
  2) Extract: client MAC, hostname, IP, DHCP server, gateway, DNS
  3) Build a table of all DHCP clients
  4) Print a summary table and export to loot

Controls:
  python3 dhcp_snoop.py [iface] [duration_seconds]

    iface             -- optional network interface to sniff on. If
                          omitted and more than one candidate is found,
                          you'll be prompted to pick one from a numbered
                          list.
    duration_seconds  -- optional time to sniff (default 60).
                          Ctrl-C stops early.

  Discovered clients and DHCP server details are printed as they're
  found, with a final summary table and JSON export when the run ends.

Loot: $CITYPOP_ROOT/loot/DHCPSnoop/

Setup: Passive, no special requirements.
"""

from payloads._web_input import request_input
import os
import sys
import time
import json
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces

try:
    from scapy.all import sniff, DHCP, BOOTP, IP, UDP, Ether, conf
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'DHCPSnoop')
os.makedirs(LOOT_DIR, exist_ok=True)

DHCP_MSG_TYPES = {
    1: "Discover", 2: "Offer", 3: "Request",
    4: "Decline", 5: "ACK", 6: "NAK",
    7: "Release", 8: "Inform",
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
clients = {}           # MAC -> {hostname, ip, server_ip, gateway, dns, lease_time, last_seen}
server_info = {
    "ip": "", "gateway": "", "dns": [],
    "subnet_mask": "", "domain": "",
}
status_msg = "Ready"
sniff_active = False
app_running = True
total_packets = 0
selected_iface = ""


# ---------------------------------------------------------------------------
# DHCP packet parser
# ---------------------------------------------------------------------------

def _extract_dhcp_options(pkt):
    """Extract DHCP options into a dict."""
    opts = {}
    if pkt.haslayer(DHCP):
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                opts[opt[0]] = opt[1]
            elif opt == "end":
                break
    return opts


def _mac_from_bootp(pkt):
    """Extract client MAC from BOOTP chaddr."""
    if pkt.haslayer(BOOTP):
        raw_mac = pkt[BOOTP].chaddr[:6]
        return ":".join(f"{b:02x}" for b in raw_mac)
    if pkt.haslayer(Ether):
        return pkt[Ether].src
    return "00:00:00:00:00:00"


def _packet_handler(pkt):
    """Process a DHCP packet."""
    global total_packets

    if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
        return

    with lock:
        total_packets += 1

    opts = _extract_dhcp_options(pkt)
    msg_type = opts.get("message-type", 0)
    client_mac = _mac_from_bootp(pkt)

    hostname = ""
    if "hostname" in opts:
        h = opts["hostname"]
        hostname = h.decode("utf-8", errors="ignore") if isinstance(h, bytes) else str(h)

    bootp = pkt[BOOTP]
    yiaddr = bootp.yiaddr if bootp.yiaddr != "0.0.0.0" else ""
    siaddr = bootp.siaddr if bootp.siaddr != "0.0.0.0" else ""

    # Extract options
    requested_ip = opts.get("requested_addr", "")
    server_id = opts.get("server_id", "")
    lease_time = opts.get("lease_time", 0)
    subnet_mask = opts.get("subnet_mask", "")
    router = opts.get("router", "")
    dns_servers = opts.get("name_server", "")
    domain = opts.get("domain", "")
    if isinstance(domain, bytes):
        domain = domain.decode("utf-8", errors="ignore")

    is_new = client_mac not in clients

    with lock:
        # Update client record
        entry = clients.get(client_mac, {
            "hostname": "", "ip": "", "server_ip": "",
            "gateway": "", "dns": [], "lease_time": 0,
            "last_seen": "", "msg_type": "",
        })

        if hostname:
            entry["hostname"] = hostname
        if yiaddr:
            entry["ip"] = yiaddr
        elif requested_ip:
            entry["ip"] = str(requested_ip)
        entry["msg_type"] = DHCP_MSG_TYPES.get(msg_type, f"Type{msg_type}")
        entry["last_seen"] = datetime.now().strftime("%H:%M:%S")

        if server_id:
            entry["server_ip"] = str(server_id)
        if lease_time:
            entry["lease_time"] = int(lease_time)

        new_clients = dict(clients)
        new_clients[client_mac] = entry
        clients.clear()
        clients.update(new_clients)

        # Update server info from Offer/ACK
        if msg_type in (2, 5):
            if server_id:
                server_info["ip"] = str(server_id)
            if router:
                server_info["gateway"] = str(router)
            if subnet_mask:
                server_info["subnet_mask"] = str(subnet_mask)
            if dns_servers:
                if isinstance(dns_servers, (list, tuple)):
                    server_info["dns"] = [str(d) for d in dns_servers]
                else:
                    server_info["dns"] = [str(dns_servers)]
            if domain:
                server_info["domain"] = domain

    if is_new:
        print(f"[+] New client {client_mac}  ip={entry['ip'] or '?'}  "
              f"host={entry['hostname'] or '?'}  {entry['msg_type']}", flush=True)


def _sniff_thread():
    """Sniff DHCP traffic."""
    global sniff_active, status_msg
    sniff_active = True
    with lock:
        status_msg = "Sniffing DHCP..."
    try:
        sniff(
            iface=selected_iface,
            filter="udp and (port 67 or port 68)",
            prn=_packet_handler,
            store=False,
            stop_filter=lambda _: not app_running or not sniff_active,
        )
    except Exception as exc:
        with lock:
            status_msg = f"Err: {exc}"
        print(f"[!] Sniff error: {exc}", flush=True)
    finally:
        sniff_active = False


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_data():
    global status_msg
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_packets": total_packets,
            "server": dict(server_info),
            "clients": dict(clients),
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"dhcp_snoop_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        with lock:
            status_msg = "Exported to loot"
        return path
    except Exception as exc:
        print(f"[!] Export failed: {exc}", flush=True)
        return None


# ---------------------------------------------------------------------------
# Interface selection
# ---------------------------------------------------------------------------

def _select_iface(iface_arg):
    """Resolve the interface to use from an optional CLI arg or a prompt."""
    if iface_arg:
        return iface_arg

    ifaces = list_interfaces("any")
    if not ifaces:
        print("No network interface found.", flush=True)
        return None
    if len(ifaces) == 1:
        return ifaces[0]["name"]

    print("Multiple interfaces found:", flush=True)
    for i, ifc in enumerate(ifaces):
        print(f"  [{i}] {ifc['name']}  ip={ifc['ip'] or '?'}  "
              f"{'UP' if ifc['is_up'] else 'DOWN'}", flush=True)
    while True:
        choice = request_input(f"Select interface [0-{len(ifaces) - 1}]: ").strip()
        if choice.isdigit() and 0 <= int(choice) < len(ifaces):
            return ifaces[int(choice)]["name"]
        print("Invalid selection, try again.", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _usage():
    print(f"Usage: {os.path.basename(__file__)} [iface] [duration_seconds]",
          flush=True)
    print("  iface             network interface (optional; omit to "
          "auto-detect/prompt)", flush=True)
    print("  duration_seconds  time to sniff, default 60 (Ctrl-C stops "
          "early)", flush=True)


def main():
    global app_running, sniff_active, status_msg, selected_iface

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0

    if not SCAPY_OK:
        print("scapy not found! pip install scapy", flush=True)
        return 1

    iface_arg = args[0] if len(args) > 0 else None
    duration_arg = args[1] if len(args) > 1 else None

    duration = 60
    if duration_arg:
        try:
            duration = max(1, int(duration_arg))
        except ValueError:
            _usage()
            return 1

    selected_iface = _select_iface(iface_arg)
    if not selected_iface:
        return 1

    print(f"[*] Sniffing DHCP on {selected_iface} for {duration}s... "
          "(Ctrl-C to stop)", flush=True)

    sniff_active = True
    threading.Thread(target=_sniff_thread, daemon=True).start()

    try:
        start = time.time()
        last_report = 0
        while time.time() - start < duration:
            time.sleep(1)
            elapsed = int(time.time() - start)
            if elapsed - last_report >= 10:
                last_report = elapsed
                with lock:
                    tp = total_packets
                    nc = len(clients)
                print(f"[*] {elapsed}s elapsed, {tp} packet(s), "
                      f"{nc} client(s) seen...", flush=True)
    except KeyboardInterrupt:
        print("\n[*] Interrupted.", flush=True)
    finally:
        app_running = False
        sniff_active = False

    with lock:
        tp = total_packets
        cl = dict(clients)
        si = dict(server_info)

    print(f"[*] {tp} packet(s) captured, {len(cl)} client(s) found.", flush=True)
    if si["ip"]:
        print(f"[*] DHCP server: {si['ip']}  gateway={si['gateway']}  "
              f"mask={si['subnet_mask']}  dns={','.join(si['dns'])}  "
              f"domain={si['domain']}", flush=True)

    if cl:
        print("[*] Clients:", flush=True)
        for mac, entry in sorted(cl.items()):
            print(f"    {mac}  {entry['ip'] or '?':<15}  "
                  f"{entry['hostname'] or '?':<16}  {entry['msg_type']}",
                  flush=True)

    path = _export_data()
    if path:
        print(f"[*] Exported to {path}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
