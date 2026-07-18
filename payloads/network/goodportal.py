#!/usr/bin/env python3
# @name: Whitelist Portal (GoodPortal)
# @desc: DNS redirect portal with MAC whitelist.
# @category: network
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- Whitelist Portal (GoodPortal)
====================================================
Author: 7h30th3r0n3

DNS redirect portal with MAC whitelist.  Whitelisted MACs get full
internet access; all others are redirected to a configurable portal page.

Uses dnsmasq + iptables for traffic steering.

Controls
--------
  CLI       -- Run: python3 goodportal.py [interface]
               If interface is omitted, pick from a numbered list.
               Then use REPL commands: start, stop, status, whitelist,
               clients, add <index>, remove <index>, quit

Config: $CITYPOP_ROOT/loot/GoodPortal/whitelist.json
"""

from payloads._web_input import request_input
import os
import sys
import time
import signal
import subprocess
import threading
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces


def _select_interface(iface_type="any"):
    """CLI replacement for the old LCD interface picker."""
    ifaces = list_interfaces(iface_type)
    if not ifaces:
        print("No matching interface found.", flush=True)
        return None
    if len(ifaces) == 1:
        print(f"Using interface: {ifaces[0]['name']}", flush=True)
        return ifaces[0]["name"]
    print("Available interfaces:", flush=True)
    for idx, info in enumerate(ifaces):
        print(f"  [{idx}] {info['name']} driver={info['driver']} "
              f"ip={info['ip'] or '-'} up={info['is_up']}", flush=True)
    while True:
        choice = request_input("Select interface number: ").strip()
        if choice.isdigit() and 0 <= int(choice) < len(ifaces):
            return ifaces[int(choice)]["name"]
        print("Invalid selection.", flush=True)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'GoodPortal')
WHITELIST_PATH = os.path.join(LOOT_DIR, "whitelist.json")
DNSMASQ_CONF = os.path.join(LOOT_DIR, "dnsmasq_portal.conf")
PORTAL_DIR = os.path.join(LOOT_DIR, "portal_pages")
os.makedirs(LOOT_DIR, exist_ok=True)
os.makedirs(PORTAL_DIR, exist_ok=True)
PORTAL_IFACE = "wlan0"
PORTAL_IP = "10.0.0.1"
PORTAL_SUBNET = "10.0.0.0/24"
PORTAL_RANGE_START = "10.0.0.10"
PORTAL_RANGE_END = "10.0.0.50"
REDIRECT_PORT = 80

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
app_running = True
portal_active = False
whitelist = []              # list of MAC strings
connected_clients = []      # [{"mac": ..., "ip": ...}]
status_msg = "Stopped"
redirected_count = 0


# ---------------------------------------------------------------------------
# Signal handlers
# ---------------------------------------------------------------------------
def _sig_handler(_sig, _frame):
    global app_running
    app_running = False


signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


# ---------------------------------------------------------------------------
# Whitelist persistence
# ---------------------------------------------------------------------------
def _load_whitelist():
    """Load whitelist from JSON file."""
    if not os.path.isfile(WHITELIST_PATH):
        return []
    try:
        with open(WHITELIST_PATH, "r") as fh:
            data = json.load(fh)
        return list(data.get("macs", []))
    except (json.JSONDecodeError, OSError):
        return []


def _save_whitelist(macs):
    """Save whitelist to JSON file."""
    data = {
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "macs": list(macs),
    }
    try:
        with open(WHITELIST_PATH, "w") as fh:
            json.dump(data, fh, indent=2)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Portal control
# ---------------------------------------------------------------------------
def _run_cmd(args, timeout_s=10):
    """Run a shell command and return (success, stdout)."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout_s,
        )
        return result.returncode == 0, result.stdout.strip()
    except Exception as exc:
        return False, str(exc)


def _write_dnsmasq_conf():
    """Generate dnsmasq config for portal."""
    conf = (
        f"interface={PORTAL_IFACE}\n"
        f"bind-interfaces\n"
        f"dhcp-range={PORTAL_RANGE_START},{PORTAL_RANGE_END},12h\n"
        f"address=/#/{PORTAL_IP}\n"
        f"no-resolv\n"
        f"log-queries\n"
        f"log-dhcp\n"
    )
    try:
        with open(DNSMASQ_CONF, "w") as fh:
            fh.write(conf)
        return True
    except OSError:
        return False


def _apply_iptables_rules(wl_macs):
    """Set up iptables for portal redirection."""
    # Flush portal chain if exists
    _run_cmd(["iptables", "-t", "nat", "-F", "GOODPORTAL"])
    _run_cmd(["iptables", "-t", "nat", "-X", "GOODPORTAL"])

    # Create portal chain
    _run_cmd(["iptables", "-t", "nat", "-N", "GOODPORTAL"])

    # Whitelist: skip redirect for known MACs
    for mac in wl_macs:
        _run_cmd(["iptables", "-t", "nat", "-A", "GOODPORTAL",
                  "-m", "mac", "--mac-source", mac, "-j", "RETURN"])

    # Redirect HTTP for non-whitelisted
    _run_cmd(["iptables", "-t", "nat", "-A", "GOODPORTAL",
              "-p", "tcp", "--dport", "80",
              "-j", "DNAT", "--to-destination", f"{PORTAL_IP}:{REDIRECT_PORT}"])
    _run_cmd(["iptables", "-t", "nat", "-A", "GOODPORTAL",
              "-p", "tcp", "--dport", "443",
              "-j", "DNAT", "--to-destination", f"{PORTAL_IP}:{REDIRECT_PORT}"])
    _run_cmd(["iptables", "-t", "nat", "-A", "GOODPORTAL",
              "-p", "udp", "--dport", "53",
              "-j", "DNAT", "--to-destination", f"{PORTAL_IP}:53"])

    # Insert chain into PREROUTING
    _run_cmd(["iptables", "-t", "nat", "-A", "PREROUTING",
              "-i", PORTAL_IFACE, "-j", "GOODPORTAL"])

    # Allow forwarding for whitelisted MACs
    for mac in wl_macs:
        _run_cmd(["iptables", "-A", "FORWARD",
                  "-m", "mac", "--mac-source", mac, "-j", "ACCEPT"])


def _clear_iptables_rules():
    """Remove portal iptables rules."""
    _run_cmd(["iptables", "-t", "nat", "-D", "PREROUTING",
              "-i", PORTAL_IFACE, "-j", "GOODPORTAL"])
    _run_cmd(["iptables", "-t", "nat", "-F", "GOODPORTAL"])
    _run_cmd(["iptables", "-t", "nat", "-X", "GOODPORTAL"])
    _run_cmd(["iptables", "-D", "FORWARD",
              "-m", "mac", "-j", "ACCEPT"])


def _start_portal():
    """Start the captive portal."""
    global portal_active, status_msg

    # Configure interface
    _run_cmd(["ip", "addr", "flush", "dev", PORTAL_IFACE])
    _run_cmd(["ip", "addr", "add", f"{PORTAL_IP}/24", "dev", PORTAL_IFACE])
    _run_cmd(["ip", "link", "set", PORTAL_IFACE, "up"])

    # Enable IP forwarding
    _run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"])

    # Write dnsmasq config
    if not _write_dnsmasq_conf():
        with lock:
            status_msg = "Config write failed"
        return

    # Kill existing dnsmasq on interface
    _run_cmd(["pkill", "-f", f"dnsmasq.*{DNSMASQ_CONF}"])
    time.sleep(0.5)

    # Start dnsmasq
    ok, _ = _run_cmd(["dnsmasq", "-C", DNSMASQ_CONF, "--pid-file",
                      os.path.join(LOOT_DIR, "dnsmasq.pid")])

    # Apply iptables
    with lock:
        wl = list(whitelist)
    _apply_iptables_rules(wl)

    with lock:
        portal_active = True
        status_msg = "Portal ACTIVE"


def _stop_portal():
    """Stop the captive portal."""
    global portal_active, status_msg

    _run_cmd(["pkill", "-f", f"dnsmasq.*{DNSMASQ_CONF}"])
    _clear_iptables_rules()

    with lock:
        portal_active = False
        status_msg = "Stopped"


def _get_connected_clients():
    """Get DHCP leases from dnsmasq."""
    clients = []
    lease_file = "/var/lib/misc/dnsmasq.leases"
    try:
        with open(lease_file, "r") as fh:
            for line in fh:
                parts = line.strip().split()
                if len(parts) >= 4:
                    clients.append({
                        "mac": parts[1],
                        "ip": parts[2],
                        "name": parts[3] if parts[3] != "*" else "",
                    })
    except OSError:
        pass
    return clients


def _refresh_clients():
    """Refresh connected clients list."""
    global connected_clients, redirected_count
    clients = _get_connected_clients()
    with lock:
        connected_clients = clients
        wl_set = {m.lower() for m in whitelist}
        redirected_count = sum(
            1 for c in clients if c["mac"].lower() not in wl_set
        )


# ---------------------------------------------------------------------------
# Status output
# ---------------------------------------------------------------------------
def _print_status():
    with lock:
        active = portal_active
        wl = list(whitelist)
        redir = redirected_count
        msg = status_msg
    state = "ACTIVE" if active else "stopped"
    print(f"Portal: {state} | Whitelist: {len(wl)} | "
          f"Redirected clients: {redir} | {msg}", flush=True)


def _print_whitelist():
    with lock:
        wl = list(whitelist)
    if not wl:
        print("Whitelist is empty.", flush=True)
        return
    for i, mac in enumerate(wl):
        print(f"  [{i}] {mac}", flush=True)


def _print_clients():
    _refresh_clients()
    with lock:
        clients = list(connected_clients)
        wl_set = {m.lower() for m in whitelist}
    if not clients:
        print("No connected clients.", flush=True)
        return
    for i, c in enumerate(clients):
        tag = "WHITELISTED" if c["mac"].lower() in wl_set else "redirected"
        print(f"  [{i}] {c['ip']}  {c['mac']}  {tag}", flush=True)


def _print_help():
    print(
        "Commands: start | stop | status | whitelist | clients | "
        "add <client-index> | remove <whitelist-index> | quit",
        flush=True,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global app_running, whitelist, status_msg

    selected_iface = _select_interface(iface_type="wifi")
    if not selected_iface:
        return

    whitelist = _load_whitelist()

    print("GoodPortal ready.", flush=True)
    _print_status()
    _print_help()

    try:
        while app_running:
            try:
                cmd = request_input("goodportal> ").strip()
            except EOFError:
                break
            if not cmd:
                continue
            parts = cmd.split()
            action = parts[0].lower()

            if action in ("quit", "exit"):
                break

            elif action == "start":
                with lock:
                    active = portal_active
                if active:
                    print("Portal already active.", flush=True)
                else:
                    threading.Thread(target=_start_portal, daemon=True).start()
                    time.sleep(0.5)
                    _print_status()

            elif action == "stop":
                with lock:
                    active = portal_active
                if not active:
                    print("Portal already stopped.", flush=True)
                else:
                    _stop_portal()
                    _print_status()

            elif action == "status":
                _print_status()

            elif action == "whitelist":
                _print_whitelist()

            elif action == "clients":
                _print_clients()

            elif action == "add" and len(parts) > 1 and parts[1].isdigit():
                idx = int(parts[1])
                with lock:
                    clients = list(connected_clients)
                if 0 <= idx < len(clients):
                    mac = clients[idx]["mac"]
                    with lock:
                        if mac.lower() not in {m.lower() for m in whitelist}:
                            whitelist = list(whitelist) + [mac]
                            _save_whitelist(whitelist)
                            status_msg = f"Added {mac[-8:]}"
                    print(f"Added {mac} to whitelist.", flush=True)
                else:
                    print("Invalid client index. Run 'clients' first.", flush=True)

            elif action == "remove" and len(parts) > 1 and parts[1].isdigit():
                idx = int(parts[1])
                with lock:
                    if 0 <= idx < len(whitelist):
                        removed = whitelist[idx]
                        whitelist = [m for i, m in enumerate(whitelist) if i != idx]
                        _save_whitelist(whitelist)
                        status_msg = f"Removed {removed[-8:]}"
                        print(f"Removed {removed} from whitelist.", flush=True)
                    else:
                        print("Invalid whitelist index.", flush=True)

            else:
                _print_help()

    finally:
        app_running = False
        if portal_active:
            _stop_portal()


if __name__ == "__main__":
    main()
