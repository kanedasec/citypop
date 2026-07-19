#!/usr/bin/env python3
# @active: true
# @name: WiFi Recon Survey
# @desc: Survey nearby access points and clients from a monitor interface and publish a temporary live web dashboard whose endpoint is printed in the terminal.
# @category: wifi
# @danger: false
# @web: true
# @inputs: [{"name":"seconds","label":"Survey duration","type":"number","default":"60"}]

import os
import sys
import time
import json
import threading
import subprocess
import copy
from datetime import datetime
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces, supports_monitor
from payloads._dashboard import DashboardServer
from payloads._web_input import request_input

try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp,
        RadioTap, sniff as scapy_sniff, conf,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── Constants ────────────────────────────────────────────────────────────────
LOOT_DIR = os.path.join(os.environ["CITYPOP_LOOT"], "WiFiSurvey")
CHANNELS_24 = list(range(1, 14))
ROWS_VISIBLE = 7
ROW_H = 12
VIEWS = ["APs", "Clients", "Channels"]
SORT_MODES = ["signal", "clients", "channel"]

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
ap_db = {}           # bssid -> {ssid, bssid, channel, enc, signal, clients: set(), last_seen}
client_db = {}       # mac -> {mac, ap_bssid, probed: set(), last_seen}
channel_usage = defaultdict(int)   # channel -> frame count
surveying = False
mon_iface = None
view_idx = 0
sort_idx = 0
scroll_pos = 0
status_msg = "Idle"
_running = True
_selected_iface = None


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


def _select_monitor_interface():
    ifaces = [item for item in list_interfaces("wifi") if item.get("supports_monitor")]
    if not ifaces:
        print("No monitor-capable Wi-Fi interface found", flush=True)
        return None
    print("Available monitor-capable interfaces:", flush=True)
    choices = []
    for item in ifaces:
        name = item["name"]
        bus = item.get("bus") or ("onboard" if item.get("is_onboard") else "external")
        state = "up" if item.get("is_up") else "down"
        print(f"  {name}: {bus}, {state}", flush=True)
        choices.append({"value": name, "label": f"{name} · {bus} · {state}"})
    selected = str(request_input(
        "Select monitor-capable Wi-Fi interface",
        input_type="select",
        choices=choices,
    ))
    if selected not in {item["name"] for item in ifaces}:
        print("Invalid interface selection", flush=True)
        return None
    return selected


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


# ── Encryption parser ───────────────────────────────────────────────────────

def _parse_encryption(pkt):
    """Extract encryption type from a beacon frame."""
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").lower()
    if "privacy" not in cap:
        return "OPEN"
    crypto = set()
    elt = pkt[Dot11Elt]
    while elt:
        if elt.ID == 48:
            crypto.add("WPA2")
        elif elt.ID == 221 and elt.info and elt.info.startswith(b"\x00\x50\xf2\x01"):
            crypto.add("WPA")
        elt = elt.payload if hasattr(elt, "payload") and isinstance(elt.payload, Dot11Elt) else None
    if not crypto:
        return "WEP"
    return "/".join(sorted(crypto))


# ── Packet handler ──────────────────────────────────────────────────────────

def _pkt_handler(pkt):
    if not pkt.haslayer(Dot11):
        return

    now_str = datetime.now().strftime("%H:%M:%S")

    # Beacon / Probe response  -> AP info
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        bssid = (pkt[Dot11].addr2 or "").upper()
        if not bssid or bssid == "FF:FF:FF:FF:FF:FF":
            return
        ssid = ""
        elt = pkt[Dot11Elt]
        if elt and elt.ID == 0:
            try:
                ssid = elt.info.decode("utf-8", errors="replace")
            except Exception:
                pass
        channel = 0
        e = pkt[Dot11Elt]
        while e:
            if e.ID == 3 and e.info:
                channel = e.info[0]
                break
            e = e.payload if hasattr(e, "payload") and isinstance(e.payload, Dot11Elt) else None

        signal = -100
        if pkt.haslayer(RadioTap):
            try:
                signal = pkt[RadioTap].dBm_AntSignal
            except Exception:
                pass

        enc = "?"
        if pkt.haslayer(Dot11Beacon):
            enc = _parse_encryption(pkt)

        with lock:
            if bssid not in ap_db:
                ap_db[bssid] = {
                    "ssid": ssid, "bssid": bssid, "channel": channel,
                    "enc": enc, "signal": signal, "clients": set(),
                    "last_seen": now_str,
                }
            else:
                entry = ap_db[bssid]
                ap_db[bssid] = {
                    **entry,
                    "ssid": ssid or entry["ssid"],
                    "channel": channel or entry["channel"],
                    "signal": signal if signal > -100 else entry["signal"],
                    "enc": enc if enc != "?" else entry["enc"],
                    "last_seen": now_str,
                }
            if channel:
                channel_usage[channel] += 1

    # Probe request -> client info
    if pkt.haslayer(Dot11ProbeReq):
        src = (pkt[Dot11].addr2 or "").upper()
        if not src or src == "FF:FF:FF:FF:FF:FF":
            return
        ssid = ""
        elt = pkt[Dot11Elt]
        if elt and elt.ID == 0 and elt.info:
            try:
                ssid = elt.info.decode("utf-8", errors="replace")
            except Exception:
                pass
        with lock:
            if src not in client_db:
                client_db[src] = {"mac": src, "ap_bssid": "", "probed": set(), "last_seen": now_str}
            else:
                client_db[src] = {**client_db[src], "last_seen": now_str}
            if ssid:
                client_db[src]["probed"] = client_db[src]["probed"] | {ssid}

    # Data frames -> client-AP association
    frame_type = pkt[Dot11].type
    if frame_type == 2:  # Data
        addr1 = (pkt[Dot11].addr1 or "").upper()
        addr2 = (pkt[Dot11].addr2 or "").upper()
        ds = pkt[Dot11].FCfield & 0x3
        ap_mac = None
        client_mac = None
        if ds == 1:    # To-DS
            ap_mac, client_mac = addr1, addr2
        elif ds == 2:  # From-DS
            ap_mac, client_mac = addr2, addr1

        if ap_mac and client_mac and client_mac != "FF:FF:FF:FF:FF:FF":
            with lock:
                if ap_mac in ap_db:
                    ap_db[ap_mac]["clients"] = ap_db[ap_mac]["clients"] | {client_mac}
                if client_mac not in client_db:
                    client_db[client_mac] = {
                        "mac": client_mac, "ap_bssid": ap_mac,
                        "probed": set(), "last_seen": now_str,
                    }
                else:
                    client_db[client_mac] = {**client_db[client_mac], "ap_bssid": ap_mac, "last_seen": now_str}


# ── Channel hopping ─────────────────────────────────────────────────────────

def _channel_hop():
    idx = 0
    while True:
        with lock:
            if not surveying:
                break
            iface = mon_iface
        if not iface:
            break
        _set_channel(iface, CHANNELS_24[idx])
        idx = (idx + 1) % len(CHANNELS_24)
        time.sleep(0.25)


def _sniff_thread():
    with lock:
        iface = mon_iface
    if not iface:
        return
    try:
        scapy_sniff(
            iface=iface, prn=_pkt_handler, store=False,
            stop_filter=lambda _: not surveying,
        )
    except Exception:
        pass


# ── Start / stop ─────────────────────────────────────────────────────────────

def _start_survey():
    global surveying, mon_iface, status_msg
    ext = _selected_iface
    if not ext:
        with lock:
            status_msg = "No USB WiFi found"
        return
    if not SCAPY_OK:
        with lock:
            status_msg = "scapy not installed"
        return
    iface = _enable_monitor(ext)
    with lock:
        mon_iface = iface
        surveying = True
        status_msg = f"Survey on {iface}"
    threading.Thread(target=_channel_hop, daemon=True).start()
    threading.Thread(target=_sniff_thread, daemon=True).start()


def _stop_survey():
    global surveying, status_msg
    with lock:
        surveying = False
        iface = mon_iface
        status_msg = "Stopped"
    time.sleep(0.5)
    if iface:
        _disable_monitor(iface)


# ── Export ───────────────────────────────────────────────────────────────────

def _export_json():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"survey_{ts}.json")
    with lock:
        aps = []
        for v in ap_db.values():
            aps.append({**v, "clients": list(v["clients"])})
        cls = []
        for v in client_db.values():
            cls.append({**v, "probed": list(v["probed"])})
        ch = dict(channel_usage)
    data = {"timestamp": ts, "access_points": aps, "clients": cls, "channel_usage": ch}
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ── Sorted lists ─────────────────────────────────────────────────────────────

def _sorted_aps():
    with lock:
        items = list(ap_db.values())
        mode = SORT_MODES[sort_idx]
    if mode == "signal":
        items.sort(key=lambda a: a["signal"], reverse=True)
    elif mode == "clients":
        items.sort(key=lambda a: len(a["clients"]), reverse=True)
    elif mode == "channel":
        items.sort(key=lambda a: a["channel"])
    return items


def _sorted_clients():
    with lock:
        items = list(client_db.values())
    items.sort(key=lambda c: c["last_seen"], reverse=True)
    return items


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    global _selected_iface
    _selected_iface = _select_monitor_interface()
    if not _selected_iface:
        return 1
    try:
        duration = float(sys.argv[1]) if len(sys.argv) > 1 else 60.0
    except ValueError:
        print("seconds must be numeric", flush=True)
        return 2
    if not 1 <= duration <= 3600:
        print("seconds must be between 1 and 3600", flush=True)
        return 2
    if not SCAPY_OK:
        print("scapy is required", flush=True)
        return 127
    print(f"Surveying on {_selected_iface} for {duration:g}s", flush=True)
    started = time.monotonic()

    def snapshot():
        ap_items = _sorted_aps()
        client_items = _sorted_clients()
        with lock:
            aps = [{
                "ssid": item["ssid"] or "(hidden)", "bssid": item["bssid"],
                "channel": item["channel"], "encryption": item["enc"],
                "signal": item["signal"], "clients": len(item["clients"]),
                "last_seen": item["last_seen"],
            } for item in ap_items]
            clients = [{
                "mac": item["mac"], "ap_bssid": item["ap_bssid"] or "unassociated",
                "probed_ssids": sorted(item["probed"]), "last_seen": item["last_seen"],
            } for item in client_items]
            channels = [{"channel": channel, "frames": frames} for channel, frames in sorted(channel_usage.items())]
            return {
                "status": status_msg,
                "interface": mon_iface or _selected_iface,
                "elapsed_seconds": round(time.monotonic() - started, 1),
                "access_points_seen": len(ap_db),
                "clients_seen": len(client_db),
                "access_points": aps,
                "clients": clients,
                "channels": channels,
            }

    dashboard = DashboardServer("Wi-Fi Recon Survey", snapshot)
    try:
        _start_survey()
        try:
            print(f"Dashboard: {dashboard.start()}", flush=True)
        except OSError as exc:
            print(f"Dashboard unavailable: {exc}", flush=True)
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            time.sleep(min(5, deadline - time.monotonic()))
            with lock:
                print(f"APs={len(ap_db)} clients={len(client_db)}", flush=True)
    except KeyboardInterrupt:
        print("Stopping survey", flush=True)
    finally:
        _stop_survey()
        dashboard.stop()
    path = _export_json()
    print(f"Saved survey to {path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
