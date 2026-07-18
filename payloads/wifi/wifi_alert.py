#!/usr/bin/env python3
# @name: WiFi Airspace Alert Monitor
# @desc: Monitors the WiFi airspace for target MACs and SSIDs defined in a watchlist.
# @category: wifi
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- WiFi Airspace Alert Monitor
=================================================
Author: 7h30th3r0n3

Monitors the WiFi airspace for target MACs and SSIDs defined in a
watchlist.  When a target appears or disappears the LCD flashes red
and an optional Discord webhook notification is sent.

Setup / Prerequisites
---------------------
- USB WiFi dongle with monitor mode support (e.g. Alfa AWUS036ACH)
- pip install scapy requests
- Watchlist: $CITYPOP_ROOT/config/wifi_alert/watchlist.json
  Format: {"targets": [{"mac": "AA:BB:CC:DD:EE:FF", "label": "Phone"},
                         {"ssid": "EvilCorp", "label": "Corp AP"}],
            "discord_webhook": "https://discord.com/api/webhooks/..."}

Controls
--------
  python3 wifi_alert.py

  If more than one WiFi interface is present, you'll be prompted to
  pick one from a numbered list. Monitoring then starts immediately;
  new watchlist events (APPEARED / MISSING) print as they happen along
  with a periodic status line every 5s.

  Ctrl-C   -- Stop monitoring and print a final watchlist status. You
              will then be asked whether to add currently visible APs
              to the watchlist, and the alert log is exported to loot.
"""

from payloads._web_input import request_input
import os
import sys
import time
import json
import threading
import subprocess
import copy
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces, supports_monitor

try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq,
        RadioTap, sniff as scapy_sniff, conf,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

# ── Constants ────────────────────────────────────────────────────────────────
CONFIG_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'config', 'wifi_alert')
CONFIG_FILE = os.path.join(CONFIG_DIR, "watchlist.json")
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'WiFiAlert')
CHANNELS_24 = list(range(1, 14))

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
watchlist = []           # [{"mac": ..., "ssid": ..., "label": ...}]
discord_webhook = ""
seen_status = {}         # label -> {"seen": bool, "last_ts": str}
visible_aps = {}         # bssid -> {"ssid": ..., "bssid": ...}
alert_log = []           # [{"ts": ..., "event": ..., "label": ...}]
monitoring = False
mon_iface = None
status_msg = "Idle"
flash_until = 0.0
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
    """Return the first external wireless interface name."""
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
    """Put *iface* into monitor mode, return monitor interface name."""
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "iw", iface, "set", "type", "monitor"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)
    return iface


def _disable_monitor(iface):
    """Restore managed mode on *iface*."""
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


# ── Config helpers ───────────────────────────────────────────────────────────

def _load_config():
    global watchlist, discord_webhook
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.isfile(CONFIG_FILE):
        _save_config()
        return
    try:
        with open(CONFIG_FILE, "r") as fh:
            data = json.load(fh)
        with lock:
            watchlist = list(data.get("targets", []))
            discord_webhook = data.get("discord_webhook", "")
            for entry in watchlist:
                label = entry.get("label", entry.get("mac", entry.get("ssid", "?")))
                if label not in seen_status:
                    seen_status[label] = {"seen": False, "last_ts": "never"}
    except Exception:
        pass


def _save_config():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with lock:
        data = {"targets": list(watchlist), "discord_webhook": discord_webhook}
    with open(CONFIG_FILE, "w") as fh:
        json.dump(data, fh, indent=2)


def _send_discord(message):
    if not REQUESTS_OK:
        return
    with lock:
        url = discord_webhook
    if not url:
        return
    try:
        requests.post(url, json={"content": message}, timeout=5)
    except Exception:
        pass


# ── Sniff callback ───────────────────────────────────────────────────────────

def _pkt_handler(pkt):
    global flash_until
    if not pkt.haslayer(Dot11):
        return

    bssid = None
    ssid = None
    src_mac = None

    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        elt = pkt[Dot11Elt]
        if elt and elt.ID == 0:
            try:
                ssid = elt.info.decode("utf-8", errors="replace")
            except Exception:
                ssid = ""
        if bssid:
            with lock:
                visible_aps[bssid.upper()] = {"ssid": ssid or "", "bssid": bssid.upper()}

    if pkt.haslayer(Dot11ProbeReq):
        src_mac = pkt[Dot11].addr2

    with lock:
        targets = list(watchlist)

    now_str = datetime.now().strftime("%H:%M:%S")

    for t in targets:
        label = t.get("label", t.get("mac", t.get("ssid", "?")))
        matched = False

        target_mac = t.get("mac", "").upper()
        target_ssid = t.get("ssid", "")

        if target_mac and bssid and bssid.upper() == target_mac:
            matched = True
        if target_mac and src_mac and src_mac.upper() == target_mac:
            matched = True
        if target_ssid and ssid and target_ssid.lower() in ssid.lower():
            matched = True

        if matched:
            with lock:
                prev = seen_status.get(label, {}).get("seen", False)
                seen_status[label] = {"seen": True, "last_ts": now_str}
                if not prev:
                    alert_log.append({"ts": now_str, "event": "APPEARED", "label": label})
                    flash_until = time.time() + 2.0
            if not prev:
                threading.Thread(
                    target=_send_discord,
                    args=(f"[WiFi Alert] {label} APPEARED at {now_str}",),
                    daemon=True,
                ).start()


# ── Channel hopping thread ──────────────────────────────────────────────────

def _channel_hop():
    ch_idx = 0
    while True:
        with lock:
            if not monitoring:
                break
            iface = mon_iface
        if iface is None:
            break
        _set_channel(iface, CHANNELS_24[ch_idx])
        ch_idx = (ch_idx + 1) % len(CHANNELS_24)
        time.sleep(0.3)


# ── Sniff thread ────────────────────────────────────────────────────────────

def _sniff_thread():
    with lock:
        iface = mon_iface
    if iface is None:
        return
    try:
        scapy_sniff(
            iface=iface,
            prn=_pkt_handler,
            store=False,
            stop_filter=lambda _: not monitoring,
        )
    except Exception:
        pass


# ── Disappearance checker thread ────────────────────────────────────────────

def _disappearance_checker():
    """Mark targets as MISSING if not seen for 30 seconds."""
    global flash_until
    while True:
        with lock:
            if not monitoring:
                break
        time.sleep(5)
        now = time.time()
        now_str = datetime.now().strftime("%H:%M:%S")
        with lock:
            for label, info in seen_status.items():
                if info["seen"] and info["last_ts"] != "never":
                    try:
                        last = datetime.strptime(info["last_ts"], "%H:%M:%S")
                        today = datetime.now().replace(
                            hour=last.hour, minute=last.minute, second=last.second
                        )
                        if (datetime.now() - today).total_seconds() > 30:
                            info["seen"] = False
                            alert_log.append({"ts": now_str, "event": "MISSING", "label": label})
                            flash_until = now + 2.0
                            threading.Thread(
                                target=_send_discord,
                                args=(f"[WiFi Alert] {label} MISSING at {now_str}",),
                                daemon=True,
                            ).start()
                    except Exception:
                        pass


# ── Start / stop ─────────────────────────────────────────────────────────────

def _start_monitoring():
    global monitoring, mon_iface, status_msg

    ext = _selected_iface
    if ext is None:
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
        monitoring = True
        status_msg = f"Monitoring on {iface}"

    threading.Thread(target=_channel_hop, daemon=True).start()
    threading.Thread(target=_sniff_thread, daemon=True).start()
    threading.Thread(target=_disappearance_checker, daemon=True).start()


def _stop_monitoring():
    global monitoring, status_msg
    with lock:
        monitoring = False
        iface = mon_iface
        status_msg = "Stopped"
    time.sleep(0.5)
    if iface:
        _disable_monitor(iface)


# ── Add visible APs to watchlist ─────────────────────────────────────────────

def _add_visible_to_watchlist():
    with lock:
        current_macs = {t.get("mac", "").upper() for t in watchlist}
        current_ssids = {t.get("ssid", "").lower() for t in watchlist}
        added = 0
        for bssid, info in visible_aps.items():
            if bssid not in current_macs:
                entry = {"mac": bssid, "label": info.get("ssid", bssid)[:16] or bssid}
                watchlist.append(entry)
                label = entry["label"]
                seen_status[label] = {"seen": True, "last_ts": datetime.now().strftime("%H:%M:%S")}
                added += 1
    if added > 0:
        _save_config()
    return added


# ── Export log ───────────────────────────────────────────────────────────────

def _export_log():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"wifi_alert_{ts}.json")
    with lock:
        data = {
            "watchlist": list(watchlist),
            "status": dict(seen_status),
            "alert_log": list(alert_log),
        }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ── WiFi interface selection ─────────────────────────────────────────────────

def _select_wifi_interface():
    """Detect WiFi interfaces and pick one. Prompts if more than one is found."""
    ifaces = list_interfaces(iface_type="wifi")

    if not ifaces:
        print("No WiFi interface found.", flush=True)
        return None

    if len(ifaces) == 1:
        return ifaces[0]["name"]

    print("Multiple WiFi interfaces found:", flush=True)
    for i, ifc in enumerate(ifaces):
        src = "USB" if not ifc["is_onboard"] else "onboard"
        caps = []
        if ifc["supports_ap"]:
            caps.append("AP")
        if ifc["supports_monitor"]:
            caps.append("mon")
        tag = f"{src} {'+'.join(caps)}" if caps else src
        state = "UP" if ifc["is_up"] else "DOWN"
        print(f"  [{i}] {ifc['name']}  {tag}  {state}", flush=True)

    while True:
        choice = request_input(f"Select interface [0-{len(ifaces) - 1}]: ").strip()
        if choice.isdigit() and 0 <= int(choice) < len(ifaces):
            return ifaces[int(choice)]["name"]
        print("Invalid selection, try again.", flush=True)


# ── Main ─────────────────────────────────────────────────────────────────────

def _usage():
    print(f"Usage: {os.path.basename(__file__)}", flush=True)
    print("  Runs until Ctrl-C. Prompts for a WiFi interface if more", flush=True)
    print("  than one is available.", flush=True)


def main():
    global _selected_iface, _running

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0

    _selected_iface = _select_wifi_interface()
    if not _selected_iface:
        return 1

    _load_config()

    with lock:
        n_targets = len(watchlist)
    print(f"Watchlist: {n_targets} target(s) loaded from {CONFIG_FILE}", flush=True)

    if not SCAPY_OK:
        print("scapy is not installed; cannot monitor.", flush=True)
        return 1

    print(f"Starting airspace monitor on {_selected_iface} ...", flush=True)
    _start_monitoring()
    with lock:
        msg = status_msg
    print(msg, flush=True)
    print("Monitoring. Press Ctrl-C to stop.", flush=True)

    start_time = time.time()
    with lock:
        last_log_count = len(alert_log)
    try:
        while _running:
            time.sleep(5.0)
            with lock:
                new_events = alert_log[last_log_count:]
                last_log_count = len(alert_log)
                n_visible = len(visible_aps)
            for ev in new_events:
                print(f"[{ev['ts']}] {ev['event']}: {ev['label']}", flush=True)
            elapsed = time.time() - start_time
            print(f"[{elapsed:6.1f}s] visible_aps={n_visible} alerts={last_log_count}",
                  flush=True)
    except KeyboardInterrupt:
        print("\nStopping monitor...", flush=True)

    _stop_monitoring()

    with lock:
        wl = list(watchlist)
        ss = dict(seen_status)
        n_visible_aps = len(visible_aps)

    print("\nFinal watchlist status:", flush=True)
    if wl:
        for entry in wl:
            label = entry.get("label", "?")
            info = ss.get(label, {})
            tag = "SEEN" if info.get("seen") else "MISSING"
            print(f"  {label:<16} {tag:<7} last={info.get('last_ts', 'never')}", flush=True)
    else:
        print("  (no targets configured)", flush=True)

    if n_visible_aps:
        try:
            choice = request_input(
                f"\nAdd currently visible APs to watchlist? "
                f"({n_visible_aps} seen) [y/N]: "
            ).strip().lower()
        except EOFError:
            choice = ""
        if choice == "y":
            added = _add_visible_to_watchlist()
            print(f"Added {added} AP(s) to watchlist.", flush=True)

    path = _export_log()
    print(f"\nAlert log exported to {path}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
