#!/usr/bin/env python3
# @name: Event Triggers
# @desc: Configurable event monitoring system.
# @category: wifi
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- Event Triggers
=====================================
Author: 7h30th3r0n3

Configurable event monitoring system. Watches for WiFi events and triggers
alerts: deauth floods, new client connections, specific MAC detection,
authentication captures, beacon floods, and probe request monitoring.

Per-trigger actions: custom shell commands and webhook/Discord notifications.

Controls:
  python3 event_triggers.py [trigger1,trigger2,...|all]

    trigger list  Comma-separated trigger names to enable using the
                   saved config values (or 'all' for every trigger).
                   Omit to interactively select and configure triggers.

  Available triggers: deauth_flood, client_connected, mac_trigger,
  auth_capture, beacon_flood, probe_request

  Once running, new alerts print as they fire and a status line prints
  every 5s. Triggers keep running until Ctrl-C, which stops them,
  prints a final summary, and exits (no background persistence).
"""
from payloads._web_input import request_input
import os, sys, time, signal, subprocess, threading, json, re
from datetime import datetime
from urllib.request import Request, urlopen


sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

try:
    from scapy.all import (Dot11, Dot11Elt, Dot11ProbeReq,
                            sniff as scapy_sniff)
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

CONFIG_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'Triggers')
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
ALERT_LOG_FILE = os.path.join(CONFIG_DIR, "alerts.log")
RESPONDER_LOG_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'Responder', 'logs')
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot')
TRIGGER_NAMES = ["deauth_flood", "client_connected", "mac_trigger",
                 "auth_capture", "beacon_flood", "probe_request"]
TRIGGER_LABELS = ["Deauth Flood", "Client Conn", "MAC Trigger",
                  "Auth Capture", "Beacon Flood", "Probe Request"]

# ── OUI lookup (~50 common vendors) ─────────────────────────────────────────
OUI_BUILTIN = {
    "00:03:93": "Apple", "00:17:F2": "Apple", "00:1E:C2": "Apple",
    "00:25:00": "Apple", "3C:15:C2": "Apple", "AC:DE:48": "Apple",
    "00:15:5D": "Microsoft", "00:50:F2": "Microsoft", "28:18:78": "Microsoft",
    "00:0C:29": "VMware", "00:50:56": "VMware", "08:00:27": "Oracle/VBox",
    "00:1A:11": "Google", "3C:5A:B4": "Google", "54:60:09": "Google",
    "00:17:C4": "Broadcom", "00:10:18": "Broadcom",
    "00:1B:21": "Intel", "00:13:02": "Intel", "A4:34:D9": "Intel",
    "00:1E:64": "Intel", "B4:6B:FC": "Intel",
    "00:09:2D": "HTC", "00:23:76": "HTC",
    "00:07:AB": "Samsung", "00:16:32": "Samsung", "00:1A:8A": "Samsung",
    "00:21:19": "Samsung", "EC:1F:72": "Samsung",
    "00:04:0E": "Linksys", "00:0C:41": "Linksys",
    "00:12:17": "Cisco", "00:14:69": "Cisco", "00:1B:0D": "Cisco",
    "00:14:6C": "Netgear", "00:1B:2F": "Netgear", "00:1E:2A": "Netgear",
    "00:1C:DF": "Belkin", "00:17:3F": "Belkin",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "2C:F0:5D": "Xiaomi", "64:09:80": "Xiaomi",
    "00:1A:79": "Huawei", "00:E0:FC": "Huawei",
    "00:26:5A": "D-Link", "00:17:9A": "D-Link",
    "00:1D:0F": "TP-Link", "50:C7:BF": "TP-Link",
    "00:24:01": "Sony", "00:1E:75": "LG", "00:19:47": "Motorola",
    "94:65:2D": "OnePlus", "F8:E4:3B": "Asus", "00:24:D7": "Realtek",
}


def _oui_lookup(mac):
    """Return vendor name for a MAC address."""
    prefix = mac.upper()[:8]
    vendor = OUI_BUILTIN.get(prefix)
    if vendor:
        return vendor
    oui_path = "/usr/share/ieee-data/oui.txt"
    if os.path.isfile(oui_path):
        try:
            key = prefix.replace(":", "-")
            with open(oui_path, "r", errors="replace") as fh:
                for line in fh:
                    if key in line and "(hex)" in line:
                        parts = line.split("(hex)")
                        if len(parts) > 1:
                            return parts[1].strip()[:20]
        except Exception:
            pass
    return "Unknown"

lock = threading.Lock()
config = {
    "deauth_flood": {"enabled": False, "threshold": 20, "window": 10,
                     "command": "", "webhook_url": "", "action_cooldown": 0},
    "client_connected": {"enabled": False, "interval": 5,
                          "command": "", "webhook_url": "", "action_cooldown": 0},
    "mac_trigger": {"enabled": False, "target_mac": "",
                    "command": "", "webhook_url": "", "action_cooldown": 0},
    "auth_capture": {"enabled": False,
                     "command": "", "webhook_url": "", "action_cooldown": 0},
    "beacon_flood": {"enabled": False, "threshold": 30, "window": 10,
                     "command": "", "webhook_url": "", "action_cooldown": 0},
    "probe_request": {"enabled": False, "target_ssid": "",
                      "command": "", "webhook_url": "", "action_cooldown": 0},
}
alerts = []
known_neighbors = set()
known_loot_files = set()
known_resp_lines = 0
_running = True
_threads = {}
_last_action_time = {}


def _sig_handler(_s, _f):
    global _running
    _running = False

signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)

def _load_config():
    global config
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.isfile(CONFIG_FILE):
        _save_config()
        return
    try:
        with open(CONFIG_FILE, "r") as fh:
            data = json.load(fh)
        with lock:
            for key in TRIGGER_NAMES:
                if key in data:
                    merged = dict(config[key])
                    merged.update(data[key])
                    config[key] = merged
    except Exception:
        pass

def _save_config():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with lock:
        data = {k: dict(v) for k, v in config.items()}
    with open(CONFIG_FILE, "w") as fh:
        json.dump(data, fh, indent=2)

def _append_alert(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    with lock:
        alerts.append(line)
        if len(alerts) > 200:
            alerts.pop(0)
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(ALERT_LOG_FILE, "a") as fh:
            fh.write(line + "\n")
    except Exception:
        pass

def _fire_trigger(name, msg):
    with lock:
        cfg = dict(config.get(name, {}))
        cooldown = cfg.get("action_cooldown", 0)
        now = time.time()
        last = _last_action_time.get(name, 0)
        if cooldown > 0 and (now - last) < cooldown:
            return
        if cooldown > 0:
            _last_action_time[name] = now
    _append_alert(msg)
    cmd = cfg.get("command", "").strip()
    webhook = cfg.get("webhook_url", "").strip()
    if cmd:
        try:
            subprocess.Popen(cmd, shell=True,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        except Exception:
            pass
    if webhook:
        _fire_webhook(webhook, name, msg)

def _fire_webhook(url, name, msg):
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    label = name
    try:
        idx = TRIGGER_NAMES.index(name)
        label = TRIGGER_LABELS[idx]
    except ValueError:
        pass
    is_discord = "discord.com/api/webhooks/" in url or "discordapp.com/api/webhooks/" in url
    if is_discord:
        payload = {
            "content": "",
            "embeds": [{
                "title": f"RaspyJack: {label}",
                "description": msg,
                "color": 15158332,
                "timestamp": ts,
            }],
        }
    else:
        payload = {
            "trigger": name,
            "label": label,
            "message": msg,
            "timestamp": ts,
            "source": "RaspyJack",
        }
    try:
        data = json.dumps(payload).encode()
        req = Request(url, data=data,
                      headers={"Content-Type": "application/json"})
        urlopen(req, timeout=10)
    except Exception:
        pass

def _run_cmd(args, timeout=5):
    subprocess.run(args, capture_output=True, timeout=timeout)


def _find_monitor_iface():
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if name.endswith("mon") and os.path.isdir(f"/sys/class/net/{name}/wireless"):
                return name
    except Exception:
        pass
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if not name.startswith("wlan"):
                continue
            if not os.path.isdir(f"/sys/class/net/{name}/wireless"):
                continue
            if "mmc" in os.path.realpath(f"/sys/class/net/{name}/device"):
                continue
            _run_cmd(["sudo", "ip", "link", "set", name, "down"])
            _run_cmd(["sudo", "iw", name, "set", "type", "monitor"])
            _run_cmd(["sudo", "ip", "link", "set", name, "up"])
            return name
    except Exception:
        pass
    return None

def _deauth_flood_worker():
    iface = _find_monitor_iface()
    if not iface:
        _append_alert("DEAUTH: No monitor iface found")
        return
    while _running:
        with lock:
            if not config["deauth_flood"]["enabled"]:
                break
            threshold = config["deauth_flood"].get("threshold", 20)
            window = config["deauth_flood"].get("window", 10)
        try:
            proc = subprocess.run(
                ["sudo", "tcpdump", "-i", iface, "-e", "-c", "100", "-l",
                 "type mgt subtype deauth or type mgt subtype disassoc"],
                capture_output=True, text=True, timeout=window + 5)
            output = proc.stderr + proc.stdout
        except subprocess.TimeoutExpired:
            output = ""
        except Exception:
            time.sleep(2); continue

        deauth_count = 0
        src_macs, dst_macs = set(), set()
        for line in output.splitlines():
            low = line.lower()
            if "deauth" in low or "disassoc" in low:
                deauth_count += 1
                macs = re.findall(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", low)
                if len(macs) >= 1:
                    src_macs.add(macs[0].upper())
                if len(macs) >= 2:
                    dst_macs.add(macs[1].upper())
        if deauth_count > threshold:
            _fire_trigger("deauth_flood",
                f"DEAUTH FLOOD: {deauth_count} frames/{window}s "
                f"src={','.join(list(src_macs)[:3]) or '?'} "
                f"dst={','.join(list(dst_macs)[:3]) or '?'}")
        time.sleep(1)

def _client_connected_worker():
    global known_neighbors
    initial = True
    while _running:
        with lock:
            if not config["client_connected"]["enabled"]:
                break
            interval = config["client_connected"].get("interval", 5)
        try:
            result = subprocess.run(["ip", "neigh", "show"],
                                    capture_output=True, text=True, timeout=5)
        except Exception:
            time.sleep(interval); continue

        current = {}
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) < 5 or parts[-1].upper() in ("FAILED", "INCOMPLETE"):
                continue
            m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
            if m:
                current[m.group(1).upper()] = parts[0]

        with lock:
            prev = set(known_neighbors)
        if not initial:
            for mac in set(current) - prev:
                _fire_trigger("client_connected",
                    f"NEW CLIENT: {mac} vendor={_oui_lookup(mac)} "
                    f"ip={current.get(mac, '?')}")
        with lock:
            known_neighbors = set(current)
        initial = False
        time.sleep(interval)

def _mac_trigger_worker():
    last_seen = False
    while _running:
        with lock:
            if not config["mac_trigger"]["enabled"]:
                break
            target = config["mac_trigger"].get("target_mac", "").upper().strip()
        if not target:
            time.sleep(5); continue
        try:
            result = subprocess.run(["ip", "neigh", "show"],
                                    capture_output=True, text=True, timeout=5)
        except Exception:
            time.sleep(10); continue

        found = target in result.stdout.upper()
        if found and not last_seen:
            ip = "?"
            for line in result.stdout.splitlines():
                if target in line.upper():
                    ip = line.split()[0] if line.split() else "?"
                    break
            _fire_trigger("mac_trigger", f"MAC DETECTED: {target} ip={ip}")
        last_seen = found
        time.sleep(10)

def _count_dir_lines(dirpath):
    """Count total lines across all files in a directory."""
    total = 0
    try:
        for fn in os.listdir(dirpath):
            fp = os.path.join(dirpath, fn)
            if os.path.isfile(fp):
                with open(fp, "r", errors="replace") as fh:
                    total += len(fh.readlines())
    except Exception:
        pass
    return total

def _auth_capture_worker():
    global known_loot_files, known_resp_lines
    cap_exts = (".cap", ".pcap", ".hccapx", ".22000", ".hc22000")
    with lock:
        if os.path.isdir(LOOT_DIR):
            known_loot_files = set(os.listdir(LOOT_DIR))
        if os.path.isdir(RESPONDER_LOG_DIR):
            known_resp_lines = _count_dir_lines(RESPONDER_LOG_DIR)
    while _running:
        with lock:
            if not config["auth_capture"]["enabled"]:
                break
        if os.path.isdir(LOOT_DIR):
            cur = set(os.listdir(LOOT_DIR))
            with lock:
                new = cur - known_loot_files
            for f in new:
                if any(f.endswith(e) for e in cap_exts):
                    _fire_trigger("auth_capture", f"HANDSHAKE CAPTURED: {f}")
            with lock:
                known_loot_files = cur
        if os.path.isdir(RESPONDER_LOG_DIR):
            total = _count_dir_lines(RESPONDER_LOG_DIR)
            with lock:
                prev = known_resp_lines
            if total > prev:
                _fire_trigger("auth_capture",
                    f"AUTH CAPTURE: {total - prev} new cred line(s)")
            with lock:
                known_resp_lines = total
        time.sleep(5)

def _beacon_flood_worker():
    if not SCAPY_OK:
        _append_alert("BEACON FLOOD: Requires scapy")
        return
    iface = _find_monitor_iface()
    if not iface:
        _append_alert("BEACON FLOOD: No monitor iface found")
        return
    while _running:
        with lock:
            if not config["beacon_flood"]["enabled"]:
                break
            threshold = config["beacon_flood"].get("threshold", 30)
            window = config["beacon_flood"].get("window", 10)
        seen = set()
        def _pkt_cb(pkt):
            try:
                if Dot11Elt in pkt:
                    elt = pkt[Dot11Elt]
                    if elt.ID == 0:
                        ssid = elt.info.decode("utf-8", errors="replace").strip()
                        if ssid:
                            seen.add(ssid)
            except Exception:
                pass
        try:
            scapy_sniff(iface=iface, prn=_pkt_cb, store=0, timeout=window)
        except Exception:
            time.sleep(2)
            continue
        if len(seen) > threshold:
            _fire_trigger("beacon_flood",
                f"BEACON FLOOD: {len(seen)} unique SSIDs in {window}s")
        time.sleep(1)

def _probe_request_worker():
    if not SCAPY_OK:
        _append_alert("PROBE REQ: Requires scapy")
        return
    iface = _find_monitor_iface()
    if not iface:
        _append_alert("PROBE REQ: No monitor iface found")
        return
    while _running:
        with lock:
            if not config["probe_request"]["enabled"]:
                break
            target = config["probe_request"].get("target_ssid", "").strip()
        probes = {}
        target_hit = False
        target_clients = set()
        def _pkt_cb(pkt):
            nonlocal target_hit
            try:
                if not pkt.haslayer(Dot11ProbeReq):
                    return
                elt = pkt[Dot11Elt]
                ssid = ""
                if elt and elt.ID == 0:
                    ssid = elt.info.decode("utf-8", errors="replace").strip()
                if not ssid:
                    return
                client = pkt[Dot11].addr2.upper()
                if target:
                    if ssid == target:
                        target_hit = True
                        target_clients.add(client)
                else:
                    if ssid not in probes:
                        probes[ssid] = set()
                    probes[ssid].add(client)
            except Exception:
                pass
        try:
            scapy_sniff(iface=iface, prn=_pkt_cb, store=0, timeout=5,
                        filter="type mgt subtype probe-req")
        except Exception:
            time.sleep(2)
            continue
        if target and target_hit:
            macs = ",".join(list(target_clients)[:3])
            _fire_trigger("probe_request",
                f"PROBE TARGET: {target} from {macs}")
        elif not target and probes:
            total = sum(len(c) for c in probes.values())
            top = sorted(probes.items(), key=lambda x: len(x[1]), reverse=True)[:3]
            summary = " ".join(f"{s}({len(c)})" for s, c in top)
            _fire_trigger("probe_request",
                f"PROBES: {total} reqs for {len(probes)} SSIDs {summary}")

_WORKERS = {
    "deauth_flood": _deauth_flood_worker,
    "client_connected": _client_connected_worker,
    "mac_trigger": _mac_trigger_worker,
    "auth_capture": _auth_capture_worker,
    "beacon_flood": _beacon_flood_worker,
    "probe_request": _probe_request_worker,
}

def _start_trigger(name):
    with lock:
        config[name]["enabled"] = True
    _save_config()
    if name in _threads and _threads[name].is_alive():
        return
    worker = _WORKERS.get(name)
    if worker:
        t = threading.Thread(target=worker, daemon=True, name=f"trig-{name}")
        t.start()
        _threads[name] = t
        _append_alert(f"TRIGGER ON: {name}")

def _stop_trigger(name):
    with lock:
        config[name]["enabled"] = False
    _save_config()
    _append_alert(f"TRIGGER OFF: {name}")

def _is_active(name):
    with lock:
        enabled = config[name]["enabled"]
    return enabled and name in _threads and _threads[name].is_alive()

def _get_cfg_keys(name):
    with lock:
        cfg = dict(config.get(name, {}))
    return [k for k in cfg if k != "enabled"]

def _prompt_bool(prompt, default=False):
    d = "Y/n" if default else "y/N"
    try:
        ans = request_input(f"{prompt} [{d}]: ").strip().lower()
    except EOFError:
        ans = ""
    if not ans:
        return default
    return ans.startswith("y")


def _configure_trigger(name):
    """Interactively edit a trigger's config values."""
    idx = TRIGGER_NAMES.index(name)
    label = TRIGGER_LABELS[idx]
    keys = _get_cfg_keys(name)
    print(f"\nConfiguring {label}:", flush=True)
    with lock:
        cfg = dict(config[name])
    for key in keys:
        cur = cfg.get(key, "")
        try:
            raw = request_input(f"  {key} [{cur}]: ").strip()
        except EOFError:
            raw = ""
        if not raw:
            continue
        if isinstance(cur, bool):
            val = raw.lower().startswith("y")
        elif isinstance(cur, (int, float)):
            try:
                val = type(cur)(raw)
            except ValueError:
                print(f"  Invalid number, keeping {cur}", flush=True)
                continue
        else:
            val = raw
        with lock:
            config[name][key] = val
    _save_config()


def _select_triggers_interactive():
    print("Available triggers:", flush=True)
    for i, name in enumerate(TRIGGER_NAMES):
        with lock:
            enabled = config[name]["enabled"]
        state = "ON" if enabled else "off"
        print(f"  [{i}] {TRIGGER_LABELS[i]:<14} ({state})", flush=True)
    try:
        raw = request_input(
            "Enter trigger numbers to enable (comma-separated), "
            "'all', or Enter to keep current: "
        ).strip()
    except EOFError:
        raw = ""

    if raw.lower() == "all":
        chosen = list(TRIGGER_NAMES)
    elif raw:
        chosen = []
        for tok in raw.split(","):
            tok = tok.strip()
            if tok.isdigit() and 0 <= int(tok) < len(TRIGGER_NAMES):
                chosen.append(TRIGGER_NAMES[int(tok)])
    else:
        with lock:
            chosen = [n for n in TRIGGER_NAMES if config[n]["enabled"]]

    for name in chosen:
        label = TRIGGER_LABELS[TRIGGER_NAMES.index(name)]
        if _prompt_bool(f"Configure {label}?", default=False):
            _configure_trigger(name)
    return chosen


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _usage():
    print(f"Usage: {os.path.basename(__file__)} [trigger1,trigger2,...|all]", flush=True)
    print(f"  Available: {', '.join(TRIGGER_NAMES)}", flush=True)
    print("  Omit to interactively select and configure triggers.", flush=True)


def main():
    global _running

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0

    _load_config()

    if os.path.isfile(ALERT_LOG_FILE):
        try:
            with open(ALERT_LOG_FILE, "r") as fh:
                with lock:
                    for line in fh.readlines()[-200:]:
                        if line.strip():
                            alerts.append(line.strip())
        except Exception:
            pass

    if args:
        arg = args[0]
        if arg == "all":
            chosen = list(TRIGGER_NAMES)
        else:
            chosen = [t.strip() for t in arg.split(",") if t.strip() in TRIGGER_NAMES]
            if not chosen:
                print(f"No valid trigger names in '{arg}'.", flush=True)
                _usage()
                return 1
    else:
        chosen = _select_triggers_interactive()

    if not chosen:
        print("No triggers enabled. Nothing to do.", flush=True)
        return 1

    for name in chosen:
        _start_trigger(name)

    print(f"\nMonitoring with: {', '.join(chosen)}", flush=True)
    print("Press Ctrl-C to stop.", flush=True)

    start_time = time.time()
    with lock:
        last_alert_count = len(alerts)
    try:
        while _running:
            time.sleep(5.0)
            with lock:
                new_alerts = alerts[last_alert_count:]
                last_alert_count = len(alerts)
            for line in new_alerts:
                print(line, flush=True)
            elapsed = time.time() - start_time
            active_now = [n for n in chosen if _is_active(n)]
            print(f"[{elapsed:6.1f}s] active={len(active_now)}/{len(chosen)} "
                  f"total_alerts={last_alert_count}", flush=True)
    except KeyboardInterrupt:
        print("\nStopping event triggers...", flush=True)

    _running = False
    for name in chosen:
        _stop_trigger(name)
    time.sleep(0.5)

    with lock:
        total = len(alerts)
        recent = alerts[-20:]
    print(f"\nFinal summary: {total} alert(s) logged.", flush=True)
    if recent:
        print("Most recent alerts:", flush=True)
        for line in recent:
            print(f"  {line}", flush=True)
    print(f"Full log: {ALERT_LOG_FILE}", flush=True)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
