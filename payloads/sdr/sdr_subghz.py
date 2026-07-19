#!/usr/bin/env python3
# @name: Sub-GHz Analyzer
# @desc: Flipper Zero-style ISM band analyzer for 433/868 MHz.
# @category: sdr
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- Sub-GHz Analyzer
=======================================
Author: 7h30th3r0n3

Flipper Zero-style ISM band analyzer for 433/868 MHz.
Decodes 200+ protocols: remotes (CAME, NICE, etc.), weather stations,
doorbells, car keys, home automation sensors, tire pressure monitors.

Uses rtl_433 for protocol decoding + raw signal capture.

Controls:
  python3 sdr_subghz.py [band] [duration_seconds] [filter]
    band              : index into the band list below, or a raw frequency
                         in Hz. If omitted, you will be prompted to choose.
    duration_seconds  : optional; stop capture after this many seconds.
                         If omitted, captures until Ctrl-C.
    filter            : optional index into the protocol filter list
                         below (default: 0 = ALL protocols).
  Decoded signals are printed as they arrive. A JSON log is written to
  the loot directory when capture stops.

Requires: apt install rtl-433
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
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), "loot", "SDR", "subghz")
BANDS = [
    {"name": "433 MHz", "freq": 433920000, "desc": "EU ISM / Remotes"},
    {"name": "315 MHz", "freq": 315000000, "desc": "US Remotes / TPMS"},
    {"name": "868 MHz", "freq": 868000000, "desc": "EU ISM / LoRa"},
    {"name": "345 MHz", "freq": 345000000, "desc": "Honeywell Security"},
    {"name": "915 MHz", "freq": 915000000, "desc": "US ISM"},
]

# Protocol filter presets (rtl_433 -R numbers)
PROTO_FILTERS = [
    {"name": "ALL protocols", "args": []},
    {"name": "Weather only", "args": ["-R", "2", "-R", "3", "-R", "8", "-R", "10", "-R", "11", "-R", "12", "-R", "16", "-R", "18", "-R", "19", "-R", "20", "-R", "31", "-R", "32", "-R", "34", "-R", "40", "-R", "41", "-R", "42", "-R", "51", "-R", "56", "-R", "71", "-R", "78"]},
    {"name": "Remotes/Gates", "args": ["-R", "1", "-R", "4", "-R", "15", "-R", "17", "-R", "22", "-R", "30", "-R", "67", "-R", "169"]},
    {"name": "Security/Alarm", "args": ["-R", "23", "-R", "29", "-R", "58", "-R", "63", "-R", "86", "-R", "102", "-R", "162", "-R", "266"]},
    {"name": "TPMS (tires)", "args": ["-R", "59", "-R", "60", "-R", "82", "-R", "88", "-R", "104", "-R", "109", "-R", "110", "-R", "123", "-R", "140", "-R", "180", "-R", "275"]},
    {"name": "Car keys/Fobs", "args": ["-R", "30", "-R", "67", "-R", "101", "-R", "189"]},
]

# Protocol categories
PROTO_CATEGORIES = {
    "remote": {"icon": "R", "keywords": ["remote", "came", "nice", "gate", "garage", "button", "keyfob"]},
    "weather": {"icon": "W", "keywords": ["weather", "temp", "humid", "rain", "wind", "baro", "thermo"]},
    "sensor": {"icon": "S", "keywords": ["sensor", "motion", "door", "window", "alarm", "smoke", "pir"]},
    "tpms": {"icon": "T", "keywords": ["tpms", "tire", "pressure"]},
    "car": {"icon": "C", "keywords": ["car", "auto", "key", "fob", "vehicle"]},
    "other": {"icon": "?", "keywords": []},
}

_running = True
_capturing = False
_rtl_proc = None
_signals = []
_signal_lock = threading.Lock()
_proto_counts = defaultdict(int)


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _categorize(model, protocol_name):
    text = (model + " " + protocol_name).lower()
    for cat, info in PROTO_CATEGORIES.items():
        if cat == "other":
            continue
        for kw in info["keywords"]:
            if kw in text:
                return cat
    return "other"


def _format_signal(sig):
    model = sig.get("model", "Unknown")
    # Show ALL fields from rtl_433, skip internal/meta keys
    skip = {"model", "time", "mic", "mod", "freq", "freq1", "freq2",
            "rssi", "snr", "noise", "protocol", "_time_local", "_category",
            "rows", "num_rows", "count"}
    parts = []
    for key, val in sig.items():
        if key in skip or key.startswith("_"):
            continue
        if val is None or val == "":
            continue
        # Format key nicely
        k = key.replace("_", " ").replace("C", "°C") if key == "temperature_C" else key.replace("_", " ")
        if isinstance(val, float):
            parts.append(f"{k}:{val:.1f}")
        elif isinstance(val, list):
            if key == "codes" and val:
                parts.append(f"code:{val[-1]}")
            continue
        elif isinstance(val, dict):
            continue
        else:
            parts.append(f"{k}:{val}")
    return model, " ".join(parts)


# ---------------------------------------------------------------------------
# rtl_433 capture thread
# ---------------------------------------------------------------------------
def _capture_thread(freq, filt_idx):
    global _rtl_proc
    os.makedirs(LOOT_DIR, exist_ok=True)

    filt = PROTO_FILTERS[filt_idx]
    cmd = [
        "rtl_433", "-f", str(freq), "-g", "49.6",
        "-F", "json", "-F", "log",
        "-M", "time:unix", "-M", "protocol", "-M", "level",
    ] + filt["args"]

    try:
        _rtl_proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )

        _last_sig = {}  # dedup: model+id+channel → last data hash
        for line in _rtl_proc.stdout:
            if not _capturing:
                break
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                # Dedup: skip if same model+id+channel with same data within 2s
                model = data.get("model", "")
                sig_key = f"{model}_{data.get('id','')}_{data.get('channel','')}"
                # Build a hash of the interesting data (skip time/rssi)
                sig_vals = {k: v for k, v in data.items() if k not in ("time", "rssi", "snr", "noise", "mic")}
                sig_hash = str(sig_vals)
                now = time.time()
                if sig_key in _last_sig:
                    last_hash, last_time = _last_sig[sig_key]
                    if sig_hash == last_hash and (now - last_time) < 2.0:
                        continue
                _last_sig[sig_key] = (sig_hash, now)

                data["_time_local"] = datetime.now().strftime("%H:%M:%S")
                data["_category"] = _categorize(
                    model, data.get("protocol", "")
                )
                with _signal_lock:
                    _signals.append(data)
                    if len(_signals) > 500:
                        _signals.pop(0)
                    _proto_counts[data.get("model", "Unknown")] += 1

                cat_info = PROTO_CATEGORIES.get(data["_category"], PROTO_CATEGORIES["other"])
                model_name, details = _format_signal(data)
                print(
                    f"[{data['_time_local']}] [{cat_info['icon']}] {model_name}: {details}",
                    flush=True,
                )
            except json.JSONDecodeError:
                pass

        _rtl_proc.terminate()
        try:
            _rtl_proc.wait(timeout=3)
        except Exception:
            _rtl_proc.kill()
    except Exception as exc:
        print(f"Capture error: {exc}", flush=True)
    _rtl_proc = None


def _start_capture(freq, filt_idx):
    global _capturing
    _stop_capture()
    _capturing = True
    threading.Thread(target=_capture_thread, args=(freq, filt_idx), daemon=True).start()


def _stop_capture():
    global _capturing, _rtl_proc
    _capturing = False
    if _rtl_proc:
        try:
            _rtl_proc.terminate()
            _rtl_proc.wait(timeout=2)
        except Exception:
            try:
                _rtl_proc.kill()
            except Exception:
                pass
        _rtl_proc = None
    subprocess.run(["pkill", "-9", "rtl_433"], capture_output=True)


def _export_log():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"capture_log_{ts}.json")
    with _signal_lock:
        data = list(_signals)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path, len(data)


# ---------------------------------------------------------------------------
# Selection helpers
# ---------------------------------------------------------------------------
def _select_band():
    print("Select a band:", flush=True)
    for i, b in enumerate(BANDS):
        print(f"  {i}) {b['name']} ({b['freq']} Hz) - {b['desc']}", flush=True)
    while True:
        try:
            choice = request_input("Band number: ").strip()
        except EOFError:
            return None
        if choice.isdigit() and 0 <= int(choice) < len(BANDS):
            return BANDS[int(choice)]["freq"]
        print("Invalid choice, try again (Ctrl-C to cancel).", flush=True)


def _resolve_band(arg):
    if not arg.isdigit():
        return None
    value = int(arg)
    if value < len(BANDS):
        return BANDS[value]["freq"]
    return value


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    r = subprocess.run(["which", "rtl_433"], capture_output=True)
    if r.returncode != 0:
        print("rtl_433 not found! Install with: apt install rtl-433", flush=True)
        return 1

    if len(sys.argv) > 1:
        freq = _resolve_band(sys.argv[1])
        if freq is None:
            print("Usage: sdr_subghz.py [band_index_or_hz] [duration_seconds] [filter_index]", flush=True)
            print("Invalid band argument.", flush=True)
            return 1
    else:
        freq = _select_band()
        if freq is None:
            print("No band selected, exiting.", flush=True)
            return 1

    duration = None
    if len(sys.argv) > 2:
        try:
            duration = float(sys.argv[2])
        except ValueError:
            print("Duration must be a number of seconds.", flush=True)
            return 1

    filt_idx = 0
    if len(sys.argv) > 3:
        if not sys.argv[3].isdigit() or int(sys.argv[3]) >= len(PROTO_FILTERS):
            print("Available filters:", flush=True)
            for i, f in enumerate(PROTO_FILTERS):
                print(f"  {i}) {f['name']}", flush=True)
            print("Invalid filter index.", flush=True)
            return 1
        filt_idx = int(sys.argv[3])

    print(f"Capturing sub-GHz signals on {freq} Hz using filter '{PROTO_FILTERS[filt_idx]['name']}'...", flush=True)
    if duration:
        print(f"Will stop automatically after {duration:.0f}s. Ctrl-C to stop earlier.", flush=True)
    else:
        print("Press Ctrl-C to stop.", flush=True)

    start_time = time.time()
    _start_capture(freq, filt_idx)

    try:
        last_stats = time.time()
        while _running:
            now = time.time()
            if duration is not None and (now - start_time) >= duration:
                break
            if now - last_stats >= 10:
                with _signal_lock:
                    total = len(_signals)
                print(f"-- status: {total} signals, uptime {now - start_time:.0f}s --", flush=True)
                last_stats = now
            time.sleep(0.2)
    finally:
        _stop_capture()
        with _signal_lock:
            has_signals = len(_signals) > 0
            total = len(_signals)
            counts = dict(_proto_counts)
        if has_signals:
            path, count = _export_log()
            print(f"Exported {count} signals to {path}", flush=True)
            print("Top protocols:", flush=True)
            for model, cnt in sorted(counts.items(), key=lambda x: -x[1])[:6]:
                print(f"  {model}: {cnt}", flush=True)
        else:
            print("No signals captured.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
