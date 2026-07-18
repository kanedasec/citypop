#!/usr/bin/env python3
# @name: SDR Capture & Replay
# @desc: Flipper Zero-style capture and replay for ISM bands (315/433/868/915 MHz).
# @category: sdr
# @danger: false
# @active: true
"""
RaspyJack Payload -- SDR Capture & Replay
==========================================
Author: 7h30th3r0n3

Flipper Zero-style capture and replay for ISM bands (315/433/868/915 MHz).
Record raw IQ signals, browse a capture library, and replay via rpitx.

Controls:
  python3 sdr_replay.py <mode> [args...]

  Modes:
    capture <band_name_or_freq> [duration_sec] [gain]
        Record raw IQ to the loot directory. Prints a periodic signal
        strength status line. Stops after duration_sec, or on Ctrl-C.
    library
        List saved captures (frequency, duration, size, timestamp).
    replay [index_or_path]
        Transmit a saved capture via rpitx. If no capture is given you
        will be prompted with a numbered list. Ctrl-C stops the
        transmission early.
    delete <index_or_path>
        Delete a saved capture after confirmation.

Requires: apt install rtl-sdr
Optional: rpitx (for TX replay)
"""

from payloads._web_input import request_input
import os
import sys
import time
import signal
import subprocess
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads.sdr._sdr_core import SDRDevice, detect_sdr

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = "/root/Raspyjack/loot/SDR/replay"
SAMPLE_RATE = 2_048_000
SIGNAL_THRESHOLD_DB = -30.0
SUBCOMMANDS = ["capture", "library", "replay", "delete"]

BANDS = [
    {"name": "300 MHz", "freq": 300_000_000, "desc": "Gate/Alarm"},
    {"name": "315 MHz", "freq": 315_000_000, "desc": "US Remotes"},
    {"name": "390 MHz", "freq": 390_000_000, "desc": "Car Keys"},
    {"name": "418 MHz", "freq": 418_000_000, "desc": "EU Remote"},
    {"name": "433 MHz", "freq": 433_920_000, "desc": "EU ISM"},
    {"name": "434 MHz", "freq": 434_000_000, "desc": "EU Sensors"},
    {"name": "868 MHz", "freq": 868_000_000, "desc": "EU LoRa"},
    {"name": "915 MHz", "freq": 915_000_000, "desc": "US ISM"},
]

GAIN_STEPS = [0, 10, 20, 30, 40, 49]

_running = True


def _sig_handler(_s, _f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


# ---------------------------------------------------------------------------
# rpitx availability
# ---------------------------------------------------------------------------
def _rpitx_available():
    try:
        r = subprocess.run(["which", "rpitx"], capture_output=True, timeout=3)
        return r.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Capture metadata helpers
# ---------------------------------------------------------------------------
def _make_capture_path(freq_hz):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    freq_mhz = freq_hz / 1e6
    filename = f"replay_{freq_mhz:.3f}MHz_{ts}.iq"
    return os.path.join(LOOT_DIR, filename)


def _write_metadata(iq_path, freq_hz, sample_rate, gain, duration):
    meta = {
        "freq_hz": freq_hz,
        "freq_mhz": freq_hz / 1e6,
        "sample_rate": sample_rate,
        "gain": gain,
        "duration_s": round(duration, 2),
        "timestamp": datetime.now().isoformat(),
        "filename": os.path.basename(iq_path),
    }
    meta_path = iq_path.replace(".iq", ".json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    return meta_path


def _read_metadata(iq_path):
    meta_path = iq_path.replace(".iq", ".json")
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, "r") as f:
                return json.load(f)
        except Exception:
            pass
    # Fallback: parse filename
    base = os.path.basename(iq_path)
    parts = base.replace(".iq", "").split("_")
    freq_str = ""
    for p in parts:
        if "MHz" in p:
            freq_str = p.replace("MHz", "")
            break
    freq_mhz = float(freq_str) if freq_str else 433.92
    size = os.path.getsize(iq_path)
    duration = size / (SAMPLE_RATE * 2)  # uint8 IQ = 2 bytes per sample
    return {
        "freq_hz": int(freq_mhz * 1e6),
        "freq_mhz": freq_mhz,
        "sample_rate": SAMPLE_RATE,
        "gain": 30,
        "duration_s": round(duration, 2),
        "timestamp": "",
        "filename": base,
    }


def _list_captures():
    if not os.path.isdir(LOOT_DIR):
        return []
    entries = []
    for f in sorted(os.listdir(LOOT_DIR), reverse=True):
        if f.endswith(".iq"):
            path = os.path.join(LOOT_DIR, f)
            meta = _read_metadata(path)
            entries.append({"path": path, "meta": meta})
    return entries


def _delete_capture(path):
    try:
        os.remove(path)
    except OSError:
        pass
    meta_path = path.replace(".iq", ".json")
    try:
        os.remove(meta_path)
    except OSError:
        pass


def _format_duration(seconds):
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    m = int(seconds) // 60
    s = int(seconds) % 60
    return f"{m}m{s:02d}s"


def _format_size(path):
    try:
        sz = os.path.getsize(path)
    except OSError:
        return "?"
    if sz < 1024:
        return f"{sz}B"
    if sz < 1024 * 1024:
        return f"{sz / 1024:.1f}K"
    return f"{sz / (1024 * 1024):.1f}M"


# ---------------------------------------------------------------------------
# TX via rpitx
# ---------------------------------------------------------------------------
_tx_proc = None


def _start_tx(iq_path, freq_hz, sample_rate):
    global _tx_proc
    _stop_tx()
    freq_khz = freq_hz / 1000.0
    cmd = [
        "rpitx", "-m", "IQ",
        "-i", iq_path,
        "-f", str(freq_khz),
        "-s", str(sample_rate),
    ]
    try:
        _tx_proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
    except FileNotFoundError:
        _tx_proc = None
        return False
    return True


def _stop_tx():
    global _tx_proc
    if _tx_proc is not None:
        try:
            os.killpg(os.getpgid(_tx_proc.pid), signal.SIGKILL)
        except Exception:
            pass
        _tx_proc = None


def _is_tx_running():
    if _tx_proc is None:
        return False
    return _tx_proc.poll() is None


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
        try:
            return int(arg)
        except ValueError:
            return None
    value = int(arg)
    if value < len(BANDS):
        return BANDS[value]["freq"]
    return value


def _select_capture(captures):
    if not captures:
        print("No captures found.", flush=True)
        return None
    print("Select a capture:", flush=True)
    for i, cap in enumerate(captures):
        meta = cap["meta"]
        print(
            f"  {i}) {meta.get('freq_mhz', 0):.3f} MHz  "
            f"{_format_duration(meta.get('duration_s', 0))}  "
            f"{_format_size(cap['path'])}  {os.path.basename(cap['path'])}",
            flush=True,
        )
    while True:
        try:
            choice = request_input("Capture number: ").strip()
        except EOFError:
            return None
        if choice.isdigit() and 0 <= int(choice) < len(captures):
            return captures[int(choice)]
        print("Invalid choice, try again (Ctrl-C to cancel).", flush=True)


def _resolve_capture(arg, captures):
    if arg.isdigit() and 0 <= int(arg) < len(captures):
        return captures[int(arg)]
    for cap in captures:
        if cap["path"] == arg or os.path.basename(cap["path"]) == arg:
            return cap
    return None


# ---------------------------------------------------------------------------
# Mode: capture
# ---------------------------------------------------------------------------
def _run_capture(args):
    if not args:
        freq = _select_band()
        if freq is None:
            print("No band selected, exiting.", flush=True)
            return 1
    else:
        freq = _resolve_band(args[0])
        if freq is None:
            print("Usage: sdr_replay.py capture <band_index_or_hz> [duration_sec] [gain]", flush=True)
            return 1

    duration = None
    if len(args) > 1:
        try:
            duration = float(args[1])
        except ValueError:
            print("Duration must be a number of seconds.", flush=True)
            return 1

    gain = GAIN_STEPS[3]
    if len(args) > 2:
        try:
            gain = int(args[2])
        except ValueError:
            print("Gain must be a number.", flush=True)
            return 1

    print("Detecting SDR hardware...", flush=True)
    found, label, backend = detect_sdr()
    if not found:
        print(f"No SDR found! ({label})", flush=True)
        return 1
    print(f"Found: {label} (backend={backend})", flush=True)

    sdr = SDRDevice()
    sdr.start(freq, SAMPLE_RATE, gain, backend)

    os.makedirs(LOOT_DIR, exist_ok=True)
    rec_path = _make_capture_path(freq)
    sdr.start_recording(rec_path)
    rec_start = time.time()

    print(f"Recording {freq} Hz to {rec_path}", flush=True)
    if duration:
        print(f"Will stop automatically after {duration:.0f}s. Ctrl-C to stop earlier.", flush=True)
    else:
        print("Press Ctrl-C to stop.", flush=True)

    try:
        last_print = 0.0
        while _running:
            now = time.time()
            elapsed = now - rec_start
            if duration is not None and elapsed >= duration:
                break
            if now - last_print >= 1.0:
                db = sdr.get_signal_db()
                tag = "SIGNAL" if db > SIGNAL_THRESHOLD_DB else "listening"
                print(f"[{elapsed:6.1f}s] {tag}  {db:6.1f}dB", flush=True)
                last_print = now
            time.sleep(0.1)
    finally:
        sdr.stop_recording()
        duration_actual = time.time() - rec_start
        meta_path = _write_metadata(rec_path, freq, SAMPLE_RATE, gain, duration_actual)
        sdr.stop()

    print(f"Saved {_format_duration(duration_actual)} to {rec_path}", flush=True)
    print(f"Metadata: {meta_path}", flush=True)
    return 0


# ---------------------------------------------------------------------------
# Mode: library
# ---------------------------------------------------------------------------
def _run_library():
    captures = _list_captures()
    if not captures:
        print("No captures yet. Use 'capture' to record one.", flush=True)
        return 0
    print(f"{len(captures)} capture(s):", flush=True)
    for i, cap in enumerate(captures):
        meta = cap["meta"]
        ts = meta.get("timestamp", "")
        ts_short = ""
        if ts:
            try:
                ts_short = datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                ts_short = ts
        print(
            f"  {i}) {meta.get('freq_mhz', 0):.3f} MHz  "
            f"dur={_format_duration(meta.get('duration_s', 0))}  "
            f"size={_format_size(cap['path'])}  {ts_short}  "
            f"{os.path.basename(cap['path'])}",
            flush=True,
        )
    return 0


# ---------------------------------------------------------------------------
# Mode: replay
# ---------------------------------------------------------------------------
def _run_replay(args):
    captures = _list_captures()
    if args:
        cap = _resolve_capture(args[0], captures)
        if cap is None:
            print(f"Capture not found: {args[0]}", flush=True)
            return 1
    else:
        cap = _select_capture(captures)
        if cap is None:
            return 1

    if not _rpitx_available():
        print("rpitx not found! Install with: apt install rpitx", flush=True)
        return 1

    meta = cap["meta"]
    freq_hz = meta.get("freq_hz", BANDS[0]["freq"])
    sample_rate = meta.get("sample_rate", SAMPLE_RATE)
    duration = meta.get("duration_s", 1)

    print(f"Transmitting {cap['path']} at {freq_hz} Hz ({duration:.1f}s)...", flush=True)
    ok = _start_tx(cap["path"], freq_hz, sample_rate)
    if not ok:
        print("Failed to start rpitx.", flush=True)
        return 1

    tx_start = time.time()
    try:
        while _running:
            elapsed = time.time() - tx_start
            progress = min(1.0, elapsed / max(0.01, duration))
            print(f"[{elapsed:5.1f}s] TX progress: {progress * 100:5.1f}%", flush=True)
            if not _is_tx_running() or progress >= 1.0:
                break
            time.sleep(1.0)
    finally:
        _stop_tx()

    print("Transmission stopped.", flush=True)
    return 0


# ---------------------------------------------------------------------------
# Mode: delete
# ---------------------------------------------------------------------------
def _run_delete(args):
    captures = _list_captures()
    if not args:
        print("Usage: sdr_replay.py delete <index_or_path>", flush=True)
        return 1
    cap = _resolve_capture(args[0], captures)
    if cap is None:
        print(f"Capture not found: {args[0]}", flush=True)
        return 1

    fname = os.path.basename(cap["path"])
    try:
        confirm = request_input(f"Delete {fname}? [y/N] ").strip().lower()
    except EOFError:
        confirm = "n"
    if confirm != "y":
        print("Cancelled.", flush=True)
        return 0

    _delete_capture(cap["path"])
    print(f"Deleted {fname}", flush=True)
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def _usage():
    print("Usage: sdr_replay.py <mode> [args...]", flush=True)
    print(f"  modes: {', '.join(SUBCOMMANDS)}", flush=True)


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in SUBCOMMANDS:
        _usage()
        return 1

    mode = sys.argv[1]
    args = sys.argv[2:]

    if mode == "capture":
        return _run_capture(args)
    elif mode == "library":
        return _run_library()
    elif mode == "replay":
        return _run_replay(args)
    elif mode == "delete":
        return _run_delete(args)

    _usage()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
