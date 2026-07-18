#!/usr/bin/env python3
# @name: POCSAG/FLEX Pager Decoder
# @desc: Passive pager message decoder for POCSAG and FLEX protocols.
# @category: sdr
# @danger: false
# @active: true
"""
RaspyJack Payload -- POCSAG/FLEX Pager Decoder
================================================
Author: 7h30th3r0n3

Passive pager message decoder for POCSAG and FLEX protocols.
Receives pager transmissions on common frequencies and decodes
messages in real-time using rtl_fm + multimon-ng.

Completely legal passive radio reception.

Controls:
  python3 sdr_pocsag.py [frequency] [duration_seconds]
    frequency          : index into the frequency list below, or a raw
                          frequency in Hz (e.g. 466075000). If omitted,
                          you will be prompted to choose one.
    duration_seconds    : optional; stop decoding after this many seconds.
                           If omitted, decodes until Ctrl-C.
  Messages are printed as they are decoded. A JSON log is written to
  the loot directory when decoding stops.

Requires: apt install rtl-sdr multimon-ng
"""

from payloads._web_input import request_input
import os
import sys
import re
import time
import signal
import subprocess
import threading
import json
from datetime import datetime
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

LOOT_DIR = "/root/Raspyjack/loot/SDR/pocsag"
MAX_MESSAGES = 500

FREQUENCIES = [
    {"name": "466.075 FR", "freq": 466075000, "desc": "France POCSAG"},
    {"name": "466.025 FR", "freq": 466025000, "desc": "France"},
    {"name": "466.050 FR", "freq": 466050000, "desc": "France"},
    {"name": "466.175 FR", "freq": 466175000, "desc": "France"},
    {"name": "153.350 FX", "freq": 153350000, "desc": "FLEX"},
    {"name": "157.900 US", "freq": 157900000, "desc": "US FLEX"},
    {"name": "152.480 US", "freq": 152480000, "desc": "US FLEX"},
    {"name": "929.613 US", "freq": 929612500, "desc": "US FLEX"},
]

# POCSAG line pattern: POCSAG512: Address: 1234567  Function: 0  Alpha:   Hello
_RE_POCSAG = re.compile(
    r"(POCSAG\d+):\s*Address:\s*(\d+)\s+Function:\s*(\d+)\s+"
    r"(Alpha|Numeric|Tone\s*Only)\s*:\s*(.*)"
)

# FLEX line pattern: FLEX: 2024-01-15 12:34:56 1200/2/K/A 12.345 [1234567] ALN  Hello
_RE_FLEX = re.compile(
    r"(FLEX):\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+"
    r"[\d/]+/[A-Z]\s+[\d.]+\s+\[(\d+)\]\s+(\w+)\s+(.*)"
)

_running = True
_decoding = False
_rtl_proc = None
_mng_proc = None
_messages = []
_msg_lock = threading.Lock()
_addr_counts = defaultdict(int)
_start_time = None


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _parse_line(line):
    """Parse a single multimon-ng output line into a message dict, or return None."""
    line = line.strip()
    if not line:
        return None

    m = _RE_POCSAG.match(line)
    if m:
        protocol = m.group(1)
        address = m.group(2)
        function = int(m.group(3))
        raw_type = m.group(4).strip()
        content = m.group(5).strip()

        if "Alpha" in raw_type:
            msg_type = "Alpha"
        elif "Numeric" in raw_type:
            msg_type = "Numeric"
        else:
            msg_type = "Tone"

        return {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "protocol": protocol,
            "address": address,
            "function": function,
            "type": msg_type,
            "message": content,
        }

    m = _RE_FLEX.match(line)
    if m:
        protocol = m.group(1)
        address = m.group(2)
        type_code = m.group(3).strip()
        content = m.group(4).strip()

        if type_code == "ALN":
            msg_type = "Alpha"
        elif type_code == "NUM":
            msg_type = "Numeric"
        elif type_code == "TON":
            msg_type = "Tone"
        else:
            msg_type = "Alpha"

        return {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "protocol": protocol,
            "address": address,
            "function": 0,
            "type": msg_type,
            "message": content,
        }

    return None


# ---------------------------------------------------------------------------
# Decoder thread: rtl_fm | multimon-ng
# ---------------------------------------------------------------------------
def _decode_thread(freq):
    global _rtl_proc, _mng_proc

    rtl_cmd = [
        "rtl_fm", "-f", str(freq), "-s", "22050", "-g", "49.6", "-",
    ]
    mng_cmd = [
        "multimon-ng", "-t", "raw",
        "-a", "POCSAG512", "-a", "POCSAG1200", "-a", "POCSAG2400",
        "-a", "FLEX", "-f", "alpha", "-",
    ]

    try:
        _rtl_proc = subprocess.Popen(
            rtl_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        _mng_proc = subprocess.Popen(
            mng_cmd, stdin=_rtl_proc.stdout, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
        )
        # Allow rtl_fm to receive SIGPIPE when multimon-ng exits
        _rtl_proc.stdout.close()

        for line in _mng_proc.stdout:
            if not _decoding:
                break
            parsed = _parse_line(line)
            if parsed is None:
                continue
            with _msg_lock:
                _messages.append(parsed)
                if len(_messages) > MAX_MESSAGES:
                    _messages.pop(0)
                _addr_counts[parsed["address"]] += 1
            print(
                f"[{parsed['timestamp']}] {parsed['protocol']} "
                f"RIC:{parsed['address']} {parsed['type']}: {parsed['message']}",
                flush=True,
            )

    except Exception as exc:
        print(f"Decode error: {exc}", flush=True)
    finally:
        _cleanup_procs()


def _cleanup_procs():
    global _rtl_proc, _mng_proc
    for proc in (_mng_proc, _rtl_proc):
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
    _rtl_proc = None
    _mng_proc = None


def _start_decode(freq):
    global _decoding, _start_time
    _stop_decode()
    _decoding = True
    _start_time = time.time()
    threading.Thread(target=_decode_thread, args=(freq,), daemon=True).start()


def _stop_decode():
    global _decoding
    _decoding = False
    _cleanup_procs()
    subprocess.run(["pkill", "-9", "rtl_fm"], capture_output=True)
    subprocess.run(["pkill", "-9", "multimon-ng"], capture_output=True)


def _export_log():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"pocsag_log_{ts}.json")
    with _msg_lock:
        data = list(_messages)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path, len(data)


# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
def _check_deps():
    """Check for rtl_fm and multimon-ng. Return True if both found."""
    missing = []
    for tool in ("rtl_fm", "multimon-ng"):
        r = subprocess.run(["which", tool], capture_output=True)
        if r.returncode != 0:
            missing.append(tool)
    if not missing:
        return True

    print("Missing required tools:", flush=True)
    for tool in missing:
        print(f"  {tool} not found", flush=True)
    print("Install with:", flush=True)
    print("  apt install rtl-sdr", flush=True)
    print("  apt install multimon-ng", flush=True)
    return False


def _select_frequency():
    """Interactively pick a frequency from FREQUENCIES."""
    print("Select a frequency:", flush=True)
    for i, f in enumerate(FREQUENCIES):
        print(f"  {i}) {f['name']} ({f['freq']} Hz) - {f['desc']}", flush=True)
    while True:
        try:
            choice = request_input("Frequency number: ").strip()
        except EOFError:
            return None
        if not choice:
            continue
        if choice.isdigit() and 0 <= int(choice) < len(FREQUENCIES):
            return FREQUENCIES[int(choice)]["freq"]
        print("Invalid choice, try again (Ctrl-C to cancel).", flush=True)


def _resolve_frequency(arg):
    """Resolve a CLI argument to a frequency in Hz: index into FREQUENCIES or raw Hz."""
    if not arg.isdigit():
        return None
    value = int(arg)
    if value < len(FREQUENCIES):
        return FREQUENCIES[value]["freq"]
    return value


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if not _check_deps():
        return 1

    if len(sys.argv) > 1:
        freq = _resolve_frequency(sys.argv[1])
        if freq is None:
            print(f"Usage: sdr_pocsag.py [frequency_index_or_hz] [duration_seconds]", flush=True)
            print("Invalid frequency argument.", flush=True)
            return 1
    else:
        freq = _select_frequency()
        if freq is None:
            print("No frequency selected, exiting.", flush=True)
            return 1

    duration = None
    if len(sys.argv) > 2:
        try:
            duration = float(sys.argv[2])
        except ValueError:
            print("Duration must be a number of seconds.", flush=True)
            return 1

    print(f"Decoding POCSAG/FLEX on {freq} Hz...", flush=True)
    if duration:
        print(f"Will stop automatically after {duration:.0f}s. Ctrl-C to stop earlier.", flush=True)
    else:
        print("Press Ctrl-C to stop.", flush=True)

    _start_decode(freq)

    try:
        last_stats = time.time()
        while _running:
            now = time.time()
            if duration is not None and _start_time is not None and (now - _start_time) >= duration:
                break
            if now - last_stats >= 10:
                with _msg_lock:
                    total = len(_messages)
                    unique = len(_addr_counts)
                elapsed = now - _start_time if _start_time else 0
                print(
                    f"-- status: {total} messages, {unique} unique RICs, "
                    f"uptime {elapsed:.0f}s --",
                    flush=True,
                )
                last_stats = now
            time.sleep(0.2)
    finally:
        _stop_decode()
        with _msg_lock:
            has_msgs = len(_messages) > 0
        if has_msgs:
            path, count = _export_log()
            print(f"Exported {count} messages to {path}", flush=True)
        else:
            print("No messages captured.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
