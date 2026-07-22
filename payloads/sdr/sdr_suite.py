#!/usr/bin/env python3
# @name: SDR Radio Suite
# @desc: Run terminal-friendly SDR waterfall status, FM playback, band scanning, preset/settings management, or raw IQ recording with supported receivers.
# @category: sdr
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"mode","label":"SDR operation to open","type":"select","choices":[{"value":"waterfall","label":"Waterfall — view live signal power across a frequency range"},{"value":"fm","label":"FM radio — tune and play a broadcast FM frequency"},{"value":"scan","label":"Band scan — search a frequency range for active signals"},{"value":"presets","label":"Presets — manage and use saved frequency presets"},{"value":"settings","label":"Settings — inspect or change SDR device configuration"}],"default":"scan"}]
"""
RaspyJack Payload -- SDR Radio Suite
======================================
Author: 7h30th3r0n3

Full-featured SDR radio suite with waterfall display, FM radio,
frequency scanner, band presets, settings, and IQ recording.

Supports RTL-SDR, HackRF, and any SoapySDR-compatible device.

Controls:
  python3 sdr_suite.py <mode> [args...]

  Modes:
    waterfall <freq_hz|preset_name> [duration_sec] [--record]
        Stream periodic signal-strength/frequency status lines for the
        tuned frequency. --record also writes raw IQ samples to loot.
    fm <freq_hz|station_name> [duration_sec]
        Play FM audio for the given station/frequency.
    scan [preset_name_or_index] [threshold_db]
        Sweep a band preset and print detected signals above threshold.
    presets
        List available band presets.
    settings [key] [value]
        Print current settings, or set one key and save it.

  If a frequency/preset argument is omitted where required, you will be
  prompted with a numbered list to choose from. Ctrl-C stops any running
  mode cleanly.

Requires: apt install rtl-sdr
Optional: python3-soapysdr soapysdr-module-hackrf
"""

from payloads._web_input import request_input
import os
import sys
import time
import signal
import subprocess
import json
from datetime import datetime
import numpy as np

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads.sdr._sdr_core import SDRDevice, detect_sdr, compute_fft, start_fm_audio, stop_fm_audio
from payloads.sdr._waterfall import COLORMAPS
from payloads.sdr._presets import (
    BAND_PRESETS, FM_STATIONS, NOAA_CHANNELS,
    load_settings, save_settings, format_freq, format_freq_short,
)

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), "loot", "SDR", "recordings")
SUBCOMMANDS = ["waterfall", "fm", "scan", "presets", "settings"]
_running = True


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGTERM, _sig)
signal.signal(signal.SIGINT, _sig)


# ═══════════════════════════════════════════════════════════════
# Selection / parsing helpers
# ═══════════════════════════════════════════════════════════════
def _parse_freq(s):
    """Parse a frequency argument: raw Hz integer or a "123.456" MHz string."""
    try:
        if "." in s:
            return int(float(s) * 1_000_000)
        return int(s)
    except ValueError:
        return None


def _select_preset(presets, label="preset"):
    print(f"Select a {label}:", flush=True)
    for i, p in enumerate(presets):
        print(f"  {i}) {p['name']}  ({format_freq(p['freq'])})", flush=True)
    while True:
        try:
            choice = request_input(f"{label.capitalize()} number: ").strip()
        except EOFError:
            return None
        if choice.isdigit() and 0 <= int(choice) < len(presets):
            return presets[int(choice)]
        print("Invalid choice, try again (Ctrl-C to cancel).", flush=True)


def _resolve_band_arg(arg):
    """Resolve a waterfall/scan frequency argument to (freq_hz, preset_or_None)."""
    freq = _parse_freq(arg)
    if freq is not None:
        return freq, None
    match = next((p for p in BAND_PRESETS if p["name"].lower() == arg.lower()), None)
    if match:
        return match["freq"], match
    match = next((p for p in BAND_PRESETS if arg.lower() in p["name"].lower()), None)
    if match:
        return match["freq"], match
    return None, None


def _resolve_fm_arg(arg):
    freq = _parse_freq(arg)
    if freq is not None:
        return freq
    match = next((f for name, f in FM_STATIONS if name.lower() == arg.lower()), None)
    if match:
        return match
    match = next((f for name, f in FM_STATIONS if arg.lower() in name.lower()), None)
    return match


# ═══════════════════════════════════════════════════════════════
# WATERFALL (spectrum monitor)
# ═══════════════════════════════════════════════════════════════
def _run_waterfall(sdr, settings, freq, duration, record):
    bw = settings["sample_rate"]
    fft_size = settings["fft_size"]
    interval = 1.0 / max(1, settings["waterfall_fps"])

    print(f"Tuning to {format_freq(freq)} (sample_rate={bw}, gain={settings['gain']})", flush=True)
    sdr.start(freq, bw, settings["gain"])

    rec_path = None
    if record:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        rec_path = os.path.join(LOOT_DIR, f"iq_{format_freq_short(freq)}_{ts}.raw")
        sdr.start_recording(rec_path)
        print(f"Recording IQ to {rec_path}", flush=True)

    start = time.monotonic()
    last_print = 0.0
    try:
        while _running:
            now = time.monotonic()
            if duration is not None and (now - start) >= duration:
                break
            iq = sdr.get_iq_block(fft_size)
            if now - last_print >= max(interval, 1.0):
                fft_db = compute_fft(iq, fft_size)
                sig_db = 20 * np.log10(np.sqrt(np.mean(np.abs(iq) ** 2)) + 1e-10)
                peak_idx = int(np.argmax(fft_db))
                peak_db = float(fft_db[peak_idx])
                print(
                    f"[{now - start:6.1f}s] freq={format_freq(freq)} "
                    f"signal={sig_db:6.1f}dB peak={peak_db:6.1f}dB",
                    flush=True,
                )
                last_print = now
            time.sleep(interval)
    finally:
        if record:
            sdr.stop_recording()
        sdr.stop()
    print("Waterfall stopped.", flush=True)
    return 0


# ═══════════════════════════════════════════════════════════════
# FM RADIO
# ═══════════════════════════════════════════════════════════════
def _run_fm(settings, freq, duration):
    if freq < 87_500_000 or freq > 108_000_000:
        print("Frequency out of FM broadcast band (87.5-108 MHz).", flush=True)
        return 1

    station = ""
    for name, f in FM_STATIONS:
        if abs(f - freq) < 50_000:
            station = name
            break

    label = f"{freq / 1e6:.1f} MHz" + (f" ({station})" if station else "")
    print(f"Playing FM: {label}", flush=True)
    fm_proc = start_fm_audio(freq, settings.get("audio_device", "default"))

    start = time.monotonic()
    try:
        while _running:
            now = time.monotonic()
            if duration is not None and (now - start) >= duration:
                break
            time.sleep(1.0)
            print(f"[{now - start:6.1f}s] playing {label}", flush=True)
    finally:
        stop_fm_audio(fm_proc)
    print("FM playback stopped.", flush=True)
    return 0


# ═══════════════════════════════════════════════════════════════
# SCANNER
# ═══════════════════════════════════════════════════════════════
def _scan_band(sdr, settings, preset, signals, progress_cb):
    """Scan using rtl_power for fast wideband sweep."""
    start = preset["start"]
    end = preset["end"]
    step = max(preset["step"], 25_000)
    threshold = settings["scanner_threshold"]

    # rtl_power does a single fast sweep across the entire band
    cmd = [
        "rtl_power", "-f", f"{start}:{end}:{step}",
        "-g", "49.6", "-i", "1", "-1", "-F", "csv",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        lines = proc.stdout.strip().splitlines()
        total = max(1, len(lines))
        for i, line in enumerate(lines):
            if not _running:
                break
            try:
                parts = line.split(",")
                if len(parts) >= 7:
                    freq_low = int(float(parts[2].strip()))
                    freq_step = float(parts[4].strip())
                    db_values = [float(x.strip()) for x in parts[6:] if x.strip()]
                    for j, db in enumerate(db_values):
                        f = freq_low + int(j * freq_step)
                        if db > threshold:
                            signals.append({"freq": f, "db": round(db, 1)})
            except Exception:
                pass
            progress_cb((i + 1) / total)
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        # Fallback to slow method if rtl_power not available
        freq = start
        total_steps = max(1, (end - start) // step)
        idx = 0
        sdr.start(start, 2_048_000, settings.get("gain", 30))
        time.sleep(0.3)
        while freq <= end and _running:
            sdr.set_freq(freq)
            time.sleep(0.1)
            sig_db = sdr.get_signal_db()
            if sig_db > threshold:
                signals.append({"freq": freq, "db": sig_db})
            idx += 1
            progress_cb(idx / total_steps)
            freq += step
        sdr.stop()
    progress_cb(1.0)


def _run_scan(sdr, settings, preset, threshold=None):
    if threshold is not None:
        settings = dict(settings)
        settings["scanner_threshold"] = threshold

    print(f"Scanning {preset['name']} ({format_freq(preset['start'])} - {format_freq(preset['end'])})...", flush=True)
    signals = []
    last_pct = [-1]

    def _progress(p):
        pct = int(p * 100)
        if pct != last_pct[0] and pct % 10 == 0:
            print(f"  progress: {pct}%", flush=True)
            last_pct[0] = pct

    _scan_band(sdr, settings, preset, signals, _progress)

    signals.sort(key=lambda s: -s["db"])
    print(f"Found {len(signals)} signal(s) above {settings['scanner_threshold']}dB:", flush=True)
    for s in signals[:30]:
        print(f"  {format_freq(s['freq'])}  {s['db']:.1f} dB", flush=True)
    return 0


# ═══════════════════════════════════════════════════════════════
# PRESETS / SETTINGS
# ═══════════════════════════════════════════════════════════════
def _run_presets():
    print("Band presets:", flush=True)
    for i, p in enumerate(BAND_PRESETS):
        print(f"  {i}) {p['name']:<16} {format_freq(p['freq']):>12}  mode={p['mode']}", flush=True)
    return 0


_SETTINGS_SCHEMA = {
    "gain": (int, 0, 49),
    "fft_size": (int, None, None),
    "colormap": (str, None, None),
    "db_min": (int, -100, -20),
    "db_max": (int, -40, 0),
    "waterfall_fps": (int, 4, 20),
    "scanner_threshold": (int, -80, -10),
    "scanner_dwell": (float, 0.1, 1.0),
}


def _run_settings(settings, args):
    if not args:
        print("Current settings:", flush=True)
        for key, val in settings.items():
            print(f"  {key} = {val}", flush=True)
        return 0

    key = args[0]
    if key not in _SETTINGS_SCHEMA:
        print(f"Unknown setting '{key}'. Known settings:", flush=True)
        for k in _SETTINGS_SCHEMA:
            print(f"  {k}", flush=True)
        return 1

    if len(args) < 2:
        print(f"{key} = {settings.get(key)}", flush=True)
        return 0

    value_str = args[1]
    kind, lo, hi = _SETTINGS_SCHEMA[key]
    if key == "fft_size":
        try:
            val = int(value_str)
        except ValueError:
            val = None
        if val not in (64, 128, 256, 512, 1024):
            print("fft_size must be one of: 64 128 256 512 1024", flush=True)
            return 1
    elif key == "colormap":
        val = value_str
        if val not in COLORMAPS:
            print(f"colormap must be one of: {', '.join(COLORMAPS.keys())}", flush=True)
            return 1
    else:
        try:
            val = kind(value_str)
        except ValueError:
            print(f"{key} must be a {kind.__name__}", flush=True)
            return 1
        if lo is not None and not (lo <= val <= hi):
            print(f"{key} must be between {lo} and {hi}", flush=True)
            return 1

    settings[key] = val
    save_settings(settings)
    print(f"Saved {key} = {val}", flush=True)
    return 0


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
def _usage():
    print("Usage: sdr_suite.py <mode> [args...]", flush=True)
    print(f"  modes: {', '.join(SUBCOMMANDS)}", flush=True)


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in SUBCOMMANDS:
        _usage()
        return 1

    mode = sys.argv[1]
    args = sys.argv[2:]
    settings = load_settings()

    if mode == "presets":
        return _run_presets()

    if mode == "settings":
        return _run_settings(settings, args)

    print("Detecting SDR hardware...", flush=True)
    found, hw_name, backend = detect_sdr()
    if not found:
        print("No SDR found! Connect RTL-SDR/HackRF and try again.", flush=True)
        return 1
    print(f"Found: {hw_name} (backend={backend})", flush=True)

    sdr = SDRDevice()

    try:
        if mode == "waterfall":
            if not args:
                preset = _select_preset(BAND_PRESETS, "band")
                if preset is None:
                    print("No band selected, exiting.", flush=True)
                    return 1
                freq = preset["freq"]
            else:
                freq, preset = _resolve_band_arg(args[0])
                if freq is None:
                    print(f"Unrecognized frequency/preset: {args[0]}", flush=True)
                    return 1
                if preset:
                    settings["sample_rate"] = min(2_048_000, max(250_000, preset["end"] - preset["start"]))

            record = "--record" in args
            duration = None
            for a in args[1:]:
                if a != "--record":
                    try:
                        duration = float(a)
                    except ValueError:
                        pass
            return _run_waterfall(sdr, settings, freq, duration, record)

        elif mode == "fm":
            if not args:
                choice = _select_preset(
                    [{"name": n, "freq": f} for n, f in FM_STATIONS], "station",
                )
                if choice is None:
                    print("No station selected, exiting.", flush=True)
                    return 1
                freq = choice["freq"]
            else:
                freq = _resolve_fm_arg(args[0])
                if freq is None:
                    print(f"Unrecognized frequency/station: {args[0]}", flush=True)
                    return 1

            duration = None
            if len(args) > 1:
                try:
                    duration = float(args[1])
                except ValueError:
                    print("Duration must be a number of seconds.", flush=True)
                    return 1
            return _run_fm(settings, freq, duration)

        elif mode == "scan":
            if not args:
                preset = _select_preset(BAND_PRESETS, "band")
                if preset is None:
                    print("No band selected, exiting.", flush=True)
                    return 1
            else:
                _, preset = _resolve_band_arg(args[0])
                if preset is None and args[0].isdigit() and int(args[0]) < len(BAND_PRESETS):
                    preset = BAND_PRESETS[int(args[0])]
                if preset is None:
                    print(f"Unrecognized band preset: {args[0]}", flush=True)
                    return 1

            threshold = None
            if len(args) > 1:
                try:
                    threshold = float(args[1])
                except ValueError:
                    print("Threshold must be a number in dB.", flush=True)
                    return 1
            return _run_scan(sdr, settings, preset, threshold)

    finally:
        sdr.stop()
        save_settings(settings)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
