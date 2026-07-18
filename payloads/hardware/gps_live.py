#!/usr/bin/env python3
# @name: GPS Live
# @desc: Real-time GPS data display: position, satellites, altitude, speed, fix status, and raw NMEA sentences scrolling.
# @category: hardware
# @danger: false
# @active: true
"""
RaspyJack Payload -- GPS Live
==============================
Real-time GPS data display: position, satellites, altitude, speed,
fix status, and raw NMEA sentences scrolling.

Controls
--------
  Usage: gps_live.py [duration_seconds]

  duration_seconds  Optional time to run, in seconds. Runs until Ctrl-C
                     if omitted.

  Streams a status line to stdout every time a new NMEA fix/position
  update is parsed. Press Ctrl-C to stop; a final position/fix summary
  is printed.
"""

import os
import sys
import time
import signal
import threading
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

NMEA_VISIBLE = 6

_lock = threading.Lock()
_gps  = {}
_nmea = []
_running = True


def _stop(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _stop)
signal.signal(signal.SIGTERM, _stop)


def _parse_gga(parts):
    if len(parts) < 10:
        return
    lat_raw, lat_ns = parts[2], parts[3]
    lon_raw, lon_ns = parts[4], parts[5]
    fix_q = parts[6]
    sats = parts[7]
    alt = parts[9]
    lat = lon = 0.0
    try:
        lat = float(lat_raw[:2]) + float(lat_raw[2:]) / 60.0
        if lat_ns == "S":
            lat = -lat
        lon = float(lon_raw[:3]) + float(lon_raw[3:]) / 60.0
        if lon_ns == "W":
            lon = -lon
    except (ValueError, IndexError):
        pass
    _gps["lat"] = lat
    _gps["lon"] = lon
    _gps["fix"] = int(fix_q) if fix_q.isdigit() else 0
    _gps["sats"] = sats
    _gps["alt"] = alt


def _parse_rmc(parts):
    if len(parts) < 8:
        return
    status = parts[2]
    speed_kn = parts[7]
    _gps["status"] = "FIX" if status == "A" else "NO FIX"
    try:
        _gps["speed"] = f"{float(speed_kn) * 1.852:.1f}"
    except (ValueError, IndexError):
        _gps["speed"] = "0.0"
    if len(parts) > 9 and parts[9]:
        _gps["date"] = parts[9]
    if parts[1]:
        _gps["time"] = parts[1][:2] + ":" + parts[1][2:4] + ":" + parts[1][4:6]


def _parse_gsa(parts):
    if len(parts) < 17:
        return
    _gps["pdop"] = parts[15] if parts[15] else "---"
    _gps["hdop"] = parts[16] if parts[16] else "---"


def _parse_vtg(parts):
    if len(parts) < 8:
        return
    if parts[5]:
        try:
            _gps["speed"] = f"{float(parts[7]):.1f}" if parts[7] else _gps.get("speed", "0.0")
        except (ValueError, IndexError):
            pass
    if parts[1]:
        _gps["heading"] = parts[1]


def _print_status():
    """Print a one-line status summary of the current fix."""
    fix_status = _gps.get("status", "---")
    lat = _gps.get("lat", 0.0)
    lon = _gps.get("lon", 0.0)
    sats = _gps.get("sats", "0")
    alt = _gps.get("alt", "---")
    spd = _gps.get("speed", "0.0")
    utc = _gps.get("time", "--:--:--")
    print(
        f"[{utc}] {fix_status}  lat={lat:+.6f} lon={lon:+.6f} "
        f"alt={alt}m speed={spd}km/h sats={sats}",
        flush=True,
    )


def _reader():
    global _running
    try:
        import serial as _serial
    except ImportError:
        print("ERROR: pyserial not installed.", flush=True)
        return

    try:
        from payloads._gps_helper import detect_gps, start_gps, _release_serial_port
    except ImportError:
        print("ERROR: GPS helper module not found.", flush=True)
        return

    # Stop gpsd so we can read the port directly
    subprocess.run(["systemctl", "stop", "gpsd.service", "gpsd.socket"],
                   capture_output=True, timeout=5)
    subprocess.run(["killall", "-9", "gpsd"], capture_output=True, timeout=3)
    time.sleep(0.3)

    dev, baud = detect_gps()
    if not dev:
        print("No GPS device found.", flush=True)
        return

    _release_serial_port(dev)
    time.sleep(0.3)

    print(f"Using GPS device {dev} @ {baud} baud", flush=True)

    try:
        ser = _serial.Serial(dev, baud, timeout=1.5)
    except Exception as e:
        print(f"ERROR opening serial port: {e}", flush=True)
        return

    last_print = 0.0
    while _running:
        try:
            raw = ser.readline().decode("ascii", errors="ignore").strip()
        except Exception:
            break
        if not raw.startswith("$"):
            continue

        with _lock:
            _nmea.append(raw)
            if len(_nmea) > 100:
                del _nmea[:50]

        parts = raw.split(",")
        tag = parts[0]
        if "GGA" in tag:
            _parse_gga(parts)
        elif "RMC" in tag:
            _parse_rmc(parts)
        elif "GSA" in tag:
            _parse_gsa(parts)
        elif "VTG" in tag:
            _parse_vtg(parts)

        now = time.time()
        if now - last_print >= 1.0:
            _print_status()
            last_print = now

    ser.close()

    # Restart gpsd for other payloads
    try:
        start_gps()
    except Exception:
        subprocess.run(["systemctl", "start", "gpsd"], capture_output=True)


def main():
    global _running

    duration = None
    if len(sys.argv) > 1:
        try:
            duration = float(sys.argv[1])
        except ValueError:
            print(f"Usage: {os.path.basename(__file__)} [duration_seconds]", flush=True)
            return 1

    print("Searching for GPS...", flush=True)

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    start = time.time()
    while _running:
        if duration is not None and (time.time() - start) >= duration:
            break
        time.sleep(0.1)

    _running = False
    reader_thread.join(timeout=4)

    print("\nFinal status:", flush=True)
    _print_status()
    print(f"NMEA sentences captured: {len(_nmea)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
