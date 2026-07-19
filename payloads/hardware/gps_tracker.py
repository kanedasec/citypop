#!/usr/bin/env python3
# @name: GPS Tracker
# @desc: Track fixes from a detected serial GPS receiver, stream position data, and optionally export the session as CSV and GPX in loot.
# @category: hardware
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- GPS Tracker
==================================
Author: 7h30th3r0n3

GPS tracking and logging via serial GPS module.  Parses NMEA sentences
($GPGGA and $GPRMC) for position, speed, altitude, and satellite info.
Logs to CSV and can export GPX.

Setup / Prerequisites
---------------------
- Serial GPS module (e.g., NEO-6M) connected to /dev/ttyUSB0 or
  /dev/serial0 at 9600 baud.
- pyserial installed (pip install pyserial).

Controls
--------
  Usage: gps_tracker.py [duration_seconds]

  duration_seconds  Optional time to run, in seconds. Runs until Ctrl-C
                     if omitted.

  You will be prompted at startup whether to log fixes to CSV. A status
  line is printed each time a new fix is obtained. Press Ctrl-C to stop
  tracking; a CSV of any logged points is written automatically and you
  will be asked whether to also export a GPX track.

Loot: $CITYPOP_ROOT/loot/GPS/
"""

from payloads._web_input import request_input
import os
import sys
import time
import signal
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

try:
    import gpsd as gpsd_mod
    GPSD_OK = True
except ImportError:
    gpsd_mod = None
    GPSD_OK = False

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), "loot", "GPS")

lock = threading.Lock()
_running = True


def _stop(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _stop)
signal.signal(signal.SIGTERM, _stop)


class GPSFix:
    __slots__ = (
        "latitude", "longitude", "altitude", "speed_knots",
        "satellites", "fix_quality", "utc_time", "valid",
    )

    def __init__(self):
        self.latitude = 0.0
        self.longitude = 0.0
        self.altitude = 0.0
        self.speed_knots = 0.0
        self.satellites = 0
        self.fix_quality = 0
        self.utc_time = ""
        self.valid = False

current_fix = GPSFix()
log_entries = []
logging_active = False
status_msg = "Searching..."
_sats_used = 0
_sats_visible = 0


def _sat_poller():
    """Poll gpsd JSON socket for satellite counts."""
    global _sats_used, _sats_visible
    import socket as _sock
    import json as _j
    while _running:
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(5)
            s.connect(("127.0.0.1", 2947))
            s.sendall(b'?WATCH={"enable":true,"json":true}\n')
            buf = ""
            while _running:
                data = s.recv(4096).decode("utf-8", errors="ignore")
                if not data:
                    break
                buf += data
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if '"class":"SKY"' not in line:
                        continue
                    try:
                        sky = _j.loads(line)
                        n = sky.get("nSat", -1)
                        if n < 0:
                            continue
                        _sats_visible = n
                        u = sky.get("uSat", 0)
                        if u == 0 and "satellites" in sky:
                            u = sum(1 for sat in sky["satellites"] if sat.get("used"))
                        _sats_used = u
                    except Exception:
                        pass
            s.close()
        except Exception:
            pass
        time.sleep(3)


def _reader_thread():
    """Poll gpsd for position updates."""
    global current_fix, status_msg, log_entries, logging_active

    try:
        gpsd_mod.connect()
    except Exception:
        with lock:
            status_msg = "gpsd connect failed"
        print(status_msg, flush=True)
        return

    with lock:
        status_msg = "Connected to gpsd"
    print(status_msg, flush=True)

    threading.Thread(target=_sat_poller, daemon=True).start()

    while _running:
        try:
            pkt = gpsd_mod.get_current()
            fix = GPSFix()
            if hasattr(pkt, 'mode') and pkt.mode >= 2:
                fix.latitude = pkt.lat
                fix.longitude = pkt.lon
                fix.altitude = pkt.alt if pkt.mode >= 3 else 0.0
                fix.speed_knots = getattr(pkt, 'hspeed', 0) / 1.852
                fix.satellites = _sats_used
                fix.fix_quality = pkt.mode
                fix.valid = True
                with lock:
                    current_fix = fix
                    status_msg = f"Fix {pkt.mode}D: {_sats_used}/{_sats_visible} sats"
                    if logging_active:
                        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                        log_entries = log_entries + [(
                            ts, fix.latitude, fix.longitude,
                            fix.altitude, fix.speed_knots,
                        )]
                print(
                    f"[{fix.utc_time or status_msg}] lat={fix.latitude:.6f} "
                    f"lon={fix.longitude:.6f} alt={fix.altitude:.1f}m "
                    f"spd={_speed_kmh(fix.speed_knots):.1f}km/h "
                    f"sats={fix.satellites} log={len(log_entries)}pts",
                    flush=True,
                )
            else:
                with lock:
                    fix.satellites = _sats_visible
                    current_fix = fix
                    status_msg = f"No fix ({_sats_visible} sats)"
                print(status_msg, flush=True)
        except Exception:
            pass

        time.sleep(1)

def _export_csv(entries):
    """Write log entries to CSV."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"gps_log_{ts}.csv"
    fpath = os.path.join(LOOT_DIR, fname)
    try:
        with open(fpath, "w") as fh:
            fh.write("timestamp,latitude,longitude,altitude,speed_knots\n")
            for e in entries:
                fh.write(f"{e[0]},{e[1]},{e[2]},{e[3]},{e[4]}\n")
        return f"CSV: {fname}"
    except OSError as exc:
        return f"Err: {exc}"

def _export_gpx(entries):
    """Write log entries as GPX file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"gps_track_{ts}.gpx"
    fpath = os.path.join(LOOT_DIR, fname)
    try:
        lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<gpx version="1.1" creator="RaspyJack">',
                 '  <trk><name>RaspyJack Track</name><trkseg>']
        for e in entries:
            lines.append(f'    <trkpt lat="{e[1]}" lon="{e[2]}"><ele>{e[3]}</ele><time>{e[0]}</time></trkpt>')
        lines += ['  </trkseg></trk>', '</gpx>']
        with open(fpath, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        return f"GPX: {fname}"
    except OSError as exc:
        return f"Err: {exc}"

def _speed_kmh(knots):
    return knots * 1.852


def main():
    global _running, logging_active, log_entries, status_msg

    if not GPSD_OK:
        print("gpsd module missing! Install it with: pip install gpsd-py3", flush=True)
        return 1

    duration = None
    if len(sys.argv) > 1:
        try:
            duration = float(sys.argv[1])
        except ValueError:
            print(f"Usage: {os.path.basename(__file__)} [duration_seconds]", flush=True)
            return 1

    try:
        answer = request_input("Log fixes to CSV while tracking? [Y/n]: ").strip().lower()
    except EOFError:
        answer = "y"
    logging_active = answer != "n"
    print(f"Logging {'enabled' if logging_active else 'disabled'}.", flush=True)

    reader = threading.Thread(target=_reader_thread, daemon=True)
    reader.start()

    start = time.time()
    try:
        while _running:
            if duration is not None and (time.time() - start) >= duration:
                break
            time.sleep(0.2)
    finally:
        _running = False
        reader.join(timeout=3)
        if log_entries:
            result = _export_csv(log_entries)
            print(result, flush=True)

    print(f"Tracking stopped. {len(log_entries)} point(s) logged.", flush=True)

    if log_entries:
        try:
            export_gpx = request_input("Also export a GPX track? [y/N]: ").strip().lower()
        except EOFError:
            export_gpx = ""
        if export_gpx == "y":
            print(_export_gpx(log_entries), flush=True)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
