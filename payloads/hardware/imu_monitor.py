#!/usr/bin/env python3
# @name: IMU Monitor (LSM6DS3TR)
# @desc: Stream LSM6DS3TR accelerometer, gyroscope, orientation, motion, and temperature data through IIO or SMBus, with optional history export.
# @category: hardware
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- IMU Monitor (LSM6DS3TR)
==============================================
Author: 7h30th3r0n3

Real-time 6-axis IMU readout for the LSM6DS3TR accelerometer +
gyroscope: accelerometer (g), gyroscope (deg/s), temperature, and
derived pitch/roll.

Sensor access
-------------
Primary:  Linux IIO sysfs  (/sys/bus/iio/devices/iio:deviceX)
Fallback: smbus2 direct I2C at 0x6A / 0x6B

Setup / Prerequisites
---------------------
- LSM6DS3TR connected on I2C bus 1.
- Overlay ``lsm6ds3tr-overlay`` loaded in config.txt.
- ``smbus2`` pip package for the I2C fallback path.

Controls
--------
  Usage: imu_monitor.py [duration_seconds]

  duration_seconds  Optional time to sample, in seconds. Runs until
                     Ctrl-C if omitted.

  Samples the IMU at 50 Hz internally and prints a status line to
  stdout roughly twice a second with accel/gyro/temperature and
  pitch/roll. Press Ctrl-C to stop; you will then be asked whether to
  export the snapshot + recent sample history to loot.

Loot: $CITYPOP_ROOT/loot/IMU/imu_YYYYMMDD_HHMMSS.json
"""

from payloads._web_input import request_input
import os
import sys
import math
import json
import time
import glob
import signal
import threading
from collections import deque
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), "loot", "IMU")
SAMPLE_RATE_HZ = 50
HISTORY_LEN = 300

# ---------------------------------------------------------------------------
# IIO sysfs sensor backend
# ---------------------------------------------------------------------------

def _find_iio_device():
    """Locate the LSM6DS3 IIO device directory, or return None."""
    for dev_path in sorted(glob.glob("/sys/bus/iio/devices/iio:device*")):
        name_file = os.path.join(dev_path, "name")
        if not os.path.isfile(name_file):
            continue
        try:
            with open(name_file, "r") as fh:
                name = fh.read().strip().lower()
            if "lsm6ds3" in name:
                return dev_path
        except OSError:
            continue
    return None


def _read_sysfs(path):
    """Read a single sysfs file and return its stripped content."""
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except OSError:
        return None


class IIOBackend:
    """Read IMU data through the Linux IIO sysfs interface."""

    def __init__(self, dev_path):
        self._base = dev_path
        self._accel_scale = self._read_float("in_accel_scale", 0.000598)
        self._gyro_scale = self._read_float("in_anglvel_scale", 0.001065)

    def _read_float(self, name, default):
        val = _read_sysfs(os.path.join(self._base, name))
        if val is not None:
            try:
                return float(val)
            except ValueError:
                pass
        return default

    def _raw(self, name):
        val = _read_sysfs(os.path.join(self._base, name))
        if val is not None:
            try:
                return int(val)
            except ValueError:
                pass
        return 0

    def read(self):
        """Return (ax, ay, az, gx, gy, gz, temp) in SI units.
        Axes swapped to match CardputerZero physical orientation."""
        raw_x = self._raw("in_accel_x_raw") * self._accel_scale / 9.80665
        raw_y = self._raw("in_accel_y_raw") * self._accel_scale / 9.80665
        az = self._raw("in_accel_z_raw") * self._accel_scale / 9.80665
        ax, ay = raw_y, -raw_x
        raw_gx = self._raw("in_anglvel_x_raw") * self._gyro_scale * (180.0 / math.pi)
        raw_gy = self._raw("in_anglvel_y_raw") * self._gyro_scale * (180.0 / math.pi)
        gz = self._raw("in_anglvel_z_raw") * self._gyro_scale * (180.0 / math.pi)
        gx, gy = raw_gy, raw_gx
        temp_raw = self._raw("in_temp_raw")
        temp_scale = self._read_float("in_temp_scale", 0.00390625)
        temp_offset = self._read_float("in_temp_offset", 6400)
        temp_c = (temp_raw + temp_offset) * temp_scale
        return (ax, ay, az, gx, gy, gz, temp_c)


# ---------------------------------------------------------------------------
# smbus2 direct I2C fallback
# ---------------------------------------------------------------------------

class SMBusBackend:
    """Read LSM6DS3TR registers directly over I2C."""

    _WHO_AM_I = 0x0F
    _CTRL1_XL = 0x10
    _CTRL2_G = 0x11
    _OUT_TEMP_L = 0x20
    _OUTX_L_G = 0x22
    _OUTX_L_XL = 0x28

    def __init__(self, bus_num=1, addr=0x6A):
        import smbus2
        self._bus = smbus2.SMBus(bus_num)
        self._addr = addr
        # Verify WHO_AM_I
        wai = self._bus.read_byte_data(self._addr, self._WHO_AM_I)
        if wai not in (0x69, 0x6A, 0x6C):
            raise RuntimeError(f"Unexpected WHO_AM_I: 0x{wai:02X}")
        # Enable accel 104 Hz, +/-2g  and gyro 104 Hz, 245 dps
        self._bus.write_byte_data(self._addr, self._CTRL1_XL, 0x40)
        self._bus.write_byte_data(self._addr, self._CTRL2_G, 0x40)
        self._accel_sens = 0.000061  # g / LSB for +/-2g
        self._gyro_sens = 0.00875   # dps / LSB for 245 dps

    def _read_i16(self, reg):
        low = self._bus.read_byte_data(self._addr, reg)
        high = self._bus.read_byte_data(self._addr, reg + 1)
        val = (high << 8) | low
        if val >= 0x8000:
            val -= 0x10000
        return val

    def read(self):
        raw_x = self._read_i16(self._OUTX_L_XL) * self._accel_sens
        raw_y = self._read_i16(self._OUTX_L_XL + 2) * self._accel_sens
        az = self._read_i16(self._OUTX_L_XL + 4) * self._accel_sens
        ax, ay = raw_y, -raw_x
        raw_gx = self._read_i16(self._OUTX_L_G) * self._gyro_sens
        raw_gy = self._read_i16(self._OUTX_L_G + 2) * self._gyro_sens
        gz = self._read_i16(self._OUTX_L_G + 4) * self._gyro_sens
        gx, gy = raw_gy, raw_gx
        temp_raw = self._read_i16(self._OUT_TEMP_L)
        temp_c = 25.0 + temp_raw / 256.0
        return (ax, ay, az, gx, gy, gz, temp_c)

    def close(self):
        try:
            self._bus.close()
        except Exception:
            pass


def _create_backend():
    """Try IIO first, then smbus2 at 0x6A / 0x6B."""
    iio_path = _find_iio_device()
    if iio_path is not None:
        try:
            return IIOBackend(iio_path), "IIO"
        except Exception:
            pass
    try:
        return SMBusBackend(1, 0x6A), "I2C:0x6A"
    except Exception:
        pass
    try:
        return SMBusBackend(1, 0x6B), "I2C:0x6B"
    except Exception:
        pass
    return None, "NONE"


# ---------------------------------------------------------------------------
# Shared state (protected by _lock)
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_running = True

# Latest reading
_latest = (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 25.0)

# Full snapshot list for export (last HISTORY_LEN samples)
_snapshot_buf = deque(maxlen=HISTORY_LEN)

_backend_label = ""


def _stop(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _stop)
signal.signal(signal.SIGTERM, _stop)


# ---------------------------------------------------------------------------
# Reader thread
# ---------------------------------------------------------------------------

def _reader_thread(backend):
    """Continuously read the IMU at ~SAMPLE_RATE_HZ."""
    global _latest
    interval = 1.0 / SAMPLE_RATE_HZ

    while _running:
        t0 = time.monotonic()
        try:
            sample = backend.read()
        except Exception as exc:
            print(f"Read error: {exc}", flush=True)
            time.sleep(0.1)
            continue

        ts = time.time()
        with _lock:
            _latest = sample
            _snapshot_buf.append({
                "t": round(ts, 3),
                "ax": round(sample[0], 4),
                "ay": round(sample[1], 4),
                "az": round(sample[2], 4),
                "gx": round(sample[3], 2),
                "gy": round(sample[4], 2),
                "gz": round(sample[5], 2),
                "tc": round(sample[6], 1),
            })
        elapsed = time.monotonic() - t0
        sleep_time = interval - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)


def _pitch_roll(ax, ay, az):
    pitch = math.degrees(math.atan2(-ax, math.sqrt(ay * ay + az * az)))
    roll = math.degrees(math.atan2(ay, az))
    return pitch, roll


def _print_status(sample):
    ax, ay, az, gx, gy, gz, temp = sample
    pitch, roll = _pitch_roll(ax, ay, az)
    print(
        f"accel(g) x={ax:+.3f} y={ay:+.3f} z={az:+.3f}  "
        f"gyro(dps) x={gx:+.1f} y={gy:+.1f} z={gz:+.1f}  "
        f"temp={temp:.1f}C  pitch={pitch:+.1f} roll={roll:+.1f}",
        flush=True,
    )


# ---------------------------------------------------------------------------
# Export to loot
# ---------------------------------------------------------------------------

def _export_loot(latest_sample):
    """Write current snapshot and recent history to JSON."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"imu_{ts}.json")

    ax, ay, az, gx, gy, gz, temp = latest_sample

    with _lock:
        history = list(_snapshot_buf)

    data = {
        "timestamp": ts,
        "sensor": "LSM6DS3TR",
        "backend": _backend_label,
        "snapshot": {
            "accel_g": {"x": round(ax, 4), "y": round(ay, 4), "z": round(az, 4)},
            "gyro_dps": {"x": round(gx, 2), "y": round(gy, 2), "z": round(gz, 2)},
            "temp_c": round(temp, 1),
        },
        "history_samples": len(history),
        "history": history,
    }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return os.path.basename(filepath)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, _backend_label

    duration = None
    if len(sys.argv) > 1:
        try:
            duration = float(sys.argv[1])
        except ValueError:
            print(f"Usage: {os.path.basename(__file__)} [duration_seconds]", flush=True)
            return 1

    # Try to initialise sensor backend
    backend, label = _create_backend()
    _backend_label = label

    if backend is None:
        print("No IMU found!", flush=True)
        return 1

    print(f"IMU backend: {label}", flush=True)

    # Start reader thread
    reader = threading.Thread(target=_reader_thread, args=(backend,), daemon=True)
    reader.start()

    start = time.time()
    try:
        while _running:
            if duration is not None and (time.time() - start) >= duration:
                break
            with _lock:
                sample = _latest
            _print_status(sample)
            time.sleep(0.5)
    finally:
        _running = False
        reader.join(timeout=1)
        if hasattr(backend, "close"):
            backend.close()

    print("Monitoring stopped.", flush=True)

    try:
        export = request_input("Export snapshot + history to loot? [y/N]: ").strip().lower()
    except EOFError:
        export = ""
    if export == "y":
        with _lock:
            sample_now = _latest
        fname = _export_loot(sample_now)
        print(f"Saved: {os.path.join(LOOT_DIR, fname)}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
