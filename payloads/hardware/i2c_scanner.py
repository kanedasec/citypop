#!/usr/bin/env python3
# @name: I2C Bus Scanner
# @desc: Probes all 127 I2C addresses on bus 1 using smbus2.
# @category: hardware
# @danger: false
# @active: true
"""
RaspyJack Payload -- I2C Bus Scanner
=====================================
Author: 7h30th3r0n3

Probes all 127 I2C addresses on bus 1 using smbus2.

Setup / Prerequisites:
  - Requires I2C enabled (dtparam=i2c_arm=on in config.txt).
  - Scans /dev/i2c-1.  Identifies responding
devices by matching against a built-in database of common I2C addresses
(OLED displays, sensors, EEPROMs, RTCs, etc.).

Controls:
  Usage: i2c_scanner.py [bus]

  bus  Optional I2C bus number (default: 1).

  Scans the bus automatically and prints each device found. If any
  devices are found you will then be prompted (interactively) whether
  to read the first 16 register bytes from one of them, and whether to
  export the results to loot. Press Ctrl-C at any time to stop.

Loot: /root/Raspyjack/loot/I2CScan/scan_YYYYMMDD_HHMMSS.json
Requires: smbus2
"""

from payloads._web_input import request_input
import os
import sys
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

try:
    import smbus2
    SMBUS_OK = True
except ImportError:
    SMBUS_OK = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
I2C_BUS = 1
LOOT_DIR = "/root/Raspyjack/loot/I2CScan"

# Built-in I2C address database (hex address -> description)
I2C_DEVICES = {
    0x0E: "MAG3110 Magnetometer",
    0x0F: "MAG3110 Magnetometer",
    0x10: "VEML7700 Light",
    0x11: "Si4713 FM TX",
    0x13: "VCNL40x0 Proximity",
    0x18: "MCP9808 Temp / LIS3DH",
    0x19: "LIS3DH Accel",
    0x1A: "AC101 Audio",
    0x1C: "MMA8452Q Accel / FXOS",
    0x1D: "ADXL345 / MMA845x",
    0x1E: "HMC5883L Compass / LSM303",
    0x20: "PCF8574 I/O Expander",
    0x21: "PCF8574 I/O Expander",
    0x22: "PCF8574 I/O Expander",
    0x23: "BH1750 Light Sensor",
    0x24: "PCF8574 I/O Expander",
    0x25: "PCF8574 I/O Expander",
    0x26: "PCF8574 I/O Expander",
    0x27: "PCF8574 LCD / I/O Exp",
    0x28: "BNO055 IMU / CAP1188",
    0x29: "VL53L0X / TSL2591 / TCS",
    0x2A: "CAP1188 Touch",
    0x38: "AHT20 Temp/Hum / FT6x06",
    0x39: "TSL2561 / APDS-9960",
    0x3C: "SSD1306 OLED 128x64",
    0x3D: "SSD1306 OLED 128x64",
    0x3E: "SSD1306 OLED (alt)",
    0x40: "INA219 / HTU21D / HDC1080",
    0x41: "INA219 Power Monitor",
    0x44: "SHT31 Temp/Hum",
    0x45: "SHT31 Temp/Hum",
    0x48: "ADS1115 ADC / TMP102",
    0x49: "ADS1115 ADC / TMP102",
    0x4A: "ADS1115 ADC / MAX44009",
    0x4B: "ADS1115 ADC",
    0x50: "AT24C32 EEPROM",
    0x51: "AT24C32 EEPROM",
    0x52: "Nunchuk / EEPROM",
    0x53: "ADXL345 Accel / EEPROM",
    0x54: "EEPROM",
    0x55: "EEPROM / MAX17048",
    0x56: "EEPROM",
    0x57: "EEPROM / MAX3010x",
    0x58: "TPA2016 Audio Amp",
    0x5A: "MLX90614 IR Temp / MPR121",
    0x5B: "MPR121 Touch / CCS811",
    0x5C: "AM2315 / BH1750 (alt)",
    0x60: "MCP4725 DAC / Si5351",
    0x61: "MCP4725 DAC / Si5351",
    0x62: "SCD40 CO2",
    0x68: "DS1307 RTC / MPU6050 IMU",
    0x69: "MPU6050 / ITG3200",
    0x6A: "LSM6DS Accel/Gyro",
    0x6B: "LSM6DS Accel/Gyro",
    0x70: "HT16K33 LED Matrix",
    0x71: "HT16K33 LED Matrix",
    0x76: "BME280 / BMP280 / MS5611",
    0x77: "BME280 / BMP180 / MS5611",
    0x78: "SSD1306 OLED (7-bit alt)",
}

# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def _scan_bus(bus_num):
    """Scan all I2C addresses on the bus. Returns list of device dicts."""
    results = []
    try:
        bus = smbus2.SMBus(bus_num)
    except Exception as exc:
        print(f"Bus error: {exc}", flush=True)
        return results

    print(f"Scanning I2C bus {bus_num}...", flush=True)
    for addr in range(0x03, 0x78):
        try:
            bus.read_byte(addr)
            desc = I2C_DEVICES.get(addr, "Unknown device")
            results.append({
                "addr": addr,
                "hex": f"0x{addr:02X}",
                "desc": desc,
            })
            print(f"  Found 0x{addr:02X}  {desc}", flush=True)
        except Exception:
            pass

    try:
        bus.close()
    except Exception:
        pass

    print(f"Scan complete: {len(results)} device(s) found.", flush=True)
    return results


def _read_registers(bus_num, addr, count=16):
    """Read first N registers from a device."""
    try:
        bus = smbus2.SMBus(bus_num)
        values = []
        for reg in range(count):
            try:
                val = bus.read_byte_data(addr, reg)
                values.append(f"{val:02X}")
            except Exception:
                values.append("--")
        bus.close()
        return " ".join(values)
    except Exception as exc:
        return f"Error: {exc}"

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot(bus_num, found_devices):
    """Write scan results to JSON loot file."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{ts}.json"
    filepath = os.path.join(LOOT_DIR, filename)

    data = {
        "timestamp": ts,
        "bus": bus_num,
        "devices_found": len(found_devices),
        "devices": found_devices,
    }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return filename

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not SMBUS_OK:
        print("smbus2 not found! Install it with: pip install smbus2", flush=True)
        return 1

    bus_num = I2C_BUS
    if len(sys.argv) > 1:
        try:
            bus_num = int(sys.argv[1])
        except ValueError:
            print(f"Usage: {os.path.basename(__file__)} [bus]", flush=True)
            return 1

    found_devices = _scan_bus(bus_num)

    if found_devices:
        try:
            choice = request_input(
                "Read first 16 register bytes from a device? "
                "Enter hex address (e.g. 0x3C) or press Enter to skip: "
            ).strip()
        except EOFError:
            choice = ""

        if choice:
            try:
                addr = int(choice, 16)
                dump = _read_registers(bus_num, addr, 16)
                print(f"Registers @ 0x{addr:02X}: {dump}", flush=True)
            except ValueError:
                print(f"Invalid address: {choice}", flush=True)

        try:
            export = request_input("Export results to loot? [y/N]: ").strip().lower()
        except EOFError:
            export = ""

        if export == "y":
            fname = _export_loot(bus_num, found_devices)
            print(f"Exported: {os.path.join(LOOT_DIR, fname)}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
