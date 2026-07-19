#!/usr/bin/env python3
# @name: NFC/RFID Reader & Cloner
# @desc: Detect supported PN532 or nfcpy readers, read and save NFC cards, clone saved dumps where writing is supported, and manage saved card data.
# @category: hardware
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- NFC/RFID Reader & Cloner
===============================================
Read, save and clone NFC/RFID cards.
Supports PN532 (UART/I2C), ACR122U, SCL3711 via nfcpy.

Modes:
  READ       Detect card, read UID + MIFARE sectors
  CLONE      Write saved dump to a new card (magic cards supported)
  SAVED      Browse and manage saved card dumps

Controls:
  Usage: nfc_reader.py

  Detects the reader on startup, then presents a numbered menu:
    1) Read card
    2) Clone card
    3) Browse saved cards
    4) Exit
  Each mode prompts interactively for further choices (which saved
  dump to clone, whether to save a read, etc). Progress is streamed to
  stdout as sectors are processed. Press Ctrl-C at any time to exit.
"""

from payloads._web_input import request_input
import os
import sys
import json
import time
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

try:
    import smbus2 as smbus
    SMBUS_OK = True
except ImportError:
    try:
        import smbus
        SMBUS_OK = True
    except ImportError:
        smbus = None
        SMBUS_OK = False

try:
    import serial
    SERIAL_OK = True
except ImportError:
    serial = None
    SERIAL_OK = False

try:
    import nfc as nfcpy
    NFCPY_OK = True
except ImportError:
    nfcpy = None
    NFCPY_OK = False

PN532_I2C_ADDR = 0x24
PN532_PREAMBLE = 0x00
PN532_STARTCODE1 = 0x00
PN532_STARTCODE2 = 0xFF
PN532_HOSTTOPN532 = 0xD4
PN532_PN532TOHOST = 0xD5
CMD_SAMCONFIGURATION = 0x14
CMD_INLISTPASSIVETARGET = 0x4A
CMD_INDATAEXCHANGE = 0x40
CMD_GETFIRMWAREVERSION = 0x02

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), "loot", "NFC")

DEFAULT_KEYS = [
    bytes.fromhex("FFFFFFFFFFFF"),
    bytes.fromhex("A0A1A2A3A4A5"),
    bytes.fromhex("D3F7D3F7D3F7"),
    bytes.fromhex("000000000000"),
    bytes.fromhex("B0B1B2B3B4B5"),
    bytes.fromhex("AABBCCDDEEFF"),
    bytes.fromhex("1A2B3C4D5E6F"),
    bytes.fromhex("010203040506"),
    bytes.fromhex("123456789ABC"),
]


# ---------------------------------------------------------------------------
# PN532 I2C driver
# ---------------------------------------------------------------------------

class PN532I2C:
    def __init__(self, bus_num=1, addr=PN532_I2C_ADDR):
        self.bus = smbus.SMBus(bus_num)
        self.addr = addr
        self.can_write = True

    def close(self):
        try:
            self.bus.close()
        except Exception:
            pass

    def _write_frame(self, data):
        length = len(data) + 1
        lcs = (~length + 1) & 0xFF
        frame = [PN532_PREAMBLE, PN532_STARTCODE1, PN532_STARTCODE2,
                 length, lcs, PN532_HOSTTOPN532] + list(data)
        dcs = (~(sum([PN532_HOSTTOPN532] + list(data))) + 1) & 0xFF
        frame += [dcs, 0x00]
        self.bus.write_i2c_block_data(self.addr, frame[0], frame[1:])

    def _read_response(self, expected_len=32, timeout=1.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                status = self.bus.read_byte(self.addr)
                if status & 0x01:
                    return self.bus.read_i2c_block_data(self.addr, 0x00, expected_len + 8)
            except OSError:
                pass
            time.sleep(0.02)
        return None

    def _parse_response(self, resp, cmd_reply):
        if resp is None:
            return None
        for i in range(len(resp) - 2):
            if resp[i] == PN532_PN532TOHOST and resp[i + 1] == cmd_reply:
                return resp[i:]
        return None

    def get_firmware_version(self):
        self._write_frame([CMD_GETFIRMWAREVERSION])
        resp = self._read_response(12)
        p = self._parse_response(resp, 0x03)
        if p and len(p) >= 6:
            return (p[2], p[3], p[4], p[5])
        return None

    def sam_config(self):
        self._write_frame([CMD_SAMCONFIGURATION, 0x01, 0x14, 0x01])
        self._read_response(12)

    def read_passive_target(self, timeout=2.0):
        self._write_frame([CMD_INLISTPASSIVETARGET, 0x01, 0x00])
        resp = self._read_response(32, timeout=timeout)
        p = self._parse_response(resp, 0x4B)
        if p is None or len(p) < 8 or p[2] < 1:
            return None
        uid_len = p[7]
        if len(p) >= 8 + uid_len:
            return bytes(p[8:8 + uid_len])
        return None

    def mifare_auth(self, block, key, uid, key_type=0x60):
        cmd = [CMD_INDATAEXCHANGE, 0x01, key_type, block] + list(key) + list(uid[:4])
        self._write_frame(cmd)
        resp = self._read_response(12)
        p = self._parse_response(resp, 0x41)
        return p is not None and len(p) >= 3 and p[2] == 0x00

    def mifare_read(self, block):
        self._write_frame([CMD_INDATAEXCHANGE, 0x01, 0x30, block])
        resp = self._read_response(32)
        p = self._parse_response(resp, 0x41)
        if p and len(p) >= 19 and p[2] == 0x00:
            return bytes(p[3:19])
        return None

    def mifare_write(self, block, data):
        cmd = [CMD_INDATAEXCHANGE, 0x01, 0xA0, block] + list(data[:16])
        self._write_frame(cmd)
        resp = self._read_response(12)
        p = self._parse_response(resp, 0x41)
        return p is not None and len(p) >= 3 and p[2] == 0x00


# ---------------------------------------------------------------------------
# PN532 UART driver
# ---------------------------------------------------------------------------

class PN532UART:
    def __init__(self, port="/dev/ttyUSB0", baudrate=115200):
        self.ser = serial.Serial(port, baudrate, timeout=0.5)
        self.can_write = True
        self._wakeup()

    def close(self):
        try:
            self.ser.close()
        except Exception:
            pass

    def _wakeup(self):
        self.ser.write(b"\x55\x55\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x03\xfd\xd4\x14\x01\x17\x00")
        time.sleep(0.1)
        self.ser.reset_input_buffer()

    def _write_frame(self, data):
        length = len(data) + 1
        lcs = (~length + 1) & 0xFF
        body = [PN532_HOSTTOPN532] + list(data)
        dcs = (~sum(body) + 1) & 0xFF
        self.ser.write(bytes([PN532_PREAMBLE, PN532_STARTCODE1, PN532_STARTCODE2,
                              length, lcs] + body + [dcs, 0x00]))

    def _read_response(self, expected_len=32, timeout=1.0):
        deadline = time.time() + timeout
        buf = b""
        while time.time() < deadline:
            chunk = self.ser.read(expected_len + 16)
            if chunk:
                buf += chunk
            ack_idx = buf.find(b"\x00\x00\xff\x00\xff\x00")
            if ack_idx >= 0:
                buf = buf[ack_idx + 6:]
            resp_idx = buf.find(b"\x00\x00\xff")
            if resp_idx >= 0 and len(buf) > resp_idx + 5:
                frame_len = buf[resp_idx + 3]
                total = resp_idx + 6 + frame_len + 1
                if len(buf) >= total:
                    return list(buf[resp_idx + 5:resp_idx + 5 + frame_len + 1])
            if not chunk:
                time.sleep(0.02)
        return None

    def _parse_response(self, resp, cmd_reply):
        if resp is None:
            return None
        for i in range(len(resp) - 2):
            if resp[i] == PN532_PN532TOHOST and resp[i + 1] == cmd_reply:
                return resp[i:]
        return None

    def get_firmware_version(self):
        self._write_frame([CMD_GETFIRMWAREVERSION])
        resp = self._read_response(12)
        p = self._parse_response(resp, 0x03)
        if p and len(p) >= 6:
            return (p[2], p[3], p[4], p[5])
        return None

    def sam_config(self):
        self._write_frame([CMD_SAMCONFIGURATION, 0x01, 0x14, 0x01])
        self._read_response(12)

    def read_passive_target(self, timeout=2.0):
        self._write_frame([CMD_INLISTPASSIVETARGET, 0x01, 0x00])
        resp = self._read_response(32, timeout=timeout)
        p = self._parse_response(resp, 0x4B)
        if p is None or len(p) < 8 or p[2] < 1:
            return None
        uid_len = p[7]
        if len(p) >= 8 + uid_len:
            return bytes(p[8:8 + uid_len])
        return None

    def mifare_auth(self, block, key, uid, key_type=0x60):
        cmd = [CMD_INDATAEXCHANGE, 0x01, key_type, block] + list(key) + list(uid[:4])
        self._write_frame(cmd)
        resp = self._read_response(12)
        p = self._parse_response(resp, 0x41)
        return p is not None and len(p) >= 3 and p[2] == 0x00

    def mifare_read(self, block):
        self._write_frame([CMD_INDATAEXCHANGE, 0x01, 0x30, block])
        resp = self._read_response(32)
        p = self._parse_response(resp, 0x41)
        if p and len(p) >= 19 and p[2] == 0x00:
            return bytes(p[3:19])
        return None

    def mifare_write(self, block, data):
        cmd = [CMD_INDATAEXCHANGE, 0x01, 0xA0, block] + list(data[:16])
        self._write_frame(cmd)
        resp = self._read_response(12)
        p = self._parse_response(resp, 0x41)
        return p is not None and len(p) >= 3 and p[2] == 0x00


# ---------------------------------------------------------------------------
# nfcpy wrapper (ACR122U, SCL3711, etc.)
# ---------------------------------------------------------------------------

class NfcpyDriver:
    def __init__(self, clf):
        self.clf = clf
        self.can_write = False

    def close(self):
        try:
            self.clf.close()
        except Exception:
            pass

    def get_firmware_version(self):
        return (0, 1, 0, 0)

    def sam_config(self):
        pass

    def read_passive_target(self, timeout=2.0):
        try:
            tag = self.clf.connect(rdwr={"on-connect": lambda t: False},
                                   terminate=lambda: False)
            if tag and hasattr(tag, "identifier"):
                return bytes(tag.identifier)
        except Exception:
            pass
        return None

    def mifare_auth(self, block, key, uid, key_type=0x60):
        return False

    def mifare_read(self, block):
        return None

    def mifare_write(self, block, data):
        return False


# ---------------------------------------------------------------------------
# Auto-detect reader
# ---------------------------------------------------------------------------

UART_PORTS = ["/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyAMA0"]


def _detect_reader():
    """Auto-detect NFC reader. Returns (driver, description) or (None, error)."""
    if NFCPY_OK:
        for path in ["usb", "usb:072f:2200", "usb:04e6:5591"]:
            try:
                clf = nfcpy.ContactlessFrontend(path)
                desc = str(clf.device) if hasattr(clf, "device") else path
                return NfcpyDriver(clf), f"nfcpy: {desc}"
            except Exception:
                pass

    if SERIAL_OK:
        for port in UART_PORTS:
            if not os.path.exists(port):
                continue
            for baud in [115200, 9600]:
                try:
                    drv = PN532UART(port, baud)
                    fw = drv.get_firmware_version()
                    if fw:
                        drv.sam_config()
                        return drv, f"PN532 UART {port}"
                    drv.close()
                except Exception:
                    pass

    if SMBUS_OK:
        for addr in [PN532_I2C_ADDR, 0x48]:
            try:
                drv = PN532I2C(addr=addr)
                fw = drv.get_firmware_version()
                if fw:
                    drv.sam_config()
                    return drv, f"PN532 I2C 0x{addr:02X}"
                drv.close()
            except Exception:
                pass

    return None, "No NFC reader found"


# ---------------------------------------------------------------------------
# Card operations
# ---------------------------------------------------------------------------

def _detect_card_type(uid):
    n = len(uid)
    if n == 4:
        return "MIFARE Classic"
    if n == 7:
        return "MIFARE UL/NTAG"
    if n == 10:
        return "MIFARE DESFire"
    return f"Unknown ({n}B)"


def _full_read(drv, uid, progress_cb=None):
    """Read all sectors of a MIFARE Classic card. Returns list of sector dicts."""
    sectors = []
    n_sectors = 16 if len(uid) == 4 else 0
    for sec in range(n_sectors):
        if progress_cb:
            progress_cb(sec, n_sectors, sectors)
        first_block = sec * 4
        authed = False
        used_key = ""
        key_type_used = 0x60
        for key in DEFAULT_KEYS:
            for kt in [0x60, 0x61]:
                if drv.mifare_auth(first_block, key, uid, kt):
                    authed = True
                    used_key = key.hex().upper()
                    key_type_used = kt
                    break
            if authed:
                break
        blocks = []
        if authed:
            for b in range(4):
                data = drv.mifare_read(first_block + b)
                blocks.append(data.hex() if data else "?" * 32)
        sectors.append({
            "sector": sec,
            "blocks": blocks,
            "key": used_key,
            "key_type": "A" if key_type_used == 0x60 else "B",
            "authed": authed,
        })
    return sectors


def _write_clone(drv, uid, dump, progress_cb=None):
    """Write a dump to a MIFARE Classic card. Returns (written, skipped, errors)."""
    written = 0
    skipped = 0
    errors = 0
    all_sectors = dump.get("sectors", [])
    total = len(all_sectors)
    for idx, sec_data in enumerate(all_sectors):
        if progress_cb:
            progress_cb(idx, total, written, skipped, errors)
        sec = sec_data["sector"]
        blocks = sec_data.get("blocks", [])
        key_hex = sec_data.get("key", "")
        if not blocks or not key_hex or key_hex in ("", "NONE"):
            skipped += 1
            continue
        key = bytes.fromhex(key_hex)
        first_block = sec * 4
        if not drv.mifare_auth(first_block, key, uid):
            for dk in DEFAULT_KEYS:
                if drv.mifare_auth(first_block, dk, uid):
                    break
            else:
                errors += 1
                continue

        for i, blk_hex in enumerate(blocks):
            block_num = first_block + i
            if block_num == 0 or i == 3 or blk_hex == "?" * 32:
                continue
            try:
                data = bytes.fromhex(blk_hex)
                if drv.mifare_write(block_num, data):
                    written += 1
                else:
                    errors += 1
            except Exception:
                errors += 1
    return written, skipped, errors


def _save_dump(uid, card_type, sectors):
    """Save card dump to JSON."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    uid_hex = uid.hex().upper()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"nfc_{uid_hex}_{ts}.json"
    dump = {
        "uid": uid_hex,
        "uid_bytes": list(uid),
        "type": card_type,
        "timestamp": ts,
        "sectors": sectors,
    }
    with open(os.path.join(LOOT_DIR, fname), "w") as f:
        json.dump(dump, f, indent=2)
    return fname


def _list_dumps():
    """List saved card dumps."""
    if not os.path.isdir(LOOT_DIR):
        return []
    result = []
    for f in sorted(os.listdir(LOOT_DIR), reverse=True):
        if f.startswith("nfc_") and f.endswith(".json"):
            path = os.path.join(LOOT_DIR, f)
            try:
                with open(path) as fh:
                    d = json.load(fh)
                result.append({
                    "file": f,
                    "path": path,
                    "uid": d.get("uid", "?"),
                    "type": d.get("type", "?"),
                    "sectors": len(d.get("sectors", [])),
                    "ts": d.get("timestamp", ""),
                })
            except Exception:
                pass
    return result


def _load_dump(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _prompt(msg):
    try:
        return request_input(msg).strip()
    except EOFError:
        return ""


def _select_dump(dumps, verb="select"):
    """Print numbered dumps and return the chosen one, or None."""
    if not dumps:
        print("No saved cards.", flush=True)
        return None
    for i, dm in enumerate(dumps, start=1):
        print(f"  {i}) {dm['uid']}  {dm['type']}  {dm['sectors']} sectors  {dm['ts']}", flush=True)
    choice = _prompt(f"Enter number to {verb} (Enter to cancel): ")
    if not choice:
        return None
    try:
        idx = int(choice) - 1
    except ValueError:
        print(f"Invalid selection: {choice}", flush=True)
        return None
    if 0 <= idx < len(dumps):
        return dumps[idx]
    print(f"Invalid selection: {choice}", flush=True)
    return None


# ---------------------------------------------------------------------------
# Mode handlers
# ---------------------------------------------------------------------------

def _mode_read(drv, drv_desc):
    if drv is None:
        print("No reader connected.", flush=True)
        return

    _prompt("Place card on reader, then press Enter...")
    print("Polling...", flush=True)
    uid = drv.read_passive_target(timeout=3.0)
    if not uid:
        print("No card detected.", flush=True)
        return

    ctype = _detect_card_type(uid)
    uid_hex = uid.hex().upper()
    print(f"UID: {uid_hex}  Type: {ctype}", flush=True)

    def _read_progress(sec, total, done):
        authed = sum(1 for s in done if s["authed"])
        print(f"  Sector {sec + 1}/{total}  cracked={authed}", flush=True)

    sectors = _full_read(drv, uid, progress_cb=_read_progress)
    authed = sum(1 for s in sectors if s["authed"])
    print(f"Read complete: {authed}/{len(sectors)} sectors cracked.", flush=True)

    if _prompt("Save this dump to loot? [y/N]: ").lower() == "y":
        fname = _save_dump(uid, ctype, sectors)
        print(f"Saved: {os.path.join(LOOT_DIR, fname)}", flush=True)


def _mode_clone(drv, drv_desc):
    if drv is None:
        print("No reader connected.", flush=True)
        return
    if not drv.can_write:
        print("Reader is read-only; cannot clone.", flush=True)
        return

    dumps = _list_dumps()
    dump = _select_dump(dumps, verb="clone")
    if dump is None:
        return

    print(f"Source: {dump['uid']}", flush=True)
    _prompt("Place TARGET card on reader, then press Enter...")
    uid = drv.read_passive_target(timeout=5.0)
    if not uid:
        print("No target card detected.", flush=True)
        return

    target_hex = uid.hex().upper()
    print(f"Target: {target_hex}", flush=True)

    dump_data = _load_dump(dump["path"])
    if dump_data is None:
        print("Failed to load dump.", flush=True)
        return

    def _clone_progress(sec, total, w, s, e):
        print(f"  Sector {sec + 1}/{total}  written={w} skipped={s} errors={e}", flush=True)

    written, skipped, errors = _write_clone(drv, uid, dump_data, progress_cb=_clone_progress)
    if errors == 0 and written > 0:
        print(f"Cloned! {written} blocks written.", flush=True)
    else:
        print(f"Done. written={written} skipped={skipped} errors={errors}", flush=True)


def _mode_saved():
    dumps = _list_dumps()
    if not dumps:
        print("No saved cards.", flush=True)
        return

    action = _prompt("View (v) or delete (d) a saved card? [v/d, Enter to cancel]: ").lower()
    if action not in ("v", "d"):
        return

    dump_info = _select_dump(dumps, verb=("view" if action == "v" else "delete"))
    if dump_info is None:
        return

    if action == "d":
        try:
            os.remove(dump_info["path"])
            print(f"Deleted {dump_info['uid']}.", flush=True)
        except Exception as exc:
            print(f"Delete failed: {exc}", flush=True)
        return

    dump = _load_dump(dump_info["path"])
    if dump is None:
        print("Failed to load dump.", flush=True)
        return

    print(f"UID:  {dump['uid']}", flush=True)
    print(f"Type: {dump.get('type', '?')}", flush=True)
    print(f"Date: {dump.get('timestamp', '?')}", flush=True)
    for s in dump.get("sectors", []):
        key_ok = s.get("key", "") not in ("", "NONE")
        key_txt = s.get("key", "?") if key_ok else "LOCKED"
        first_block = s["blocks"][0][:12] if s.get("blocks") else ""
        print(f"  S{s['sector']:02d} [{key_txt}] {first_block}", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not SMBUS_OK and not SERIAL_OK and not NFCPY_OK:
        print("No NFC library! Install with: pip install nfcpy (or smbus2 / pyserial)", flush=True)
        return 1

    print("Detecting reader...", flush=True)
    drv, drv_desc = _detect_reader()
    print(f"Reader: {drv_desc}", flush=True)

    try:
        while True:
            print("\n1) Read card", flush=True)
            print("2) Clone card", flush=True)
            print("3) Browse saved cards", flush=True)
            print("4) Exit", flush=True)
            choice = _prompt("Select option [1-4]: ")

            if choice in ("4", "", "exit", "quit"):
                break
            elif choice == "1":
                if drv is None:
                    drv, drv_desc = _detect_reader()
                    print(f"Reader: {drv_desc}", flush=True)
                _mode_read(drv, drv_desc)
            elif choice == "2":
                _mode_clone(drv, drv_desc)
            elif choice == "3":
                _mode_saved()
            else:
                print(f"Unknown option: {choice}", flush=True)
    finally:
        if drv:
            drv.close()

    print("Exiting.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
