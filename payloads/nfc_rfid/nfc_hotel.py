#!/usr/bin/env python3
# @name: Hotel Card Reader
# @desc: Read hotel key cards (MIFARE Classic) with hospitality-specific key dictionary.
# @category: nfc_rfid
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- Hotel Card Reader
=========================================
Read hotel key cards (MIFARE Classic) with hospitality-specific key dictionary.
Targets: Assa Abloy/VingCard, Dormakaba, Onity, Salto, ASSA ABLOY Hospitality.

Controls:
  Usage: nfc_hotel.py

  Presents a numbered menu:
    1) Read hotel card
    2) Save last read dump to loot
    3) Exit
  Progress is streamed per-sector to stdout as keys are tried. Press
  Ctrl-C to exit.
"""
from payloads._web_input import request_input
import os, sys, time, json
from datetime import datetime
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
from payloads.nfc_rfid._nfc_driver import auto_detect, is_classic
from payloads.nfc_rfid._nfc_keys import KNOWN_KEYS
from payloads.nfc_rfid._nfc_cards import save_dump

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'NFC', 'hotel')

# Hotel-specific keys (ordered by likelihood)
HOTEL_KEYS = [bytes.fromhex(k) for k in [
    "FFFFFFFFFFFF", "A0A1A2A3A4A5", "D3F7D3F7D3F7",
    # Assa Abloy / VingCard
    "AE8E8B3C0AFF", "A0A1A2A3A4A5", "484558414354",
    "564C505249CB", "4B0B20107CCB", "FC00018778F7",
    # Dormakaba / ILCO / Kaba
    "010203040506", "0A0B0C0D0E0F", "D3F7D3F7D3F7",
    "A22AE129C013", "49FAE4E3849F", "38FCF33072E0",
    # Onity / Allegion
    "FC00018778F7", "A0478CC39091", "8FD0A4F256E9",
    "533CB6C723F6", "2612FEE7F4CE",
    # Salto
    "A22AE129C013", "62D0C424ED8E", "E64A986A5D94",
    "8829DA9DAF76", "8A1F424104D3",
    # Saflok
    "314B49474956", "564C505249CB", "0604DF988000",
    # Generic hotel
    "000000000000", "B0B1B2B3B4B5", "AABBCCDDEEFF",
    "1A2B3C4D5E6F",
]] + KNOWN_KEYS[:20]

# Deduplicate
_seen = set()
HOTEL_KEYS_UNIQUE = []
for k in HOTEL_KEYS:
    h = k.hex()
    if h not in _seen:
        _seen.add(h)
        HOTEL_KEYS_UNIQUE.append(k)
HOTEL_KEYS = HOTEL_KEYS_UNIQUE

def _prompt(msg):
    try:
        return request_input(msg).strip()
    except EOFError:
        return ""

def _interpret_sector(blocks, sector):
    """Try to interpret hotel card data from sector blocks."""
    hints = []
    for blk in blocks:
        if not blk or blk == "?" * 32: continue
        raw = bytes.fromhex(blk)
        # Look for ASCII strings (room numbers, dates)
        ascii_chars = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
        cleaned = ascii_chars.replace(".", "").strip()
        if len(cleaned) >= 3:
            hints.append(f"Text: {cleaned[:16]}")
        # Look for date patterns (YYMM, DDMM, timestamps)
        h = blk.upper()
        for i in range(0, len(h) - 7, 2):
            chunk = h[i:i+8]
            if chunk[:2] in ("20", "19") and chunk[2:4].isdigit():
                yy, mm = int(chunk[2:4]), int(chunk[4:6])
                if 1 <= mm <= 12:
                    hints.append(f"Date: 20{yy:02d}/{mm:02d}")
    return hints[:2]

def _read_hotel_card(drv):
    """Scan a card and try hotel keys sector by sector. Returns (card, sectors) or (None, None)."""
    _prompt("Place hotel card on reader, then press Enter...")
    print("Polling...", flush=True)
    card = drv.read_passive_target(timeout=5.0)
    if not card or not is_classic(card):
        print(f"Not a MIFARE Classic card: {card.card_type}" if card else "No card detected.", flush=True)
        return None, None

    sectors = []
    last_key = None
    for sec in range(16):
        block = sec * 4
        print(f"  Sector {sec + 1}/16 ...", flush=True)

        key_found = None
        kt_found = 0x60
        if last_key:
            if drv.mifare_auth(block, last_key[0], card.uid, last_key[1]):
                key_found, kt_found = last_key
        if not key_found:
            for key in HOTEL_KEYS:
                if drv.mifare_auth(block, key, card.uid, 0x60):
                    key_found = key; kt_found = 0x60; break
        if not key_found:
            for key in HOTEL_KEYS[:10]:
                if drv.mifare_auth(block, key, card.uid, 0x61):
                    key_found = key; kt_found = 0x61; break
        blocks = []
        if key_found:
            last_key = (key_found, kt_found)
            for b in range(4):
                data = drv.mifare_read(block + b)
                blocks.append(data.hex() if data else "?" * 32)
        hints = _interpret_sector(blocks, sec) if blocks else []
        sectors.append({"sector": sec, "blocks": blocks,
                        "key": key_found.hex().upper() if key_found else "",
                        "key_type": "A" if kt_found == 0x60 else "B",
                        "hints": hints})
        if key_found:
            print(f"    key={key_found.hex().upper()} type={'A' if kt_found == 0x60 else 'B'}"
                  + (f"  hints={hints}" if hints else ""), flush=True)
        else:
            print("    locked (no key found)", flush=True)

    cracked = sum(1 for s in sectors if s["key"])
    print(f"Read complete: {cracked}/16 sectors read.  UID: {card.uid_hex}", flush=True)
    return card, sectors


def _save_hotel_dump(card, sectors):
    if not (card and sectors):
        print("No dump loaded yet. Read a card first.", flush=True)
        return
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"hotel_{card.uid_hex}_{ts}.json"
    with open(os.path.join(LOOT_DIR, fname), "w") as f:
        json.dump({"uid": card.uid_hex, "type": card.card_type, "sectors": sectors, "timestamp": ts}, f, indent=2)
    print(f"Saved: {os.path.join(LOOT_DIR, fname)}", flush=True)


def main():
    print("Detecting reader...", flush=True)
    drv, drv_desc = auto_detect()
    print(f"Reader: {drv_desc}", flush=True)
    print(f"{len(HOTEL_KEYS)} hotel keys loaded.", flush=True)
    card = None
    sectors = []

    try:
        while True:
            if drv is None:
                print("No reader connected.", flush=True)
                break
            print("\n1) Read hotel card", flush=True)
            print("2) Save last read dump to loot", flush=True)
            print("3) Exit", flush=True)
            choice = _prompt("Select option [1-3]: ")

            if choice in ("3", "", "exit", "quit"):
                break
            elif choice == "1":
                card, sectors = _read_hotel_card(drv)
            elif choice == "2":
                _save_hotel_dump(card, sectors)
            else:
                print(f"Unknown option: {choice}", flush=True)
    finally:
        if drv:
            drv.close()

    print("Exiting.", flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
