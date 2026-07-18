#!/usr/bin/env python3
# @name: NFC Reader
# @desc: Read and identify NFC cards.
# @category: nfc_rfid
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- NFC Reader
=================================
Read and identify NFC cards. Supports MIFARE Classic, Ultralight, NTAG, EMV.
Auto-detects PN532 (UART/I2C) and USB readers (ACR122U, SCL3711).

Controls:
  Usage: nfc_reader.py

  Prompts for card placement, then reads the card (streaming per-sector
  or per-page progress to stdout) and prints a summary: UID, type,
  sector/page status, NDEF records and EMV applications. Prompts to
  show a full hex dump and to save the dump to loot, then to scan
  another card. Press Ctrl-C at any time to stop.
"""

from payloads._web_input import request_input
import os
import sys
import time

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads.nfc_rfid._nfc_driver import auto_detect, CardInfo, is_classic, is_ultralight, is_emv
from payloads.nfc_rfid._nfc_keys import KNOWN_KEYS, try_all_keys
from payloads.nfc_rfid._nfc_cards import (
    parse_ndef, read_ultralight_pages, detect_ntag_type,
    ntag_user_pages, save_dump,
)

FAST_KEYS = KNOWN_KEYS[:5]


def _prompt(msg):
    try:
        return request_input(msg).strip()
    except EOFError:
        return ""


def _read_classic(drv, card):
    """Read MIFARE Classic sectors with progress."""
    uid = card.uid
    n_sectors = 16 if "1K" in card.card_type or "Classic" in card.card_type else 40
    if "Mini" in card.card_type:
        n_sectors = 5
    if "4K" in card.card_type:
        n_sectors = 40

    sectors = []
    last_good_key = None

    for sec in range(n_sectors):
        authed_count = sum(1 for s in sectors if s["key"])
        print(f"  Sector {sec}/{n_sectors}  cracked={authed_count} locked={sec - authed_count}", flush=True)

        block = sec * 4 if sec < 32 else 128 + (sec - 32) * 16
        key_found = None
        kt_found = 0x60

        # Try last successful key first (most cards use same key for all sectors)
        if last_good_key:
            if drv.mifare_auth(block, last_good_key[0], uid, last_good_key[1]):
                key_found = last_good_key[0]
                kt_found = last_good_key[1]

        # Try fast key list - Key A only first
        if not key_found:
            for key in FAST_KEYS:
                if drv.mifare_auth(block, key, uid, 0x60):
                    key_found = key
                    kt_found = 0x60
                    break

        # Key B only if A failed
        if not key_found:
            for key in FAST_KEYS:
                if drv.mifare_auth(block, key, uid, 0x61):
                    key_found = key
                    kt_found = 0x61
                    break

        if key_found:
            last_good_key = (key_found, kt_found)

        blocks = []
        if key_found:
            n_blocks = 4 if sec < 32 else 16
            for b in range(n_blocks):
                data = drv.mifare_read(block + b)
                blocks.append(data.hex() if data else "?" * 32)

        sectors.append({
            "sector": sec,
            "blocks": blocks,
            "key": key_found.hex().upper() if key_found else "",
            "key_type": "A" if kt_found == 0x60 else "B",
        })

    return {"sectors": sectors}


def _read_ultralight(drv, card):
    """Read Ultralight/NTAG pages with progress."""
    print("  Reading pages...", flush=True)

    pages = read_ultralight_pages(drv, max_pages=45)
    ntag_type = detect_ntag_type(pages)

    # Rebuild with correct page count
    total_pages = ntag_user_pages(pages) + 4
    if total_pages > 45:
        print(f"  Re-reading with {total_pages} pages...", flush=True)
        pages = read_ultralight_pages(drv, max_pages=total_pages)

    page_hexes = []
    for p in pages:
        page_hexes.append(p.hex() if p else None)

    # Parse NDEF from user pages (starting page 4)
    raw = b""
    for p in pages[4:]:
        if p:
            raw += p
        else:
            break
    ndef_records = parse_ndef(raw)

    return {
        "ntag_type": ntag_type,
        "pages": page_hexes,
        "ndef": [{"kind": r["kind"], "parsed": r["parsed"]} for r in ndef_records],
    }


def _read_emv(drv, card):
    """Read EMV contactless card via APDU."""
    # SELECT PPSE (Proximity Payment System Environment)
    select_ppse = bytes.fromhex("00A404000E325041592E5359532E444446303100")
    resp = drv.data_exchange(select_ppse)
    if not resp:
        return {"emv": "No PPSE response"}

    result = {"emv_raw": resp.hex(), "apps": []}

    # Try to parse basic TLV for application names
    # SELECT each application
    select_aid_prefix = bytes.fromhex("00A40400")
    common_aids = [
        ("Visa", "A0000000031010"),
        ("Mastercard", "A0000000041010"),
        ("Amex", "A00000002501"),
        ("CB", "A0000000421010"),
        ("JCB", "A0000000651010"),
    ]

    for name, aid in common_aids:
        aid_bytes = bytes.fromhex(aid)
        apdu = select_aid_prefix + bytes([len(aid_bytes)]) + aid_bytes + b"\x00"
        resp = drv.data_exchange(apdu)
        if resp and len(resp) > 2:
            result["apps"].append({"name": name, "aid": aid, "response": resp.hex()[:40]})

    return result


def _print_summary(card, card_data):
    print(f"UID: {card.uid_hex}", flush=True)
    print(f"Type: {card.card_type}", flush=True)
    print(f"ATQA: {card.atqa:04X}  SAK: {card.sak:02X}", flush=True)

    sectors = card_data.get("sectors", [])
    if sectors:
        authed = sum(1 for s in sectors if s.get("key"))
        print(f"Sectors: {authed}/{len(sectors)} cracked", flush=True)
        for s in sectors:
            key_txt = f"{s['key']} ({s['key_type']})" if s.get("key") else "LOCKED"
            print(f"  S{s['sector']:02d}  {key_txt}", flush=True)

    pages = card_data.get("pages", [])
    if pages:
        ntag = card_data.get("ntag_type", "")
        print(f"{ntag}  {len(pages)} pages", flush=True)

    ndef = card_data.get("ndef", [])
    if ndef:
        print(f"NDEF: {len(ndef)} record(s)", flush=True)
        for r in ndef:
            print(f"  [{r['kind']}] {r['parsed']}", flush=True)

    apps = card_data.get("apps", [])
    if apps:
        print(f"EMV: {len(apps)} app(s)", flush=True)
        for a in apps:
            print(f"  {a['name']}: {a['aid']}", flush=True)


def _print_hex_dump(card_data):
    sectors = card_data.get("sectors", [])
    pages = card_data.get("pages", [])
    if sectors:
        for s in sectors:
            for i, blk in enumerate(s.get("blocks", [])):
                print(f"  B{s['sector']*4+i:03d} {blk}", flush=True)
    elif pages:
        for i, p in enumerate(pages):
            print(f"  P{i:03d} {p if p else '--------'}", flush=True)
    else:
        print("  (no raw data)", flush=True)


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
            card = drv.read_passive_target(timeout=3.0)
            if not card:
                print("No card detected.", flush=True)
            else:
                print(f"Reading {card.card_type}...", flush=True)
                if is_classic(card):
                    card_data = _read_classic(drv, card)
                elif is_ultralight(card):
                    card_data = _read_ultralight(drv, card)
                elif is_emv(card):
                    card_data = _read_emv(drv, card)
                else:
                    card_data = {}

                _print_summary(card, card_data)

                choice = _prompt("Show full hex dump? [y/N]: ").lower()
                if choice == "y":
                    _print_hex_dump(card_data)

                if card_data:
                    choice = _prompt("Save dump to loot? [y/N]: ").lower()
                    if choice == "y":
                        fname = save_dump(card.uid, card.card_type, card_data)
                        print(f"Saved: {fname}", flush=True)

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
