#!/usr/bin/env python3
# @name: NFC Card Formatter
# @desc: Erase/format NFC cards.
# @category: nfc_rfid
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- NFC Card Formatter
=========================================
Erase/format NFC cards. Reset data, keys, or NDEF.

Controls:
  Usage: nfc_format.py [mode]

  mode: 0=Quick Format (erase data, keep keys), 1=Full Format (erase
  all + reset keys), 2=NDEF Format (write empty NDEF). If omitted, a
  numbered prompt lets you pick. Confirms before erasing, then prompts
  for card placement and streams format progress to stdout.
"""
from payloads._web_input import request_input
import os, sys, time
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
from payloads.nfc_rfid._nfc_driver import auto_detect, is_classic, is_ultralight
from payloads.nfc_rfid._nfc_keys import KNOWN_KEYS

MODES = [
    ("Quick Format", "Erase data, keep keys"),
    ("Full Format", "Erase all + reset keys"),
    ("NDEF Format", "Write empty NDEF"),
]

def _prompt(msg):
    try:
        return request_input(msg).strip()
    except EOFError:
        return ""

def _format_classic(drv, uid, mode):
    """Format MIFARE Classic. Returns (formatted_blocks, errors)."""
    zeros = b"\x00" * 16
    trailer_default = bytes.fromhex("FFFFFFFFFFFF") + bytes.fromhex("FF078069") + bytes.fromhex("FFFFFFFFFFFF")
    formatted = 0
    errors = 0
    n_sectors = 16

    for sec in range(n_sectors):
        block = sec * 4
        print(f"  Sector {sec}/{n_sectors}  done={formatted} err={errors}", flush=True)

        authed = False
        for key in KNOWN_KEYS[:10]:
            for kt in [0x60, 0x61]:
                if drv.mifare_auth(block, key, uid, kt):
                    authed = True
                    break
            if authed: break

        if not authed:
            errors += 1
            continue

        for b in range(3):
            if block + b == 0: continue
            if drv.mifare_write(block + b, zeros):
                formatted += 1
            else:
                errors += 1

        if mode == 1:
            if drv.mifare_write(block + 3, trailer_default):
                formatted += 1
            else:
                errors += 1

    return formatted, errors

def _format_ultralight(drv, mode):
    """Format Ultralight/NTAG."""
    zeros = b"\x00\x00\x00\x00"
    formatted = 0
    errors = 0

    if mode == 2:
        ndef_empty = b"\x03\x00\xFE\x00"
        if drv.mifare_ul_write(4, ndef_empty):
            formatted += 1
            for p in range(5, 40):
                if drv.mifare_ul_write(p, zeros): formatted += 1
                else: break
        return formatted, errors

    for p in range(4, 40):
        print(f"  Page {p}/40  done={formatted} err={errors}", flush=True)
        if drv.mifare_ul_write(p, zeros):
            formatted += 1
        else:
            errors += 1
            break
    return formatted, errors

def main():
    args = sys.argv[1:]
    preset_mode = None
    if args:
        try:
            preset_mode = int(args[0])
        except ValueError:
            preset_mode = None
        if preset_mode is None or not (0 <= preset_mode < len(MODES)):
            print(f"Usage: {sys.argv[0]} [mode]  (mode 0-{len(MODES) - 1})", flush=True)
            return 1

    print("Detecting reader...", flush=True)
    drv, drv_desc = auto_detect()
    print(f"Reader: {drv_desc}", flush=True)
    if not drv:
        print("No NFC reader connected.", flush=True)
        return 1

    try:
        while True:
            if preset_mode is not None:
                sel = preset_mode
            else:
                print("\nFormat modes:", flush=True)
                for i, (name, desc) in enumerate(MODES):
                    print(f"  {i}) {name} - {desc}", flush=True)
                choice = _prompt("Select mode (number), or q to quit: ").lower()
                if choice in ("q", "quit", "exit", ""):
                    break
                try:
                    sel = int(choice)
                except ValueError:
                    print(f"Invalid selection: {choice}", flush=True)
                    continue
                if not (0 <= sel < len(MODES)):
                    print(f"Invalid selection: {choice}", flush=True)
                    continue

            name, desc = MODES[sel]
            print(f"Mode: {name} ({desc})", flush=True)
            confirm = _prompt("This will erase data. Type YES to confirm: ")
            if confirm != "YES":
                print("Cancelled.", flush=True)
                if preset_mode is not None:
                    break
                continue

            _prompt("Place card on reader, then press Enter (Ctrl-C to cancel)...")
            print("Polling...", flush=True)
            card = drv.read_passive_target(timeout=5.0)
            if card:
                if is_classic(card):
                    fmt, err = _format_classic(drv, card.uid, sel)
                    print(f"Done: {fmt} blocks written, {err} errors.", flush=True)
                elif is_ultralight(card):
                    fmt, err = _format_ultralight(drv, sel)
                    print(f"Done: {fmt} pages written, {err} errors.", flush=True)
                else:
                    print(f"Unsupported card type: {card.card_type}", flush=True)
            else:
                print("No card detected.", flush=True)

            if preset_mode is not None:
                break
            choice = _prompt("Format another card? [y/N]: ").lower()
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
