#!/usr/bin/env python3
# @name: Magic Card Detector
# @desc: Detect magic card type: Gen1a, Gen2 (CUID), Gen3 (UFUID), Gen4 (GDM), or Original.
# @category: nfc_rfid
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- Magic Card Detector
==========================================
Detect magic card type: Gen1a, Gen2 (CUID), Gen3 (UFUID), Gen4 (GDM), or Original.

Controls:
  Usage: nfc_magic.py

  Prompts for card placement, then runs the magic-card detection
  sequence and prints the UID, card type, magic generation and cloning
  capability to stdout. Prompts to scan another card. Press Ctrl-C to
  stop.
"""
from payloads._web_input import request_input
import os, sys, time
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
from payloads.nfc_rfid._nfc_driver import auto_detect, is_classic

def _prompt(msg):
    try:
        return request_input(msg).strip()
    except EOFError:
        return ""

def _reselect(drv, timeout=1.0):
    """Re-detect card after auth failure (card goes to HALT state)."""
    return drv.read_passive_target(timeout=timeout)


def _detect_magic(drv, uid):
    """Detect magic card generation. Returns (type_name, details)."""
    key_ff = bytes.fromhex("FFFFFFFFFFFF")
    key_rand = bytes.fromhex("DEADBEEF1337")

    # Test 1: Auth block 0 with default key
    auth_ff = drv.mifare_auth(0, key_ff, uid, 0x60)
    if not auth_ff:
        return "Original", "Cannot auth block 0 with default key"

    # Read block 0
    block0 = drv.mifare_read(0)
    if not block0:
        return "Unknown", "Cannot read block 0"

    # Test 2: Try writing block 0 (flip one bit, then restore)
    original_b0 = block0
    test_data = bytes([block0[0] ^ 0x01]) + block0[1:]

    drv.mifare_auth(0, key_ff, uid, 0x60)
    write_ok = drv.mifare_write(0, test_data)

    if write_ok:
        # Restore immediately
        drv.mifare_auth(0, key_ff, uid, 0x60)
        drv.mifare_write(0, original_b0)

        # Test 3: Re-detect card and try random key
        _reselect(drv)
        auth_rand = drv.mifare_auth(0, key_rand, uid, 0x60)

        if auth_rand:
            return "Gen1a", "Any key accepted + Block 0 writable"

        # Re-detect after failed auth
        _reselect(drv)

        # Test 4: Gen4 detection
        if drv.mifare_auth(0, key_ff, uid, 0x60):
            gen4_cmd = bytes.fromhex("CF00000000CE")
            resp = drv.data_exchange(gen4_cmd, timeout=0.3)
            if resp:
                return "Gen4 (GDM)", "Block 0 writable + Gen4 config"

        return "Gen2 (CUID)", "Block 0 writable with default key"
    else:
        # Cannot write block 0 — check SAK for hints
        if uid[0] == 0x04:
            return "Original (NXP)", "Block 0 read-only, genuine NXP"
        return "Original / Gen3 locked", "Block 0 read-only"


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
            card = drv.read_passive_target(timeout=5.0)
            if card and is_classic(card):
                print(f"UID: {card.uid_hex}  Type: {card.card_type}", flush=True)
                print("Detecting magic generation...", flush=True)
                magic_type, detail = _detect_magic(drv, card.uid)
                print(f"Result: {magic_type} - {detail}", flush=True)

                if "Gen1" in magic_type or "Gen2" in magic_type:
                    print("UID cloning: YES  (full clone possible)", flush=True)
                elif "Gen4" in magic_type:
                    print("Advanced clone: YES  (configurable magic)", flush=True)
                else:
                    print("UID cloning: NO  (data-only clone)", flush=True)
            elif card:
                print(f"Not Classic: {card.card_type}", flush=True)
            else:
                print("No card detected.", flush=True)

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
