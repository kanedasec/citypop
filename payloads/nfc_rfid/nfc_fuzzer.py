#!/usr/bin/env python3
# @name: NFC APDU Fuzzer
# @desc: Interactive APDU terminal for exploring unknown NFC cards.
# @category: nfc_rfid
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- NFC APDU Fuzzer
=======================================
Interactive APDU terminal for exploring unknown NFC cards.
Send arbitrary commands, decode responses, scan SFI/records.

Controls:
  Usage: nfc_fuzzer.py

  Prompts for card placement, then presents a numbered menu:
    1..N  send a template APDU and print the response/status word
    s     scan all SFI/record combinations, streaming progress
    r     re-place a card
    q     quit
  Press Ctrl-C to stop a running scan or exit.
"""
from payloads._web_input import request_input
import os, sys, time
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
from payloads.nfc_rfid._nfc_driver import auto_detect

HEX_CHARS = "0123456789ABCDEF"

SW_CODES = {
    "9000": "OK", "6A82": "File not found", "6A86": "P1P2 incorrect",
    "6985": "Conditions not satisfied", "6D00": "INS not supported",
    "6E00": "CLA not supported", "6700": "Wrong length",
    "6300": "Auth failed", "6982": "Security not satisfied",
    "6A81": "Function not supported", "6A88": "Data not found",
    "6F00": "Internal error", "6283": "Selected file invalidated",
}

TEMPLATES = [
    ("SELECT PPSE", "00A404000E325041592E5359532E444446303100"),
    ("SELECT Visa", "00A4040007A000000003101000"),
    ("SELECT MC", "00A4040007A000000004101000"),
    ("SELECT CB", "00A4040007A000000042101000"),
    ("GPO", "80A8000002830000"),
    ("READ REC 1,1", "00B2010C00"),
    ("READ REC 1,2", "00B2011400"),
    ("READ REC 2,1", "00B2010C00"),
    ("GET DATA ATC", "80CA9F3600"),
    ("GET DATA PIN", "80CA9F1700"),
    ("GET CHALLENGE", "0084000008"),
]

def _prompt(msg):
    try:
        return request_input(msg).strip()
    except EOFError:
        return ""

def _decode_sw(resp_hex):
    if len(resp_hex) >= 4:
        sw = resp_hex[-4:].upper()
        return SW_CODES.get(sw, f"SW:{sw}")
    return ""

def _scan_sfi(drv):
    """Scan all SFI/records, print found records, return count."""
    found = 0
    try:
        for sfi in range(1, 32):
            for rec in range(1, 6):
                p2 = (sfi << 3) | 0x04
                apdu = bytes([0x00, 0xB2, rec, p2, 0x00])
                resp = drv.data_exchange(apdu, timeout=0.3)
                if resp and len(resp) > 2:
                    resp_hex = resp.hex().upper()
                    sw = _decode_sw(resp_hex)
                    if "9000" in resp_hex[-4:] or len(resp) > 4:
                        found += 1
                        print(f"  SFI{sfi} REC{rec}: {resp_hex[:32]}  {sw}", flush=True)
            if sfi % 4 == 0 or sfi == 31:
                pct = sfi * 100 // 31
                print(f"  [{pct}%] SFI {sfi}/31  Found: {found}", flush=True)
    except KeyboardInterrupt:
        print("\nScan stopped by user.", flush=True)
    return found

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
            if not card:
                print("No card detected.", flush=True)
                choice = _prompt("Retry? [y/N]: ").lower()
                if choice != "y":
                    break
                continue

            print(f"Card: {card.uid_hex}", flush=True)

            while True:
                print("\nTemplates:", flush=True)
                for i, (name, apdu_hex) in enumerate(TEMPLATES, start=1):
                    print(f"  {i}) {name}  ({apdu_hex[:16]}...)" if len(apdu_hex) > 16
                          else f"  {i}) {name}  ({apdu_hex})", flush=True)
                print("s) scan all SFI/records   r) re-place card   q) quit", flush=True)

                choice = _prompt("Select: ").lower()
                if choice in ("q", "quit", "exit", ""):
                    return 0
                elif choice == "r":
                    break
                elif choice == "s":
                    print("Scanning all SFI/record combinations...", flush=True)
                    found = _scan_sfi(drv)
                    print(f"Found {found} records.", flush=True)
                    continue

                try:
                    idx = int(choice) - 1
                except ValueError:
                    print(f"Invalid selection: {choice}", flush=True)
                    continue
                if not (0 <= idx < len(TEMPLATES)):
                    print(f"Invalid selection: {choice}", flush=True)
                    continue

                name, apdu_hex = TEMPLATES[idx]
                apdu = bytes.fromhex(apdu_hex)
                resp = drv.data_exchange(apdu)
                resp_hex = resp.hex().upper() if resp else "NO RESPONSE"
                sw = _decode_sw(resp_hex) if resp else ""
                print(f"{name}: {resp_hex}  {sw}", flush=True)
    except KeyboardInterrupt:
        print("\nStopped by user.", flush=True)
    finally:
        if drv:
            drv.close()

    print("Exiting.", flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
