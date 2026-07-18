#!/usr/bin/env python3
# @name: NFC Cloner
# @desc: Clone NFC cards: load a saved dump and write it to a new card.
# @category: nfc_rfid
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- NFC Cloner
=================================
Clone NFC cards: load a saved dump and write it to a new card.
Supports MIFARE Classic and Ultralight/NTAG.
Magic card (Gen1a/Gen2) detection for UID cloning.

Controls:
  Usage: nfc_cloner.py [--verify]

  Presents a numbered menu of saved dumps:
    1) <uid> <type> ...
    2) ...
    v) toggle verify mode
    d) delete a dump
    q) quit
  Selecting a dump prompts for the target card, then streams clone
  progress (sector/page counters) to stdout. Press Ctrl-C to exit.
"""

from payloads._web_input import request_input
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads.nfc_rfid._nfc_driver import auto_detect, is_classic, is_ultralight
from payloads.nfc_rfid._nfc_keys import KNOWN_KEYS
from payloads.nfc_rfid._nfc_cards import list_dumps, load_dump, save_dump


def _prompt(msg):
    try:
        return request_input(msg).strip()
    except EOFError:
        return ""


def _is_magic_card(drv, uid):
    """Detect if card is a Gen1a magic card (supports backdoor commands)."""
    try:
        # Gen1a: auth with any key on block 0 works without prior auth
        for key in [bytes.fromhex("FFFFFFFFFFFF"), bytes.fromhex("000000000000")]:
            if drv.mifare_auth(0, key, uid, 0x60):
                data = drv.mifare_read(0)
                if data:
                    return True
        return False
    except Exception:
        return False


def _clone_classic(drv, uid, dump, verify=False):
    """Write MIFARE Classic sectors from dump to target card."""
    sectors = dump.get("sectors", [])
    total = len(sectors)
    written = 0
    skipped = 0
    errors = 0
    verified = 0
    magic = _is_magic_card(drv, uid)
    print(f"Target: {uid.hex().upper()}  Magic card: {'yes' if magic else 'no'}", flush=True)

    for idx, sec in enumerate(sectors):
        print(f"  Sector {idx + 1}/{total}  written={written} skipped={skipped} errors={errors}", flush=True)

        blocks = sec.get("blocks", [])
        key_hex = sec.get("key", "")
        sec_num = sec.get("sector", idx)

        if not blocks or not key_hex:
            skipped += 1
            continue

        first_block = sec_num * 4
        # Auth target card
        src_key = bytes.fromhex(key_hex)
        authed = drv.mifare_auth(first_block, src_key, uid, 0x60)
        if not authed:
            # Try default keys on target
            for dk in KNOWN_KEYS[:20]:
                if drv.mifare_auth(first_block, dk, uid, 0x60):
                    authed = True
                    break
        if not authed:
            errors += 1
            continue

        for i, blk_hex in enumerate(blocks):
            block_num = first_block + i
            if not magic and block_num == 0:
                continue
            if i == 3:
                continue
            if not blk_hex or blk_hex == "?" * 32:
                continue
            try:
                data = bytes.fromhex(blk_hex)
                if drv.mifare_write(block_num, data):
                    written += 1
                    if verify:
                        readback = drv.mifare_read(block_num)
                        if readback and readback == data:
                            verified += 1
                else:
                    errors += 1
            except Exception:
                errors += 1

    return written, skipped, errors, verified, magic


def _clone_ultralight(drv, uid, dump):
    """Write Ultralight/NTAG pages from dump to target card."""
    pages = dump.get("pages", [])
    written = 0
    skipped = 0
    errors = 0

    # Skip first 4 pages (UID/lock/CC) - start from page 4
    for i in range(4, len(pages)):
        print(f"  Page {i}/{len(pages)}  written={written} skipped={skipped} errors={errors}", flush=True)

        page_hex = pages[i]
        if not page_hex:
            skipped += 1
            continue
        try:
            data = bytes.fromhex(page_hex)
            if drv.mifare_ul_write(i, data):
                written += 1
            else:
                errors += 1
        except Exception:
            errors += 1

    return written, skipped, errors


def main():
    verify_mode = "--verify" in sys.argv[1:]

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

            if not drv.can_write:
                print(f"Reader can't write ({drv_desc}); need a PN532 for cloning.", flush=True)
                break

            dumps = list_dumps()
            print(f"\nSaved dumps: {len(dumps)}  Verify mode: {'ON' if verify_mode else 'OFF'}", flush=True)
            if not dumps:
                print("No saved cards. Use the NFC Reader payload first.", flush=True)
                break

            for i, dm in enumerate(dumps, start=1):
                print(f"  {i}) {dm['uid']}  {dm['type']}", flush=True)
            print("v) toggle verify mode   d) delete a dump   q) quit", flush=True)

            choice = _prompt("Select dump to clone (number), or v/d/q: ").lower()
            if choice in ("q", "quit", "exit", ""):
                break
            elif choice == "v":
                verify_mode = not verify_mode
                print(f"Verify mode: {'ON' if verify_mode else 'OFF'}", flush=True)
                continue
            elif choice == "d":
                sel = _prompt("Enter number to delete: ")
                try:
                    idx = int(sel) - 1
                except ValueError:
                    print(f"Invalid selection: {sel}", flush=True)
                    continue
                if 0 <= idx < len(dumps):
                    try:
                        os.remove(dumps[idx]["path"])
                        print(f"Deleted {dumps[idx]['uid']}.", flush=True)
                    except Exception as exc:
                        print(f"Delete failed: {exc}", flush=True)
                else:
                    print(f"Invalid selection: {sel}", flush=True)
                continue

            try:
                idx = int(choice) - 1
            except ValueError:
                print(f"Invalid selection: {choice}", flush=True)
                continue
            if not (0 <= idx < len(dumps)):
                print(f"Invalid selection: {choice}", flush=True)
                continue

            dump = load_dump(dumps[idx]["path"])
            if not dump:
                print("Failed to load dump.", flush=True)
                continue

            print(f"Source: {dump.get('uid', '?')}", flush=True)
            _prompt("Place TARGET card on reader, then press Enter (Ctrl-C to cancel)...")
            print("Polling...", flush=True)
            card = drv.read_passive_target(timeout=10.0)
            if not card:
                print("No target card detected.", flush=True)
                continue

            if dump.get("sectors"):
                w, s, e, v, magic = _clone_classic(drv, card.uid, dump, verify_mode)
                if e == 0 and w > 0:
                    msg = f"Cloned! {w} blocks written{' (magic card)' if magic else ''}"
                    if verify_mode:
                        msg += f", {v} verified"
                    print(msg, flush=True)
                else:
                    print(f"Done. written={w} skipped={s} errors={e}", flush=True)
            elif dump.get("pages"):
                w, s, e = _clone_ultralight(drv, card.uid, dump)
                if e == 0 and w > 0:
                    print(f"Cloned! {w} pages written.", flush=True)
                else:
                    print(f"Done. written={w} skipped={s} errors={e}", flush=True)
            else:
                print("Empty dump; nothing to write.", flush=True)

    finally:
        if drv:
            drv.close()

    print("Exiting.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
