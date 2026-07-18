#!/usr/bin/env python3
# @name: NFC Card Manager
# @desc: Browse, view, delete and export saved NFC card dumps.
# @category: nfc_rfid
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- NFC Card Manager
========================================
Browse, view, delete and export saved NFC card dumps.
Supports Flipper Zero .nfc export format.

Controls:
  Usage: nfc_saved.py

  Presents a numbered menu of saved dumps:
    <number>  view card detail (UID, type, sectors/pages, NDEF)
    e <n>     export dump <n> to Flipper .nfc format
    d <n>     delete dump <n>
    q         quit
"""

from payloads._web_input import request_input
import os
import sys
import time

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads.nfc_rfid._nfc_cards import list_dumps, load_dump, export_flipper_nfc


def _prompt(msg):
    try:
        return request_input(msg).strip()
    except EOFError:
        return ""


def _print_detail(dump):
    print(f"UID: {dump.get('uid', '?')}", flush=True)
    print(f"Type: {dump.get('type', '?')}", flush=True)
    print(f"Date: {dump.get('timestamp', '?')}", flush=True)

    secs = dump.get("sectors", [])
    pages = dump.get("pages", [])
    ndef = dump.get("ndef", [])

    if secs:
        cracked = sum(1 for s in secs if s.get("key"))
        print(f"Sectors: {cracked}/{len(secs)} cracked", flush=True)
        for s in secs:
            key_txt = s["key"] if s.get("key") else "LOCKED"
            print(f"  S{s['sector']:02d} {key_txt}", flush=True)

    if pages:
        print(f"Pages: {len(pages)}", flush=True)
        for i, p in enumerate(pages):
            print(f"  P{i:03d} {p if p else '--------'}", flush=True)

    if ndef:
        for r in ndef:
            print(f"  [{r['kind']}] {r['parsed']}", flush=True)


def main():
    try:
        while True:
            dumps = list_dumps()
            print(f"\nSaved dumps: {len(dumps)}", flush=True)
            if not dumps:
                print("No saved cards. Use the NFC Reader payload first.", flush=True)
                return 0

            for i, dm in enumerate(dumps, start=1):
                info = f"{dm['sectors']} sectors" if dm['sectors'] else f"{dm['pages']} pages"
                print(f"  {i}) {dm['uid']}  {dm['type']}  ({info})", flush=True)
            print("Commands: <number>=view  e <n>=export .nfc  d <n>=delete  q=quit", flush=True)

            choice = _prompt("Select: ").strip()
            if choice.lower() in ("q", "quit", "exit", ""):
                break

            parts = choice.split()
            cmd = parts[0].lower()

            if cmd in ("e", "export") and len(parts) > 1:
                try:
                    idx = int(parts[1]) - 1
                except ValueError:
                    print(f"Invalid selection: {parts[1]}", flush=True)
                    continue
                if not (0 <= idx < len(dumps)):
                    print(f"Invalid selection: {parts[1]}", flush=True)
                    continue
                dump = load_dump(dumps[idx]["path"])
                if dump:
                    path = export_flipper_nfc(dump)
                    if path:
                        print(f"Exported: {path}", flush=True)
                    else:
                        print("Export failed.", flush=True)
                else:
                    print("Load failed.", flush=True)
                continue

            if cmd in ("d", "delete") and len(parts) > 1:
                try:
                    idx = int(parts[1]) - 1
                except ValueError:
                    print(f"Invalid selection: {parts[1]}", flush=True)
                    continue
                if not (0 <= idx < len(dumps)):
                    print(f"Invalid selection: {parts[1]}", flush=True)
                    continue
                try:
                    os.remove(dumps[idx]["path"])
                    print(f"Deleted {dumps[idx]['uid']}.", flush=True)
                except Exception as exc:
                    print(f"Delete failed: {exc}", flush=True)
                continue

            try:
                idx = int(cmd) - 1
            except ValueError:
                print(f"Invalid selection: {choice}", flush=True)
                continue
            if not (0 <= idx < len(dumps)):
                print(f"Invalid selection: {choice}", flush=True)
                continue

            dump = load_dump(dumps[idx]["path"])
            if not dump:
                print("Load failed.", flush=True)
                continue
            _print_detail(dump)
    except KeyboardInterrupt:
        print("\nStopped by user.", flush=True)

    print("Exiting.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
