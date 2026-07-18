#!/usr/bin/env python3
# @name: NFC NDEF Writer
# @desc: Write NDEF records (URL, text, WiFi config) to Ultralight/NTAG tags.
# @category: nfc_rfid
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- NFC NDEF Writer
=======================================
Write NDEF records (URL, text, WiFi config) to Ultralight/NTAG tags.
Useful for demos, rickrolls, and WiFi config sharing.

Controls:
  Usage: nfc_ndef_writer.py

  Presents a numbered menu of templates (URL, Text, WiFi, Phone,
  Email, Rickroll). After selecting one, prompts for the text to write
  (with the template default shown), then prompts for tag placement
  and streams write progress (page counters) to stdout. Press Ctrl-C
  to cancel/exit.
"""

from payloads._web_input import request_input
import os
import sys
import time

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads.nfc_rfid._nfc_driver import auto_detect, is_ultralight

CHARSET = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/:@?=&#!+%"

TEMPLATES = [
    {"name": "URL", "prefix": "https://", "text": "example.com"},
    {"name": "Text", "prefix": "", "text": "Hello World"},
    {"name": "WiFi", "prefix": "WIFI:T:WPA;S:", "text": "MySSID;P:password;;"},
    {"name": "Phone", "prefix": "tel:", "text": "+33600000000"},
    {"name": "Email", "prefix": "mailto:", "text": "user@example.com"},
    {"name": "Rickroll", "prefix": "https://", "text": "youtu.be/dQw4w9WgXcQ"},
]

URL_PREFIXES = {
    "http://www.": 0x01, "https://www.": 0x02,
    "http://": 0x03, "https://": 0x04,
    "tel:": 0x05, "mailto:": 0x06,
}


def _prompt(msg):
    try:
        return request_input(msg).strip()
    except EOFError:
        return ""


def _build_ndef_url(url: str) -> bytes:
    """Build NDEF TLV for a URL record."""
    prefix_byte = 0x00
    payload_str = url
    for prefix, code in URL_PREFIXES.items():
        if url.startswith(prefix):
            prefix_byte = code
            payload_str = url[len(prefix):]
            break
    payload = bytes([prefix_byte]) + payload_str.encode("utf-8")
    # NDEF record: MB|ME|SR|TNF=0x01, type_len=1, payload_len, type="U", payload
    record = bytes([0xD1, 0x01, len(payload), 0x55]) + payload
    # TLV: type=0x03, length, data, terminator=0xFE
    tlv = bytes([0x03, len(record)]) + record + bytes([0xFE])
    return tlv


def _build_ndef_text(text: str) -> bytes:
    """Build NDEF TLV for a text record."""
    lang = b"en"
    payload = bytes([len(lang)]) + lang + text.encode("utf-8")
    record = bytes([0xD1, 0x01, len(payload), 0x54]) + payload
    tlv = bytes([0x03, len(record)]) + record + bytes([0xFE])
    return tlv


def _write_ndef_to_tag(drv, ndef_bytes: bytes):
    """Write NDEF TLV to Ultralight/NTAG starting at page 4."""
    # Pad to 4-byte page boundary
    data = ndef_bytes
    while len(data) % 4:
        data += b"\x00"

    total_pages = len(data) // 4
    written = 0

    for i in range(total_pages):
        print(f"  Page {4 + i}/{4 + total_pages}  written={written}", flush=True)
        page_data = data[i * 4:(i + 1) * 4]
        if drv.mifare_ul_write(4 + i, page_data):
            written += 1
        else:
            return written, total_pages

    return written, total_pages


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

            print("\nTemplates:", flush=True)
            for i, tmpl in enumerate(TEMPLATES, start=1):
                print(f"  {i}) {tmpl['name']}  ({tmpl['prefix']}{tmpl['text']})", flush=True)

            choice = _prompt("Select template (number), or q to quit: ").lower()
            if choice in ("q", "quit", "exit", ""):
                break
            try:
                idx = int(choice) - 1
            except ValueError:
                print(f"Invalid selection: {choice}", flush=True)
                continue
            if not (0 <= idx < len(TEMPLATES)):
                print(f"Invalid selection: {choice}", flush=True)
                continue

            tmpl = TEMPLATES[idx]
            default_text = tmpl["prefix"] + tmpl["text"]
            entered = _prompt(f"Text to write [{default_text}]: ")
            current_text = entered if entered else default_text

            if not drv.can_write:
                print("Reader can't write.", flush=True)
                continue

            if tmpl["name"] == "Text":
                ndef = _build_ndef_text(current_text)
            else:
                ndef = _build_ndef_url(current_text)

            _prompt("Place NTAG/UL tag on reader, then press Enter (Ctrl-C to cancel)...")
            print("Polling...", flush=True)
            card = drv.read_passive_target(timeout=8.0)
            if not card:
                print("No tag detected.", flush=True)
                continue
            if not is_ultralight(card):
                print(f"Not UL/NTAG: {card.card_type}", flush=True)
                continue

            written, total = _write_ndef_to_tag(drv, ndef)
            if written == total:
                print(f"Written! {len(ndef)} bytes ({written}/{total} pages).", flush=True)
            else:
                print(f"Partial write: {written}/{total} pages.", flush=True)

    except KeyboardInterrupt:
        print("\nStopped by user.", flush=True)
    finally:
        if drv:
            drv.close()

    print("Exiting.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
