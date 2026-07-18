#!/usr/bin/env python3
# @name: Amiibo Reader/Cloner
# @desc: Read, identify and clone Nintendo Amiibo (NTAG215).
# @category: nfc_rfid
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- Amiibo Reader/Cloner
============================================
Read, identify and clone Nintendo Amiibo (NTAG215).

Controls:
  Usage: nfc_amiibo.py

  Presents a numbered menu:
    1) Read Amiibo
    2) Clone last read Amiibo to a blank NTAG215
    3) Save last read dump to loot
    4) Exit
  Prompts interactively for placing the card on the reader. Progress and
  identification results are streamed to stdout. Press Ctrl-C to exit.
"""
from payloads._web_input import request_input
import os, sys, json
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
from payloads.nfc_rfid._nfc_driver import auto_detect, is_ultralight
from payloads.nfc_rfid._nfc_cards import read_ultralight_pages, save_dump

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'NFC', 'amiibo')

# Amiibo character database (top 50)
AMIIBO_DB = {
    "0000": "Mario", "0001": "Luigi", "0002": "Peach", "0003": "Yoshi",
    "0004": "Rosalina", "0005": "Bowser", "0006": "Bowser Jr", "0007": "Wario",
    "0008": "Donkey Kong", "0009": "Diddy Kong", "000a": "Toad", "000c": "Zelda",
    "000d": "Sheik", "000e": "Ganondorf", "000f": "Toon Link", "0010": "Samus",
    "0011": "Zero Suit Samus", "0013": "Fox", "0014": "Falco", "0017": "Pikachu",
    "0018": "Charizard", "0019": "Jigglypuff", "001a": "Mewtwo", "001b": "Lucario",
    "001c": "Greninja", "001f": "Marth", "0020": "Ike", "0021": "Lucina",
    "0022": "Robin", "0023": "Captain Falcon", "0024": "Villager",
    "0025": "Isabelle", "0028": "Kirby", "0029": "King Dedede",
    "002a": "Meta Knight", "002c": "Little Mac", "002f": "Pit",
    "0030": "Palutena", "0031": "Dark Pit", "0034": "Olimar",
    "0038": "Ness", "003c": "Shulk", "0100": "Inkling",
    "0101": "Inkling Boy", "0102": "Inkling Girl", "0103": "Callie",
    "0104": "Marie", "0200": "Tom Nook", "0201": "K.K. Slider",
    "0340": "Link", "0341": "Link (Rider)", "0342": "Link (Archer)",
}

GAME_SERIES = {
    "00": "Super Mario", "01": "Legend of Zelda", "02": "Animal Crossing",
    "03": "Star Fox", "04": "Metroid", "05": "F-Zero",
    "06": "Pikmin", "07": "Punch-Out", "08": "Wii Fit",
    "09": "Kid Icarus", "0a": "Fire Emblem", "0c": "Kirby",
    "0d": "Pokemon", "0e": "Splatoon", "0f": "Earthbound",
    "10": "Xenoblade", "19": "Smash Bros",
}

def _identify_amiibo(pages):
    """Identify amiibo from NTAG215 pages. Returns (name, series, char_id)."""
    if len(pages) < 23 or pages[21] is None or pages[22] is None:
        return None, None, None
    # Character ID is at pages 21-22 (bytes 84-91)
    char_bytes = pages[21] + pages[22]
    game_id = char_bytes[0:1].hex()
    char_id = char_bytes[0:2].hex()
    name = AMIIBO_DB.get(char_id, f"Unknown ({char_id})")
    series = GAME_SERIES.get(game_id, f"Series {game_id}")
    return name, series, char_id

def _is_amiibo(pages):
    """Check if tag looks like an Amiibo (7-byte UID + data at pages 21-22)."""
    if len(pages) < 23: return False
    if pages[21] is None or pages[22] is None: return False
    # Check page 21-22 have non-zero data (character ID area)
    return any(b != 0 for b in pages[21]) or any(b != 0 for b in pages[22])

def _prompt(msg):
    try:
        return request_input(msg).strip()
    except EOFError:
        return ""


def _do_read(drv):
    """Scan a card and try to identify it as an Amiibo. Returns (amiibo_data, pages) or (None, None)."""
    _prompt("Place Amiibo on reader, then press Enter...")
    print("Polling...", flush=True)
    card = drv.read_passive_target(timeout=5.0)
    if card and (is_ultralight(card) or len(card.uid) == 7):
        pages = read_ultralight_pages(drv, max_pages=135)
        if _is_amiibo(pages):
            name, series, char_id = _identify_amiibo(pages)
            amiibo_data = {"name": name, "series": series, "id": char_id, "uid": card.uid_hex}
            last_pages = [p.hex() if p else None for p in pages]
            print(f"Amiibo: {name}  Series: {series}  ID: {char_id}  UID: {card.uid_hex}", flush=True)
            return amiibo_data, last_pages
        print("Not an Amiibo (no character data found).", flush=True)
        return None, None
    elif card:
        print(f"Card is not Ultralight/NTAG (type: {card.card_type}).", flush=True)
        return None, None
    print("No card detected.", flush=True)
    return None, None


def _do_clone(drv, last_pages):
    if not last_pages:
        print("No dump loaded yet. Read an Amiibo first.", flush=True)
        return
    _prompt("Place blank NTAG215 on reader, then press Enter...")
    print("Polling...", flush=True)
    card = drv.read_passive_target(timeout=8.0)
    if card and is_ultralight(card):
        written = 0
        for i in range(3, 130):
            if i < len(last_pages) and last_pages[i]:
                data = bytes.fromhex(last_pages[i])
                if drv.mifare_ul_write(i, data):
                    written += 1
        print(f"Cloned! {written} pages written.", flush=True)
    else:
        print("No target tag detected.", flush=True)


def _do_save(amiibo_data, last_pages):
    if not (amiibo_data and last_pages):
        print("No dump loaded yet. Read an Amiibo first.", flush=True)
        return
    os.makedirs(LOOT_DIR, exist_ok=True)
    from datetime import datetime
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"amiibo_{amiibo_data.get('name', 'unknown')}_{ts}.json"
    with open(os.path.join(LOOT_DIR, fname), "w") as f:
        json.dump({**amiibo_data, "pages": last_pages, "timestamp": ts}, f, indent=2)
    print(f"Saved: {os.path.join(LOOT_DIR, fname)}", flush=True)


def main():
    print("Detecting reader...", flush=True)
    drv, drv_desc = auto_detect()
    print(f"Reader: {drv_desc}", flush=True)
    amiibo_data = None
    last_pages = None

    try:
        while True:
            if drv is None:
                print("No reader connected.", flush=True)
                break
            print("\n1) Read Amiibo", flush=True)
            print("2) Clone last read Amiibo to blank tag", flush=True)
            print("3) Save last read dump to loot", flush=True)
            print("4) Exit", flush=True)
            choice = _prompt("Select option [1-4]: ")

            if choice in ("4", "", "exit", "quit"):
                break
            elif choice == "1":
                amiibo_data, last_pages = _do_read(drv)
            elif choice == "2":
                _do_clone(drv, last_pages)
            elif choice == "3":
                _do_save(amiibo_data, last_pages)
            else:
                print(f"Unknown option: {choice}", flush=True)
    finally:
        if drv:
            drv.close()

    print("Exiting.", flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
