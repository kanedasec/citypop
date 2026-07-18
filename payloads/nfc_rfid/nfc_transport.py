#!/usr/bin/env python3
# @name: Transport Card Reader
# @desc: Read transit cards (Calypso/Navigo, MIFARE DESFire-based transport).
# @category: nfc_rfid
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- Transport Card Reader
=============================================
Read transit cards (Calypso/Navigo, MIFARE DESFire-based transport).
Extracts: card type, environment, contracts, counters, last events.

Controls:
  Usage: nfc_transport.py

  Prompts for card placement, reads the transport applet, and prints
  the network/environment, contracts, events and counters to stdout.
  Prompts to save the dump to loot and to scan another card. Press
  Ctrl-C at any time to stop.
"""
from payloads._web_input import request_input
import os, sys, time, json
from datetime import datetime
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
from payloads.nfc_rfid._nfc_driver import auto_detect

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'NFC', 'transport')

TRANSPORT_AIDS = [
    ("Calypso", "315449432E494341"),
    ("Navigo", "A00000000401"),
    ("Calypso2", "A000000404"),
    ("Intercode", "315449432E494341D380"),
    ("RATP", "A00000000401"),
]

CALYPSO_SFIS = {
    0x07: "Environment",
    0x08: "Events Log",
    0x09: "Contracts",
    0x0A: "Counters",
    0x19: "Special Events",
    0x1D: "Contract List",
}

NETWORKS = {
    "0001": "RATP (Paris)", "0002": "SNCF", "0003": "TCL (Lyon)",
    "0004": "TAN (Nantes)", "0005": "RTM (Marseille)",
    "0006": "TBC (Bordeaux)", "0007": "Tiseo (Toulouse)",
    "0064": "Ile-de-France Mobilites", "0100": "STIB (Brussels)",
    "0115": "De Lijn", "0116": "TEC",
}

def _prompt(msg):
    try:
        return request_input(msg).strip()
    except EOFError:
        return ""

def _read_transport(drv):
    """Try to read transport card via ISO-DEP APDU."""
    result = {"type": "", "network": "", "records": [], "raw": []}

    # Try each transport AID
    for name, aid in TRANSPORT_AIDS:
        aid_bytes = bytes.fromhex(aid)
        # Calypso SELECT: CLA=94 INS=A4 P1=04 P2=00
        apdu = bytes([0x94, 0xA4, 0x04, 0x00, len(aid_bytes)]) + aid_bytes
        resp = drv.data_exchange(apdu)
        if not resp or len(resp) < 2:
            # Try standard ISO SELECT
            apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(aid_bytes)]) + aid_bytes + b"\x00"
            resp = drv.data_exchange(apdu)
        if resp and len(resp) > 4:
            result["type"] = name
            result["raw"].append({"aid": aid, "select_resp": resp.hex()})
            break

    if not result["type"]:
        return None

    # Read Calypso SFIs
    for sfi, sfi_name in CALYPSO_SFIS.items():
        for rec in range(1, 4):
            p2 = (sfi << 3) | 0x04
            # Calypso READ RECORD: CLA=94
            apdu = bytes([0x94, 0xB2, rec, p2, 0x00])
            resp = drv.data_exchange(apdu)
            if not resp or len(resp) <= 2:
                # Try standard ISO
                apdu = bytes([0x00, 0xB2, rec, p2, 0x00])
                resp = drv.data_exchange(apdu)
            if resp and len(resp) > 4:
                record = {
                    "sfi": sfi, "sfi_name": sfi_name,
                    "record": rec, "data": resp.hex(),
                }
                # Try to parse
                h = resp.hex().upper()
                if sfi == 0x07:  # Environment
                    # Network ID is often in first bytes
                    if len(h) >= 8:
                        net_id = h[0:4]
                        record["network"] = NETWORKS.get(net_id, f"Net:{net_id}")
                        result["network"] = record["network"]
                elif sfi == 0x09:  # Contracts
                    record["info"] = f"Contract {rec}"
                elif sfi == 0x08:  # Events
                    record["info"] = f"Event {rec}"
                elif sfi == 0x0A:  # Counters
                    if len(resp) >= 3:
                        counter = int.from_bytes(resp[:3], "big")
                        record["counter"] = counter
                        record["info"] = f"Counter: {counter}"

                result["records"].append(record)

    return result if result["records"] else None


def _print_transport(data):
    print(f"Type: {data.get('type', '?')}", flush=True)
    if data.get("network"):
        print(f"Network: {data['network']}", flush=True)

    for rec in data.get("records", []):
        name = rec.get("sfi_name", "?")
        info = rec.get("info", "")
        counter = rec.get("counter")
        network = rec.get("network", "")
        if counter is not None:
            print(f"  {name} R{rec['record']}: {counter}", flush=True)
        elif network:
            print(f"  {name} R{rec['record']}: {network}", flush=True)
        elif info:
            print(f"  {name} R{rec['record']}: {info}", flush=True)
        else:
            print(f"  {name} R{rec['record']}: {rec.get('data', '')}", flush=True)


def main():
    print("Detecting reader...", flush=True)
    drv, drv_desc = auto_detect()
    print(f"Reader: {drv_desc}", flush=True)
    if not drv:
        print("No NFC reader connected.", flush=True)
        return 1

    try:
        while True:
            _prompt("Place transport card on reader, then press Enter (Ctrl-C to quit)...")
            print("Polling...", flush=True)
            card = drv.read_passive_target(timeout=5.0)
            data = None
            if card:
                print("Reading...", flush=True)
                data = _read_transport(drv)
                if data:
                    _print_transport(data)
                else:
                    print("Not a transport card.", flush=True)
            else:
                print("No card detected.", flush=True)

            if data:
                choice = _prompt("Save to loot? [y/N]: ").lower()
                if choice == "y":
                    os.makedirs(LOOT_DIR, exist_ok=True)
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    fname = f"transport_{ts}.json"
                    with open(os.path.join(LOOT_DIR, fname), "w") as f:
                        json.dump({**data, "timestamp": ts}, f, indent=2)
                    print(f"Saved: {os.path.join(LOOT_DIR, fname)}", flush=True)

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
