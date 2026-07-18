#!/usr/bin/env python3
# @name: NFC Scanner
# @desc: Continuous NFC detection.
# @category: nfc_rfid
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- NFC Scanner
==================================
Continuous NFC detection. Shows card type, UID, and for EMV
cards extracts the masked PAN and app name on the fly.

Controls:
  Usage: nfc_scanner.py [duration_seconds]

  duration_seconds defaults to 60. Polls for cards for that long,
  printing each new detection (and repeat counts) to stdout. Press
  Ctrl-C to stop early. Prints a final summary and saves a CSV log to
  loot.
"""

import os
import sys
import time
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads.nfc_rfid._nfc_driver import auto_detect, is_emv, is_classic, is_ultralight

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'NFC')

EMV_AIDS = [
    ("Visa", "A0000000031010"), ("MC", "A0000000041010"),
    ("CB", "A0000000421010"), ("Amex", "A00000002501"),
    ("JCB", "A0000000651010"), ("Disc", "A0000001523010"),
]


def _quick_emv(drv):
    """Fast EMV probe: get app name, full PAN, expiry."""
    ppse = bytes.fromhex("00A404000E325041592E5359532E444446303100")
    resp = drv.data_exchange(ppse)
    if not resp or len(resp) < 6:
        return None, None, None

    app_name = ""
    pan_full = ""
    expiry = ""

    for name, aid in EMV_AIDS:
        aid_b = bytes.fromhex(aid)
        apdu = bytes.fromhex("00A40400") + bytes([len(aid_b)]) + aid_b + b"\x00"
        resp = drv.data_exchange(apdu)
        if not resp or len(resp) <= 4:
            continue
        app_name = name

        gpo = bytes.fromhex("80A8000002830000")
        gpo_resp = drv.data_exchange(gpo)
        if not gpo_resp:
            break

        afl = b""
        i = 0
        while i < len(gpo_resp) - 1:
            if gpo_resp[i] == 0x94:
                ln = gpo_resp[i + 1]
                afl = gpo_resp[i + 2:i + 2 + ln]
                break
            i += 1

        sfis = []
        if afl:
            for j in range(0, len(afl), 4):
                if j + 3 >= len(afl):
                    break
                sfi = (afl[j] >> 3) & 0x1F
                first = afl[j + 1]
                last = afl[j + 2]
                for rec in range(first, min(last + 1, first + 2)):
                    sfis.append((sfi, rec))
        else:
            sfis = [(1, 1), (2, 1), (1, 2)]

        for sfi, rec in sfis[:4]:
            p2 = (sfi << 3) | 0x04
            rr = drv.data_exchange(bytes([0x00, 0xB2, rec, p2, 0x00]))
            if not rr or len(rr) < 10:
                continue
            h = rr.hex().upper()
            for marker in ["57", "5A"]:
                idx = 0
                while idx < len(h) - 4:
                    if h[idx:idx+2] == marker:
                        ln = int(h[idx+2:idx+4], 16)
                        data = h[idx+4:idx+4+ln*2]
                        if "D" in data:
                            pan_full = data.split("D")[0]
                            trail = data.split("D")[1]
                            if len(trail) >= 4:
                                expiry = f"{trail[2:4]}/20{trail[0:2]}"
                        elif "F" in data:
                            pan_full = data.rstrip("F")
                        else:
                            pan_full = data
                        break
                    idx += 2
                if pan_full:
                    break
            if pan_full:
                break
        break

    return app_name, pan_full, expiry


def main():
    try:
        duration = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    except ValueError:
        print(f"Usage: {sys.argv[0]} [duration_seconds]", flush=True)
        return 1

    print("Detecting reader...", flush=True)
    drv, drv_desc = auto_detect()
    print(f"Reader: {drv_desc}", flush=True)
    if not drv:
        print("No NFC reader connected.", flush=True)
        return 1

    history = []
    unique_uids = set()
    start = time.time()

    print(f"Scanning for {duration}s (Ctrl-C to stop early)...", flush=True)
    try:
        while time.time() - start < duration:
            card = drv.read_passive_target(timeout=1.0)
            if card:
                uid_hex = card.uid_hex
                unique_uids.add(uid_hex)
                existing = next((h for h in history if h["uid"] == uid_hex), None)
                if existing:
                    existing["count"] += 1
                    existing["last"] = time.time()
                    print(f"  [{datetime.now().strftime('%H:%M:%S')}] {uid_hex}  "
                          f"{existing['type']}  (seen {existing['count']}x)", flush=True)
                else:
                    entry = {
                        "uid": uid_hex,
                        "type": card.card_type,
                        "ts": datetime.now().strftime("%H:%M:%S"),
                        "count": 1,
                        "last": time.time(),
                        "emv_app": "",
                        "pan": "",
                    }
                    # Quick EMV probe — any card with ISO-DEP capability (SAK bit 5)
                    if card.sak & 0x20 or is_emv(card) or "ISO" in card.card_type or "DESFire" in card.card_type:
                        app, pan, exp = _quick_emv(drv)
                        if app:
                            entry["emv_app"] = app
                            entry["type"] = app
                        if pan:
                            entry["pan"] = pan
                        if exp:
                            entry["expiry"] = exp

                    history.insert(0, entry)
                    line = f"  [{entry['ts']}] NEW {entry['type']}  {uid_hex}"
                    if entry.get("pan"):
                        pan_display = " ".join(entry["pan"][i:i+4] for i in range(0, len(entry["pan"]), 4))
                        line += f"  PAN:{pan_display}"
                        if entry.get("expiry"):
                            line += f"  Exp:{entry['expiry']}"
                    print(line, flush=True)
    except KeyboardInterrupt:
        print("\nStopped by user.", flush=True)
    finally:
        if drv:
            drv.close()

    total = sum(h["count"] for h in history)
    print(f"\nDone. {len(unique_uids)} unique card(s), {total} total detection(s).", flush=True)

    if history:
        os.makedirs(LOOT_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(LOOT_DIR, f"scan_log_{ts}.csv")
        with open(path, "w") as f:
            f.write("timestamp,uid,type,emv_app,pan_masked,count\n")
            for h in history:
                f.write(f"{h['ts']},{h['uid']},{h['type']},"
                        f"{h.get('emv_app','')},{h.get('pan','')},{h['count']}\n")
        print(f"Saved log: {path}", flush=True)

    print("Exiting.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
