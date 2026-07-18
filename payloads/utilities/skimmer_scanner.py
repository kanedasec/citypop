#!/usr/bin/env python3
# @name: BLE Skimmer Scanner
# @desc: Scans for Bluetooth Low Energy devices that match known skimmer module names (HC-05, HC-06, JDY-31, etc.).
# @category: utilities
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"seconds","label":"Scan duration","type":"number","default":"15"}]

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from bleak import BleakScanner

PATTERNS = ("hc-05", "hc-06", "hc05", "hc06", "jdy-31", "jdy-30", "jdy31", "jdy30", "ble-cc41", "cc41-a", "cc2541", "at-09", "at09", "mlt-bt05", "hm-10", "hm-11", "hm10", "hm11", "blk-md", "db-b10", "spp-ca", "rnbt", "firefly", "bolutek")


async def scan(seconds: int):
    return await BleakScanner.discover(timeout=seconds, return_adv=True)


def main() -> int:
    try:
        seconds = max(2, min(int(sys.argv[1] if len(sys.argv) > 1 else "15"), 300))
    except ValueError:
        print("Scan duration must be a whole number.")
        return 2
    print(f"Scanning for {seconds} seconds…", flush=True)
    try:
        discovered = asyncio.run(scan(seconds))
    except Exception as exc:
        print(f"BLE scan failed: {exc}")
        return 1
    records = []
    for address, pair in discovered.items():
        device, advertisement = pair
        name = advertisement.local_name or device.name or "(unknown)"
        suspicious = any(pattern in name.lower() for pattern in PATTERNS)
        records.append({"address": address, "name": name, "rssi": advertisement.rssi, "pattern_match": suspicious})
        print(f"{'MATCH' if suspicious else 'seen ':5} · {address} · {advertisement.rssi} dBm · {name}")
    root = Path(os.environ.get("CITYPOP_ROOT", Path(__file__).resolve().parents[2]))
    output_dir = root / "loot" / "SkimmerScan"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"scan_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    output.write_text(json.dumps(records, indent=2), encoding="utf-8")
    print(f"{len(records)} device(s); {sum(r['pattern_match'] for r in records)} name-pattern match(es). This is an indicator, not proof of a skimmer.\nSaved: {output.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
