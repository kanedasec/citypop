#!/usr/bin/env python3
# @active: true
# @web: true
# @name: WiFi Probe Request Dump
# @desc: Passively capture Wi-Fi probe requests on a selected monitor interface for a bounded period and save unique client/SSID observations to loot.
# @category: wifi
# @danger: false
# @inputs: [{"name":"seconds","label":"Capture duration","type":"number","default":"30"}]
import json
import os
import sys
import time
from pathlib import Path
from payloads._iface_helper import list_interfaces
from payloads._web_input import request_input

try:
    from scapy.all import Dot11Elt, Dot11ProbeReq, sniff
except ImportError:
    print("scapy is required", flush=True)
    raise SystemExit(127)


def main():
    ifaces = [item for item in list_interfaces("wifi") if item.get("supports_monitor")]
    if not ifaces:
        print("No monitor-capable Wi-Fi interface found", flush=True)
        return 1
    choices = []
    print("Available monitor-capable interfaces:", flush=True)
    for item in ifaces:
        name = item["name"]
        bus = item.get("bus") or ("onboard" if item.get("is_onboard") else "external")
        state = "up" if item.get("is_up") else "down"
        print(f"  {name}: {bus}, {state}", flush=True)
        choices.append({"value": name, "label": f"{name} · {bus} · {state}"})
    iface = str(request_input(
        "Select monitor-capable Wi-Fi interface",
        input_type="select",
        choices=choices,
    ))
    if iface not in {item["name"] for item in ifaces}:
        print("Invalid interface selection", flush=True)
        return 1
    try:
        duration = float(sys.argv[1]) if len(sys.argv) > 1 else 30.0
    except ValueError:
        print("seconds must be a number", flush=True)
        return 2
    if duration <= 0 or duration > 3600:
        print("seconds must be between 0 and 3600", flush=True)
        return 2

    rows = []

    def handle(pkt):
        if not pkt.haslayer(Dot11ProbeReq):
            return
        ssid = ""
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                ssid = bytes(elt.info).decode(errors="replace")
                break
            elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, "getlayer") else None
        row = {"mac": pkt.addr2 or "", "ssid": ssid, "time": time.time()}
        rows.append(row)
        print(json.dumps(row), flush=True)

    try:
        sniff(iface=iface, prn=handle, store=False, timeout=duration)
    except PermissionError:
        print("Permission denied opening the monitor interface", flush=True)
        return 1
    except OSError as exc:
        print(f"Capture failed: {exc}", flush=True)
        return 1

    loot = Path(os.environ["CITYPOP_LOOT"])
    loot.mkdir(parents=True, exist_ok=True)
    output = loot / "wifi_probe_requests.json"
    output.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    print(f"Saved {len(rows)} probe requests to {output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
