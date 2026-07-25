#!/usr/bin/env python3
# @name: Passive OS Signal Collector
# @desc: Passively inspect IPv4 and IPv6 TCP SYN fingerprints, report conservative operating-system family estimates, and save structured results to loot.
# @category: reconnaissance
# @danger: false
# @active: true
# @web: true
# @maturity: functional
# @inputs: [{"name":"seconds","label":"Capture duration","type":"number","default":"30"}]
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from payloads._web_input import request_input


def initial_hop_limit(observed):
    """Return the nearest common initial TTL/hop-limit at or above observed."""
    if observed is None or observed < 1:
        return None
    for candidate in (32, 64, 128, 255):
        if observed <= candidate:
            return candidate
    return None


def infer_os_family(hop_limit, window, mss):
    """Return a conservative family estimate and the signals behind it."""
    initial = initial_hop_limit(hop_limit)
    evidence = []
    if initial:
        evidence.append(f"initial TTL/hop-limit≈{initial}")
    if window:
        evidence.append(f"TCP window={window}")
    if mss:
        evidence.append(f"MSS={mss}")

    if initial == 128:
        family = "Windows-family"
        confidence = "moderate"
    elif initial == 64 and window == 65535:
        family = "Apple/BSD or mobile Unix-like"
        confidence = "low"
    elif initial == 64 and window in {29200, 5840, 64240, 65320}:
        family = "Linux/Android-family"
        confidence = "low"
    elif initial == 64:
        family = "Unix-like"
        confidence = "low"
    elif initial == 255:
        family = "Network appliance or Unix-like"
        confidence = "low"
    else:
        family = "Unknown"
        confidence = "insufficient"
    return family, confidence, evidence


def parse_tshark_fields(output):
    records = []
    for line in output.splitlines():
        fields = line.split("\t")
        fields += [""] * (6 - len(fields))
        ipv4, ipv6, ttl, hop_limit, window, mss = fields[:6]
        address = ipv4 or ipv6
        if not address:
            continue
        try:
            observed_hop = int(ttl or hop_limit)
        except ValueError:
            observed_hop = None
        try:
            window_value = int(window)
        except ValueError:
            window_value = None
        try:
            mss_value = int(mss)
        except ValueError:
            mss_value = None
        family, confidence, evidence = infer_os_family(
            observed_hop, window_value, mss_value,
        )
        records.append({
            "address": address,
            "ip_version": 4 if ipv4 else 6,
            "ttl_or_hop_limit": observed_hop,
            "estimated_initial_hop_limit": initial_hop_limit(observed_hop),
            "tcp_window": window_value,
            "mss": mss_value,
            "os_family": family,
            "confidence": confidence,
            "evidence": evidence,
        })
    return records


def main():
    interfaces = sorted(
        path.name for path in Path("/sys/class/net").iterdir()
        if path.name != "lo"
    )
    iface = str(request_input(
        "Select connected capture interface — it must observe the authorized "
        "TCP traffic; monitor mode is not required",
        input_type="select",
        choices=interfaces,
    ))
    try:
        seconds = max(1, min(int(sys.argv[1] if len(sys.argv) > 1 else "30"), 600))
    except ValueError:
        return 2

    command = [
        "tshark", "-i", iface, "-a", f"duration:{seconds}",
        "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
        "-e", "ip.src", "-e", "ipv6.src",
        "-e", "ip.ttl", "-e", "ipv6.hlim",
        "-e", "tcp.window_size_value", "-e", "tcp.options.mss_val",
    ]
    print(
        "Capturing initial TCP SYN fingerprints "
        f"(IPv4 and IPv6) on {iface} for {seconds}s…",
        flush=True,
    )
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=seconds + 20,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"Capture failed: {exc}", flush=True)
        return 1
    if result.stderr:
        print(result.stderr.strip(), flush=True)
    if result.returncode:
        return result.returncode

    records = parse_tshark_fields(result.stdout)
    grouped = Counter(
        (
            record["address"], record["ip_version"],
            record["ttl_or_hop_limit"], record["tcp_window"], record["mss"],
            record["os_family"], record["confidence"],
        )
        for record in records
    )
    print("IP address\tVer\tTTL/Hop\tTCP window\tMSS\tOS-family estimate", flush=True)
    for fingerprint, count in grouped.items():
        address, version, hop, window, mss, family, confidence = fingerprint
        suffix = f" ×{count}" if count > 1 else ""
        print(
            f"{address}\tIPv{version}\t{hop or '-'}\t{window or '-'}\t"
            f"{mss or '-'}\t{family} ({confidence}){suffix}",
            flush=True,
        )

    loot_root = Path(os.environ.get("CITYPOP_LOOT", "/tmp/citypop_loot"))
    loot_dir = loot_root / "PassiveOS"
    loot_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc)
    output_path = loot_dir / f"fingerprints_{timestamp.strftime('%Y%m%dT%H%M%SZ')}.json"
    output_path.write_text(json.dumps({
        "timestamp": timestamp.isoformat(),
        "interface": iface,
        "duration_seconds": seconds,
        "packet_count": len(records),
        "note": (
            "OS families are heuristic estimates, not definitive identification; "
            "NAT, VPNs and TCP tuning can alter these signals."
        ),
        "fingerprints": records,
    }, indent=2), encoding="utf-8")
    print(f"Saved {len(records)} fingerprint(s): {output_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
