#!/usr/bin/env python3
# @name: PCAP Analyzer
# @desc: Browse and analyze pcap/cap/pcapng files directly on the device.
# @category: utilities
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"view","label":"Analysis view","type":"select","choices":["overview","protocols","endpoints","conversations"],"default":"overview"}]

import os
import shutil
import subprocess
import sys
from pathlib import Path

from payloads._web_input import request_input

ROOT = Path(os.environ.get("CITYPOP_ROOT", Path(__file__).resolve().parents[2])).resolve()
LOOT = ROOT / "loot"


def main() -> int:
    tshark = shutil.which("tshark")
    if not tshark:
        print("tshark is not installed.")
        return 2
    captures = sorted((p for p in LOOT.rglob("*") if p.suffix.lower() in {".pcap", ".pcapng", ".cap"}), key=lambda p: p.stat().st_mtime, reverse=True)
    if not captures:
        print("No captures were found under loot/.")
        return 1
    selected = int(request_input("Select capture", input_type="select", choices=[
        {"value": str(i), "label": f"{p.relative_to(LOOT)} · {p.stat().st_size // 1024} KiB"} for i, p in enumerate(captures)
    ]))
    capture = captures[selected]
    view = sys.argv[1] if len(sys.argv) > 1 else "overview"
    statistics = {
        "overview": ["-z", "capture,comment", "-z", "io,stat,0"],
        "protocols": ["-z", "io,phs"],
        "endpoints": ["-z", "endpoints,ip", "-z", "endpoints,ipv6"],
        "conversations": ["-z", "conv,ip", "-z", "conv,tcp", "-z", "conv,udp"],
    }.get(view)
    if statistics is None:
        print("Unknown analysis view.")
        return 2
    print(f"Analyzing {capture.relative_to(ROOT)}…", flush=True)
    result = subprocess.run([tshark, "-r", str(capture), "-q", *statistics], capture_output=True, text=True, timeout=300)
    print(result.stdout.strip() or result.stderr.strip())
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
