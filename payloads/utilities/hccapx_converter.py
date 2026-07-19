#!/usr/bin/env python3
# @name: Wi-Fi Capture Converter
# @desc: Select a .cap, .pcap, or .pcapng file from loot and convert it to Hashcat .hc22000 format with hcxpcapngtool.
# @category: utilities
# @danger: false
# @active: true
# @web: true

import os
import shutil
import subprocess
from pathlib import Path

from payloads._web_input import request_input

ROOT = Path(os.environ.get("CITYPOP_ROOT", Path(__file__).resolve().parents[2])).resolve()
LOOT = ROOT / "loot"


def main() -> int:
    tool = shutil.which("hcxpcapngtool")
    if not tool:
        print("hcxpcapngtool is not installed. Install the hcxtools package.")
        return 2
    captures = sorted((p for p in LOOT.rglob("*") if p.suffix.lower() in {".cap", ".pcap", ".pcapng"}), key=lambda p: p.stat().st_mtime, reverse=True)
    if not captures:
        print("No capture files were found under loot/.")
        return 1
    choices = [{"value": str(i), "label": f"{p.relative_to(LOOT)} · {p.stat().st_size // 1024} KiB"} for i, p in enumerate(captures)]
    index = int(request_input("Select capture", input_type="select", choices=choices))
    source = captures[index]
    output_dir = LOOT / "Hashcat"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{source.stem}.hc22000"
    result = subprocess.run([tool, "-o", str(output), str(source)], text=True, capture_output=True, timeout=300)
    print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip())
    if result.returncode == 0:
        print(f"Saved: {output.relative_to(ROOT)}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
