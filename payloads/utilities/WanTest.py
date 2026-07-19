#!/usr/bin/env python3
# @name: WAN Speed Test
# @desc: Measure internet latency, download speed, and upload speed with an installed Speedtest backend.
# @category: utilities
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"mode","label":"Connection mode","type":"select","choices":["multi","single"],"default":"multi"}]

import json
import os
import shutil
import subprocess
import sys


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "multi"
    single = mode == "single"
    if shutil.which("speedtest-cli"):
        command = ["speedtest-cli", "--json"]
        if single:
            command.append("--single")
    elif shutil.which("speedtest"):
        command = ["speedtest", "--accept-license", "--accept-gdpr", "--format=json"]
    else:
        print("No speed-test backend is installed (speedtest-cli or Ookla speedtest).")
        return 2

    print("Running WAN speed test; this may take a minute…", flush=True)
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if result.returncode:
        print(result.stderr.strip() or result.stdout.strip())
        return result.returncode
    try:
        data = json.loads(result.stdout)
        if isinstance(data.get("download"), dict):
            download = float(data["download"].get("bandwidth", 0)) * 8 / 1_000_000
            upload = float(data["upload"].get("bandwidth", 0)) * 8 / 1_000_000
            latency = float(data.get("ping", {}).get("latency", 0))
        else:
            download = float(data.get("download", 0)) / 1_000_000
            upload = float(data.get("upload", 0)) / 1_000_000
            latency = float(data.get("ping", 0))
        print(f"Download: {download:.2f} Mbps\nUpload:   {upload:.2f} Mbps\nLatency:  {latency:.2f} ms")
    except (ValueError, TypeError, json.JSONDecodeError):
        print(result.stdout.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
