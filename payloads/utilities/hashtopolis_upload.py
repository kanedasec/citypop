#!/usr/bin/env python3
# @name: Hashtopolis Uploader
# @desc: Upload .hc22000 / .hccapx hash files to a Hashtopolis server via its REST API.
# @category: utilities
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"url","label":"Hashtopolis URL","type":"text","placeholder":"https://hash.example","required":true},{"name":"key","label":"API access key","type":"password","required":true}]

import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from payloads._web_input import request_input

ROOT = Path(os.environ.get("CITYPOP_ROOT", Path(__file__).resolve().parents[2])).resolve()
LOOT = ROOT / "loot"
EXTENSIONS = {".txt", ".hash", ".hashes", ".hc22000", ".hccapx", ".pot", ".potfile"}


def main() -> int:
    if len(sys.argv) < 3 or not sys.argv[1].startswith(("http://", "https://")):
        print("A valid Hashtopolis URL and access key are required.")
        return 2
    files = sorted((p for p in LOOT.rglob("*") if p.suffix.lower() in EXTENSIONS), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        print("No hash files were found under loot/.")
        return 1
    selected = int(request_input("Select hash file", input_type="select", choices=[
        {"value": str(i), "label": f"{p.relative_to(LOOT)} · {p.stat().st_size // 1024} KiB"} for i, p in enumerate(files)
    ]))
    source = files[selected]
    boundary = "----CityPop" + uuid.uuid4().hex
    fields = [("accessKey", sys.argv[2]), ("action", "importFile")]
    body = bytearray()
    for name, value in fields:
        body.extend(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode())
    body.extend(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{source.name}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode())
    body.extend(source.read_bytes())
    body.extend(f"\r\n--{boundary}--\r\n".encode())
    endpoint = sys.argv[1].rstrip("/")
    if not endpoint.endswith("/api/user.php"):
        endpoint += "/api/user.php"
    request = urllib.request.Request(endpoint, data=body, method="POST", headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            output = response.read().decode(errors="replace")
        try:
            output = json.dumps(json.loads(output), indent=2)
        except json.JSONDecodeError:
            pass
        print(f"Uploaded {source.relative_to(ROOT)}\n{output[:2000]}")
        return 0
    except (urllib.error.URLError, OSError) as exc:
        print(f"Upload failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
