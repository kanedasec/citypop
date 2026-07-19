#!/usr/bin/env python3
# @name: QR and Barcode Scanner
# @desc: Decode QR codes and barcodes from a selected loot image or a still captured with a supported Raspberry Pi camera command.
# @category: utilities
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"source","label":"Image source","type":"select","choices":["loot image","Pi camera"],"default":"loot image"}]

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image
from pyzbar.pyzbar import decode
from payloads._web_input import request_input

ROOT = Path(os.environ.get("CITYPOP_ROOT", Path(__file__).resolve().parents[2])).resolve()
LOOT = ROOT / "loot"


def main() -> int:
    source = sys.argv[1] if len(sys.argv) > 1 else "loot image"
    temporary = None
    if source == "Pi camera":
        camera = shutil.which("rpicam-still") or shutil.which("libcamera-still")
        if not camera:
            print("No Pi camera capture command was found.")
            return 2
        temporary = tempfile.NamedTemporaryFile(suffix=".jpg", delete=False)
        temporary.close()
        result = subprocess.run([camera, "-n", "-t", "1500", "-o", temporary.name], capture_output=True, text=True, timeout=20)
        if result.returncode:
            print(result.stderr.strip())
            return result.returncode
        image_path = Path(temporary.name)
    else:
        images = sorted((p for p in LOOT.rglob("*") if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".bmp"}), key=lambda p: p.stat().st_mtime, reverse=True)
        if not images:
            print("No images were found under loot/.")
            return 1
        selected = int(request_input("Select image", input_type="select", choices=[
            {"value": str(i), "label": str(p.relative_to(LOOT))} for i, p in enumerate(images)
        ]))
        image_path = images[selected]
    try:
        results = decode(Image.open(image_path))
        if not results:
            print("No QR code or barcode was detected.")
            return 1
        for item in results:
            print(f"{item.type}: {item.data.decode('utf-8', errors='replace')}")
        return 0
    finally:
        if temporary:
            Path(temporary.name).unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
