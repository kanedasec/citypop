#!/usr/bin/env python3
# @name: M5Burner
# @desc: Flash M5Stack firmwares using the official M5Burner catalog.
# @category: utilities
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- M5Burner
==============================
Author: 7h30th3r0n3

Flash M5Stack firmwares using the official M5Burner catalog.
Downloads binaries from m5burner-cdn.m5stack.com.

Controls:
  python3 m5burner.py [serial-port]

    serial-port  -- optional, force a specific device (e.g. /dev/ttyUSB0)
                     instead of auto-detecting one.

  Once running, the tool presents numbered menus on stdin/stdout to
  browse categories, search the catalog, and flash or erase a device.
"""

from payloads._web_input import request_input
import os
import sys
import subprocess
import glob
import json

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

CDN_BASE = "https://m5burner-cdn.m5stack.com/firmware/"
API_URL = "http://m5burner-api-fc-hk-cdn.m5stack.com/api/firmware"
FW_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'Firmwares', 'M5Stack')


def _ensure_esptool():
    try:
        import esptool  # noqa: F401
        return True
    except ImportError:
        pass
    print("Installing esptool...", flush=True)
    r = subprocess.run(
        ["pip3", "install", "--break-system-packages", "esptool"],
        capture_output=True, timeout=120)
    return r.returncode == 0


def _fetch_catalog():
    """Fetch firmware catalog from M5Stack API."""
    import urllib.request
    try:
        req = urllib.request.Request(API_URL, headers={"User-Agent": "M5Burner-Raspyjack"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
        if isinstance(data, list):
            return data
        return data.get("list", data.get("options", []))
    except Exception:
        return []


def _get_categories(catalog):
    cats = {}
    for item in catalog:
        cat = item.get("category", "other")
        if cat not in cats:
            cats[cat] = []
        cats[cat].append(item)
    order = ["cardputer", "stickc", "core", "core2 & tough", "cores3",
             "atoms3", "paper", "sticks3", "tab5", "atom", "stamps3"]
    sorted_cats = []
    for c in order:
        if c in cats:
            sorted_cats.append(c)
    for c in sorted(cats.keys()):
        if c not in sorted_cats:
            sorted_cats.append(c)
    return sorted_cats, cats


def _detect_serial():
    return sorted(glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*"))


def _detect_chip(port):
    try:
        r = subprocess.run(
            ["esptool.py", "--port", port, "chip_id"],
            capture_output=True, text=True, timeout=15)
        output = r.stdout + r.stderr
        for line in output.split("\n"):
            if "Chip type:" in line:
                return line.split("Chip type:")[-1].strip().split("(")[0].strip()
            if "Detecting chip type..." in line:
                raw = line.split("...")[-1].strip()
                if raw:
                    return raw
        return "Unknown" if r.returncode == 0 else None
    except Exception:
        return None


def _download_firmware(file_hash):
    import urllib.request
    os.makedirs(FW_DIR, exist_ok=True)
    dest = os.path.join(FW_DIR, file_hash)
    if os.path.isfile(dest):
        return dest
    url = CDN_BASE + file_hash
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "M5Burner-Raspyjack"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
        return dest if os.path.isfile(dest) else None
    except Exception:
        if os.path.isfile(dest):
            os.remove(dest)
        return None


def _flash(port, fw_path, progress_cb):
    cmd = ["esptool.py", "--port", port, "--baud", "460800",
           "write_flash", "0x0", fw_path]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=0)
    buf = b""
    while proc.poll() is None:
        ch = proc.stdout.read(1)
        if not ch:
            break
        if ch == b"\r" or ch == b"\n":
            line = buf.decode(errors="replace")
            buf = b""
            if not line:
                continue
            if "%" in line:
                try:
                    idx = line.index("%")
                    num_str = ""
                    i = idx - 1
                    while i >= 0 and (line[i].isdigit() or line[i] == '.'):
                        num_str = line[i] + num_str
                        i -= 1
                    if num_str:
                        pct = int(float(num_str))
                        progress_cb(min(pct, 100))
                except Exception:
                    pass
            elif "Hash" in line or "Leaving" in line:
                progress_cb(100)
        else:
            buf += ch
    proc.wait()
    return proc.returncode == 0


def _erase(port):
    r = subprocess.run(
        ["esptool.py", "--port", port, "erase_flash"],
        capture_output=True, text=True, timeout=30)
    return r.returncode == 0


# ---------------------------------------------------------------------------
# CLI menus
# ---------------------------------------------------------------------------

def _prompt_index(prompt, count):
    """Prompt for a 1-based index in [1, count]. Returns 0-based index, or None."""
    raw = request_input(prompt).strip()
    if not raw:
        return None
    if raw.lower() in ("b", "back", "q", "quit"):
        return None
    try:
        n = int(raw)
    except ValueError:
        print("Not a number.", flush=True)
        return None
    if 1 <= n <= count:
        return n - 1
    print("Out of range.", flush=True)
    return None


def _search_catalog(catalog):
    query = request_input("Search query: ").strip().lower()
    if not query:
        return []
    return [fw for fw in catalog
            if query in fw.get("name", "").lower()
            or query in fw.get("description", "").lower()
            or query in fw.get("author", "").lower()]


def _print_firmware_list(firmwares):
    for i, fw in enumerate(firmwares, start=1):
        name = fw.get("name", "?")
        vers = fw.get("versions", [])
        ver = vers[0].get("version", "") if vers else ""
        print(f"  {i}. {name}  (v{ver})", flush=True)


def _print_firmware_detail(fw):
    vers = fw.get("versions", [])
    latest = vers[0] if vers else {}
    print(f"Name:    {fw.get('name', '?')}", flush=True)
    print(f"Author:  {fw.get('author', '?')}", flush=True)
    print(f"Version: {latest.get('version', '?')} ({latest.get('published_at', '?')})", flush=True)
    desc = fw.get("description", "No description")
    print(f"Desc:    {desc}", flush=True)
    changelog = latest.get("change_log", "")
    if changelog:
        print("Changelog:", flush=True)
        for line in changelog.split("\n"):
            print(f"  {line}", flush=True)


def _flash_firmware(fw, port):
    vers = fw.get("versions", [])
    if not vers:
        print("No version available for this firmware.", flush=True)
        return
    latest = vers[0]
    file_hash = latest.get("file", "")
    if not file_hash:
        print("No downloadable file for this firmware.", flush=True)
        return

    print(f"Downloading {fw.get('name', '?')}...", flush=True)
    fw_path = _download_firmware(file_hash)
    if not fw_path:
        print("Download failed.", flush=True)
        return

    print(f"Flashing {fw.get('name', '?')} to {port}...", flush=True)
    last_pct = -1

    def _progress(pct):
        nonlocal last_pct
        if pct != last_pct:
            last_pct = pct
            print(f"  {pct}%", flush=True)

    ok = _flash(port, fw_path, _progress)
    print("Flash OK." if ok else "Flash FAILED.", flush=True)


def main():
    args = sys.argv[1:]
    forced_port = args[0] if args else None

    if not _ensure_esptool():
        print("Failed to install esptool.", flush=True)
        return 1

    print("Fetching M5Burner catalog...", flush=True)
    catalog = _fetch_catalog()
    if not catalog:
        print("Fetch failed. Check internet connectivity.", flush=True)
        return 1
    print(f"Loaded {len(catalog)} firmware entries.", flush=True)

    cat_names, cat_map = _get_categories(catalog)

    port = forced_port
    chip = None
    if port:
        print(f"Using forced serial port {port}", flush=True)
        chip = _detect_chip(port)
    else:
        ports = _detect_serial()
        if ports:
            port = ports[0]
            print(f"Detecting chip on {port}...", flush=True)
            chip = _detect_chip(port)
    if port:
        print(f"Device: {port}  Chip: {chip or 'unknown'}", flush=True)
    else:
        print("No device detected. Flash/erase disabled until one is found.", flush=True)

    try:
        while True:
            print("\nCategories:", flush=True)
            for i, cat in enumerate(cat_names, start=1):
                print(f"  {i}. {cat} ({len(cat_map[cat])})", flush=True)
            print("  s. Search catalog", flush=True)
            print("  r. Rescan serial device", flush=True)
            print("  q. Quit", flush=True)

            choice = request_input("Select category, s, r, or q: ").strip().lower()
            if choice in ("q", "quit"):
                break
            if choice in ("r", "rescan"):
                ports = _detect_serial()
                if ports:
                    port = ports[0]
                    chip = _detect_chip(port)
                    print(f"Device: {port}  Chip: {chip or 'unknown'}", flush=True)
                else:
                    print("No device found.", flush=True)
                continue
            if choice in ("s", "search"):
                firmwares = _search_catalog(catalog)
                if not firmwares:
                    print("No results.", flush=True)
                    continue
            else:
                try:
                    idx = int(choice) - 1
                except ValueError:
                    print("Invalid choice.", flush=True)
                    continue
                if not (0 <= idx < len(cat_names)):
                    print("Invalid choice.", flush=True)
                    continue
                firmwares = cat_map[cat_names[idx]]

            while True:
                print("\nFirmwares:", flush=True)
                _print_firmware_list(firmwares)
                sel = _prompt_index("Select firmware number (or 'b' to go back): ", len(firmwares))
                if sel is None:
                    break
                fw = firmwares[sel]
                print(flush=True)
                _print_firmware_detail(fw)

                action = request_input("Action: [f]lash, [e]rase device, [b]ack: ").strip().lower()
                if action == "f":
                    if not port:
                        print("No device connected, cannot flash.", flush=True)
                        continue
                    _flash_firmware(fw, port)
                elif action == "e":
                    if not port:
                        print("No device connected, cannot erase.", flush=True)
                        continue
                    confirm = request_input(f"Erase flash on {port}? [y/N]: ").strip().lower()
                    if confirm == "y":
                        print("Erasing...", flush=True)
                        print("Erased." if _erase(port) else "Erase failed.", flush=True)
                # any other input just loops back to firmware list
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
