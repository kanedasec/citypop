#!/usr/bin/env python3
# @name: USB Mass Storage Gadget
# @desc: Creates a FAT32 disk image and configures the Pi Zero as a USB mass storage device via Linux configfs.
# @category: usb
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- USB Mass Storage Gadget
=============================================
Author: 7h30th3r0n3

Creates a FAT32 disk image and configures the Pi Zero as a USB mass storage
device via Linux configfs.  Can pre-load files from template directories.
Monitors host access via inotify on the mount point.

Setup / Prerequisites:
  - Requires Pi Zero USB OTG port.
  - Creates FAT32 disk image. Target sees Pi as USB drive.

Controls (CLI):
  python3 usb_mass_storage.py [template] [--duration SECONDS]

  template            Optional. One of: empty, documents, autorun. If
                       omitted, you'll be prompted to pick one.
  --duration SECONDS  Optional. Stop automatically after this many
                       seconds. If omitted, runs until Ctrl-C.

  Host access to the backing image is logged as it happens. Press
  Ctrl-C at any time to stop and clean up the gadget.

Requires: root privileges, configfs support, dosfstools
"""

from payloads._web_input import request_input
import os
import sys
import time
import shutil
import argparse
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
GADGET_NAME = "raspyjack_usb"
CONFIGFS_BASE = "/sys/kernel/config/usb_gadget"
GADGET_PATH = os.path.join(CONFIGFS_BASE, GADGET_NAME)
IMAGE_PATH = "/tmp/raspyjack_usb.img"
MOUNT_PATH = "/tmp/raspyjack_usb_mount"
IMAGE_SIZE_MB = 64
TEMPLATE_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'templates', 'usb')

TEMPLATES = ["empty", "documents", "autorun"]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
gadget_active = False
access_log = []
files_loaded = 0

# ---------------------------------------------------------------------------
# Image creation
# ---------------------------------------------------------------------------

def _create_image(size_mb):
    """Create a FAT32 disk image."""
    try:
        subprocess.run(
            ["dd", "if=/dev/zero", f"of={IMAGE_PATH}",
             "bs=1M", f"count={size_mb}"],
            capture_output=True, timeout=60,
        )
        subprocess.run(
            ["mkfs.vfat", "-F", "32", "-n", "RASPYJACK", IMAGE_PATH],
            capture_output=True, timeout=30,
        )
        return True
    except Exception:
        return False


def _mount_image():
    """Mount the image to load files."""
    os.makedirs(MOUNT_PATH, exist_ok=True)
    try:
        subprocess.run(
            ["mount", "-o", "loop", IMAGE_PATH, MOUNT_PATH],
            capture_output=True, timeout=10,
        )
        return True
    except Exception:
        return False


def _unmount_image():
    """Unmount the image."""
    try:
        subprocess.run(
            ["umount", MOUNT_PATH],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass


def _load_template(template_name):
    """Load files from template directory into the image."""
    global files_loaded
    template_path = os.path.join(TEMPLATE_DIR, template_name)

    if not _mount_image():
        return 0

    count = 0
    if template_name == "empty":
        # Just create a readme
        readme = os.path.join(MOUNT_PATH, "README.txt")
        try:
            with open(readme, "w") as f:
                f.write("USB Storage Device\n")
            count = 1
        except Exception:
            pass

    elif template_name == "autorun":
        # Create autorun.inf pointing to a placeholder
        try:
            inf_path = os.path.join(MOUNT_PATH, "autorun.inf")
            with open(inf_path, "w") as f:
                f.write("[autorun]\n")
                f.write("open=setup.exe\n")
                f.write("icon=setup.exe,0\n")
                f.write("label=System Update\n")
            count = 1
        except Exception:
            pass

    elif os.path.isdir(template_path):
        # Copy all files from template directory
        try:
            for item in os.listdir(template_path):
                src = os.path.join(template_path, item)
                dst = os.path.join(MOUNT_PATH, item)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)
                    count += 1
                elif os.path.isdir(src):
                    shutil.copytree(src, dst)
                    count += 1
        except Exception:
            pass

    _unmount_image()

    with lock:
        files_loaded = count
    return count

# ---------------------------------------------------------------------------
# ConfigFS gadget setup
# ---------------------------------------------------------------------------

def _setup_gadget():
    """Configure USB mass storage gadget via configfs."""
    try:
        os.makedirs(GADGET_PATH, exist_ok=True)

        # Device descriptors
        _write_sysfs(os.path.join(GADGET_PATH, "idVendor"), "0x1d6b")
        _write_sysfs(os.path.join(GADGET_PATH, "idProduct"), "0x0104")
        _write_sysfs(os.path.join(GADGET_PATH, "bcdDevice"), "0x0100")
        _write_sysfs(os.path.join(GADGET_PATH, "bcdUSB"), "0x0200")

        # Strings
        strings_dir = os.path.join(GADGET_PATH, "strings", "0x409")
        os.makedirs(strings_dir, exist_ok=True)
        _write_sysfs(os.path.join(strings_dir, "serialnumber"), "000000000001")
        _write_sysfs(os.path.join(strings_dir, "manufacturer"), "RaspyJack")
        _write_sysfs(os.path.join(strings_dir, "product"), "USB Storage")

        # Mass storage function
        func_dir = os.path.join(GADGET_PATH, "functions", "mass_storage.usb0")
        os.makedirs(func_dir, exist_ok=True)
        lun_dir = os.path.join(func_dir, "lun.0")
        os.makedirs(lun_dir, exist_ok=True)
        _write_sysfs(os.path.join(lun_dir, "cdrom"), "0")
        _write_sysfs(os.path.join(lun_dir, "nofua"), "0")
        _write_sysfs(os.path.join(lun_dir, "removable"), "1")
        _write_sysfs(os.path.join(lun_dir, "ro"), "0")
        _write_sysfs(os.path.join(lun_dir, "file"), IMAGE_PATH)

        # Configuration
        config_dir = os.path.join(GADGET_PATH, "configs", "c.1")
        os.makedirs(config_dir, exist_ok=True)
        config_str = os.path.join(config_dir, "strings", "0x409")
        os.makedirs(config_str, exist_ok=True)
        _write_sysfs(os.path.join(config_str, "configuration"), "Mass Storage")
        _write_sysfs(os.path.join(config_dir, "MaxPower"), "250")

        # Link function to config
        link_path = os.path.join(config_dir, "mass_storage.usb0")
        if not os.path.exists(link_path):
            os.symlink(func_dir, link_path)

        # Bind to UDC
        udc = _find_udc()
        if udc:
            _write_sysfs(os.path.join(GADGET_PATH, "UDC"), udc)
            return True
        return False

    except Exception:
        return False


def _teardown_gadget():
    """Remove the USB gadget configuration."""
    try:
        # Unbind from UDC
        udc_file = os.path.join(GADGET_PATH, "UDC")
        if os.path.exists(udc_file):
            _write_sysfs(udc_file, "")
            time.sleep(0.5)

        # Remove symlink
        link_path = os.path.join(GADGET_PATH, "configs", "c.1", "mass_storage.usb0")
        if os.path.islink(link_path):
            os.unlink(link_path)

        # Remove directories (reverse order)
        for subdir in [
            "configs/c.1/strings/0x409",
            "configs/c.1",
            "functions/mass_storage.usb0/lun.0",
            "functions/mass_storage.usb0",
            "strings/0x409",
        ]:
            path = os.path.join(GADGET_PATH, subdir)
            if os.path.isdir(path):
                try:
                    os.rmdir(path)
                except OSError:
                    pass

        if os.path.isdir(GADGET_PATH):
            os.rmdir(GADGET_PATH)

    except Exception:
        pass


def _find_udc():
    """Find available USB Device Controller."""
    udc_dir = "/sys/class/udc"
    try:
        entries = os.listdir(udc_dir)
        if entries:
            return entries[0]
    except Exception:
        pass
    return None


def _write_sysfs(path, value):
    """Write a value to a sysfs file."""
    with open(path, "w") as f:
        f.write(value)

# ---------------------------------------------------------------------------
# Access monitoring thread
# ---------------------------------------------------------------------------

def _monitor_thread():
    """Monitor the gadget backing file for access."""
    global access_log

    last_mtime = 0.0
    while _running:
        if gadget_active and os.path.exists(IMAGE_PATH):
            try:
                stat = os.stat(IMAGE_PATH)
                if stat.st_mtime != last_mtime and last_mtime > 0:
                    ts = datetime.now().strftime("%H:%M:%S")
                    with lock:
                        access_log.append(f"{ts} Image accessed")
                        if len(access_log) > 50:
                            access_log = access_log[-50:]
                    last_mtime = stat.st_mtime
                elif last_mtime == 0:
                    last_mtime = stat.st_mtime
            except Exception:
                pass
        time.sleep(2)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _prompt_for_template():
    """Prompt the operator to pick a template from the fixed list."""
    print("Available templates:", flush=True)
    for i, t in enumerate(TEMPLATES, 1):
        print(f"  {i}. {t}", flush=True)
    choice = request_input(f"Select template [1-{len(TEMPLATES)}] (default 1): ").strip()
    if not choice:
        return TEMPLATES[0]
    if not choice.isdigit() or not (1 <= int(choice) <= len(TEMPLATES)):
        print("Invalid selection, using default.", flush=True)
        return TEMPLATES[0]
    return TEMPLATES[int(choice) - 1]


def main():
    global _running, gadget_active

    parser = argparse.ArgumentParser(
        description="USB Mass Storage Gadget - present the Pi as a USB "
                     "drive and log host access.",
    )
    parser.add_argument(
        "template", nargs="?", choices=TEMPLATES,
        help="Template to load onto the image: empty, documents, or "
             "autorun. If omitted, you'll be prompted to pick one.",
    )
    parser.add_argument(
        "--duration", type=float, default=None,
        help="Stop automatically after this many seconds. If omitted, "
             "runs until Ctrl-C.",
    )
    opts = parser.parse_args()

    if not os.path.isdir(CONFIGFS_BASE):
        print("configfs not found. Try: modprobe libcomposite", flush=True)
        return 1

    template = opts.template or _prompt_for_template()

    threading.Thread(target=_monitor_thread, daemon=True).start()

    print(f"Creating {IMAGE_SIZE_MB}MB FAT32 image...", flush=True)
    if not _create_image(IMAGE_SIZE_MB):
        print("Failed to create disk image.", flush=True)
        return 1

    count = _load_template(template)
    print(f"Template '{template}' loaded ({count} file(s)).", flush=True)

    print("Configuring USB mass storage gadget...", flush=True)
    if not _setup_gadget():
        print("Gadget setup failed.", flush=True)
        return 1

    gadget_active = True
    udc = _find_udc()
    print(
        f"Gadget active on UDC={udc or 'none'}. Waiting for host access. "
        "Press Ctrl-C to stop.",
        flush=True,
    )

    seen = 0
    start = time.time()
    try:
        while True:
            with lock:
                log_copy = list(access_log)
            if len(log_copy) > seen:
                for entry in log_copy[seen:]:
                    print(entry, flush=True)
                seen = len(log_copy)

            if opts.duration is not None and (time.time() - start) >= opts.duration:
                print(f"Duration {opts.duration:.0f}s elapsed; stopping.", flush=True)
                break

            time.sleep(1)
    except KeyboardInterrupt:
        print("\nInterrupted by operator; stopping...", flush=True)
    finally:
        _running = False
        gadget_active = False
        _teardown_gadget()
        if os.path.exists(IMAGE_PATH):
            try:
                os.remove(IMAGE_PATH)
            except Exception:
                pass

    print(f"Done. {seen} access log entr{'y' if seen == 1 else 'ies'} recorded.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
