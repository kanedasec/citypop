#!/usr/bin/env python3
# @name: BadUSB detector payload
# @desc: Watches for USB insertion events and raises a RED alert if:.
# @category: usb
# @danger: false
# @active: true
# @web: true
"""
BadUSB detector payload
-----------------------
Watches for USB insertion events and raises a RED alert if:
- a new USB keyboard starts sending keystrokes quickly after insertion
- a removable mass-storage device is mounted

Controls (CLI):
  python3 badusb_detector.py [duration_seconds]

  duration_seconds   Optional. Stop automatically after this many
                      seconds. If omitted, runs until Ctrl-C.

  Progress and alerts are streamed to stdout as they happen. Press
  Ctrl-C at any time to stop monitoring cleanly.
"""

import os
import sys
import time
import threading

# Ensure RaspyJack modules are importable when launched directly
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

try:
    import pyudev  # type: ignore
except Exception:
    pyudev = None

try:
    from evdev import InputDevice, ecodes, list_devices  # type: ignore
except Exception:
    InputDevice = None
    ecodes = None
    list_devices = None


ALERT_WINDOW_SEC = 8
KEY_EVENT_THRESHOLD = 1
KEY_WINDOW_SEC = None
DETECT_ANY_KEYBOARD = True  # Any keyboard device with ID_INPUT_KEYBOARD=1

running = True
alert_active = False
alert_reason = ""
alert_since = 0.0
watched_keyboards = set()


def _ts():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(msg):
    print(f"[{_ts()}] {msg}", flush=True)


def is_removable_mount_present():
    try:
        with open("/proc/mounts", "r") as f:
            mounts = f.read().splitlines()
        log(f"Mounts checked: {len(mounts)} entries")
        for line in mounts:
            parts = line.split()
            if len(parts) < 3:
                continue
            device, mnt, fstype = parts[0], parts[1], parts[2]
            if device.startswith("/dev/sd") or device.startswith("/dev/mmcblk"):
                # Check removable flag if available
                base = device.replace("/dev/", "").rstrip("0123456789")
                removable = f"/sys/block/{base}/removable"
                if os.path.exists(removable):
                    try:
                        if open(removable).read().strip() == "1":
                            log(f"Removable mounted: {device} at {mnt} ({fstype})")
                            return True, f"Mounted: {os.path.basename(device)}"
                    except Exception:
                        pass
                # Fallback: common mount points for removable media
                if mnt.startswith(("/media/", "/mnt/", "/run/media/")):
                    log(f"Mounted under removable path: {device} at {mnt} ({fstype})")
                    return True, f"Mounted: {os.path.basename(device)}"
    except Exception:
        pass
    return False, ""


def count_keyboard_events_on_device(dev_path, duration_sec=KEY_WINDOW_SEC):
    if not list_devices or not InputDevice or not ecodes:
        log("evdev not available")
        return 0
    count = 0
    try:
        dev = InputDevice(dev_path)
        caps = dev.capabilities()
        if ecodes.EV_KEY not in caps:
            log(f"Device {dev.path} has no EV_KEY capability")
            return 0
        log(f"Monitoring keyboard device: {dev.path} ({dev.name})")
        if hasattr(dev, "set_blocking"):
            dev.set_blocking(False)
        elif hasattr(dev, "setblocking"):
            dev.setblocking(False)
        else:
            try:
                import fcntl
                flags = fcntl.fcntl(dev.fd, fcntl.F_GETFL)
                fcntl.fcntl(dev.fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            except Exception:
                pass
        start = time.time()
        while True:
            try:
                for event in dev.read():
                    if event.type == ecodes.EV_KEY and event.value == 1:
                        count += 1
                        if count >= KEY_EVENT_THRESHOLD:
                            log(f"Key threshold reached on {dev_path}")
                            return count
            except Exception:
                pass
            time.sleep(0.02)
            if duration_sec is not None and (time.time() - start) >= duration_sec:
                break
    except Exception as e:
        log(f"Keyboard read error: {e}")
    if duration_sec is None:
        log(f"Keyboard events counted: {count} on {dev_path} (continuous)")
    else:
        log(f"Keyboard events counted: {count} on {dev_path} in {duration_sec:.1f}s")
    return count


def _is_usb_keyboard(devnode):
    if not pyudev:
        return False
    try:
        ctx = pyudev.Context()
        dev = pyudev.Devices.from_device_file(ctx, devnode)
        return dev.get("ID_INPUT_KEYBOARD") == "1" and dev.get("ID_BUS") == "usb"
    except Exception:
        return False


def _list_keycap_devices():
    if not list_devices or not InputDevice or not ecodes:
        return []
    devs = []
    for path in list_devices():
        if not path.startswith("/dev/input/event"):
            continue
        try:
            dev = InputDevice(path)
            caps = dev.capabilities()
            if ecodes.EV_KEY in caps:
                devs.append((dev.path, dev.name))
        except Exception:
            continue
    return devs


def trigger_alert(reason):
    global alert_active, alert_reason, alert_since
    alert_active = True
    alert_reason = reason
    alert_since = time.time()
    log(f"Trigger alert: {reason}")


def _watch_keyboard_continuous(devnode):
    log(f"Continuous watch started on {devnode}")
    keys = count_keyboard_events_on_device(devnode, duration_sec=None)
    if keys >= KEY_EVENT_THRESHOLD:
        trigger_alert(f"Keys: {keys}")


def monitor_usb():
    if not pyudev:
        log("pyudev not available; cannot monitor USB")
        return
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="usb")
    log("USB monitor started (subsystem=usb)")
    # No snapshot needed in "any keyboard" mode; we will watch all on startup

    for device in iter(monitor.poll, None):
        if not running:
            break
        if device.action == "add":
            log(f"USB add: {device}")
            # Quick checks after insertion
            time.sleep(0.5)

            mounted, msg = is_removable_mount_present()
            if mounted:
                trigger_alert(msg)
                continue

            # USB add: we just log; keyboard detection handled by input monitor
            if not alert_active:
                log("USB device added; input monitor will handle keyboards")
        elif device.action == "remove":
            log(f"USB remove: {device}")


def monitor_input():
    if not pyudev:
        log("pyudev not available; cannot monitor input")
        return
    context = pyudev.Context()
    mon = pyudev.Monitor.from_netlink(context)
    mon.filter_by(subsystem="input")
    log("Input monitor started (subsystem=input)")

    for device in iter(mon.poll, None):
        if not running:
            break
        if device.action == "add":
            devnode = device.device_node
            if devnode and devnode.startswith("/dev/input/event"):
                try:
                    dev = InputDevice(devnode)
                    caps = dev.capabilities()
                    if ecodes.EV_KEY in caps:
                        if devnode in watched_keyboards:
                            continue
                        watched_keyboards.add(devnode)
                        name = getattr(dev, "name", "input")
                        log(f"Input add (keycap): {devnode} ({name})")
                        t = threading.Thread(
                            target=_watch_keyboard_continuous,
                            args=(devnode,),
                            daemon=True,
                        )
                        t.start()
                    else:
                        log(f"Input add (no-keycap): {devnode}")
                except Exception as e:
                    log(f"Input add read error: {devnode} ({e})")
        elif device.action == "remove":
            devnode = device.device_node
            if devnode and devnode.startswith("/dev/input/event"):
                log(f"Input remove: {devnode}")
                if devnode in watched_keyboards:
                    watched_keyboards.remove(devnode)


def main():
    global running, alert_active

    duration = None
    if len(sys.argv) > 1:
        try:
            duration = float(sys.argv[1])
        except ValueError:
            print(f"Usage: python3 {os.path.basename(__file__)} [duration_seconds]", flush=True)
            return 1

    if not pyudev:
        log("pyudev not available; cannot monitor USB. Exiting.")
        return 1

    t = threading.Thread(target=monitor_usb, daemon=True)
    t.start()
    log("Background USB monitor thread started")

    ti = threading.Thread(target=monitor_input, daemon=True)
    ti.start()
    log("Background input monitor thread started")

    # Start watching any existing keyboards immediately
    try:
        kbds = _list_keycap_devices()
        log(f"Key-capable inputs at start: {len(kbds)}")
        for devnode, name in kbds:
            if devnode in watched_keyboards:
                continue
            watched_keyboards.add(devnode)
            log(f"Watching input: {devnode} ({name})")
            t = threading.Thread(
                target=_watch_keyboard_continuous,
                args=(devnode,),
                daemon=True,
            )
            t.start()
    except Exception as e:
        log(f"Keycap init scan error: {e}")

    log(
        "Monitoring for BadUSB indicators (Ctrl-C to stop)"
        + (f", timeout {duration:.0f}s" if duration is not None else "")
    )

    start = time.time()
    last_status = 0.0
    try:
        while running:
            now = time.time()
            if alert_active:
                if now - last_status > 2.0:
                    log(f"*** ALERT ACTIVE: {alert_reason} ***")
                    last_status = now
                if now - alert_since > ALERT_WINDOW_SEC:
                    alert_active = False
                    log("Alert window elapsed; back to idle")
            elif now - last_status > 10.0:
                log("Status: watching (no alert)")
                last_status = now

            if duration is not None and (now - start) >= duration:
                log(f"Duration {duration:.0f}s elapsed; stopping")
                break
            time.sleep(0.1)
    except KeyboardInterrupt:
        log("Interrupted by operator")
    finally:
        running = False

    log("Shutdown complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
