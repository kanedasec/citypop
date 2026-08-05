#!/usr/bin/env python3
# @name: Bounded BadUSB keyboard detector
# @desc: Inventory USB keyboards and briefly trace exact keys only from keyboards attached after the detector starts.
# @category: usb
# @danger: true
# @active: true
# @web: true
# @maturity: functional
# @inputs: [{"name":"seconds","label":"Watch duration","type":"number","default":"300","help":"How long to watch for newly attached USB keyboards. Exact keys are captured for only 10 seconds after attachment."}]
"""Defensive, bounded USB keyboard activity detector.

USB keyboards present when the payload starts are inventoried and only receive
non-content responsiveness counters.  A USB keyboard attached later receives a
fixed, short exact-key trace so an operator can identify injection behavior.
"""

from __future__ import annotations

import json
import fcntl
import os
from pathlib import Path
import signal
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone

# Make the project package importable when the payload is launched directly.
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._dashboard import DashboardServer

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


TRACE_WINDOW_SEC = 10.0
MAX_TRACE_EVENTS_PER_DEVICE = 256
MAX_RECENT_EVENTS = 100
POLL_INTERVAL_SEC = 0.05
TYPING_KEY_CODES = ("KEY_A", "KEY_Z", "KEY_SPACE", "KEY_ENTER")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def log(message: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)


def _property(device, name: str, default: str = "") -> str:
    try:
        value = device.get(name)
        if value is not None:
            return str(value)
    except Exception:
        pass
    try:
        value = device.properties.get(name)
        if value is not None:
            return str(value)
    except Exception:
        pass
    return default


def _udev_for_node(context, devnode: str):
    try:
        return pyudev.Devices.from_device_file(context, devnode)
    except Exception:
        return None


def is_keyboard(udev_device, input_device=None) -> bool:
    """Require keyboard identity and, when available, EV_KEY capability."""
    if udev_device is None:
        return False
    if _property(udev_device, "ID_INPUT_KEYBOARD") != "1":
        return False
    if input_device is None or ecodes is None:
        return True
    try:
        key_codes = input_device.capabilities().get(ecodes.EV_KEY, [])
        required = {
            getattr(ecodes, name)
            for name in TYPING_KEY_CODES
            if hasattr(ecodes, name)
        }
        return bool(required) and required.issubset(set(key_codes))
    except OSError:
        return False


def is_usb_keyboard(udev_device, input_device=None) -> bool:
    """Limit exact tracing to keyboards whose udev bus is USB."""
    return (
        is_keyboard(udev_device, input_device)
        and _property(udev_device, "ID_BUS").lower() == "usb"
    )


def device_identity(devnode: str, input_device, udev_device, origin: str) -> dict:
    return {
        "origin": origin,
        "name": getattr(input_device, "name", None) or _property(udev_device, "ID_MODEL", "USB keyboard"),
        "device": devnode,
        "bus": _property(udev_device, "ID_BUS", "unknown"),
        "vendor_id": _property(udev_device, "ID_VENDOR_ID"),
        "product_id": _property(udev_device, "ID_MODEL_ID"),
        "serial": _property(udev_device, "ID_SERIAL_SHORT"),
        "path": _property(udev_device, "ID_PATH"),
        "connected_at": utc_now(),
        "responsive": False,
        "activity_events": 0,
        "exact_trace": origin == "new",
        "trace_status": "pending" if origin == "new" else "disabled (pre-existing)",
    }


def decode_key_event(event) -> tuple[str, str]:
    key = ecodes.KEY.get(event.code, f"KEY_{event.code}")
    if isinstance(key, (tuple, list)):
        key = "/".join(str(item) for item in key)
    action = {0: "release", 1: "press", 2: "repeat"}.get(event.value, str(event.value))
    return str(key), action


def set_nonblocking(input_device) -> None:
    """Enable nonblocking evdev reads across old and new python-evdev APIs."""
    flags = fcntl.fcntl(input_device.fd, fcntl.F_GETFL)
    fcntl.fcntl(input_device.fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


class SecureJsonl:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.parent.chmod(0o700)
        except OSError:
            pass
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.chmod(path, 0o600)
        self.path = path
        self._stream = os.fdopen(fd, "a", encoding="utf-8")
        self._lock = threading.Lock()

    def write(self, event: str, **fields) -> None:
        record = {"timestamp": utc_now(), "event": event, **fields}
        with self._lock:
            self._stream.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._stream.flush()

    def close(self) -> None:
        with self._lock:
            self._stream.close()


class Detector:
    def __init__(self, duration: float | None):
        self.duration = duration
        self.stop_event = threading.Event()
        self.lock = threading.RLock()
        self.context = pyudev.Context()
        self.startup_nodes: set[str] = set()
        self.devices: dict[str, dict] = {}
        self.recent_events: deque[dict] = deque(maxlen=MAX_RECENT_EVENTS)
        self.total_exact_events = 0
        self.new_keyboards = 0
        self.active_traces = 0
        self.status = "starting"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        loot_root = Path(os.environ.get("CITYPOP_LOOT", "/tmp/citypop_loot"))
        self.journal = SecureJsonl(loot_root / "BadUSB" / f"usb_keyboard_trace_{stamp}.jsonl")
        self.dashboard = DashboardServer("Bounded USB Keyboard Trace", self.snapshot)
        self.threads: list[threading.Thread] = []

    def snapshot(self) -> dict:
        with self.lock:
            devices = []
            for item in self.devices.values():
                devices.append({
                    "origin": item["origin"],
                    "name": item["name"],
                    "device": item["device"],
                    "bus": item["bus"],
                    "usb_id": f"{item['vendor_id']}:{item['product_id']}",
                    "responsive": item["responsive"],
                    "activity_events": item["activity_events"],
                    "exact_trace": item["exact_trace"],
                    "trace_status": item["trace_status"],
                })
            return {
                "status": self.status,
                "trace_window_seconds": int(TRACE_WINDOW_SEC),
                "pre_existing_keyboards": sum(d["origin"] == "pre-existing" for d in self.devices.values()),
                "new_usb_keyboards": self.new_keyboards,
                "active_traces": self.active_traces,
                "captured_exact_events": self.total_exact_events,
                "devices": devices,
                "recent_new_device_key_events": list(self.recent_events),
            }

    def inventory_startup(self) -> int:
        found = 0
        if not list_devices:
            return found
        for devnode in list_devices():
            if not devnode.startswith("/dev/input/event"):
                continue
            self.startup_nodes.add(devnode)
            try:
                input_device = InputDevice(devnode)
                udev_device = _udev_for_node(self.context, devnode)
                if not is_keyboard(udev_device, input_device):
                    input_device.close()
                    continue
                identity = device_identity(devnode, input_device, udev_device, "pre-existing")
                with self.lock:
                    self.devices[devnode] = identity
                found += 1
                self.journal.write("device_inventory", **identity)
                log(
                    f"Pre-existing keyboard inventoried: {devnode} "
                    f"({identity['name']}, bus={identity['bus']})"
                )
                input_device.close()
                self._start_reader(devnode, exact=False)
            except (OSError, PermissionError) as exc:
                log(f"Could not inventory {devnode}: {exc}")
        self.journal.write("inventory_complete", keyboard_count=found)
        if found == 0:
            log("No pre-existing keyboards were classified; check evdev permissions and udev properties")
        else:
            log(f"Pre-existing keyboard inventory complete: {found} device(s)")
        return found

    def _start_reader(self, devnode: str, exact: bool) -> None:
        thread = threading.Thread(target=self._read_device, args=(devnode, exact), daemon=True)
        self.threads.append(thread)
        thread.start()

    def _read_device(self, devnode: str, exact: bool) -> None:
        started = time.monotonic()
        deadline = started + TRACE_WINDOW_SEC if exact else None
        captured = 0
        device = None
        try:
            device = InputDevice(devnode)
            set_nonblocking(device)
            if exact:
                with self.lock:
                    self.active_traces += 1
                    self.devices[devnode]["trace_status"] = "active"
                self.journal.write("trace_start", device=devnode, window_seconds=TRACE_WINDOW_SEC)
                log(f"New USB keyboard trace started for {devnode} ({TRACE_WINDOW_SEC:.0f}s)")

            while not self.stop_event.is_set():
                if deadline is not None and time.monotonic() >= deadline:
                    break
                try:
                    events = device.read()
                except BlockingIOError:
                    events = []
                for event in events:
                    if event.type != ecodes.EV_KEY:
                        continue
                    with self.lock:
                        record = self.devices.get(devnode)
                        if record is None:
                            return
                        was_responsive = record["responsive"]
                        record["responsive"] = True
                        record["activity_events"] += 1
                        device_name = record["name"]
                        activity_count = record["activity_events"]
                    if not was_responsive:
                        self.journal.write(
                            "keyboard_responsive",
                            device=devnode,
                            device_name=device_name,
                            origin=record["origin"],
                            bus=record["bus"],
                        )
                        log(f"Keyboard responsive: {devnode} ({device_name})")
                    elif not exact and activity_count % 25 == 0:
                        self.journal.write(
                            "keyboard_activity",
                            device=devnode,
                            origin="pre-existing",
                            activity_events=activity_count,
                        )
                    if not exact or captured >= MAX_TRACE_EVENTS_PER_DEVICE:
                        continue
                    key, action = decode_key_event(event)
                    item = {
                        "elapsed_ms": int((time.monotonic() - started) * 1000),
                        "device": devnode,
                        "device_name": device_name,
                        "key": key,
                        "code": event.code,
                        "action": action,
                    }
                    with self.lock:
                        self.recent_events.appendleft(item)
                        self.total_exact_events += 1
                    self.journal.write("key_event", origin="new", **item)
                    captured += 1
                time.sleep(POLL_INTERVAL_SEC)
        except (OSError, PermissionError) as exc:
            self.journal.write("device_read_error", device=devnode, error=str(exc))
            log(f"Input reader ended for {devnode}: {exc}")
        finally:
            if device is not None:
                try:
                    device.close()
                except OSError:
                    pass
            if exact:
                with self.lock:
                    self.active_traces = max(0, self.active_traces - 1)
                    if devnode in self.devices:
                        self.devices[devnode]["trace_status"] = "complete"
                self.journal.write("trace_end", device=devnode, captured_events=captured)
                log(f"Trace complete for {devnode}: {captured} exact events")

    def _register_new_input(self, devnode: str) -> None:
        # udev properties can lag behind creation of the event node.
        for _attempt in range(10):
            if self.stop_event.is_set():
                return
            try:
                input_device = InputDevice(devnode)
                udev_device = _udev_for_node(self.context, devnode)
                if is_usb_keyboard(udev_device, input_device):
                    break
                input_device.close()
            except OSError:
                pass
            time.sleep(0.2)
        else:
            return

        with self.lock:
            if devnode in self.startup_nodes or devnode in self.devices:
                input_device.close()
                return
            identity = device_identity(devnode, input_device, udev_device, "new")
            self.devices[devnode] = identity
            self.new_keyboards += 1
        input_device.close()
        self.journal.write("device_attached", **identity)
        log(f"New USB keyboard correlated: {devnode} ({identity['name']})")
        self._start_reader(devnode, exact=True)

    def monitor_input(self) -> None:
        monitor = pyudev.Monitor.from_netlink(self.context)
        monitor.filter_by(subsystem="input")
        while not self.stop_event.is_set():
            device = monitor.poll(timeout=0.5)
            if device is None:
                continue
            devnode = device.device_node
            if not devnode or not devnode.startswith("/dev/input/event"):
                continue
            if device.action == "add":
                threading.Thread(target=self._register_new_input, args=(devnode,), daemon=True).start()
            elif device.action == "remove":
                with self.lock:
                    known = self.devices.pop(devnode, None)
                    if known:
                        known["trace_status"] = "disconnected"
                        archive_key = f"{devnode}#removed-{time.monotonic_ns()}"
                        self.devices[archive_key] = known
                    self.startup_nodes.discard(devnode)
                if known:
                    self.journal.write("device_removed", device=devnode, origin=known["origin"])
                    log(f"USB keyboard removed: {devnode}")

    def run(self) -> int:
        self.journal.write(
            "session_start",
            trace_window_seconds=TRACE_WINDOW_SEC,
            max_trace_events_per_device=MAX_TRACE_EVENTS_PER_DEVICE,
        )
        self.inventory_startup()
        url = self.dashboard.start()
        log(f"Dashboard: {url}")
        log(f"Permission-restricted JSONL trace: {self.journal.path}")
        log("Pre-existing keyboards: responsiveness only; exact key values are never retained")
        log(f"New USB keyboards: exact key events retained for {TRACE_WINDOW_SEC:.0f}s after attachment")
        self.status = "watching"
        monitor_thread = threading.Thread(target=self.monitor_input, daemon=True)
        self.threads.append(monitor_thread)
        monitor_thread.start()
        started = time.monotonic()
        try:
            while not self.stop_event.wait(0.2):
                if self.duration is not None and time.monotonic() - started >= self.duration:
                    log(f"Duration {self.duration:.0f}s elapsed; stopping")
                    break
        except KeyboardInterrupt:
            log("Interrupted by operator")
        finally:
            self.status = "stopping"
            self.stop_event.set()
            for thread in self.threads:
                thread.join(timeout=1.0)
            self.journal.write(
                "session_end",
                new_usb_keyboards=self.new_keyboards,
                captured_exact_events=self.total_exact_events,
            )
            self.dashboard.stop()
            self.journal.close()
            self.status = "stopped"
        log("Shutdown complete")
        return 0


def main() -> int:
    if pyudev is None or InputDevice is None or ecodes is None or list_devices is None:
        log("pyudev and evdev are required; install the USB payload dependencies")
        return 1
    duration = None
    if len(sys.argv) > 1:
        try:
            duration = float(sys.argv[1])
            if duration <= 0:
                raise ValueError
        except ValueError:
            print(f"Usage: python3 {os.path.basename(__file__)} [positive_duration_seconds]", flush=True)
            return 1

    detector = Detector(duration)

    def stop_handler(_signum, _frame):
        detector.stop_event.set()

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    return detector.run()


if __name__ == "__main__":
    raise SystemExit(main())
