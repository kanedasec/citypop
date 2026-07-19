#!/usr/bin/env python3
# @name: LED Controller
# @desc: Inspect and control available Raspberry Pi sysfs LEDs with on, off, blink, heartbeat, timer, and restore actions through web prompts.
# @category: hardware
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- LED Controller
=====================================
Author: 7h30th3r0n3

Pi LED controller for operational feedback.  Controls the ACT (activity)
and PWR (power) LEDs via sysfs with predefined blink patterns and a
custom timing editor.

Setup / Prerequisites
---------------------
- Raspberry Pi with accessible LED sysfs entries:
    /sys/class/leds/ACT/brightness
    /sys/class/leds/PWR/brightness
- Must run as root to write to LED sysfs.
- Some Pi models use 'led0'/'led1' instead of 'ACT'/'PWR'.

Controls
--------
  Usage: led_control.py

  Presents a numbered menu of blink patterns plus manual per-LED
  toggles. Enter a number to apply a pattern or toggle an LED; the menu
  reprints with the current state after each action. Enter 0 or press
  Ctrl-C to exit -- this restores each LED's original trigger.
"""

from payloads._web_input import request_input
import os
import sys
import time
import signal
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

_running = True
lock = threading.Lock()


def _stop(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _stop)
signal.signal(signal.SIGTERM, _stop)

# ---------------------------------------------------------------------------
# LED sysfs paths -- try common names
# ---------------------------------------------------------------------------

_LED_CANDIDATES = {
    "ACT": [
        "/sys/class/leds/ACT",
        "/sys/class/leds/led0",
        "/sys/class/leds/default-on",
    ],
    "PWR": [
        "/sys/class/leds/PWR",
        "/sys/class/leds/led1",
        "/sys/class/leds/input0::scrolllock",
    ],
}


def _find_led_path(name):
    """Find a working sysfs LED path."""
    for candidate in _LED_CANDIDATES.get(name, []):
        brightness = os.path.join(candidate, "brightness")
        if os.path.exists(brightness):
            return candidate
    return None


ACT_PATH = _find_led_path("ACT")
PWR_PATH = _find_led_path("PWR")


def _led_set(led_path, value):
    """Write brightness value (0 or 1) to an LED."""
    if led_path is None:
        return
    bpath = os.path.join(led_path, "brightness")
    try:
        with open(bpath, "w") as fh:
            fh.write(str(value))
    except OSError:
        pass


def _led_get(led_path):
    """Read current brightness from an LED."""
    if led_path is None:
        return 0
    bpath = os.path.join(led_path, "brightness")
    try:
        with open(bpath, "r") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return 0


def _led_set_trigger(led_path, trigger):
    """Set the LED trigger (e.g., 'mmc0', 'default-on', 'none')."""
    if led_path is None:
        return
    tpath = os.path.join(led_path, "trigger")
    try:
        with open(tpath, "w") as fh:
            fh.write(trigger)
    except OSError:
        pass


def _led_get_trigger(led_path):
    """Read the current trigger, returning the [active] one."""
    if led_path is None:
        return "none"
    tpath = os.path.join(led_path, "trigger")
    try:
        with open(tpath, "r") as fh:
            content = fh.read()
        for part in content.split():
            if part.startswith("[") and part.endswith("]"):
                return part[1:-1]
    except OSError:
        pass
    return "none"


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

PATTERNS = [
    {"name": "Idle",     "desc": "Slow pulse",         "act": [(0.5, 1), (0.5, 0)],           "pwr": [(0.5, 1), (0.5, 0)]},
    {"name": "Scanning", "desc": "Fast blink",          "act": [(0.1, 1), (0.1, 0)],           "pwr": [(0.1, 1), (0.1, 0)]},
    {"name": "Attacking","desc": "Solid on",            "act": [(1.0, 1)],                     "pwr": [(1.0, 1)]},
    {"name": "Alert",    "desc": "Rapid triple-blink",  "act": [(0.08, 1), (0.08, 0), (0.08, 1), (0.08, 0), (0.08, 1), (0.5, 0)], "pwr": [(0.08, 1), (0.08, 0), (0.08, 1), (0.08, 0), (0.08, 1), (0.5, 0)]},
    {"name": "Stealth",  "desc": "All off",             "act": [(1.0, 0)],                     "pwr": [(1.0, 0)]},
    {"name": "Custom",   "desc": "User-defined timing", "act": [(0.3, 1), (0.7, 0)],           "pwr": [(0.3, 1), (0.7, 0)]},
]

# Active pattern state
active_pattern_idx = 0
pattern_running = False
act_manual = None   # None=pattern-controlled, True/False=manual override
pwr_manual = None


# ---------------------------------------------------------------------------
# Pattern playback thread
# ---------------------------------------------------------------------------

def _pattern_thread():
    """Continuously play the active LED pattern."""
    global pattern_running
    pattern_running = True

    while _running and pattern_running:
        with lock:
            pat = PATTERNS[active_pattern_idx]
            a_manual = act_manual
            p_manual = pwr_manual

        act_steps = pat["act"]
        pwr_steps = pat["pwr"]
        max_steps = max(len(act_steps), len(pwr_steps))

        for step_idx in range(max_steps):
            if not _running or not pattern_running:
                return

            # ACT LED
            if a_manual is None and step_idx < len(act_steps):
                duration, value = act_steps[step_idx]
                _led_set(ACT_PATH, value)
            elif a_manual is not None:
                _led_set(ACT_PATH, 1 if a_manual else 0)

            # PWR LED
            if p_manual is None and step_idx < len(pwr_steps):
                duration, value = pwr_steps[step_idx]
                _led_set(PWR_PATH, value)
            elif p_manual is not None:
                _led_set(PWR_PATH, 1 if p_manual else 0)

            # Wait for the longer duration of the two step lists
            act_dur = act_steps[step_idx][0] if step_idx < len(act_steps) else 0
            pwr_dur = pwr_steps[step_idx][0] if step_idx < len(pwr_steps) else 0
            wait = max(act_dur, pwr_dur)

            deadline = time.time() + wait
            while _running and pattern_running and time.time() < deadline:
                time.sleep(0.02)


_pattern_thread_ref = None


def _start_pattern():
    """Launch the pattern playback thread."""
    global _pattern_thread_ref, pattern_running
    _stop_pattern()
    pattern_running = True
    _pattern_thread_ref = threading.Thread(target=_pattern_thread, daemon=True)
    _pattern_thread_ref.start()


def _stop_pattern():
    """Stop the current pattern thread."""
    global pattern_running
    pattern_running = False
    if _pattern_thread_ref is not None:
        _pattern_thread_ref.join(timeout=2)


# ---------------------------------------------------------------------------
# Custom pattern editing
# ---------------------------------------------------------------------------

custom_on_time = 0.3
custom_off_time = 0.7


def _update_custom_pattern():
    """Apply custom timing to the Custom pattern entry."""
    PATTERNS[-1]["act"] = [(custom_on_time, 1), (custom_off_time, 0)]
    PATTERNS[-1]["pwr"] = [(custom_on_time, 1), (custom_off_time, 0)]


# ---------------------------------------------------------------------------
# Restore defaults
# ---------------------------------------------------------------------------

_original_act_trigger = None
_original_pwr_trigger = None


def _save_original_triggers():
    global _original_act_trigger, _original_pwr_trigger
    _original_act_trigger = _led_get_trigger(ACT_PATH)
    _original_pwr_trigger = _led_get_trigger(PWR_PATH)


def _restore_defaults():
    """Restore LED triggers to their original state."""
    _stop_pattern()
    if _original_act_trigger:
        _led_set_trigger(ACT_PATH, _original_act_trigger)
    if _original_pwr_trigger:
        _led_set_trigger(PWR_PATH, _original_pwr_trigger)


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

def _print_status():
    act_on = _led_get(ACT_PATH)
    pwr_on = _led_get(PWR_PATH)
    with lock:
        active_name = PATTERNS[active_pattern_idx]["name"]
        a_m = act_manual
        p_m = pwr_manual
    print(
        f"\nACT={'on' if act_on else 'off'}  PWR={'on' if pwr_on else 'off'}  "
        f"Active pattern: {active_name}"
        + ("  [manual override active]" if (a_m is not None or p_m is not None) else ""),
        flush=True,
    )
    for i, pat in enumerate(PATTERNS, start=1):
        print(f"  {i}) {pat['name']} - {pat['desc']}", flush=True)
    print("  7) Toggle ACT LED manually", flush=True)
    print("  8) Toggle PWR LED manually", flush=True)
    print("  0) Exit (restores default triggers)", flush=True)


def main():
    global active_pattern_idx, act_manual, pwr_manual
    global custom_on_time, custom_off_time

    if ACT_PATH is None and PWR_PATH is None:
        print("No accessible LED sysfs entries found.", flush=True)
        return 1

    _save_original_triggers()

    # Disable triggers for manual control
    _led_set_trigger(ACT_PATH, "none")
    _led_set_trigger(PWR_PATH, "none")

    try:
        while _running:
            _print_status()
            try:
                choice = request_input("Select option [0-8]: ").strip()
            except EOFError:
                choice = "0"

            if choice in ("0", "", "exit", "quit"):
                break

            elif choice in ("1", "2", "3", "4", "5"):
                idx = int(choice) - 1
                with lock:
                    active_pattern_idx = idx
                    act_manual = None
                    pwr_manual = None
                _start_pattern()
                print(f"Pattern applied: {PATTERNS[idx]['name']}", flush=True)

            elif choice == "6":
                try:
                    on_raw = request_input(f"On time seconds [{custom_on_time:.1f}]: ").strip()
                    off_raw = request_input(f"Off time seconds [{custom_off_time:.1f}]: ").strip()
                except EOFError:
                    on_raw = off_raw = ""
                if on_raw:
                    try:
                        custom_on_time = max(0.05, min(5.0, float(on_raw)))
                    except ValueError:
                        print(f"Invalid value: {on_raw}", flush=True)
                if off_raw:
                    try:
                        custom_off_time = max(0.05, min(5.0, float(off_raw)))
                    except ValueError:
                        print(f"Invalid value: {off_raw}", flush=True)
                _update_custom_pattern()
                with lock:
                    active_pattern_idx = len(PATTERNS) - 1
                    act_manual = None
                    pwr_manual = None
                _start_pattern()
                print(
                    f"Custom pattern applied: on={custom_on_time:.1f}s off={custom_off_time:.1f}s",
                    flush=True,
                )

            elif choice == "7":
                with lock:
                    if act_manual is None:
                        act_manual = not bool(_led_get(ACT_PATH))
                    else:
                        act_manual = not act_manual
                    _led_set(ACT_PATH, 1 if act_manual else 0)
                print(f"ACT LED manually set to {'on' if act_manual else 'off'}", flush=True)

            elif choice == "8":
                with lock:
                    if pwr_manual is None:
                        pwr_manual = not bool(_led_get(PWR_PATH))
                    else:
                        pwr_manual = not pwr_manual
                    _led_set(PWR_PATH, 1 if pwr_manual else 0)
                print(f"PWR LED manually set to {'on' if pwr_manual else 'off'}", flush=True)

            else:
                print(f"Unknown option: {choice}", flush=True)

    finally:
        _restore_defaults()

    print("Exiting. LED triggers restored.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
