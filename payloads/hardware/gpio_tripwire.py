#!/usr/bin/env python3
# @name: GPIO Tripwire (Physical Intrusion Detection)
# @desc: Monitors spare GPIO pins for state changes from contact switches, PIR sensors, or other triggers.
# @category: hardware
# @danger: false
# @active: true
"""
RaspyJack Payload -- GPIO Tripwire (Physical Intrusion Detection)
=================================================================
Author: 7h30th3r0n3

Monitors spare GPIO pins for state changes from contact switches, PIR
sensors, or other triggers.

Setup / Prerequisites:
  - Wire sensors to GPIO pins (PIR, door contacts, etc.).
  - Optional: Discord webhook in config for remote alerts.  On trigger:
    console alert, optional Discord webhook notification, optional
    buzzer output.

Controls:
  Usage: gpio_tripwire.py [preset] [duration_seconds]

  preset            Optional pin preset name or index (see list printed
                     at startup). Defaults to the first preset.
  duration_seconds  Optional time to stay armed, in seconds. Runs until
                     Ctrl-C if omitted.

  The tripwire arms immediately and prints a line to stdout every time a
  sensor triggers. A "test" trigger can be requested interactively by
  typing "t" + Enter while armed (stdin is polled between sensor
  checks). Press Ctrl-C to disarm and exit; a final event summary is
  printed.

Config: /root/Raspyjack/config/tripwire.json
"""

from payloads._web_input import request_input
import os
import sys
import json
import time
import signal
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CONFIG_PATH = "/root/Raspyjack/config/tripwire.json"

# Preset pin configurations
PIN_PRESETS = [
    {"name": "PIR+Door", "pins": [17, 27], "labels": ["PIR", "Door"]},
    {"name": "3-Zone", "pins": [17, 27, 22], "labels": ["Zone1", "Zone2", "Zone3"]},
    {"name": "Single PIR", "pins": [17], "labels": ["PIR"]},
    {"name": "Window+Door", "pins": [22, 27], "labels": ["Window", "Door"]},
]

BUZZER_PIN = 18  # optional buzzer output

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
trigger_count = 0
last_trigger_time = ""
event_log = []
discord_webhook_url = ""
buzzer_enabled = True


def _stop(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _stop)
signal.signal(signal.SIGTERM, _stop)

# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _load_config():
    """Load configuration from JSON file."""
    global discord_webhook_url, buzzer_enabled
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        discord_webhook_url = cfg.get("discord_webhook", "")
        buzzer_enabled = cfg.get("buzzer_enabled", True)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Sensor pin setup
# ---------------------------------------------------------------------------

def _setup_sensor_pins(preset):
    """Set up GPIO pins for the current sensor preset."""
    for pin in preset["pins"]:
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)


def _setup_buzzer():
    """Set up buzzer output pin."""
    try:
        GPIO.setup(BUZZER_PIN, GPIO.OUT)
        GPIO.output(BUZZER_PIN, GPIO.LOW)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Alert actions
# ---------------------------------------------------------------------------

def _add_event(label, pin_num):
    """Record a trigger event."""
    global trigger_count, last_trigger_time
    ts = datetime.now().strftime("%H:%M:%S")
    entry = f"{ts} [{label}] pin {pin_num}"
    with lock:
        event_log.append(entry)
        if len(event_log) > 100:
            # Keep only the latest events
            del event_log[:len(event_log) - 100]
        trigger_count += 1
        last_trigger_time = ts
    print(f"TRIGGER: {entry}", flush=True)


def _buzz_alert(duration=0.5):
    """Sound the buzzer briefly."""
    if not buzzer_enabled:
        return
    try:
        GPIO.output(BUZZER_PIN, GPIO.HIGH)
        time.sleep(duration)
        GPIO.output(BUZZER_PIN, GPIO.LOW)
    except Exception:
        pass


def _send_discord_alert(label, pin_num):
    """Send alert to Discord webhook."""
    if not discord_webhook_url:
        return
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = json.dumps({
        "content": f"**TRIPWIRE ALERT** [{ts}]\nSensor: {label} (GPIO {pin_num})\nTrigger count: {trigger_count}",
    })
    try:
        subprocess.run(
            [
                "curl", "-s", "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", payload,
                discord_webhook_url,
            ],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Monitor thread
# ---------------------------------------------------------------------------

def _monitor_thread(preset):
    """Continuously monitor sensor pins for state changes."""
    pin_states = {}

    # Initialize pin states
    for pin in preset["pins"]:
        pin_states[pin] = GPIO.input(pin)

    # Debounce: ignore triggers within 500ms of each other per pin
    last_trigger = {}

    while _running:
        for i, pin in enumerate(preset["pins"]):
            current = GPIO.input(pin)
            prev = pin_states.get(pin, current)

            if current != prev:
                now = time.time()
                if now - last_trigger.get(pin, 0) > 0.5:
                    label = preset["labels"][i] if i < len(preset["labels"]) else f"Pin{pin}"
                    _add_event(label, pin)

                    # Alert in separate thread to avoid blocking
                    threading.Thread(
                        target=_buzz_alert, args=(0.3,), daemon=True
                    ).start()
                    threading.Thread(
                        target=_send_discord_alert, args=(label, pin),
                        daemon=True,
                    ).start()

                    last_trigger[pin] = now

            pin_states[pin] = current

        time.sleep(0.05)


def _stdin_test_thread():
    """Watch stdin for a 't' + Enter to fire a test alarm."""
    while _running:
        try:
            line = sys.stdin.readline()
        except Exception:
            return
        if not line:
            return
        if line.strip().lower() == "t":
            _add_event("TEST", 0)
            threading.Thread(target=_buzz_alert, args=(0.5,), daemon=True).start()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _select_preset():
    """Pick a preset from argv[1] or an interactive prompt."""
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        for i, preset in enumerate(PIN_PRESETS):
            if arg == str(i) or arg.lower() == preset["name"].lower():
                return preset
        print(f"Unknown preset: {arg}", flush=True)

    print("Available pin presets:", flush=True)
    for i, preset in enumerate(PIN_PRESETS):
        pins_str = ", ".join(str(p) for p in preset["pins"])
        print(f"  {i}: {preset['name']} (pins {pins_str})", flush=True)
    try:
        choice = request_input("Select preset [0]: ").strip()
    except EOFError:
        choice = ""
    if not choice:
        return PIN_PRESETS[0]
    for i, preset in enumerate(PIN_PRESETS):
        if choice == str(i) or choice.lower() == preset["name"].lower():
            return preset
    print("Invalid selection, using default preset.", flush=True)
    return PIN_PRESETS[0]


def main():
    global _running

    duration = None
    if len(sys.argv) > 2:
        try:
            duration = float(sys.argv[2])
        except ValueError:
            print(f"Usage: {os.path.basename(__file__)} [preset] [duration_seconds]", flush=True)
            return 1

    GPIO.setmode(GPIO.BCM)

    _load_config()
    preset = _select_preset()
    _setup_sensor_pins(preset)
    _setup_buzzer()

    pins_str = ", ".join(str(p) for p in preset["pins"])
    print(f"Armed with preset '{preset['name']}' (pins {pins_str}).", flush=True)
    print("Type 't' + Enter to fire a test alarm. Press Ctrl-C to disarm and exit.", flush=True)

    monitor = threading.Thread(target=_monitor_thread, args=(preset,), daemon=True)
    monitor.start()
    stdin_thread = threading.Thread(target=_stdin_test_thread, daemon=True)
    stdin_thread.start()

    start = time.time()
    try:
        while _running:
            if duration is not None and (time.time() - start) >= duration:
                break
            time.sleep(0.2)
    finally:
        _running = False
        try:
            GPIO.output(BUZZER_PIN, GPIO.LOW)
        except Exception:
            pass
        monitor.join(timeout=1)
        GPIO.cleanup()

    print(f"Disarmed. Total triggers: {trigger_count}", flush=True)
    if last_trigger_time:
        print(f"Last trigger at: {last_trigger_time}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
