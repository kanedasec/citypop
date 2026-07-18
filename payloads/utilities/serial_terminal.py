#!/usr/bin/env python3
# @name: Serial Terminal (Multi-port)
# @desc: Multi-port serial terminal with auto-baud detection.
# @category: utilities
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- Serial Terminal (Multi-port)
===================================================
Author: 7h30th3r0n3

Multi-port serial terminal with auto-baud detection.
Supports USB serial adapters and onboard UARTs.

Controls:
  Usage: serial_terminal.py [port] [baud|auto]
    port   Serial device path (e.g. /dev/ttyUSB0). If omitted, detected
           ports are listed and you pick one.
    baud   Baud rate, or "auto" to auto-detect (default: auto)
  Type a line and press Enter to send it to the port.
  Type ~c and Enter to send Ctrl+C to the device.
  Type ~q and Enter, or press Ctrl+C, to disconnect and exit.
"""

from payloads._web_input import request_input
import os
import sys
import time
import signal
import subprocess
import glob
import threading

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

try:
    import serial
except ImportError:
    subprocess.run(["pip3", "install", "--break-system-packages", "pyserial"],
                   capture_output=True, timeout=60)
    import serial

BAUDS = [300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]

_running = True


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


class SerialPort:
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)
        self.baud = 115200
        self.ser = None
        self.connected = False
        self.lines = []
        self.lock = threading.Lock()
        self.thread = None

    def connect(self):
        try:
            self.ser = serial.Serial(self.path, self.baud, timeout=0.2)
            self.connected = True
            self.thread = threading.Thread(target=self._rx_loop, daemon=True)
            self.thread.start()
            return True
        except Exception as exc:
            print(f"[!] Failed to open {self.path}: {exc}", flush=True)
            self.connected = False
            return False

    def disconnect(self):
        self.connected = False
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None

    def send(self, data):
        if self.ser and self.connected:
            try:
                self.ser.write(data.encode())
            except Exception:
                pass

    def send_line(self, line):
        self.send(line + "\r\n")
        print(f"> {line}", flush=True)

    def _rx_loop(self):
        while self.connected and _running:
            try:
                raw = self.ser.readline()
                if raw:
                    line = raw.decode(errors="replace").rstrip("\r\n")
                    if line:
                        print(f"< {line}", flush=True)
            except Exception:
                time.sleep(0.05)

    def auto_baud(self):
        """Try baud rates and find the one producing readable ASCII."""
        best_baud = 115200
        best_score = 0
        was_connected = self.connected
        if was_connected:
            self.disconnect()
            time.sleep(0.2)

        for baud in [115200, 9600, 57600, 38400, 19200, 230400, 460800, 4800, 1200]:
            try:
                s = serial.Serial(self.path, baud, timeout=0.5)
                s.reset_input_buffer()
                time.sleep(0.3)
                data = s.read(256)
                s.close()
                if not data:
                    continue
                printable = sum(1 for b in data if 32 <= b <= 126 or b in (10, 13, 9))
                score = printable / len(data)
                if score > best_score:
                    best_score = score
                    best_baud = baud
                if score > 0.8:
                    break
            except Exception:
                continue

        self.baud = best_baud
        if was_connected:
            self.connect()
        return best_baud, best_score


def _scan_ports():
    ports = []
    for p in sorted(glob.glob("/dev/ttyUSB*")):
        ports.append(p)
    for p in sorted(glob.glob("/dev/ttyACM*")):
        ports.append(p)
    if os.path.exists("/dev/ttyS0"):
        ports.append("/dev/ttyS0")
    if os.path.exists("/dev/ttyAMA0") and "/dev/ttyAMA0" not in ports:
        ports.append("/dev/ttyAMA0")
    return ports


def _choose_port():
    ports = _scan_ports()
    if not ports:
        print("[!] No serial ports found.", flush=True)
        return None
    if len(ports) == 1:
        print(f"[*] Using only detected port: {ports[0]}", flush=True)
        return ports[0]
    print("Detected serial ports:", flush=True)
    for i, p in enumerate(ports):
        print(f"  {i + 1}. {p}", flush=True)
    try:
        choice = request_input(f"Select port [1-{len(ports)}]: ").strip()
        idx = int(choice) - 1
        if 0 <= idx < len(ports):
            return ports[idx]
    except (ValueError, EOFError, KeyboardInterrupt):
        pass
    print("[!] Invalid selection.", flush=True)
    return None


def main():
    global _running

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        print(__doc__, flush=True)
        return 0

    port_path = args[0] if len(args) >= 1 else None
    baud_arg = args[1] if len(args) >= 2 else "auto"

    if not port_path:
        port_path = _choose_port()
        if not port_path:
            return 1

    sp = SerialPort(port_path)

    if baud_arg.lower() == "auto":
        print(f"[*] Auto-detecting baud rate on {port_path}...", flush=True)
        baud, score = sp.auto_baud()
        print(f"[*] Detected {baud} baud (confidence {int(score * 100)}%)", flush=True)
    else:
        try:
            sp.baud = int(baud_arg)
        except ValueError:
            print(f"[!] Invalid baud rate: {baud_arg}", flush=True)
            return 1

    if not sp.connect():
        return 1

    print(f"[*] Connected to {port_path} @ {sp.baud} baud. "
          f"Type ~c for Ctrl+C, ~q or Ctrl+C to quit.", flush=True)

    try:
        while _running:
            try:
                line = request_input()
            except EOFError:
                break
            if not _running:
                break
            if line == "~q":
                break
            if line == "~c":
                sp.send("\x03")
                print("> ^C", flush=True)
                continue
            sp.send_line(line)
    except KeyboardInterrupt:
        pass
    finally:
        _running = False
        sp.disconnect()
        print("[*] Disconnected.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
