#!/usr/bin/env python3
# @name: TCP/IP Fingerprint Spoofer
# @desc: Spoof the TCP/IP stack fingerprint via sysctl to impersonate different operating systems.
# @category: evasion
# @danger: true
# @active: true
"""
RaspyJack Payload -- TCP/IP Fingerprint Spoofer
=================================================
Author: 7h30th3r0n3

Spoof the TCP/IP stack fingerprint via sysctl to impersonate different
operating systems.  Changes: net.ipv4.ip_default_ttl, TCP window size,
and DF bit behaviour.

Presets: Linux, Windows 10, macOS, Cisco IOS, Printer.

Setup / Prerequisites
---------------------
- Root privileges (for sysctl writes).
- Linux kernel with sysctl support.

Usage
-----
    fingerprint_spoof.py [profile]

    profile -- one of: linux, windows10, macos, cisco, printer
               (prompted from a numbered list if omitted)

Applies the chosen fingerprint profile via sysctl, prints the resulting
stack values, and keeps it active -- printing periodic status lines --
until interrupted with Ctrl-C, at which point the original sysctl values
are restored.
"""

from payloads._web_input import request_input
import os
import sys
import time
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Profile definitions: (name, ttl, tcp_window, df_bit_pmtu)
# df_bit_pmtu: "want" = set DF (pmtu discovery on), "dont" = clear DF
PROFILES = [
    {
        "name": "Linux",
        "ttl": 64,
        "tcp_rmem": "4096 87380 6291456",
        "tcp_wmem": "4096 16384 4194304",
        "ip_no_pmtu_disc": 0,      # DF bit ON
        "tcp_sack": 1,
        "tcp_timestamps": 1,
        "tcp_window_scaling": 1,
    },
    {
        "name": "Windows 10",
        "ttl": 128,
        "tcp_rmem": "4096 65535 65535",
        "tcp_wmem": "4096 65535 65535",
        "ip_no_pmtu_disc": 1,      # DF bit OFF
        "tcp_sack": 1,
        "tcp_timestamps": 0,
        "tcp_window_scaling": 1,
    },
    {
        "name": "macOS",
        "ttl": 64,
        "tcp_rmem": "4096 131072 6291456",
        "tcp_wmem": "4096 16384 4194304",
        "ip_no_pmtu_disc": 0,
        "tcp_sack": 1,
        "tcp_timestamps": 1,
        "tcp_window_scaling": 1,
    },
    {
        "name": "Cisco IOS",
        "ttl": 255,
        "tcp_rmem": "4096 4128 4128",
        "tcp_wmem": "4096 4128 4128",
        "ip_no_pmtu_disc": 1,
        "tcp_sack": 0,
        "tcp_timestamps": 0,
        "tcp_window_scaling": 0,
    },
    {
        "name": "Printer",
        "ttl": 64,
        "tcp_rmem": "4096 2048 2048",
        "tcp_wmem": "4096 2048 2048",
        "ip_no_pmtu_disc": 1,
        "tcp_sack": 0,
        "tcp_timestamps": 0,
        "tcp_window_scaling": 0,
    },
]

_SLUGS = {
    "linux": "Linux",
    "windows10": "Windows 10",
    "windows": "Windows 10",
    "macos": "macOS",
    "mac": "macOS",
    "cisco": "Cisco IOS",
    "ciscoios": "Cisco IOS",
    "printer": "Printer",
}

STATUS_INTERVAL = 10.0

_original_values = {}


# ---------------------------------------------------------------------------
# Sysctl helpers
# ---------------------------------------------------------------------------
def _sysctl_read(key):
    """Read a sysctl value."""
    try:
        out = subprocess.run(
            ["sysctl", "-n", key],
            capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip()
    except Exception:
        return "?"


def _sysctl_write(key, value):
    """Write a sysctl value. Returns True on success."""
    try:
        result = subprocess.run(
            ["sysctl", "-w", f"{key}={value}"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _read_current_values():
    """Read all relevant sysctl values."""
    return {
        "ttl": _sysctl_read("net.ipv4.ip_default_ttl"),
        "tcp_rmem": _sysctl_read("net.ipv4.tcp_rmem"),
        "tcp_wmem": _sysctl_read("net.ipv4.tcp_wmem"),
        "ip_no_pmtu_disc": _sysctl_read("net.ipv4.ip_no_pmtu_disc"),
        "tcp_sack": _sysctl_read("net.ipv4.tcp_sack"),
        "tcp_timestamps": _sysctl_read("net.ipv4.tcp_timestamps"),
        "tcp_window_scaling": _sysctl_read("net.ipv4.tcp_window_scaling"),
    }


def _save_originals():
    """Save original values for restoration."""
    global _original_values
    if _original_values:
        return  # Already saved
    _original_values = _read_current_values()


def _apply_profile(profile):
    """Apply a fingerprint profile via sysctl."""
    print(f"Applying profile: {profile['name']}...", flush=True)
    _save_originals()

    success = True
    success = _sysctl_write("net.ipv4.ip_default_ttl", profile["ttl"]) and success
    success = _sysctl_write("net.ipv4.tcp_rmem", profile["tcp_rmem"]) and success
    success = _sysctl_write("net.ipv4.tcp_wmem", profile["tcp_wmem"]) and success
    success = _sysctl_write("net.ipv4.ip_no_pmtu_disc", profile["ip_no_pmtu_disc"]) and success
    success = _sysctl_write("net.ipv4.tcp_sack", profile["tcp_sack"]) and success
    success = _sysctl_write("net.ipv4.tcp_timestamps", profile["tcp_timestamps"]) and success
    success = _sysctl_write("net.ipv4.tcp_window_scaling", profile["tcp_window_scaling"]) and success

    if success:
        print(f"Applied: {profile['name']}", flush=True)
    else:
        print(f"Partial: {profile['name']} (one or more sysctl writes failed)", flush=True)

    return success


def _restore_defaults():
    """Restore original sysctl values."""
    if not _original_values:
        print("No originals saved; nothing to restore.", flush=True)
        return

    print("Restoring original sysctl values...", flush=True)

    _sysctl_write("net.ipv4.ip_default_ttl", _original_values.get("ttl", "64"))
    _sysctl_write("net.ipv4.tcp_rmem", _original_values.get("tcp_rmem", "4096 87380 6291456"))
    _sysctl_write("net.ipv4.tcp_wmem", _original_values.get("tcp_wmem", "4096 16384 4194304"))
    _sysctl_write("net.ipv4.ip_no_pmtu_disc", _original_values.get("ip_no_pmtu_disc", "0"))
    _sysctl_write("net.ipv4.tcp_sack", _original_values.get("tcp_sack", "1"))
    _sysctl_write("net.ipv4.tcp_timestamps", _original_values.get("tcp_timestamps", "1"))
    _sysctl_write("net.ipv4.tcp_window_scaling", _original_values.get("tcp_window_scaling", "1"))

    print("Defaults restored.", flush=True)


def _print_current_values():
    """Print all current sysctl values."""
    values = _read_current_values()
    print("Current TCP/IP stack values:", flush=True)
    for key, val in values.items():
        print(f"  {key}: {val}", flush=True)


# ---------------------------------------------------------------------------
# Profile selection
# ---------------------------------------------------------------------------
def _prompt_profile():
    print("Fingerprint profiles:", flush=True)
    for i, prof in enumerate(PROFILES, 1):
        print(f"  {i}. {prof['name']} (TTL={prof['ttl']})", flush=True)
    while True:
        choice = request_input("Select profile number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(PROFILES):
            return PROFILES[int(choice) - 1]
        print("Invalid selection, try again.", flush=True)


def _resolve_profile(arg):
    if arg:
        slug = arg.strip().lower().replace(" ", "").replace("-", "")
        name = _SLUGS.get(slug)
        if name:
            for prof in PROFILES:
                if prof["name"] == name:
                    return prof
        print(
            f"Unknown profile '{arg}'. Choose from: "
            f"{', '.join(sorted({'linux', 'windows10', 'macos', 'cisco', 'printer'}))}",
            flush=True,
        )
        return None
    return _prompt_profile()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    profile_arg = sys.argv[1] if len(sys.argv) > 1 else None
    profile = _resolve_profile(profile_arg)
    if not profile:
        return 1

    _save_originals()
    _apply_profile(profile)
    _print_current_values()

    print(
        f"Fingerprint spoofing active ({profile['name']}). "
        "Press Ctrl-C to stop and restore original values.",
        flush=True,
    )
    try:
        while True:
            time.sleep(STATUS_INTERVAL)
            print(f"[status] Still spoofing as {profile['name']}", flush=True)
    except KeyboardInterrupt:
        print("\nStopping fingerprint spoofing...", flush=True)
    finally:
        _restore_defaults()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
