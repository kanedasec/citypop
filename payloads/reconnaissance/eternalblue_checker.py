#!/usr/bin/env python3
# @name: EternalBlue (MS17-010) Checker
# @desc: DETECTION ONLY -- no exploitation code.
# @category: reconnaissance
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- EternalBlue (MS17-010) Checker
=====================================================
DETECTION ONLY -- no exploitation code.

Scans local subnet for port 445 hosts, then sends SMB1 negotiate +
session setup + tree connect + Trans2 PeekNamedPipe to check MS17-010.
STATUS_INSUFF_SERVER_RESOURCES (0xC0000205) = VULNERABLE.

Results: $CITYPOP_ROOT/loot/EternalBlue/scan_TIMESTAMP.json
Controls:
  python3 eternalblue_checker.py

  No arguments needed -- the local subnet is auto-detected and the scan
  starts immediately. Progress is printed as hosts are checked.

  Ctrl-C    -- stop the scan early and save/print whatever was found so far
"""

import os, sys, json, socket, struct, subprocess, re
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'EternalBlue')
os.makedirs(LOOT_DIR, exist_ok=True)

SMB_PORT = 445
CONNECT_TIMEOUT = 3
RECV_TIMEOUT = 5
NT_INSUFF_RESOURCES = 0xC0000205

# ---------------------------------------------------------------------------
# SMB1 packet builders (raw bytes -- detection only)
# ---------------------------------------------------------------------------

def _nb_wrap(payload):
    """Prepend NetBIOS session header to SMB payload."""
    return b"\x00" + struct.pack(">I", len(payload))[1:] + payload


def _smb_header(command, tid=0, uid=0):
    """Build a 32-byte SMB1 header."""
    hdr = b"\xff\x53\x4d\x42"          # SMB magic
    hdr += bytes([command])             # Command
    hdr += b"\x00\x00\x00\x00"         # Status
    hdr += b"\x18\x53\xc8"             # Flags + Flags2
    hdr += b"\x00" * 12                # PID high, signature, reserved
    hdr += struct.pack("<H", tid)       # TID
    hdr += b"\xff\xfe"                  # PID
    hdr += struct.pack("<H", uid)       # UID
    hdr += b"\x00\x00"                  # MID
    return hdr


def _smb1_negotiate():
    """SMB1 Negotiate with NT LM 0.12 dialect."""
    dialect = b"\x02NT LM 0.12\x00"
    payload = _smb_header(0x72)
    payload += b"\x00"                          # Word count = 0
    payload += struct.pack("<H", len(dialect))  # Byte count
    payload += dialect
    return _nb_wrap(payload)


def _smb1_session_setup():
    """SMB1 Session Setup AndX -- null/anonymous authentication."""
    words = b"\x0d"         # Word count = 13
    words += b"\xff\x00"    # AndXCommand + reserved
    words += b"\x00\x00"    # AndXOffset
    words += b"\x04\x11"    # Max buffer
    words += b"\x0a\x00"    # Max Mpx
    words += b"\x00\x00"    # VC number
    words += b"\x00" * 4    # Session key
    words += b"\x01\x00"    # ANSI pw len = 1
    words += b"\x00\x00"    # Unicode pw len = 0
    words += b"\x00" * 4    # Reserved
    words += b"\xd4\x00\x00\x00"  # Capabilities
    byte_data = b"\x00" * 4       # Null password + padding
    payload = _smb_header(0x73) + words + struct.pack("<H", len(byte_data)) + byte_data
    return _nb_wrap(payload)


def _smb1_tree_connect(ip, uid=0):
    """SMB1 Tree Connect AndX to IPC$ share."""
    words = b"\x04"         # Word count = 4
    words += b"\xff\x00"    # AndXCommand + reserved
    words += b"\x00\x00"    # AndXOffset
    words += b"\x00\x00"    # Flags
    words += b"\x01\x00"    # Password length = 1
    ipc_path = f"\\\\{ip}\\IPC$\x00".encode("ascii")
    byte_data = b"\x00" + ipc_path + b"?????\x00"
    payload = _smb_header(0x75, uid=uid) + words
    payload += struct.pack("<H", len(byte_data)) + byte_data
    return _nb_wrap(payload)


def _smb1_peeknamedpipe(tid=0, uid=0):
    """Trans request -- PeekNamedPipe FID 0 (the MS17-010 fingerprint)."""
    words = b"\x10"         # Word count = 16
    words += b"\x00\x00"    # Total param count
    words += b"\x00\x00"    # Total data count
    words += b"\xff\xff"    # Max param count
    words += b"\xff\xff"    # Max data count
    words += b"\x00\x00"    # Max setup + reserved
    words += b"\x00\x00"    # Flags
    words += b"\x00" * 4    # Timeout
    words += b"\x00\x00"    # Reserved
    words += b"\x00\x00"    # Param count
    words += b"\x4a\x00"    # Param offset
    words += b"\x00\x00"    # Data count
    words += b"\x4a\x00"    # Data offset
    words += b"\x02\x00"    # Setup count + reserved
    words += b"\x23\x00"    # PeekNamedPipe (0x0023)
    words += b"\x00\x00"    # FID = 0
    byte_data = b"\x07\x00\\PIPE\\\x00"
    payload = _smb_header(0x25, tid, uid) + words
    payload += struct.pack("<H", len(byte_data)) + byte_data
    return _nb_wrap(payload)


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------

def _parse_nt_status(resp):
    return struct.unpack("<I", resp[9:13])[0] if len(resp) >= 13 else 0

def _parse_uid(resp):
    return struct.unpack("<H", resp[36:38])[0] if len(resp) >= 38 else 0

def _parse_tid(resp):
    return struct.unpack("<H", resp[32:34])[0] if len(resp) >= 34 else 0

def _parse_os_info(resp):
    """Try to extract OS string from Session Setup response."""
    try:
        raw = resp[36:]
        if len(raw) < 3:
            return ""
        wc = raw[0]
        off = 1 + (wc * 2) + 2
        if off >= len(raw):
            return ""
        section = raw[off:]
        for encoding in ("utf-16-le", "ascii"):
            decoded = section.decode(encoding, errors="ignore")
            for part in decoded.split("\x00"):
                cleaned = part.strip()
                if len(cleaned) > 3:
                    return cleaned[:40]
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# MS17-010 check for a single host
# ---------------------------------------------------------------------------

def check_ms17_010(ip):
    """Returns dict with host, status (VULNERABLE/PATCHED/ERROR), os_info, detail."""
    result = {"host": ip, "status": "ERROR", "os_info": "", "detail": ""}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((ip, SMB_PORT))
        sock.settimeout(RECV_TIMEOUT)

        # 1) Negotiate
        sock.send(_smb1_negotiate())
        resp = sock.recv(4096)
        if len(resp) < 36:
            result["detail"] = "Bad negotiate response"
            return result

        # 2) Session Setup (anonymous)
        sock.send(_smb1_session_setup())
        resp = sock.recv(4096)
        uid = _parse_uid(resp)
        result["os_info"] = _parse_os_info(resp)

        # 3) Tree Connect to IPC$
        sock.send(_smb1_tree_connect(ip, uid))
        resp = sock.recv(4096)
        tid = _parse_tid(resp)

        # 4) PeekNamedPipe -- the actual MS17-010 fingerprint
        sock.send(_smb1_peeknamedpipe(tid, uid))
        resp = sock.recv(4096)
        nt_status = _parse_nt_status(resp)

        if nt_status == NT_INSUFF_RESOURCES:
            result["status"] = "VULNERABLE"
            result["detail"] = "STATUS_INSUFF_SERVER_RESOURCES"
        else:
            result["status"] = "PATCHED"
            result["detail"] = f"NT_STATUS=0x{nt_status:08X}"

    except socket.timeout:
        result["detail"] = "Connection timeout"
    except ConnectionRefusedError:
        result["detail"] = "Port 445 refused"
    except OSError as exc:
        result["detail"] = str(exc)[:50]
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return result


# ---------------------------------------------------------------------------
# Subnet discovery
# ---------------------------------------------------------------------------

def _get_local_cidr():
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            if "127." in line:
                continue
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def _scan_port_445(cidr, on_progress, stop_fn):
    """TCP connect scan for port 445 across the subnet."""
    import ipaddress
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    hosts = []
    total = min(network.num_addresses, 256)
    checked = 0
    for addr in network.hosts():
        if stop_fn():
            break
        ip = str(addr)
        checked += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((ip, SMB_PORT)) == 0:
                hosts.append(ip)
            s.close()
        except Exception:
            pass
        on_progress(checked, total, len(hosts))
    return hosts


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------

_stop_requested = False


def _request_stop(*_a):
    global _stop_requested
    _stop_requested = True


def _do_scan():
    print("Detecting subnet...", flush=True)
    cidr = _get_local_cidr()
    if not cidr:
        print("No network found.", flush=True)
        return []

    print(f"Scanning {cidr} for port 445 (SMB)...", flush=True)

    def on_progress(checked, total, found):
        if checked % 16 == 0 or checked == total:
            print(f"  445: {checked}/{total} checked ({found} SMB hosts)", flush=True)

    stop_fn = lambda: _stop_requested
    smb_hosts = _scan_port_445(cidr, on_progress, stop_fn)

    if _stop_requested:
        print("Cancelled.", flush=True)
        return []
    if not smb_hosts:
        print("No SMB hosts found.", flush=True)
        return []

    print(f"Checking {len(smb_hosts)} host(s) for MS17-010...", flush=True)
    results = []
    try:
        for idx, ip in enumerate(smb_hosts):
            if _stop_requested:
                break
            print(f"  [{idx + 1}/{len(smb_hosts)}] {ip} ...", end=" ", flush=True)
            entry = check_ms17_010(ip)
            results.append(entry)
            print(f"{entry['status']} ({entry['detail']})", flush=True)
    except KeyboardInterrupt:
        print("\nInterrupted, saving partial results...", flush=True)

    vuln_count = sum(1 for r in results if r["status"] == "VULNERABLE")
    print(f"Done: {vuln_count} vulnerable / {len(results)} hosts checked", flush=True)
    _save_results(results)
    return results


def _save_results(results):
    if not results:
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    data = {
        "scan_time": ts,
        "description": "MS17-010 EternalBlue detection scan",
        "host_count": len(results),
        "vulnerable": sum(1 for r in results if r["status"] == "VULNERABLE"),
        "patched": sum(1 for r in results if r["status"] == "PATCHED"),
        "errors": sum(1 for r in results if r["status"] == "ERROR"),
        "hosts": results,
    }
    path = os.path.join(LOOT_DIR, f"scan_{ts}.json")
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"Saved results to {path}", flush=True)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("EternalBlue (MS17-010) Checker -- DETECTION ONLY", flush=True)
    print("Auto-discovers SMB hosts on the local subnet.", flush=True)
    print("Press Ctrl-C to stop the scan early.\n", flush=True)

    try:
        _do_scan()
    except KeyboardInterrupt:
        _request_stop()
        print("\nInterrupted, stopping...", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
