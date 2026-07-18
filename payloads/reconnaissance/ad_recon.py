#!/usr/bin/env python3
# @name: Active Directory Reconnaissance
# @desc: Active Directory reconnaissance via LDAP.
# @category: reconnaissance
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- Active Directory Reconnaissance
======================================================
Author: 7h30th3r0n3

Active Directory reconnaissance via LDAP.  Connects to a discovered or
user-specified LDAP server on port 389/636, attempts anonymous bind
then null-session enumeration.  Extracts: domain name, naming contexts,
users (sAMAccountName), groups, computers, and OUs.

Uses subprocess ``ldapsearch`` when available; otherwise crafts
lightweight raw LDAP search requests over a plain TCP socket (no
ldap3 dependency required).

Setup / Prerequisites
---------------------
- Network access to a domain controller on port 389 or 636.
- ``ldapsearch`` recommended (from ldap-utils package).

Controls
--------
  Usage: ad_recon.py [ldap_server_ip]

  If no LDAP server IP is given, the local subnet is scanned for hosts
  with port 389 open and the operator is prompted to pick one. Full
  enumeration (domain, users, groups, computers, OUs) runs automatically
  and results are printed to stdout and exported as JSON to loot.
"""

from payloads._web_input import request_input
import os
import sys
import time
import json
import re
import socket
import struct
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_LOOT", "/tmp/citypop_loot"), "ADRecon")
os.makedirs(LOOT_DIR, exist_ok=True)

LDAP_PORT = 389
VIEWS = ["domain", "users", "groups", "computers"]
VIEW_LABELS = ["Domain", "Users", "Groups", "Computers"]

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_state = {
    "ldap_servers": [],
    "selected_server": "",
    "domain": "",
    "naming_contexts": [],
    "base_dn": "",
    "users": [],
    "groups": [],
    "computers": [],
    "ous": [],
    "status": "Idle",
    "scanning": False,
    "stop": False,
    "view_idx": 0,
    "scroll": 0,
}


def _get(key):
    val = _state[key]
    if isinstance(val, (list, dict)):
        return list(val) if isinstance(val, list) else dict(val)
    return val


def _set(**kw):
    for k, v in kw.items():
        _state[k] = v
    if "status" in kw:
        print(f"[*] {kw['status']}", flush=True)


# ---------------------------------------------------------------------------
# LDAP server discovery
# ---------------------------------------------------------------------------
def _get_local_subnet():
    """Return local subnet in CIDR form, e.g. 192.168.1.0/24."""
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            if "127." not in line:
                m = re.search(r"inet (\d+\.\d+\.\d+)\.\d+/(\d+)", line)
                if m:
                    return f"{m.group(1)}.0/{m.group(2)}"
    except Exception:
        pass
    return "192.168.1.0/24"


def _scan_ldap_servers():
    """Scan local subnet for hosts with port 389 open."""
    _set(scanning=True, status="Scanning for LDAP...")
    subnet = _get_local_subnet()
    servers = []

    try:
        out = subprocess.run(
            ["nmap", "-p", "389", "--open", "-T4", "-oG", "-", subnet],
            capture_output=True, text=True, timeout=60,
        )
        for line in out.stdout.splitlines():
            m = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m and "389/open" in line:
                servers.append(m.group(1))
    except FileNotFoundError:
        # nmap not available, try ARP + connect
        servers = _fallback_ldap_scan()
    except Exception:
        pass

    _set(ldap_servers=servers, scanning=False,
         status=f"Found {len(servers)} LDAP server(s)")
    if servers and not _get("selected_server"):
        _set(selected_server=servers[0])


def _fallback_ldap_scan():
    """Simple connect scan of ARP neighbors for port 389."""
    servers = []
    try:
        out = subprocess.run(
            ["arp", "-an"], capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
            if m:
                ip = m.group(1)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.8)
                try:
                    if s.connect_ex((ip, LDAP_PORT)) == 0:
                        servers.append(ip)
                except Exception:
                    pass
                finally:
                    s.close()
    except Exception:
        pass
    return servers


# ---------------------------------------------------------------------------
# LDAP enumeration via ldapsearch subprocess
# ---------------------------------------------------------------------------
def _has_ldapsearch():
    try:
        subprocess.run(["ldapsearch", "--help"],
                       capture_output=True, timeout=3)
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return True  # exists but returned error


def _ldapsearch(server, base_dn, ldap_filter, attrs, scope="sub"):
    """Run ldapsearch and return raw output text."""
    cmd = [
        "ldapsearch", "-x", "-H", f"ldap://{server}",
        "-b", base_dn, "-s", scope, ldap_filter,
    ] + attrs
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
        )
        return out.stdout
    except Exception as exc:
        return f"ERROR: {exc}"


def _parse_ldapsearch(text, attr_name):
    """Extract values for a given attribute from ldapsearch output."""
    results = []
    for line in text.splitlines():
        if line.startswith(f"{attr_name}:"):
            val = line.split(":", 1)[1].strip()
            if val:
                results.append(val)
    return results


# ---------------------------------------------------------------------------
# Raw LDAP (minimal ASN.1 / BER) for environments without ldapsearch
# ---------------------------------------------------------------------------
def _ber_length(length):
    """Encode a BER length field."""
    if length < 0x80:
        return bytes([length])
    if length < 0x100:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _ber_seq(tag, data):
    """Wrap data in a BER TLV."""
    return bytes([tag]) + _ber_length(len(data)) + data


def _ber_int(val):
    """Encode integer."""
    if val < 0x80:
        return _ber_seq(0x02, bytes([val]))
    buf = val.to_bytes((val.bit_length() + 8) // 8, "big", signed=False)
    return _ber_seq(0x02, buf)


def _ber_str(val, tag=0x04):
    """Encode octet string."""
    encoded = val.encode("utf-8") if isinstance(val, str) else val
    return _ber_seq(tag, encoded)


def _ber_enum(val):
    return _ber_seq(0x0A, bytes([val]))


def _build_bind_request(msg_id):
    """Build anonymous LDAP BindRequest."""
    version = _ber_int(3)
    name = _ber_str("")
    auth = _ber_str("", tag=0x80)  # simple auth, empty password
    bind_body = version + name + auth
    bind_req = _ber_seq(0x60, bind_body)
    msg = _ber_int(msg_id) + bind_req
    return _ber_seq(0x30, msg)


def _build_search_request(msg_id, base_dn, ldap_filter, attrs):
    """Build a simple LDAP SearchRequest."""
    base = _ber_str(base_dn)
    scope = _ber_enum(2)        # subtree
    deref = _ber_enum(0)        # neverDerefAliases
    size_limit = _ber_int(100)
    time_limit = _ber_int(10)
    types_only = bytes([0x01, 0x01, 0x00])

    # Simple present filter: (objectClass=*)
    filt = _ber_str(ldap_filter, tag=0x87)

    # Attribute list
    attr_items = b"".join(_ber_str(a) for a in attrs)
    attr_seq = _ber_seq(0x30, attr_items)

    search_body = (base + scope + deref + size_limit + time_limit +
                   types_only + filt + attr_seq)
    search_req = _ber_seq(0x63, search_body)
    msg = _ber_int(msg_id) + search_req
    return _ber_seq(0x30, msg)


def _raw_ldap_query(server, base_dn, ldap_filter, attrs):
    """Send raw LDAP bind+search and return attribute values as list."""
    results = []
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8)
    try:
        s.connect((server, LDAP_PORT))

        # Bind
        s.sendall(_build_bind_request(1))
        s.recv(4096)

        # Search
        s.sendall(_build_search_request(2, base_dn, ldap_filter, attrs))

        buf = b""
        while True:
            try:
                chunk = s.recv(8192)
                if not chunk:
                    break
                buf += chunk
            except socket.timeout:
                break

        # Crude extraction: look for printable attribute values
        text = buf.decode("utf-8", errors="replace")
        for attr in attrs:
            for m in re.finditer(re.escape(attr) + r"[\x00-\x10]*([^\x00\x01\x02\x03\x04\x30]{2,60})", text):
                val = m.group(1).strip()
                if val and len(val) > 1:
                    results.append(val)
    except Exception:
        pass
    finally:
        s.close()
    return results


# ---------------------------------------------------------------------------
# Enumeration orchestration
# ---------------------------------------------------------------------------
def _do_enumerate():
    """Full AD enumeration."""
    _set(scanning=True, stop=False, status="Connecting...")

    server = _get("selected_server")
    if not server:
        _set(scanning=False, status="No LDAP server set")
        return

    use_cli = _has_ldapsearch()

    # Step 1: get rootDSE / naming contexts
    _set(status="Reading rootDSE...")
    if use_cli:
        raw = _ldapsearch(server, "", "objectClass=*",
                          ["namingContexts", "defaultNamingContext",
                           "dnsHostName"], scope="base")
        nc_list = _parse_ldapsearch(raw, "namingContexts")
        default_nc = _parse_ldapsearch(raw, "defaultNamingContext")
        base = default_nc[0] if default_nc else (nc_list[0] if nc_list else "")
        domain_name = base.replace("DC=", "").replace(",", ".") if base else ""
    else:
        vals = _raw_ldap_query(server, "", "objectClass",
                               ["namingContexts", "defaultNamingContext"])
        nc_list = vals
        base = vals[0] if vals else ""
        domain_name = base.replace("DC=", "").replace(",", ".") if base else server

    _set(naming_contexts=nc_list, base_dn=base, domain=domain_name)

    if not base:
        _set(scanning=False, status="No base DN found")
        return

    if _get("stop"):
        _set(scanning=False)
        return

    # Step 2: Users
    _set(status="Enumerating users...")
    if use_cli:
        raw = _ldapsearch(server, base, "(&(objectClass=user)(sAMAccountName=*))",
                          ["sAMAccountName"])
        users = _parse_ldapsearch(raw, "sAMAccountName")
    else:
        users = _raw_ldap_query(server, base, "sAMAccountName",
                                ["sAMAccountName"])
    _set(users=users)

    if _get("stop"):
        _set(scanning=False)
        return

    # Step 3: Groups
    _set(status="Enumerating groups...")
    if use_cli:
        raw = _ldapsearch(server, base, "(objectClass=group)", ["cn"])
        groups = _parse_ldapsearch(raw, "cn")
    else:
        groups = _raw_ldap_query(server, base, "group", ["cn"])
    _set(groups=groups)

    if _get("stop"):
        _set(scanning=False)
        return

    # Step 4: Computers
    _set(status="Enumerating computers...")
    if use_cli:
        raw = _ldapsearch(server, base, "(objectClass=computer)",
                          ["dNSHostName", "cn"])
        computers = _parse_ldapsearch(raw, "cn")
        if not computers:
            computers = _parse_ldapsearch(raw, "dNSHostName")
    else:
        computers = _raw_ldap_query(server, base, "computer", ["cn"])
    _set(computers=computers)

    if _get("stop"):
        _set(scanning=False)
        return

    # Step 5: OUs
    _set(status="Enumerating OUs...")
    if use_cli:
        raw = _ldapsearch(server, base,
                          "(objectClass=organizationalUnit)", ["ou"])
        ous = _parse_ldapsearch(raw, "ou")
    else:
        ous = _raw_ldap_query(server, base, "organizationalUnit", ["ou"])
    _set(ous=ous)

    u = len(_get("users"))
    g = len(_get("groups"))
    c = len(_get("computers"))
    _set(scanning=False,
         status=f"U:{u} G:{g} C:{c}")


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
def _export_json():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    data = {
        "scan_time": ts,
        "server": _get("selected_server"),
        "domain": _get("domain"),
        "base_dn": _get("base_dn"),
        "naming_contexts": _get("naming_contexts"),
        "users": _get("users"),
        "groups": _get("groups"),
        "computers": _get("computers"),
        "ous": _get("ous"),
    }
    path = os.path.join(LOOT_DIR, f"adrecon_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def _print_results():
    print("", flush=True)
    print(f"Server: {_get('selected_server') or '(none)'}", flush=True)
    print(f"Domain: {_get('domain') or '?'}", flush=True)
    print(f"Base DN: {_get('base_dn') or '?'}", flush=True)
    print(f"Naming contexts: {_get('naming_contexts')}", flush=True)

    for label, key in (("Users", "users"), ("Groups", "groups"),
                        ("Computers", "computers"), ("OUs", "ous")):
        items = _get(key)
        print(f"\n{label} ({len(items)}):", flush=True)
        for item in items:
            print(f"  - {item}", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("AD RECON - LDAP enumeration", flush=True)

    args = sys.argv[1:]
    server = args[0] if args else ""

    if not server:
        print("[*] No LDAP server given, scanning local subnet...", flush=True)
        _scan_ldap_servers()
        servers = _get("ldap_servers")
        if not servers:
            print("No LDAP servers found on the local subnet.", flush=True)
            print("Usage: ad_recon.py [ldap_server_ip]", flush=True)
            return 1

        print("\nDiscovered LDAP servers:", flush=True)
        for i, s in enumerate(servers, 1):
            print(f"  {i}. {s}", flush=True)

        try:
            choice = request_input(f"Select server [1-{len(servers)}]: ").strip()
            idx = int(choice) - 1
            if not (0 <= idx < len(servers)):
                raise ValueError
        except (ValueError, EOFError, KeyboardInterrupt):
            print("Invalid selection, aborting.", flush=True)
            return 1

        server = servers[idx]

    _set(selected_server=server)

    try:
        _do_enumerate()
    except KeyboardInterrupt:
        _set(stop=True)
        print("\n[!] Enumeration interrupted by user", flush=True)

    _print_results()

    path = _export_json()
    print(f"\n[*] Exported results to {path}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
