#!/usr/bin/env python3
# @name: Shodan InternetDB Query
# @desc: Queries the free Shodan InternetDB API (no API key required) for IP intelligence.
# @category: reconnaissance
# @danger: false
# @active: true
# @maturity: functional
# @web: true
"""
RaspyJack Payload -- Shodan InternetDB Query
=============================================
Author: 7h30th3r0n3

Queries the free Shodan InternetDB API (no API key required) for IP
intelligence.  Auto-detects public IP or allows manual entry via a
character picker.  Displays open ports, hostnames, CVEs, CPEs, and tags.

Controls:
  Usage: shodan_query.py [ip1 ip2 ...]

  With one or more IPv4 addresses given as arguments, each is queried
  directly. With no arguments, the host's public IP is auto-detected and
  the rest of the engagement's loot is scanned for other public IPs seen
  in past artifacts (this payload's own saved results are excluded, so a
  prior query is never re-offered as a new candidate). Each candidate is
  labeled with where it came from, and you are prompted with a real
  select dialog to pick which to query. All results are printed to
  stdout and exported to loot as JSON.
"""

from payloads._web_input import request_input
import os
import sys
import json
import re
from datetime import datetime

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_LOOT", "/tmp/citypop_loot"), "Shodan")
LOOT_SRC_DIR = os.environ.get("CITYPOP_LOOT", "/tmp/citypop_loot")
API_URL = "https://internetdb.shodan.io/"
API_TIMEOUT = 10

IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

all_results = {}     # ip -> result_data

# ---------------------------------------------------------------------------
# Public IP detection
# ---------------------------------------------------------------------------

def _detect_public_ip():
    """Auto-detect public IP via ifconfig.me."""
    try:
        req = urllib.request.Request(
            "https://ifconfig.me",
            headers={"User-Agent": "curl/7.0"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            ip = resp.read().decode("utf-8").strip()
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            return ip
    except Exception:
        pass
    return ""

# ---------------------------------------------------------------------------
# IP extraction from loot
# ---------------------------------------------------------------------------

def _is_public_ip(ip_str):
    """Check if IP is public (non-RFC1918, non-loopback)."""
    try:
        parts = ip_str.split(".")
        if len(parts) != 4:
            return False
        octets = [int(p) for p in parts]
        if octets[0] == 10:
            return False
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return False
        if octets[0] == 192 and octets[1] == 168:
            return False
        if octets[0] == 127:
            return False
        if octets[0] == 0 or octets[0] >= 224:
            return False
        return True
    except (ValueError, IndexError):
        return False


def _load_ips_from_loot():
    """Scan the rest of the engagement's loot for public IP addresses.

    Returns a dict of ip -> sorted list of file paths (relative to the
    loot root) where that IP was found. This payload's own output
    directory is excluded so a previously exported result is never
    rediscovered and re-offered as a new candidate.
    """
    found: dict[str, set[str]] = {}
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    if not os.path.isdir(LOOT_SRC_DIR):
        return {}

    own_output = os.path.realpath(LOOT_DIR)
    for root, dirs, files in os.walk(LOOT_SRC_DIR):
        if os.path.realpath(root) == own_output:
            dirs[:] = []
            continue
        for fname in files:
            if not fname.endswith((".json", ".txt", ".log", ".csv")):
                continue
            filepath = os.path.join(root, fname)
            try:
                with open(filepath, "r", errors="ignore") as f:
                    content = f.read(512 * 1024)
            except Exception:
                continue
            matches = ip_pattern.findall(content)
            if not matches:
                continue
            relative = os.path.relpath(filepath, LOOT_SRC_DIR)
            for ip in matches:
                if _is_public_ip(ip):
                    found.setdefault(ip, set()).add(relative)

    return {ip: sorted(paths) for ip, paths in found.items()}

# ---------------------------------------------------------------------------
# Shodan InternetDB query
# ---------------------------------------------------------------------------

def _query_internetdb(ip_str):
    """Query Shodan InternetDB for an IP. Returns dict or error string."""
    url = f"{API_URL}{ip_str}"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "RaspyJack/1.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        return data
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"error": "No data for this IP"}
        return {"error": f"HTTP {exc.code}"}
    except urllib.error.URLError as exc:
        return {"error": f"Network error: {str(exc.reason)[:30]}"}
    except Exception as exc:
        return {"error": str(exc)[:40]}

# ---------------------------------------------------------------------------
# Format results
# ---------------------------------------------------------------------------

def _format_results(data):
    """Convert API response dict into printable text lines."""
    lines = []

    if "error" in data:
        lines.append("Error: " + data["error"])
        return lines

    ip = data.get("ip", "?")
    lines.append(f"IP: {ip}")

    ports = data.get("ports", [])
    lines.append(f"-- Ports ({len(ports)}) --")
    lines.append("  " + (", ".join(str(p) for p in ports) if ports else "None"))

    hostnames = data.get("hostnames", [])
    lines.append(f"-- Hostnames ({len(hostnames)}) --")
    if hostnames:
        for h in hostnames:
            lines.append(f"  {h}")
    else:
        lines.append("  None")

    vulns = data.get("vulns", [])
    lines.append(f"-- Vulns ({len(vulns)}) --")
    if vulns:
        for v in vulns:
            lines.append(f"  {v}")
    else:
        lines.append("  None")

    cpes = data.get("cpes", [])
    lines.append(f"-- CPEs ({len(cpes)}) --")
    if cpes:
        for c in cpes:
            lines.append(f"  {c}")
    else:
        lines.append("  None")

    tags = data.get("tags", [])
    lines.append(f"-- Tags ({len(tags)}) --")
    lines.append("  " + (", ".join(tags) if tags else "None"))

    return lines

# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------

def _run_query(ip_str):
    """Query InternetDB for ip_str, print results, and record them."""
    print(f"Querying {ip_str}...", flush=True)
    data = _query_internetdb(ip_str)
    for line in _format_results(data):
        print(line, flush=True)
    print("", flush=True)
    all_results[ip_str] = dict(data)

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_results():
    """Export all query results to JSON."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"shodan_{ts}.json")

    data = {
        "timestamp": ts,
        "queries": len(all_results),
        "results": {ip: dict(r) for ip, r in all_results.items()},
    }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    return filepath

# ---------------------------------------------------------------------------
# Candidate selection
# ---------------------------------------------------------------------------

def _prompt_ip_selection(candidates):
    """Ask once per candidate (ip + provenance) with a real select prompt.

    ``candidates`` is a list of {"ip": ..., "sources": [...]} dicts so each
    choice can show the operator where that IP came from instead of
    appearing out of nowhere. Returns a plain list of selected IP strings.
    """
    remaining = list(candidates)
    selected = []

    while remaining:
        choices = [{"value": "all", "label": "All remaining candidates"}]
        choices += [
            {"value": entry["ip"], "label": f"{entry['ip']} — {'; '.join(entry['sources'])}"}
            for entry in remaining
        ]
        choices.append({"value": "manual", "label": "Enter a different IP"})
        if selected:
            choices.append({"value": "done", "label": "Done - query the selected IPs"})
        choices.append({"value": "cancel", "label": "Cancel"})

        label = "Select an IP to query" if not selected else "Select another IP, or finish"
        try:
            answer = request_input(
                label, input_type="select", choices=choices,
                default="cancel", required=True,
            )
        except EOFError:
            return [entry["ip"] for entry in selected]

        if answer in (None, "", "cancel"):
            return [entry["ip"] for entry in selected]
        if answer == "done":
            break
        if answer == "all":
            selected.extend(remaining)
            remaining = []
            break
        if answer == "manual":
            try:
                manual = request_input(
                    "Enter an IP to query", required=False,
                ).strip()
            except EOFError:
                manual = ""
            if manual and IP_RE.match(manual) and manual not in (e["ip"] for e in selected):
                selected.append({"ip": manual, "sources": ["manual entry"]})
                print(f"Added {manual} to the query list.", flush=True)
            elif manual:
                print(f"Ignoring invalid IP: {manual}", flush=True)
            continue

        match = next((entry for entry in remaining if entry["ip"] == answer), None)
        if match is None:
            print(f"Ignoring unknown selection: {answer}", flush=True)
            continue
        selected.append(match)
        remaining.remove(match)
        print(f"Added {match['ip']} to the query list.", flush=True)

    return [entry["ip"] for entry in selected]

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    argv_ips = [ip for ip in sys.argv[1:] if IP_RE.match(ip)]

    target_ips = list(argv_ips)

    if not target_ips:
        print("No IP given on the command line.", flush=True)
        print("Usage: shodan_query.py [ip1 ip2 ...]", flush=True)

        detected = _detect_public_ip()
        loot_ips = _load_ips_from_loot()

        candidates = []

        def _add_candidate(ip, source):
            for entry in candidates:
                if entry["ip"] == ip:
                    if source not in entry["sources"]:
                        entry["sources"].append(source)
                    return
            candidates.append({"ip": ip, "sources": [source]})

        if detected:
            _add_candidate(detected, "this host's public IP (ifconfig.me)")
        for ip, files in loot_ips.items():
            for path in files:
                _add_candidate(ip, f"seen in loot: {path}")

        if detected:
            print(f"Detected public IP: {detected}", flush=True)
        if loot_ips:
            print(f"Found {len(loot_ips)} public IP(s) referenced in loot.", flush=True)

        if not candidates:
            try:
                manual = request_input(
                    "Enter an IP to query (blank to abort)", required=False,
                ).strip()
            except EOFError:
                manual = ""
            if manual and IP_RE.match(manual):
                target_ips = [manual]
        else:
            print("Candidate IPs:", flush=True)
            for entry in candidates:
                print(f"  - {entry['ip']} ({'; '.join(entry['sources'])})", flush=True)
            target_ips = _prompt_ip_selection(candidates)

    if not target_ips:
        print("No IP selected. Nothing to do.", flush=True)
        return 0

    try:
        for ip in target_ips:
            _run_query(ip)
    except KeyboardInterrupt:
        print("\nStopped by user.", flush=True)

    if all_results:
        path = _export_results()
        print(f"Exported {len(all_results)} result(s) to {path}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
