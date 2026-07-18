#!/usr/bin/env python3
# @name: NTLM Hash Cracker
# @desc: Cracks captured NTLM hashes using John the Ripper.
# @category: credentials
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- NTLM Hash Cracker
=======================================
Author: 7h30th3r0n3

Cracks captured NTLM hashes using John the Ripper.
Scans Responder logs and NTLMRelay loot for hash files, then runs
john with user-selected attack mode.

Setup / Prerequisites:
  - Requires john (/usr/sbin/john): apt install john
  - Reads hashes from Responder/logs/ and loot/NTLMRelay/.

Controls:
  python3 ntlm_cracker.py [hashfile] [mode] [wordlist]

  hashfile  -- optional path to an NTLM/NetNTLM hash file. If omitted,
               Responder logs and NTLMRelay loot are scanned and you
               pick one from a numbered list.
  mode      -- optional attack mode: Quick, Wordlist, Incremental, or
               Rules. If omitted, you're prompted to choose.
  wordlist  -- optional path to a wordlist (used by Wordlist/Rules
               mode). If omitted and needed, you're prompted to pick
               one from loot/wordlists/.

  Cracked passwords are printed as john finds them and the full list
  is exported to loot when cracking finishes (or is interrupted with
  Ctrl-C, which stops john cleanly).

Loot: $CITYPOP_ROOT/loot/CrackedNTLM/
"""

from payloads._web_input import request_input
import os
import sys
import re
import time
import signal
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
JOHN_BIN = "/usr/sbin/john"
DEFAULT_WORDLIST = "/usr/share/john/password.lst"
WORDLIST_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'wordlists')
RESPONDER_LOG_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'Responder', 'logs')
RELAY_LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'NTLMRelay')
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'CrackedNTLM')

ATTACK_MODES = [
    {"name": "Quick", "desc": "Default wordlist"},
    {"name": "Wordlist", "desc": "Select wordlist"},
    {"name": "Incremental", "desc": "Brute-force"},
    {"name": "Rules", "desc": "Wordlist + rules"},
]

# Selected wordlist (set by user in Wordlist/Rules mode)
_selected_wordlist = DEFAULT_WORDLIST


def _list_wordlists():
    """List available wordlist files."""
    wlists = []
    # Default john wordlist
    if os.path.isfile(DEFAULT_WORDLIST):
        wlists.append({"path": DEFAULT_WORDLIST, "name": "john default",
                        "size": os.path.getsize(DEFAULT_WORDLIST)})
    # All .txt files in wordlist dir
    if os.path.isdir(WORDLIST_DIR):
        for f in sorted(os.listdir(WORDLIST_DIR)):
            if f.endswith(".txt"):
                fp = os.path.join(WORDLIST_DIR, f)
                sz = os.path.getsize(fp)
                if sz > 0:
                    wlists.append({"path": fp, "name": f, "size": sz})
    return wlists

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
hash_files = []         # [{path, name, count, fmt}]
cracked_count = 0
last_cracked = ""
elapsed_secs = 0
all_cracked = []        # list of cracked "user:password" strings
_running = True
_john_proc = None


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def _detect_john_format(filename):
    """Auto-detect john format flag from filename."""
    upper = filename.upper()
    if "NTLMV2" in upper:
        return "netntlmv2"
    if "NTLMV1" in upper:
        return "netntlm"
    if "NTLM" in upper:
        return "nt"
    return "netntlmv2"


# ---------------------------------------------------------------------------
# Hash file discovery
# ---------------------------------------------------------------------------

def _count_lines(filepath):
    """Count non-empty, non-comment lines in a file."""
    count = 0
    try:
        with open(filepath, "r", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    count += 1
    except Exception:
        pass
    return count


def _scan_hash_files():
    """Scan known directories for NTLM hash files."""
    found = []
    search_dirs = [
        (RESPONDER_LOG_DIR, ["NTLMv2", "NTLMv1", "NTLM"]),
        (RELAY_LOOT_DIR, None),
    ]

    for dirpath, patterns in search_dirs:
        if not os.path.isdir(dirpath):
            continue
        try:
            for fname in sorted(os.listdir(dirpath)):
                fpath = os.path.join(dirpath, fname)
                if not os.path.isfile(fpath):
                    continue
                if not fname.endswith(".txt"):
                    continue
                if patterns is not None:
                    if not any(p.lower() in fname.lower() for p in patterns):
                        continue
                line_count = _count_lines(fpath)
                if line_count == 0:
                    continue
                fmt = _detect_john_format(fname)
                found.append({
                    "path": fpath,
                    "name": fname,
                    "count": line_count,
                    "fmt": fmt,
                })
        except Exception:
            pass

    return found


# ---------------------------------------------------------------------------
# John the Ripper execution
# ---------------------------------------------------------------------------

def _build_john_cmd(hashfile, fmt, mode_name):
    """Build the john command list for the selected attack mode."""
    base = [JOHN_BIN, f"--format={fmt}"]

    if mode_name == "Quick":
        return base + [f"--wordlist={DEFAULT_WORDLIST}", hashfile]

    if mode_name == "Wordlist":
        return base + [f"--wordlist={_selected_wordlist}", hashfile]

    if mode_name == "Incremental":
        return base + ["--incremental", hashfile]

    if mode_name == "Rules":
        wl = _selected_wordlist if os.path.isfile(_selected_wordlist) else DEFAULT_WORDLIST
        return base + [f"--wordlist={wl}", "--rules", hashfile]

    return base + [f"--wordlist={DEFAULT_WORDLIST}", hashfile]


def _fmt_elapsed(secs):
    """Format seconds as MM:SS."""
    m, s = divmod(secs, 60)
    return f"{m:02d}:{s:02d}"


def _run_crack(hashfile, fmt, mode_name):
    """Run john against a hash file, streaming cracked passwords as they appear."""
    global _john_proc, cracked_count, last_cracked, elapsed_secs

    cmd = _build_john_cmd(hashfile, fmt, mode_name)
    start_time = time.time()
    last_report = 0

    with lock:
        cracked_count = 0
        last_cracked = ""
        elapsed_secs = 0

    print(f"[*] Starting {mode_name} attack against {os.path.basename(hashfile)}...", flush=True)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        _john_proc = proc

        # John jumbo output format for cracked passwords:
        # "PASSWORD         (USERNAME)"
        # Must have at least 1 char password, spaces, then (username)
        # Exclude john status/info lines that contain known keywords
        crack_re = re.compile(r"^(.+?)\s{2,}\((.+?)\)\s*$")
        skip_words = {"loaded", "will run", "press", "session", "proceeding",
                      "using default", "cost", "guesses", "remaining"}

        while _running:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
            if not line:
                continue

            line = line.rstrip()
            with lock:
                elapsed_secs = int(time.time() - start_time)

            if elapsed_secs - last_report >= 15:
                last_report = elapsed_secs
                print(f"[*] {_fmt_elapsed(elapsed_secs)} elapsed, "
                      f"{cracked_count} cracked so far...", flush=True)

            # Skip john info/status lines
            if any(w in line.lower() for w in skip_words):
                continue

            match = crack_re.match(line)
            if match:
                password = match.group(1).strip()
                username = match.group(2).strip()
                with lock:
                    cracked_count += 1
                    last_cracked = password
                    all_cracked.append(f"{username}:{password}")
                print(f"[+] Cracked: {username}:{password}", flush=True)

        proc.wait(timeout=5)

        # Also run --show to catch any results from pot file
        try:
            show_result = subprocess.run(
                [JOHN_BIN, "--show", f"--format={fmt}", hashfile],
                capture_output=True, text=True, timeout=10)
            for line in show_result.stdout.splitlines():
                if ":" in line and "password hash" not in line.lower():
                    parts = line.split(":")
                    if len(parts) >= 2:
                        username = parts[0]
                        password = parts[1]
                        entry = f"{username}:{password}"
                        with lock:
                            if entry not in all_cracked and password:
                                all_cracked.append(entry)
                                cracked_count = len(all_cracked)
                                last_cracked = password
        except Exception:
            pass

    except Exception as exc:
        print(f"[!] Error: {exc}", flush=True)
    finally:
        _john_proc = None
        with lock:
            elapsed_secs = int(time.time() - start_time)
            count = cracked_count
        if count == 0:
            print("[*] Done. No passwords cracked.", flush=True)
        else:
            print(f"[*] Done. {count} password(s) cracked.", flush=True)


def _kill_john():
    """Kill the running john process."""
    global _john_proc
    proc = _john_proc
    if proc is not None:
        try:
            os.kill(proc.pid, signal.SIGTERM)
            proc.wait(timeout=5)
        except Exception:
            try:
                os.kill(proc.pid, signal.SIGKILL)
            except Exception:
                pass
        _john_proc = None


# ---------------------------------------------------------------------------
# Show cracked passwords (john --show)
# ---------------------------------------------------------------------------

def _john_show(hashfile, fmt):
    """Run john --show and return list of cracked entries."""
    try:
        result = subprocess.run(
            [JOHN_BIN, "--show", f"--format={fmt}", hashfile],
            capture_output=True, text=True, timeout=15,
        )
        lines = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped and ":" in stripped and not stripped.startswith("("):
                lines.append(stripped)
        return lines
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_cracked(hashfile, fmt):
    """Export cracked passwords to loot directory."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    shown = _john_show(hashfile, fmt)
    if not shown:
        with lock:
            combined = list(all_cracked)
        if not combined:
            return None
        shown = combined

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"cracked_{ts}.txt")
    with open(filepath, "w") as fh:
        fh.write("\n".join(shown) + "\n")
    return os.path.basename(filepath)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running, hash_files, _selected_wordlist

    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: python3 ntlm_cracker.py [hashfile] [mode] [wordlist]", flush=True)
        print(f"  mode: {'|'.join(m['name'] for m in ATTACK_MODES)}", flush=True)
        return 0

    args = sys.argv[1:]

    print("[*] NTLM Hash Cracker -- John the Ripper", flush=True)

    # --- Select hash file ---
    hashfile_arg = args[0] if len(args) > 0 else None
    if hashfile_arg and os.path.isfile(hashfile_arg):
        fname = os.path.basename(hashfile_arg)
        selected_file = {
            "path": hashfile_arg,
            "name": fname,
            "count": _count_lines(hashfile_arg),
            "fmt": _detect_john_format(fname),
        }
    else:
        if hashfile_arg:
            print(f"[!] '{hashfile_arg}' not found, scanning for hash files instead.", flush=True)
        print("[*] Scanning for hash files...", flush=True)
        found = _scan_hash_files()
        with lock:
            hash_files = found
        if not found:
            print("[!] No hash files found in Responder logs or NTLMRelay loot.", flush=True)
            return 1
        print(f"[*] Found {len(found)} hash file(s):", flush=True)
        for i, hf in enumerate(found, 1):
            print(f"  {i}. {hf['name']} ({hf['count']} hashes, fmt={hf['fmt']})", flush=True)
        choice = request_input(f"Select a file [1-{len(found)}]: ").strip()
        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(found):
                raise ValueError
        except ValueError:
            print("[!] Invalid selection.", flush=True)
            return 1
        selected_file = found[idx]

    print(f"[*] Selected: {selected_file['name']} (format={selected_file['fmt']}, "
          f"{selected_file['count']} hashes)", flush=True)

    # --- Select attack mode ---
    mode_arg = args[1] if len(args) > 1 else None
    mode_names = [m["name"] for m in ATTACK_MODES]
    if mode_arg:
        matches = [m for m in mode_names if m.lower() == mode_arg.lower()]
        if not matches:
            print(f"[!] Unknown mode '{mode_arg}'. Choices: {', '.join(mode_names)}", flush=True)
            return 1
        mode_name = matches[0]
    else:
        print("Select attack mode:", flush=True)
        for i, m in enumerate(ATTACK_MODES, 1):
            print(f"  {i}. {m['name']} -- {m['desc']}", flush=True)
        choice = request_input(f"Mode [1-{len(ATTACK_MODES)}]: ").strip()
        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(ATTACK_MODES):
                raise ValueError
        except ValueError:
            print("[!] Invalid selection.", flush=True)
            return 1
        mode_name = ATTACK_MODES[idx]["name"]

    # --- Select wordlist if needed ---
    if mode_name in ("Wordlist", "Rules"):
        wl_arg = args[2] if len(args) > 2 else None
        if wl_arg and os.path.isfile(wl_arg):
            _selected_wordlist = wl_arg
        elif mode_name == "Wordlist":
            if wl_arg:
                print(f"[!] Wordlist '{wl_arg}' not found.", flush=True)
            wlists = _list_wordlists()
            if not wlists:
                print("[!] No wordlists found. Falling back to john's default list.", flush=True)
            else:
                print("Select a wordlist:", flush=True)
                for i, wl in enumerate(wlists, 1):
                    sz = wl["size"]
                    sz_str = f"{sz // 1024}K" if sz > 1024 else f"{sz}B"
                    print(f"  {i}. {wl['name']} ({sz_str})", flush=True)
                choice = request_input(f"Wordlist [1-{len(wlists)}]: ").strip()
                try:
                    idx = int(choice) - 1
                    if idx < 0 or idx >= len(wlists):
                        raise ValueError
                    _selected_wordlist = wlists[idx]["path"]
                except ValueError:
                    print("[!] Invalid selection, using default wordlist.", flush=True)

    print(f"[*] Attack mode: {mode_name}", flush=True)

    try:
        _run_crack(selected_file["path"], selected_file["fmt"], mode_name)
    except KeyboardInterrupt:
        print("\n[*] Interrupted, stopping john...", flush=True)
        _kill_john()
    finally:
        _running = False

    with lock:
        count = cracked_count
        cracked = list(all_cracked)

    if cracked:
        print(f"[*] {count} credential(s) cracked:", flush=True)
        for entry in cracked:
            print(f"    {entry}", flush=True)
        fname = _export_cracked(selected_file["path"], selected_file["fmt"])
        if fname:
            print(f"[*] Exported to {os.path.join(LOOT_DIR, fname)}", flush=True)
    else:
        print("[*] No passwords cracked.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
