#!/usr/bin/env python3
# @name: WPA/WPA2 Cracker
# @desc: Locate WPA capture or PMKID material in loot and attempt wordlist recovery with aircrack-ng or John the Ripper.
# @category: credentials
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- WPA/WPA2 Cracker
======================================
Author: 7h30th3r0n3

Cracks WPA handshakes (.cap) using aircrack-ng and PMKID hashes
using John the Ripper. Scans loot directories for crack targets.

Setup / Prerequisites:
  - Requires aircrack-ng for .cap handshake files.
  - Requires john for PMKID hash cracking.
  - Optional wordlists: $CITYPOP_ROOT/loot/wordlists/rockyou.txt,
    custom.txt

Controls:
  python3 wpa_cracker.py [capfile|all] [wordlist] [bssid]

  capfile   -- optional path to a .cap/.pcap handshake file, or "all"/
               "batch" to crack every discovered target. If omitted,
               discovered targets are listed and you're prompted to
               pick one (or 'A' for batch mode).
  wordlist  -- optional path to a wordlist. If omitted, you're
               prompted to pick one from loot/wordlists/ or the
               system default.
  bssid     -- optional BSSID to target when a capture contains
               multiple networks. If omitted and the capture has more
               than one network, you're prompted to pick one (blank
               selection cracks all networks in that file).

  Progress and cracked keys are printed as aircrack-ng runs; results
  are exported to loot when cracking finishes (or is interrupted with
  Ctrl-C, which stops aircrack-ng cleanly).

Loot: $CITYPOP_ROOT/loot/CrackedWPA/
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
AIRCRACK_BIN = "/usr/bin/aircrack-ng"
WORDLIST_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'wordlists')
SYSTEM_WORDLIST = "/usr/share/john/password.lst"
HANDSHAKE_DIRS = [
    os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'Handshakes'),
    os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'Pwnagotchi', 'handshakes'),
    os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'ESPNow', 'handshakes'),
]
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'CrackedWPA')

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
keys_tested = 0
speed_kps = ""
elapsed_secs = 0
found_key = ""
_running = True
_crack_proc = None


# ---------------------------------------------------------------------------
# Target file discovery
# ---------------------------------------------------------------------------

def _file_size_kb(filepath):
    """Return file size in KB."""
    try:
        return os.path.getsize(filepath) // 1024
    except Exception:
        return 0


def _scan_targets():
    """Scan for .cap/.pcap handshake files and PMKID hash files."""
    found = []
    seen = set()

    # Handshake .cap / .pcap files from all known directories
    for hs_dir in HANDSHAKE_DIRS:
        if not os.path.isdir(hs_dir):
            continue
        try:
            for fname in sorted(os.listdir(hs_dir)):
                fpath = os.path.join(hs_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                low = fname.lower()
                if low.endswith(".cap") or low.endswith(".pcap"):
                    if fpath not in seen:
                        # Skip empty pcaps (header-only, 24 bytes)
                        try:
                            fsize = os.path.getsize(fpath)
                        except Exception:
                            fsize = 0
                        if fsize <= 24:
                            continue
                        seen.add(fpath)
                        found.append({
                            "path": fpath,
                            "name": fname,
                            "ftype": "CAP",
                            "size_kb": fsize // 1024,
                        })
        except Exception:
            pass

    return found


def _build_wordlist_options():
    """Build available wordlist options from loot/wordlists/ and system."""
    options = []

    # Scan project wordlists directory
    if os.path.isdir(WORDLIST_DIR):
        try:
            for fname in sorted(os.listdir(WORDLIST_DIR)):
                fpath = os.path.join(WORDLIST_DIR, fname)
                if not os.path.isfile(fpath):
                    continue
                low = fname.lower()
                if low.endswith(".txt") or low.endswith(".lst"):
                    name = os.path.splitext(fname)[0][:14]
                    options.append({"name": name, "path": fpath})
        except Exception:
            pass

    # System wordlist as fallback
    if os.path.isfile(SYSTEM_WORDLIST):
        options.append({"name": "john_default", "path": SYSTEM_WORDLIST})

    if not options:
        options.append({"name": "john_default", "path": SYSTEM_WORDLIST})
    return options


# ---------------------------------------------------------------------------
# Aircrack-ng output parsing
# ---------------------------------------------------------------------------

# Pattern: [00:01:23] 12345/67890 keys tested (2456.78 k/s)
_AIRCRACK_PROGRESS_RE = re.compile(
    r"\[\d+:\d+:\d+\]\s+([\d,]+)(?:/[\d,]+)?\s+keys?\s+tested\s+\(([^\)]+)\)"
)
# Pattern: KEY FOUND! [ password123 ]
_AIRCRACK_KEY_RE = re.compile(r"KEY FOUND!\s*\[\s*(.+?)\s*\]")


# ---------------------------------------------------------------------------
# Network / handshake analysis
# ---------------------------------------------------------------------------

def _extract_essid_from_filename(fname):
    """Extract ESSID from capture filename.

    Filenames follow patterns like:
      hs_{essid}_{date}.pcap
      hs4_{essid}_{date}.pcap
      hs_half_{essid}_{date}.pcap
      pmkid_{essid}_{date}.pcap
    """
    base = os.path.splitext(os.path.basename(fname))[0]
    # Remove prefix (hs_, hs4_, hs_half_, pmkid_)
    for prefix in ("hs_half_", "hs4_", "hs_", "pmkid_"):
        if base.startswith(prefix):
            rest = base[len(prefix):]
            # Remove trailing _YYYYMMDD_HHMMSS
            parts = rest.rsplit("_", 2)
            if len(parts) >= 3 and len(parts[-1]) == 6 and len(parts[-2]) == 8:
                return "_".join(parts[:-2])
            if len(parts) >= 2 and len(parts[-1]) == 8:
                return "_".join(parts[:-1])
            return rest
    return ""


def _list_networks_in_cap(capfile):
    """List networks with valid handshakes in a pcap using aircrack-ng.

    Returns list of {"bssid": ..., "essid": ..., "enc": ..., "hs_count": ...}.
    Only includes networks with at least 1 handshake.
    """
    networks = []
    try:
        proc = subprocess.run(
            [AIRCRACK_BIN, capfile],
            capture_output=True, text=True, timeout=15,
            input="q\n",
        )
        # Strip ANSI escape codes from aircrack output
        _ansi = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
        clean_output = _ansi.sub("", proc.stdout)
        # Parse aircrack-ng network listing lines
        net_re = re.compile(
            r"^\s*\d+\s+([0-9A-Fa-f:]{17})\s+(.+?)\s+(WPA|WEP|OPN)\s+\((\d+)\s+handshake",
        )
        for line in clean_output.splitlines():
            m = net_re.match(line)
            if m:
                hs_count = int(m.group(4))
                has_pmkid = "PMKID" in line
                # Keep if has handshake OR has PMKID
                if hs_count > 0 or has_pmkid:
                    networks.append({
                        "bssid": m.group(1),
                        "essid": m.group(2).strip(),
                        "enc": m.group(3),
                        "hs_count": hs_count,
                        "pmkid": has_pmkid,
                    })
    except Exception:
        pass
    return networks


# ---------------------------------------------------------------------------
# Cracking
# ---------------------------------------------------------------------------

def _run_aircrack(capfile, wordlist_path, bssid, label):
    """Run aircrack-ng against capfile (optionally scoped to bssid).

    Streams progress to stdout as it runs and returns the cracked key,
    or None if it wasn't found.
    """
    global _crack_proc, keys_tested, speed_kps, elapsed_secs, found_key

    start_time = time.time()
    with lock:
        keys_tested = 0
        speed_kps = ""
        elapsed_secs = 0
        found_key = ""

    print(f"[*] Starting aircrack-ng against {label}...", flush=True)

    cmd = [AIRCRACK_BIN, "-w", wordlist_path]
    if bssid:
        cmd += ["-b", bssid]
    cmd.append(capfile)

    key = None
    last_report = 0

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        _crack_proc = proc

        while _running:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
            if not line:
                continue

            line = line.rstrip()
            with lock:
                elapsed_secs = int(time.time() - start_time)

            key_match = _AIRCRACK_KEY_RE.search(line)
            if key_match:
                key = key_match.group(1)
                with lock:
                    found_key = key
                print(f"[+] KEY FOUND: {key}", flush=True)
                continue

            progress_match = _AIRCRACK_PROGRESS_RE.search(line)
            if progress_match:
                raw_keys = progress_match.group(1).replace(",", "")
                with lock:
                    try:
                        keys_tested = int(raw_keys)
                    except ValueError:
                        pass
                    speed_kps = progress_match.group(2).strip()

            if elapsed_secs - last_report >= 15:
                last_report = elapsed_secs
                print(f"[*] {elapsed_secs}s elapsed, {keys_tested} keys tested "
                      f"({speed_kps})", flush=True)

        proc.wait(timeout=5)

    except Exception as exc:
        print(f"[!] Error: {exc}", flush=True)
    finally:
        _crack_proc = None

    if key:
        print(f"[*] Done. Key: {key}", flush=True)
    else:
        print("[*] Done. Key not found.", flush=True)

    return key


def _kill_crack_proc():
    """Kill the running cracking process."""
    global _crack_proc
    proc = _crack_proc
    if proc is not None:
        try:
            os.kill(proc.pid, signal.SIGTERM)
            proc.wait(timeout=5)
        except Exception:
            try:
                os.kill(proc.pid, signal.SIGKILL)
            except Exception:
                pass
        _crack_proc = None


# ---------------------------------------------------------------------------
# Batch crack (multiple files/networks, deduplicated by BSSID)
# ---------------------------------------------------------------------------

def _build_batch_jobs(file_list):
    """Build a deduplicated (by BSSID) list of crack jobs from target files."""
    jobs = []
    seen_bssids = set()

    for tf in file_list:
        nets = _list_networks_in_cap(tf["path"])
        if not nets:
            continue
        for net in nets:
            if net["bssid"] in seen_bssids:
                continue
            seen_bssids.add(net["bssid"])
            jobs.append({
                "path": tf["path"],
                "name": tf["name"],
                "bssid": net["bssid"],
                "essid": net["essid"],
            })

    return jobs


def _batch_crack(wordlist_path, jobs):
    """Crack a list of jobs, printing progress and results as it goes."""
    results = []
    total = len(jobs)

    for idx, job in enumerate(jobs):
        if not _running:
            break
        print(f"[*] Batch {idx + 1}/{total}: {job['essid'] or '(hidden)'} "
              f"({job['bssid']})", flush=True)
        key = _run_aircrack(job["path"], wordlist_path, job["bssid"],
                             label=job["essid"] or job["bssid"])
        results.append({
            "file": job["name"],
            "essid": job["essid"],
            "bssid": job["bssid"],
            "key": key,
        })

    cracked = sum(1 for r in results if r["key"])
    print(f"[*] Batch done: {cracked}/{len(results)} cracked", flush=True)
    return results


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_result(target_name, key):
    """Export a single cracked WPA key to loot directory."""
    if not key:
        return None

    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"cracked_{ts}.txt")
    with open(filepath, "w") as fh:
        fh.write(f"Target: {target_name}\n")
        fh.write(f"Key: {key}\n")
        fh.write(f"Date: {datetime.now().isoformat()}\n")
    return os.path.basename(filepath)


def _export_batch_results(results):
    """Export all batch cracking results to loot directory."""
    cracked = [r for r in results if r["key"]]
    if not cracked:
        return None

    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"batch_{ts}.txt")
    with open(filepath, "w") as fh:
        fh.write(f"Batch Crack Results - {datetime.now().isoformat()}\n")
        fh.write(f"Total: {len(results)} | Cracked: {len(cracked)}\n")
        fh.write("-" * 40 + "\n")
        for r in results:
            status = r["key"] if r["key"] else "NOT FOUND"
            fh.write(f"{r['essid']} ({r['bssid']}): {status}\n")
    return os.path.basename(filepath)


def _finish_batch(results):
    """Print a summary of batch results and export them."""
    cracked = [r for r in results if r["key"]]
    if cracked:
        for r in cracked:
            print(f"[+] {r['essid'] or '(hidden)'} ({r['bssid']}): {r['key']}", flush=True)
        fname = _export_batch_results(results)
        if fname:
            print(f"[*] Exported to {os.path.join(LOOT_DIR, fname)}", flush=True)
    else:
        print("[*] No keys cracked.", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: python3 wpa_cracker.py [capfile|all] [wordlist] [bssid]",
              flush=True)
        return 0

    args = sys.argv[1:]
    target_arg = args[0] if len(args) > 0 else None
    wordlist_arg = args[1] if len(args) > 1 else None
    bssid_arg = args[2] if len(args) > 2 else None

    print("[*] WPA/WPA2 Cracker -- aircrack-ng", flush=True)
    print("[*] Scanning for targets...", flush=True)
    found_files = _scan_targets()
    wl_options = _build_wordlist_options()

    batch_mode = False
    selected_target = None

    if target_arg and target_arg.lower() in ("all", "batch"):
        batch_mode = True
    elif target_arg and os.path.isfile(target_arg):
        selected_target = {
            "path": target_arg,
            "name": os.path.basename(target_arg),
            "ftype": "CAP",
            "size_kb": _file_size_kb(target_arg),
        }
    elif target_arg:
        print(f"[!] '{target_arg}' not found, scanning for targets instead.", flush=True)

    if not batch_mode and selected_target is None:
        if not found_files:
            print("[!] No handshake/PMKID targets found in loot dirs.", flush=True)
            return 1
        print(f"[*] Found {len(found_files)} target(s):", flush=True)
        for i, tf in enumerate(found_files, 1):
            print(f"  {i}. {tf['name']} ({tf['size_kb']}K)", flush=True)
        choice = request_input(
            f"Select a target [1-{len(found_files)}] (or 'A' for batch-crack all): "
        ).strip()
        if choice.lower() == "a":
            batch_mode = True
        else:
            try:
                idx = int(choice) - 1
                if idx < 0 or idx >= len(found_files):
                    raise ValueError
            except ValueError:
                print("[!] Invalid selection.", flush=True)
                return 1
            selected_target = found_files[idx]

    # --- Select wordlist ---
    if wordlist_arg and os.path.isfile(wordlist_arg):
        wordlist_path = wordlist_arg
    else:
        if wordlist_arg:
            print(f"[!] Wordlist '{wordlist_arg}' not found, prompting instead.", flush=True)
        if not wl_options:
            print("[!] No wordlists available.", flush=True)
            return 1
        print("Select a wordlist:", flush=True)
        for i, wl in enumerate(wl_options, 1):
            print(f"  {i}. {wl['name']}", flush=True)
        choice = request_input(f"Wordlist [1-{len(wl_options)}]: ").strip()
        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(wl_options):
                raise ValueError
        except ValueError:
            print("[!] Invalid selection.", flush=True)
            return 1
        wordlist_path = wl_options[idx]["path"]

    try:
        if batch_mode:
            file_list = [selected_target] if selected_target else found_files
            if not file_list:
                print("[!] No targets available for batch crack.", flush=True)
                return 1
            print("[*] Analyzing pcap(s) for networks...", flush=True)
            jobs = _build_batch_jobs(file_list)
            if not jobs:
                print("[!] No valid handshakes/PMKIDs found.", flush=True)
                return 1
            print(f"[*] {len(jobs)} network(s) queued for cracking.", flush=True)
            results = _batch_crack(wordlist_path, jobs)
            _finish_batch(results)

        else:
            print("[*] Analyzing pcap for networks...", flush=True)
            nets = _list_networks_in_cap(selected_target["path"])
            if not nets:
                print("[!] No valid handshake or PMKID found in this file.", flush=True)
                return 1

            bssid = None
            if bssid_arg:
                matches = [n for n in nets if n["bssid"].lower() == bssid_arg.lower()]
                if matches:
                    bssid = matches[0]["bssid"]
                else:
                    print(f"[!] BSSID '{bssid_arg}' not found in this capture.", flush=True)
                    return 1
            elif len(nets) == 1:
                bssid = nets[0]["bssid"]
            else:
                print(f"[*] {len(nets)} network(s) in this capture:", flush=True)
                for i, n in enumerate(nets, 1):
                    tag = "PMKID" if n["pmkid"] else f"{n['hs_count']} handshake(s)"
                    print(f"  {i}. {n['essid'] or '(hidden)'} ({n['bssid']}) [{tag}]",
                          flush=True)
                choice = request_input(
                    f"Select a network [1-{len(nets)}] (blank = crack all in this file): "
                ).strip()
                if not choice:
                    jobs = _build_batch_jobs([selected_target])
                    if not jobs:
                        print("[!] No valid handshakes/PMKIDs found.", flush=True)
                        return 1
                    results = _batch_crack(wordlist_path, jobs)
                    _finish_batch(results)
                    return 0
                try:
                    idx = int(choice) - 1
                    if idx < 0 or idx >= len(nets):
                        raise ValueError
                except ValueError:
                    print("[!] Invalid selection.", flush=True)
                    return 1
                bssid = nets[idx]["bssid"]

            key = _run_aircrack(selected_target["path"], wordlist_path, bssid,
                                 label=selected_target["name"])
            if key:
                fname = _export_result(selected_target["name"], key)
                if fname:
                    print(f"[*] Exported to {os.path.join(LOOT_DIR, fname)}", flush=True)

    except KeyboardInterrupt:
        print("\n[*] Interrupted, stopping aircrack-ng...", flush=True)
        _kill_crack_proc()
    finally:
        _running = False

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
