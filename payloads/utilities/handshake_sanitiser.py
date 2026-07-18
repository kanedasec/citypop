#!/usr/bin/env python3
# @name: Handshake File Sanitizer
# @desc: Strip irrelevant frames from capture files, keeping only EAPOL handshake packets and beacon frames needed for cracking.
# @category: utilities
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- Handshake File Sanitizer
================================================
Author: 7h30th3r0n3

Strip irrelevant frames from capture files, keeping only EAPOL
handshake packets and beacon frames needed for cracking.

Uses tshark to filter: ``eapol || wlan.fc.type_subtype == 0x08``

Controls
--------
  python3 handshake_sanitiser.py [index|all|q]
  With no argument, lists discovered capture files and prompts for a
  selection (a file number, "all" to batch-process everything, or "q"
  to quit). Ctrl-C stops a batch cleanly after the current file.

Input:  $CITYPOP_ROOT/loot/ (recursive .cap/.pcap/.pcapng)
Output: $CITYPOP_ROOT/loot/Handshakes_Clean/
"""

from payloads._web_input import request_input
import os
import sys
import signal
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot')
OUTPUT_DIR = os.path.join(LOOT_DIR, "Handshakes_Clean")
os.makedirs(OUTPUT_DIR, exist_ok=True)
EXTENSIONS = (".cap", ".pcap", ".pcapng")
TSHARK_FILTER = "eapol || wlan.fc.type_subtype == 0x08"

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
app_running = True


# ---------------------------------------------------------------------------
# Signal handlers
# ---------------------------------------------------------------------------
def _sig_handler(_sig, _frame):
    global app_running
    app_running = False


signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------
def _find_cap_files():
    """Recursively find capture files in loot directory."""
    found = []
    for root, _dirs, files in os.walk(LOOT_DIR):
        # Skip output directory
        if root.startswith(OUTPUT_DIR):
            continue
        for fname in sorted(files):
            if fname.lower().endswith(EXTENSIONS):
                full_path = os.path.join(root, fname)
                try:
                    size = os.path.getsize(full_path)
                except OSError:
                    size = 0
                found.append({
                    "path": full_path,
                    "name": fname,
                    "size": size,
                })
    return found


def _fmt_size(size_bytes):
    """Format file size for display."""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes // 1024}K"
    return f"{size_bytes // (1024 * 1024)}M"


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------
def _count_packets(filepath, display_filter=None):
    """Count packets in a capture file, optionally with a filter."""
    args = ["tshark", "-r", filepath, "-T", "fields", "-e", "frame.number"]
    if display_filter:
        args.extend(["-Y", display_filter])
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=60,
        )
        lines = [l for l in result.stdout.strip().splitlines() if l.strip()]
        return len(lines)
    except Exception:
        return 0


def _sanitize_file(input_path):
    """Sanitize a single capture file, return result dict."""
    basename = os.path.basename(input_path)
    name_no_ext = os.path.splitext(basename)[0]
    output_path = os.path.join(OUTPUT_DIR, f"{name_no_ext}_clean.pcap")

    input_size = 0
    try:
        input_size = os.path.getsize(input_path)
    except OSError:
        pass

    # Run tshark filter
    args = [
        "tshark", "-r", input_path,
        "-Y", TSHARK_FILTER,
        "-w", output_path,
    ]
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=120,
        )
        success = result.returncode == 0
    except Exception as exc:
        return {
            "success": False,
            "input": basename,
            "error": str(exc),
            "input_size": input_size,
            "output_size": 0,
            "total_pkts": 0,
            "eapol_pkts": 0,
        }

    output_size = 0
    if success and os.path.isfile(output_path):
        try:
            output_size = os.path.getsize(output_path)
        except OSError:
            pass

    # Count packets
    total_pkts = _count_packets(input_path)
    eapol_pkts = _count_packets(input_path, "eapol")

    return {
        "success": success,
        "input": basename,
        "output": os.path.basename(output_path),
        "input_size": input_size,
        "output_size": output_size,
        "total_pkts": total_pkts,
        "eapol_pkts": eapol_pkts,
    }


def _process_single(file_entry):
    """Sanitize a single file, printing progress and a result summary."""
    print(f"Sanitizing {file_entry['name']}...", flush=True)
    result = _sanitize_file(file_entry["path"])
    if result["success"]:
        print(
            f"OK  in={_fmt_size(result['input_size'])} "
            f"out={_fmt_size(result['output_size'])} "
            f"pkts={result['total_pkts']} eapol={result['eapol_pkts']} "
            f"-> {result['output']}",
            flush=True,
        )
    else:
        print(f"FAILED: {result.get('error', 'tshark error')}", flush=True)
    return result


def _process_batch(files):
    """Sanitize every discovered file, printing progress per file."""
    total = len(files)
    succeeded = 0
    failed = 0
    for i, entry in enumerate(files, 1):
        if not app_running:
            print("Stopped.", flush=True)
            break
        print(f"[{i}/{total}] {entry['name']}...", flush=True)
        result = _sanitize_file(entry["path"])
        if result["success"]:
            succeeded += 1
        else:
            failed += 1
    print(f"Batch complete: {succeeded} ok, {failed} failed, {total} total",
          flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def _sig_handler(_sig, _frame):
    global app_running
    app_running = False


def main():
    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    cap_files = _find_cap_files()
    print(f"{len(cap_files)} capture file(s) found in {LOOT_DIR}", flush=True)
    if not cap_files:
        return 0

    args = sys.argv[1:]
    if args:
        selection = args[0]
    else:
        for i, f in enumerate(cap_files):
            print(f"  [{i}] {f['name']} ({_fmt_size(f['size'])})", flush=True)
        selection = request_input(
            "Enter a file number to sanitize, 'all' to batch-process "
            "everything, or 'q' to quit: "
        ).strip()

    if selection.lower() in ("q", "quit", "exit"):
        return 0
    if selection.lower() in ("a", "all", "batch"):
        _process_batch(cap_files)
        return 0

    try:
        entry = cap_files[int(selection)]
    except (ValueError, IndexError):
        print(f"Invalid selection: {selection!r}", flush=True)
        return 1

    result = _process_single(entry)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
