#!/usr/bin/env python3
# @name: Engagement Log Cleaner
# @desc: Selective cleanup of forensic artifacts after an engagement.
# @category: evasion
# @danger: true
# @active: true
"""
RaspyJack Payload -- Engagement Log Cleaner
--------------------------------------------
Author: 7h30th3r0n3

Selective cleanup of forensic artifacts after an engagement.
Protects /root/Raspyjack/loot/ (operator data).

Usage
-----
    log_cleaner.py [item_name ...] | all

    item_name -- one or more of: bash_history, journal, dhcp_leases,
                 arp_cache, dns_cache, tmp_files, auth_logs
    all       -- clean every item

    If no arguments are given, an interactive numbered checklist is shown.
    In both cases, the selected items are listed and a confirmation prompt
    is shown before anything is cleaned.
"""

from payloads._web_input import request_input
import os
import sys
import time
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

CLEAN_ITEMS = [
    {"name": "bash_history", "label": "Bash History"},
    {"name": "journal", "label": "System Journal"},
    {"name": "dhcp_leases", "label": "DHCP Leases"},
    {"name": "arp_cache", "label": "ARP Cache"},
    {"name": "dns_cache", "label": "DNS Cache"},
    {"name": "tmp_files", "label": "Tmp Files"},
    {"name": "auth_logs", "label": "Auth Logs"},
]


def _run(cmd):
    """Run a shell command, return (returncode, output)."""
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
            shell=isinstance(cmd, str),
        )
        return res.returncode, res.stdout.strip()
    except Exception as exc:
        return 1, str(exc)


def _clean_item(item_name):
    """Clean a single item. Returns (success, message)."""
    if item_name == "bash_history":
        targets = [
            os.path.expanduser("~/.bash_history"),
            "/root/.bash_history",
            os.path.expanduser("~/.zsh_history"),
        ]
        cleaned = 0
        for path in targets:
            if os.path.isfile(path):
                rc, _ = _run(["shred", "-fzu", path])
                if rc == 0:
                    cleaned += 1
        return True, f"Shredded {cleaned} files"

    elif item_name == "journal":
        rc, out = _run(["journalctl", "--vacuum-size=1M"])
        return rc == 0, "Journal vacuumed" if rc == 0 else out[:40]

    elif item_name == "dhcp_leases":
        leases = [
            "/var/lib/dhcp/dhclient.leases",
            "/var/lib/dhcpcd/dhcpcd-eth0.lease",
            "/var/lib/dhcpcd/dhcpcd-wlan0.lease",
            "/var/lib/dhcpcd5/dhcpcd-eth0.lease",
            "/var/lib/dhcpcd5/dhcpcd-wlan0.lease",
        ]
        cleaned = 0
        for path in leases:
            if os.path.isfile(path):
                rc, _ = _run(["shred", "-fzu", path])
                if rc == 0:
                    cleaned += 1
        return True, f"Cleared {cleaned} leases"

    elif item_name == "arp_cache":
        rc, _ = _run(["ip", "neigh", "flush", "all"])
        return rc == 0, "ARP flushed" if rc == 0 else "ARP flush failed"

    elif item_name == "dns_cache":
        rc, _ = _run(["systemctl", "restart", "systemd-resolved"])
        if rc != 0:
            rc, _ = _run(["resolvectl", "flush-caches"])
        return True, "DNS cache cleared"

    elif item_name == "tmp_files":
        cleaned = 0
        for tmp_dir in ["/tmp", "/var/tmp"]:
            if not os.path.isdir(tmp_dir):
                continue
            try:
                for entry in os.listdir(tmp_dir):
                    full = os.path.join(tmp_dir, entry)
                    if os.path.isfile(full):
                        try:
                            os.remove(full)
                            cleaned += 1
                        except OSError:
                            pass
            except OSError:
                pass
        return True, f"Removed {cleaned} tmp files"

    elif item_name == "auth_logs":
        targets = [
            "/var/log/auth.log",
            "/var/log/auth.log.1",
            "/var/log/secure",
            "/var/log/wtmp",
            "/var/log/btmp",
            "/var/log/lastlog",
        ]
        cleaned = 0
        for path in targets:
            if os.path.isfile(path):
                rc, _ = _run(["shred", "-fzu", path])
                if rc == 0:
                    cleaned += 1
        return True, f"Shredded {cleaned} logs"

    return False, "Unknown item"


def _prompt_selection():
    """Show a numbered checklist and read a comma-separated selection."""
    print("Forensic artifacts available for cleanup:", flush=True)
    for i, item in enumerate(CLEAN_ITEMS, 1):
        print(f"  {i}. {item['label']} ({item['name']})", flush=True)
    print("Enter comma-separated numbers, 'all', or blank to cancel.", flush=True)

    raw = request_input("Select items to clean: ").strip()
    if not raw:
        return []
    if raw.lower() == "all":
        return list(range(len(CLEAN_ITEMS)))

    indices = []
    for part in raw.split(","):
        part = part.strip()
        if not part.isdigit():
            print(f"Ignoring invalid entry: {part}", flush=True)
            continue
        n = int(part)
        if 1 <= n <= len(CLEAN_ITEMS):
            indices.append(n - 1)
        else:
            print(f"Ignoring out-of-range entry: {part}", flush=True)
    return sorted(set(indices))


def _resolve_from_args(args):
    """Resolve item names / 'all' passed on the command line to indices."""
    if len(args) == 1 and args[0].lower() == "all":
        return list(range(len(CLEAN_ITEMS)))

    name_to_idx = {item["name"]: i for i, item in enumerate(CLEAN_ITEMS)}
    indices = []
    for a in args:
        key = a.strip().lower()
        if key in name_to_idx:
            indices.append(name_to_idx[key])
        else:
            print(f"Unknown item '{a}'. Valid items: {', '.join(name_to_idx)}, all", flush=True)
            return None
    return sorted(set(indices))


def _clean_selected(items, selected_indices):
    """Clean all selected items, printing progress."""
    total = len(selected_indices)
    results = []
    for i, idx in enumerate(sorted(selected_indices), 1):
        item = items[idx]
        print(f"[{i}/{total}] Cleaning {item['label']}...", flush=True)
        ok, msg = _clean_item(item["name"])
        print(f"  -> {msg}", flush=True)
        results.append((item["label"], ok, msg))

    print("Done.", flush=True)
    return results


def main():
    """Main entry point."""
    args = sys.argv[1:]
    if args:
        indices = _resolve_from_args(args)
        if indices is None:
            print("Usage: log_cleaner.py [item_name ...] | all", flush=True)
            print(f"Valid items: {', '.join(i['name'] for i in CLEAN_ITEMS)}", flush=True)
            return 1
    else:
        indices = _prompt_selection()

    if not indices:
        print("Nothing selected. Exiting.", flush=True)
        return 0

    print(f"About to clean {len(indices)} item(s):", flush=True)
    for idx in indices:
        print(f"  - {CLEAN_ITEMS[idx]['label']}", flush=True)

    confirm = request_input("Proceed? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Cancelled.", flush=True)
        return 0

    _clean_selected(CLEAN_ITEMS, indices)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
