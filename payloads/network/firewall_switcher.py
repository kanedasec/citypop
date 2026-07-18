#!/usr/bin/env python3
# @name: Firewall Preset Switcher
# @desc: Switch between iptables firewall presets on the fly.
# @category: network
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- Firewall Preset Switcher
===============================================
Author: 7h30th3r0n3

Switch between iptables firewall presets on the fly.
Four built-in presets plus a user-defined custom ruleset.

Presets
-------
  OPEN       -- Accept all traffic (flush rules, policy ACCEPT).
  STEALTH    -- Drop ICMP, reject unsolicited inbound connections.
  BLOCK-ALL  -- Drop all INPUT except ESTABLISHED/RELATED.
  CUSTOM     -- User rules loaded from a JSON config file.

Controls:
  python3 firewall_switcher.py [preset|show|save]

    preset  -- one of OPEN, STEALTH, BLOCK-ALL, CUSTOM (case-insensitive).
               Applies it immediately.
    show    -- print the currently active iptables rules.
    save    -- save the currently active iptables rules as the CUSTOM
               preset.
    (none)  -- print the currently detected active preset and prompt
               for a preset to apply from a numbered list.

Config: $CITYPOP_ROOT/loot/Firewall/presets.json
"""

from payloads._web_input import request_input
import os
import sys
import time
import subprocess
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'Firewall')
CONFIG_PATH = os.path.join(LOOT_DIR, "presets.json")
os.makedirs(LOOT_DIR, exist_ok=True)
PRESET_NAMES = ["OPEN", "STEALTH", "BLOCK-ALL", "CUSTOM"]


# ---------------------------------------------------------------------------
# iptables helpers
# ---------------------------------------------------------------------------
def _run_ipt(args):
    """Run an iptables command and return (success, output)."""
    try:
        result = subprocess.run(
            ["iptables"] + args,
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as exc:
        return False, str(exc)


def _flush_rules():
    """Flush all iptables rules and set default ACCEPT."""
    _run_ipt(["-F"])
    _run_ipt(["-X"])
    _run_ipt(["-P", "INPUT", "ACCEPT"])
    _run_ipt(["-P", "FORWARD", "ACCEPT"])
    _run_ipt(["-P", "OUTPUT", "ACCEPT"])


def _apply_open():
    """OPEN preset: accept everything."""
    _flush_rules()
    return "OPEN applied"


def _apply_stealth():
    """STEALTH preset: drop ICMP, reject unsolicited inbound."""
    _flush_rules()
    _run_ipt(["-A", "INPUT", "-m", "conntrack", "--ctstate",
              "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    _run_ipt(["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
    _run_ipt(["-A", "INPUT", "-p", "icmp", "-j", "DROP"])
    _run_ipt(["-A", "INPUT", "-p", "tcp", "--syn", "-j", "REJECT",
              "--reject-with", "tcp-reset"])
    _run_ipt(["-A", "INPUT", "-p", "udp", "-j", "REJECT",
              "--reject-with", "icmp-port-unreachable"])
    _run_ipt(["-P", "INPUT", "DROP"])
    return "STEALTH applied"


def _apply_block_all():
    """BLOCK-ALL preset: drop all input except established."""
    _flush_rules()
    _run_ipt(["-A", "INPUT", "-m", "conntrack", "--ctstate",
              "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    _run_ipt(["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
    _run_ipt(["-P", "INPUT", "DROP"])
    return "BLOCK-ALL applied"


def _load_custom_rules():
    """Load custom rules from config file."""
    if not os.path.isfile(CONFIG_PATH):
        return None
    try:
        with open(CONFIG_PATH, "r") as fh:
            data = json.load(fh)
        return data.get("custom_rules", [])
    except (json.JSONDecodeError, OSError):
        return None


def _apply_custom():
    """CUSTOM preset: apply user-defined rules from config."""
    rules = _load_custom_rules()
    if rules is None:
        return "No custom preset"
    _flush_rules()
    for rule in rules:
        if not isinstance(rule, list):
            continue
        # Validate: only allow known iptables flags
        _run_ipt(rule)
    return "CUSTOM applied"


def _save_custom_preset():
    """Save current iptables rules as custom preset."""
    ok, output = _run_ipt(["-S"])
    if not ok:
        return "Save failed"
    rules = []
    for line in output.strip().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "-A":
            rules.append(parts)
    data = {
        "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "custom_rules": rules,
    }
    try:
        with open(CONFIG_PATH, "w") as fh:
            json.dump(data, fh, indent=2)
        return f"Saved {len(rules)} rules"
    except OSError as exc:
        return f"Save err: {exc}"


def _get_current_rules():
    """Get current iptables rules as lines."""
    ok, output = _run_ipt(["-L", "-n", "--line-numbers"])
    if not ok:
        return ["Error reading rules"]
    lines = output.strip().splitlines()
    return lines if lines else ["No rules"]


def _detect_active_preset():
    """Detect which preset is currently active (best guess)."""
    ok, output = _run_ipt(["-S"])
    if not ok:
        return "unknown"
    text = output.strip()
    lines = text.splitlines()
    a_lines = [l for l in lines if l.startswith("-A")]
    if not a_lines:
        return "OPEN"
    has_icmp_drop = any("icmp" in l and "DROP" in l for l in a_lines)
    has_reject = any("REJECT" in l for l in a_lines)
    if has_icmp_drop and has_reject:
        return "STEALTH"
    if not has_reject and not has_icmp_drop:
        established_only = all(
            "ESTABLISHED" in l or "RELATED" in l or "lo" in l
            for l in a_lines
        )
        if established_only:
            return "BLOCK-ALL"
    return "CUSTOM"


APPLY_FNS = {
    "OPEN": _apply_open,
    "STEALTH": _apply_stealth,
    "BLOCK-ALL": _apply_block_all,
    "CUSTOM": _apply_custom,
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def _usage():
    print(f"Usage: {os.path.basename(__file__)} [preset|show|save]",
          flush=True)
    print(f"  preset  one of: {', '.join(PRESET_NAMES)}", flush=True)
    print("  show    print the currently active iptables rules", flush=True)
    print("  save    save current rules as the CUSTOM preset", flush=True)
    print("  (none)  prompt interactively for a preset", flush=True)


def main():
    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0

    active = _detect_active_preset()
    print(f"[*] Current active preset (detected): {active}", flush=True)

    if not args:
        print("Available presets:", flush=True)
        for i, name in enumerate(PRESET_NAMES):
            marker = "*" if name == active else " "
            print(f"  [{i}] {marker}{name}", flush=True)
        choice = request_input(
            f"Select preset [0-{len(PRESET_NAMES) - 1}] "
            f"(blank to cancel): "
        ).strip()
        if not choice:
            print("[*] Cancelled.", flush=True)
            return 0
        if not (choice.isdigit() and 0 <= int(choice) < len(PRESET_NAMES)):
            print("[!] Invalid selection.", flush=True)
            return 1
        target = PRESET_NAMES[int(choice)]
        result = APPLY_FNS[target]()
        print(f"[*] {result}", flush=True)
        return 0

    action = args[0]
    action_upper = action.upper()

    if action.lower() == "show":
        for line in _get_current_rules():
            print(line, flush=True)
        return 0

    if action.lower() == "save":
        result = _save_custom_preset()
        print(f"[*] {result}", flush=True)
        return 0

    if action_upper in APPLY_FNS:
        result = APPLY_FNS[action_upper]()
        print(f"[*] {result}", flush=True)
        return 0

    print(f"[!] Unknown preset/action '{action}'.", flush=True)
    _usage()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
