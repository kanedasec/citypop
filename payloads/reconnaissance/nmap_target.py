#!/usr/bin/env python3
# @active: true
# @web: true
# @name: Nmap Target Scan
# @desc: Run a service/version scan against an engagement target
# @category: reconnaissance
# @danger: false
# @maturity: functional
# @inputs: [{"name":"target","label":"Authorized scan target (blank = pick from loot)","type":"text","placeholder":"10.0.0.5 or example.com","required":false}]
import os, shutil, subprocess, sys
from payloads import _target_helper as target_helper

LOOT_ROOT = os.environ.get("CITYPOP_LOOT", "/tmp/citypop_loot")


def _select_target():
    ips = target_helper.find_ips_in_loot(LOOT_ROOT)
    hosts = target_helper.find_hostnames_in_loot(LOOT_ROOT)
    candidates = target_helper.merge_candidates(
        (ips, "IP seen in loot"), (hosts, "hostname seen in loot"),
    )
    for entry in candidates:
        print(f"  - {entry['value']} ({'; '.join(entry['sources'])})", flush=True)
    return target_helper.prompt_target_selection(
        candidates,
        prompt_label="Select a scan target",
        manual_label="Enter an IP address or hostname",
    )


target = sys.argv[1] if len(sys.argv) > 1 else ""
if not target:
    target = _select_target() or ""
if not target:
    print("Usage: provide one IP address or URL", flush=True); raise SystemExit(2)
if not shutil.which("nmap"):
    print("nmap is not installed; install it with: sudo apt install nmap", flush=True); raise SystemExit(127)
print(f"Starting authorized scan of {target}", flush=True)
subprocess.run(["nmap", "-sV", "--", target], check=False)
