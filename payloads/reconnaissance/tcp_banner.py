#!/usr/bin/env python3
# @active: true
# @web: true
# @name: TCP Banner Check
# @desc: Read a banner from a scoped TCP service
# @category: reconnaissance
# @danger: false
# @maturity: functional
# @inputs: [{"name":"host","label":"Target host","type":"text","placeholder":"example.com","required":false},{"name":"port","label":"TCP port","type":"number","default":"80"}]
import os,socket,sys
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
        prompt_label="Select a host to connect to",
        manual_label="Enter a host",
    )


if len(sys.argv)!=3: print("Usage: host port",flush=True); raise SystemExit(2)
host=sys.argv[1] or (_select_target() or '')
if not host: print("Usage: host port",flush=True); raise SystemExit(2)
try:
 with socket.create_connection((host,int(sys.argv[2])),timeout=5) as s: print(s.recv(1024).decode(errors="replace"),flush=True)
except Exception as e: print(e,flush=True)
