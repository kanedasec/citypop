#!/usr/bin/env python3
# @active: true
# @web: true
# @name: DNS Lookup
# @desc: Resolve a scoped hostname using the local resolver
# @category: reconnaissance
# @danger: false
# @maturity: functional
# @inputs: [{"name":"target","label":"Hostname or URL (blank = pick from loot)","type":"text","placeholder":"example.com","required":false}]
import os,socket,sys
from urllib.parse import urlparse
from payloads import _target_helper as target_helper

LOOT_ROOT = os.environ.get("CITYPOP_LOOT", "/tmp/citypop_loot")


def _select_target():
    hosts = target_helper.find_hostnames_in_loot(LOOT_ROOT)
    candidates = target_helper.merge_candidates((hosts, "seen in loot"))
    for entry in candidates:
        print(f"  - {entry['value']} ({'; '.join(entry['sources'])})", flush=True)
    return target_helper.prompt_target_selection(
        candidates,
        prompt_label="Select a hostname to resolve",
        manual_label="Enter a hostname or URL",
    )


target=sys.argv[1] if len(sys.argv)>1 else ''
if not target:
    target = _select_target() or ''
if not target: print("Usage: hostname",flush=True); raise SystemExit(2)
host=urlparse(target if '://' in target else '//' + target).hostname
if not host: print('Invalid hostname or URL',flush=True); raise SystemExit(2)
try:
 for x in socket.getaddrinfo(host,None): print(x[4][0],flush=True)
except Exception as e: print(e,flush=True)
