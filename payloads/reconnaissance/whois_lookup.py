#!/usr/bin/env python3
# @name: WHOIS and Reverse DNS Lookup
# @desc: Performs WHOIS lookups and reverse DNS resolution for external IPs.
# @category: reconnaissance
# @danger: false
# @active: true
# @web: true
# @maturity: functional
# @runtime_links: false
# @inputs: [{"name":"target","label":"Domain or IP address (blank = pick from loot)","type":"text","required":false}]
import os, re, socket, subprocess, sys
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
        prompt_label="Select a domain or IP to look up",
        manual_label="Enter a domain or IP address",
    )


def main():
    target=sys.argv[1] if len(sys.argv)>1 else ''
    if not target:
        target = _select_target() or ''
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}',target): print('Invalid target.'); return 2
    result=subprocess.run(['whois',target],capture_output=True,text=True,timeout=45); print(result.stdout[:30000] or result.stderr)
    try: print('Reverse DNS:',socket.gethostbyaddr(target)[0])
    except (OSError,socket.herror): pass
    return result.returncode
if __name__=="__main__": raise SystemExit(main())
