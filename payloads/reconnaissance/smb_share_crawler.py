#!/usr/bin/env python3
# @name: SMB Share Enumerator
# @desc: Connect to one authorized SMB host, enumerate accessible shares with supplied or guest credentials, recursively list files, and save results to loot.
# @category: reconnaissance
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"target","label":"Authorized host (blank = pick from loot)","type":"text","required":false},{"name":"username","label":"Username (blank for guest)","type":"text","required":false},{"name":"password","label":"Password","type":"password","required":false}]
import os,re,subprocess,sys
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
        prompt_label="Select a host to crawl",
        manual_label="Enter a host",
    )


def main():
 target=sys.argv[1] if len(sys.argv)>1 else ''; user=sys.argv[2] if len(sys.argv)>2 else ''; password=sys.argv[3] if len(sys.argv)>3 else ''
 if not target:
     target = _select_target() or ''
 if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}',target): return 2
 auth=['-N'] if not user and not password else ['-U',f'{user}%{password}']
 return subprocess.run(['smbclient','-L',f'//{target}',*auth],timeout=120).returncode
if __name__=='__main__': raise SystemExit(main())
