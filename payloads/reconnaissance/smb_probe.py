#!/usr/bin/env python3
# @name: SMB Probe
# @desc: Run scoped SMB discovery and security scripts against one authorized host with nmap, reporting dialect, signing, OS, and exposure details.
# @category: reconnaissance
# @danger: false
# @active: true
# @web: true
# @maturity: functional
# @inputs: [{"name":"target","label":"Authorized host (blank = pick from loot)","type":"text","required":false}]
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
        prompt_label="Select a host to probe",
        manual_label="Enter a host",
    )


def main():
 target=sys.argv[1] if len(sys.argv)>1 else ''
 if not target:
     target = _select_target() or ''
 if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}',target): return 2
 return subprocess.run(['nmap','-Pn','-p','445','--script','smb-protocols,smb2-security-mode,smb2-time',target],timeout=300).returncode
if __name__=='__main__': raise SystemExit(main())
