#!/usr/bin/env python3
# @active: true
# @web: true
# @name: Certificate Info
# @desc: Inspect a scoped TLS certificate subject
# @category: reconnaissance
# @danger: false
# @maturity: functional
# @inputs: [{"name":"host","label":"TLS host","type":"text","placeholder":"example.com","required":false},{"name":"port","label":"TLS port","type":"number","default":"443"}]
import os,socket,ssl,sys
from urllib.parse import urlparse
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
        prompt_label="Select a TLS host",
        manual_label="Enter a TLS host",
    )


if len(sys.argv)==2 and ':' in sys.argv[1]:
 host,port=sys.argv[1].rsplit(':',1)
else:
 if len(sys.argv)!=3: print('Usage: host port',flush=True); raise SystemExit(2)
 raw_host=sys.argv[1] or (_select_target() or '')
 host=urlparse(raw_host if '://' in raw_host else '//' + raw_host).hostname if raw_host else ''
 port=sys.argv[2]
if not host: print('Invalid hostname or URL',flush=True); raise SystemExit(2)
try:
 c=ssl.create_default_context(); c.check_hostname=False;c.verify_mode=ssl.CERT_NONE
 with c.wrap_socket(socket.socket(),server_hostname=host) as s: s.settimeout(5);s.connect((host,int(port)));print(f'peer={s.getpeername()} cipher={s.cipher()}',flush=True); print('certificate retrieved',flush=True)
except Exception as e: print(e,flush=True)
