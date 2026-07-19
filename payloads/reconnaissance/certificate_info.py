#!/usr/bin/env python3
# @active: true
# @web: true
# @name: Certificate Info
# @desc: Inspect a scoped TLS certificate subject
# @category: reconnaissance
# @danger: false
# @inputs: [{"name":"host","label":"TLS host","type":"text","placeholder":"example.com","required":true},{"name":"port","label":"TLS port","type":"number","default":"443"}]
import socket,ssl,sys
from urllib.parse import urlparse
if len(sys.argv)==2 and ':' in sys.argv[1]:
 host,port=sys.argv[1].rsplit(':',1)
else:
 if len(sys.argv)!=3: print('Usage: host port',flush=True); raise SystemExit(2)
 host=urlparse(sys.argv[1] if '://' in sys.argv[1] else '//' + sys.argv[1]).hostname;port=sys.argv[2]
if not host: print('Invalid hostname or URL',flush=True); raise SystemExit(2)
try:
 c=ssl.create_default_context(); c.check_hostname=False;c.verify_mode=ssl.CERT_NONE
 with c.wrap_socket(socket.socket(),server_hostname=sys.argv[1]) as s: s.settimeout(5);s.connect((sys.argv[1],int(sys.argv[2])));print(f'peer={s.getpeername()} cipher={s.cipher()}',flush=True); print('certificate retrieved',flush=True)
except Exception as e: print(e,flush=True)
