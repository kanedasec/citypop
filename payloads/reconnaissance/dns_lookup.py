#!/usr/bin/env python3
# @active: true
# @name: DNS Lookup
# @desc: Resolve a scoped hostname using the local resolver
# @category: reconnaissance
# @danger: false
# @inputs: [{"name":"target","label":"Hostname or URL","type":"text","placeholder":"example.com","required":true}]
import socket,sys
from urllib.parse import urlparse
if len(sys.argv)!=2: print("Usage: hostname",flush=True); raise SystemExit(2)
host=urlparse(sys.argv[1] if '://' in sys.argv[1] else '//' + sys.argv[1]).hostname
if not host: print('Invalid hostname or URL',flush=True); raise SystemExit(2)
try:
 for x in socket.getaddrinfo(host,None): print(x[4][0],flush=True)
except Exception as e: print(e,flush=True)
