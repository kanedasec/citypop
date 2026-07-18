#!/usr/bin/env python3
# @active: true
# @name: Reverse DNS
# @desc: Look up a scoped IP address hostname
# @category: reconnaissance
# @danger: false
# @inputs: [{"name":"target","label":"IP address","type":"text","placeholder":"10.0.0.5","required":true}]
import socket,sys
if len(sys.argv)!=2: print("Usage: IP address",flush=True); raise SystemExit(2)
try: print(socket.gethostbyaddr(sys.argv[1]),flush=True)
except Exception as e: print(e,flush=True)
