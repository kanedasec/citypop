#!/usr/bin/env python3
# @active: true
# @web: true
# @name: TCP Banner Check
# @desc: Read a banner from a scoped TCP service
# @category: reconnaissance
# @danger: false
# @inputs: [{"name":"host","label":"Target host","type":"text","placeholder":"example.com","required":true},{"name":"port","label":"TCP port","type":"number","default":"80"}]
import socket,sys
if len(sys.argv)!=3: print("Usage: host port",flush=True); raise SystemExit(2)
try:
 with socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=5) as s: print(s.recv(1024).decode(errors="replace"),flush=True)
except Exception as e: print(e,flush=True)
