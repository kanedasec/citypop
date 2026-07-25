#!/usr/bin/env python3
# @name: Bounded Loot FTP Server
# @desc: Temporarily serve City Pop's loot directory read-only over authenticated FTP and print the reachable endpoint in the web terminal.
# @category: exfiltration
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"username","label":"Temporary username","type":"text","default":"citypop"},{"name":"password","label":"Temporary password","type":"password","required":true},{"name":"port","label":"Listen port","type":"number","default":"2121"},{"name":"seconds","label":"Duration","type":"number","default":"300"}]
import os,sys,threading,time
from pathlib import Path
from payloads._dashboard import primary_ip
from payloads._ufw import TemporaryUfwRules
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
def main():
 try:user=sys.argv[1];password=sys.argv[2];port=int(sys.argv[3]);seconds=max(1,min(int(sys.argv[4]),3600));assert user and password and 1024<=port<65536
 except (IndexError,ValueError,AssertionError):return 2
 root=Path(os.environ.get('CITYPOP_ROOT',Path(__file__).resolve().parents[2]));auth=DummyAuthorizer();auth.add_user(user,password,str(root/'loot'),perm='elr');FTPHandler.authorizer=auth;FTPHandler.passive_ports=range(30000,30010)
 address=primary_ip();firewall=TemporaryUfwRules('loot-ftp')
 try:
  firewall.allow_lan_service(address,port)
  firewall.allow_lan_service(address,'30000:30009')
  server=FTPServer(('0.0.0.0',port),FTPHandler);threading.Timer(seconds,server.close_all).start()
  print(f'FTP endpoint: ftp://{address}:{port}/',flush=True)
  print(f'Username: {user} · Mode: read-only · Duration: {seconds}s · Passive ports: 30000-30009',flush=True)
  print(f'Serving: {root / "loot"}',flush=True)
  server.serve_forever(timeout=1);return 0
 finally:firewall.close()
if __name__=='__main__':raise SystemExit(main())
