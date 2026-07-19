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
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
def main():
 try:user=sys.argv[1];password=sys.argv[2];port=int(sys.argv[3]);seconds=max(1,min(int(sys.argv[4]),3600));assert user and password and 1024<=port<65536
 except (IndexError,ValueError,AssertionError):return 2
 root=Path(os.environ.get('CITYPOP_ROOT',Path(__file__).resolve().parents[2]));auth=DummyAuthorizer();auth.add_user(user,password,str(root/'loot'),perm='elr');FTPHandler.authorizer=auth;server=FTPServer(('0.0.0.0',port),FTPHandler)
 threading.Timer(seconds,server.close_all).start();print(f'Read-only FTP available on port {port} for {seconds}s.',flush=True);server.serve_forever(timeout=1);return 0
if __name__=='__main__':raise SystemExit(main())
