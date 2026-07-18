#!/usr/bin/env python3
# @name: Bounded TCP Honeypot
# @desc: Lightweight, low‑interaction honeypot that listens on multiple TCP ports and logs connection attempts.
# @category: reconnaissance
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"port","label":"Listen port","type":"number","default":"8081"},{"name":"seconds","label":"Duration","type":"number","default":"300"},{"name":"banner","label":"Optional banner","type":"text","required":false}]
import os, socket, sys, time
from datetime import datetime,timezone
from pathlib import Path
def main():
    try: port=int(sys.argv[1]); seconds=max(1,min(int(sys.argv[2]),3600)); assert 0<port<65536
    except (IndexError,ValueError,AssertionError): return 2
    banner=(sys.argv[3] if len(sys.argv)>3 else '')[:512].encode(); root=Path(os.environ.get('CITYPOP_ROOT',Path(__file__).resolve().parents[2])); out=root/'loot'/'Honeypot'; out.mkdir(parents=True,exist_ok=True); log=out/f"tcp_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.log"
    deadline=time.monotonic()+seconds
    with socket.socket() as server,log.open('a') as fh:
        server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); server.bind(('0.0.0.0',port)); server.listen(); server.settimeout(1); print(f'Listening on TCP {port} for {seconds}s…',flush=True)
        while time.monotonic()<deadline:
            try: client,address=server.accept()
            except socket.timeout: continue
            with client:
                if banner: client.sendall(banner+b'\r\n')
                client.settimeout(1)
                try: data=client.recv(1024)
                except OSError: data=b''
            line=f"{datetime.now(timezone.utc).isoformat()} {address[0]}:{address[1]} bytes={len(data)} preview={data[:80]!r}"; print(line,flush=True); fh.write(line+'\n'); fh.flush()
    print('Saved:',log.relative_to(root)); return 0
if __name__=='__main__': raise SystemExit(main())
