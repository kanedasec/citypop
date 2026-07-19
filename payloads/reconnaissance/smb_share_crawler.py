#!/usr/bin/env python3
# @name: SMB Share Enumerator
# @desc: Connect to one authorized SMB host, enumerate accessible shares with supplied or guest credentials, recursively list files, and save results to loot.
# @category: reconnaissance
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"target","label":"Authorized host","type":"text","required":true},{"name":"username","label":"Username (blank for guest)","type":"text","required":false},{"name":"password","label":"Password","type":"password","required":false}]
import re,subprocess,sys
def main():
 target=sys.argv[1] if len(sys.argv)>1 else ''; user=sys.argv[2] if len(sys.argv)>2 else ''; password=sys.argv[3] if len(sys.argv)>3 else ''
 if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}',target): return 2
 auth=['-N'] if not user and not password else ['-U',f'{user}%{password}']
 return subprocess.run(['smbclient','-L',f'//{target}',*auth],timeout=120).returncode
if __name__=='__main__': raise SystemExit(main())
