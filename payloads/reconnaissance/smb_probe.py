#!/usr/bin/env python3
# @name: SMB Probe
# @desc: Run scoped SMB discovery and security scripts against one authorized host with nmap, reporting dialect, signing, OS, and exposure details.
# @category: reconnaissance
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"target","label":"Authorized host","type":"text","required":true}]
import re,subprocess,sys
def main():
 target=sys.argv[1] if len(sys.argv)>1 else ''
 if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}',target): return 2
 return subprocess.run(['nmap','-Pn','-p','445','--script','smb-protocols,smb2-security-mode,smb2-time',target],timeout=300).returncode
if __name__=='__main__': raise SystemExit(main())
