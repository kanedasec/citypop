#!/usr/bin/env python3
# @name: WHOIS and Reverse DNS Lookup
# @desc: Performs WHOIS lookups and reverse DNS resolution for external IPs.
# @category: reconnaissance
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"target","label":"Domain or IP address","type":"text","required":true}]
import re, socket, subprocess, sys
def main():
    target=sys.argv[1] if len(sys.argv)>1 else ''
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}',target): print('Invalid target.'); return 2
    result=subprocess.run(['whois',target],capture_output=True,text=True,timeout=45); print(result.stdout[:30000] or result.stderr)
    try: print('Reverse DNS:',socket.gethostbyaddr(target)[0])
    except (OSError,socket.herror): pass
    return result.returncode
if __name__=="__main__": raise SystemExit(main())
