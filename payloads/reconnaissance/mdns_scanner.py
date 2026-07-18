#!/usr/bin/env python3
# @name: mDNS/Bonjour Discovery
# @desc: Discovers devices on the local network via mDNS (multicast DNS).
# @category: reconnaissance
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"seconds","label":"Browse duration","type":"number","default":"30"}]
import shutil, subprocess, sys
from pathlib import Path
from payloads._web_input import request_input
def main():
    if not shutil.which("avahi-browse"): print("avahi-browse is unavailable; install avahi-utils."); return 2
    interfaces=sorted(p.name for p in Path('/sys/class/net').iterdir() if p.name!='lo'); iface=str(request_input("Select interface",input_type="select",choices=interfaces))
    try: seconds=max(1,min(int(sys.argv[1] if len(sys.argv)>1 else '30'),300))
    except ValueError: return 2
    result=subprocess.run(["timeout",str(seconds),"avahi-browse","-a","-r","-p","-i",iface],text=True,timeout=seconds+10)
    return 0 if result.returncode in {0,124} else result.returncode
if __name__=="__main__": raise SystemExit(main())
