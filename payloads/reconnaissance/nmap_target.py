#!/usr/bin/env python3
# @active: true
# @name: Nmap Target Scan
# @desc: Run a service/version scan against an engagement target
# @category: reconnaissance
# @danger: false
# @inputs: [{"name":"target","label":"Authorized scan target","type":"text","placeholder":"10.0.0.5 or example.com","required":true}]
import shutil, subprocess, sys
if len(sys.argv) != 2:
    print("Usage: provide one IP address or URL", flush=True); raise SystemExit(2)
if not shutil.which("nmap"):
    print("nmap is not installed; install it with: sudo apt install nmap", flush=True); raise SystemExit(127)
target=sys.argv[1]
print(f"Starting authorized scan of {target}", flush=True)
subprocess.run(["nmap", "-sV", "--", target], check=False)
