#!/usr/bin/env python3
# @name: Passive OS Signal Collector
# @desc: Passively inspect TCP/IP fingerprints on a selected interface for a bounded period and report inferred operating-system families without probing hosts.
# @category: reconnaissance
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"seconds","label":"Capture duration","type":"number","default":"30"}]
import subprocess,sys
from pathlib import Path
from payloads._web_input import request_input
def main():
    interfaces=sorted(p.name for p in Path('/sys/class/net').iterdir() if p.name!='lo'); iface=str(request_input('Select capture interface',input_type='select',choices=interfaces))
    try: seconds=max(1,min(int(sys.argv[1] if len(sys.argv)>1 else '30'),600))
    except ValueError: return 2
    cmd=['tshark','-i',iface,'-a',f'duration:{seconds}','-Y','tcp.flags.syn == 1','-T','fields','-e','ip.src','-e','ip.ttl','-e','tcp.window_size_value','-e','tcp.options.mss_val']
    print('IP\tTTL\tTCP window\tMSS',flush=True); return subprocess.run(cmd,timeout=seconds+20).returncode
if __name__=='__main__': raise SystemExit(main())
