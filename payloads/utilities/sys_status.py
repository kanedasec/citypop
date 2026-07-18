#!/usr/bin/env python3
# @active: true
# @name: System Status
# @desc: Show local system health and network identity
# @category: utilities
# @danger: false
import os, platform, socket, subprocess

def run(*cmd):
    try: return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT).strip()
    except Exception as exc: return f"unavailable: {exc}"
print(f"hostname  {socket.gethostname()}", flush=True)
print(f"kernel    {platform.release()}", flush=True)
print(f"uptime    {run('uptime','-p')}", flush=True)
print(f"address   {run('hostname','-I')}", flush=True)
print(f"load      {os.getloadavg()}", flush=True)
