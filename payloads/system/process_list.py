#!/usr/bin/env python3
# @active: true
# @name: Process List
# @desc: List local processes with PID, owner, and command, sorted by current CPU usage.
# @category: system
# @danger: false
# @web: true
# @maturity: functional
import subprocess
subprocess.run(['ps','-eo','pid,user,comm','--sort=-%cpu'],check=False)
