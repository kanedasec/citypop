#!/usr/bin/env python3
# @active: true
# @name: Process List
# @desc: List local processes for diagnostics
# @category: utilities
# @danger: false
import subprocess
subprocess.run(['ps','-eo','pid,user,comm','--sort=-%cpu'],check=False)
