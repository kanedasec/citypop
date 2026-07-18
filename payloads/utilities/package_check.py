#!/usr/bin/env python3
# @active: true
# @name: Tool Check
# @desc: Check availability of common assessment tools
# @category: utilities
# @danger: false
import shutil
for x in ['nmap','iw','ip','ping','whois','curl','openssl']: print(f"{x}: {shutil.which(x) or 'missing'}",flush=True)
