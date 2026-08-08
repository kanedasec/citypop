#!/usr/bin/env python3
# @active: true
# @name: Tool Check
# @desc: Report whether nmap, iw, ip, ping, whois, curl, and openssl are available on the Pi.
# @category: system
# @danger: false
# @web: true
# @maturity: functional

import shutil
for x in ['nmap','iw','ip','ping','whois','curl','openssl']: print(f"{x}: {shutil.which(x) or 'missing'}",flush=True)
