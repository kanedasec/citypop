#!/usr/bin/env python3
# @active: true
# @name: List Interfaces
# @desc: List local network interfaces without changing state
# @category: utilities
# @danger: false
import os
for name in sorted(os.listdir('/sys/class/net')):
    print(name, flush=True)
