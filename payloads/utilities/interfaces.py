#!/usr/bin/env python3
# @active: true
# @name: List Interfaces
# @desc: List local network interfaces and their current addresses without changing their state.
# @category: utilities
# @danger: false
# @web: true
import os
for name in sorted(os.listdir('/sys/class/net')):
    print(name, flush=True)
