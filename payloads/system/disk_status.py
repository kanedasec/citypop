#!/usr/bin/env python3
# @active: true
# @name: Disk Status
# @desc: Show filesystem capacity, used space, free space, and mount points on the Pi.
# @category: system
# @danger: false
# @web: true
# @maturity: functional
import shutil
x=shutil.disk_usage('/');print(f"total={x.total} used={x.used} free={x.free}",flush=True)
