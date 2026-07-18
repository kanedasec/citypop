#!/usr/bin/env python3
# @active: true
# @name: Disk Status
# @desc: Show local disk usage
# @category: utilities
# @danger: false
import shutil
x=shutil.disk_usage('/');print(f"total={x.total} used={x.used} free={x.free}",flush=True)
