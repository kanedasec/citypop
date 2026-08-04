#!/usr/bin/env python3
# @name: Gobuster Directory Scan
# @desc: Run a bounded gobuster directory enumeration against an authorized URL with a selected wordlist and capped thread count.
# @category: reconnaissance
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"url","label":"Authorized URL (blank = pick from loot)","type":"text","placeholder":"https://example.test","required":false},{"name":"wordlist","label":"Wordlist path","type":"text","default":"/usr/share/wordlists/dirb/common.txt"},{"name":"threads","label":"Threads (max 20)","type":"number","default":"5"}]
import os, shutil, subprocess, sys
from payloads import _target_helper as target_helper

LOOT_ROOT = os.environ.get("CITYPOP_LOOT", "/tmp/citypop_loot")


def _select_target():
    urls = target_helper.find_urls_in_loot(LOOT_ROOT)
    candidates = target_helper.merge_candidates((urls, "seen in loot"))
    for entry in candidates:
        print(f"  - {entry['value']} ({'; '.join(entry['sources'])})", flush=True)
    return target_helper.prompt_target_selection(
        candidates,
        prompt_label="Select a URL to enumerate",
        manual_label="Enter an authorized URL",
    )


def main():
    if len(sys.argv)<4: print("A valid URL and gobuster are required."); return 2
    url = sys.argv[1] or (_select_target() or '')
    if not url.startswith(("http://","https://")) or not shutil.which("gobuster"): print("A valid URL and gobuster are required."); return 2
    try: threads=max(1,min(int(sys.argv[3]),20))
    except ValueError: return 2
    return subprocess.run(["gobuster","dir","-u",url,"-w",sys.argv[2],"-t",str(threads),"--no-color"],timeout=1800).returncode
if __name__=="__main__": raise SystemExit(main())
