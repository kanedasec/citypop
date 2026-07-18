#!/usr/bin/env python3
# @name: Gobuster Directory Scan
# @desc: Runs gobuster dir against a URL.
# @category: reconnaissance
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"url","label":"Authorized URL","type":"text","placeholder":"https://example.test","required":true},{"name":"wordlist","label":"Wordlist path","type":"text","default":"/usr/share/wordlists/dirb/common.txt"},{"name":"threads","label":"Threads (max 20)","type":"number","default":"5"}]
import shutil, subprocess, sys
def main():
    if len(sys.argv)<4 or not sys.argv[1].startswith(("http://","https://")) or not shutil.which("gobuster"): print("A valid URL and gobuster are required."); return 2
    try: threads=max(1,min(int(sys.argv[3]),20))
    except ValueError: return 2
    return subprocess.run(["gobuster","dir","-u",sys.argv[1],"-w",sys.argv[2],"-t",str(threads),"--no-color"],timeout=1800).returncode
if __name__=="__main__": raise SystemExit(main())
