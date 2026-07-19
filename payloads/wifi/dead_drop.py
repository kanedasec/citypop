#!/usr/bin/env python3
# @name: WiFi Dead Drop
# @desc: Secure anonymous file sharing via WiFi captive portal.
# @category: wifi
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"ssid","label":"Dead Drop SSID","type":"text","default":"DeadDrop"},{"name":"channel","label":"Wi-Fi channel","type":"number","default":"6"},{"name":"seconds","label":"Dashboard duration","type":"number","default":"300"}]
"""
RaspyJack Payload -- WiFi Dead Drop
=====================================
Author: 7h30th3r0n3

Secure anonymous file sharing via WiFi captive portal.
Opens a WiFi AP with a web portal where anyone can upload and download
files from a sandboxed directory. Real-time dashboard on LCD.

Security:
  Sandboxed directory (0700), path traversal prevention, filename
  sanitization, extension blacklist, file size limit, no internet
  forwarding, rate limiting, no CGI/shell.

Controls:
  python3 dead_drop.py [ssid]

    ssid   Optional AP name (default: saved config or 'DeadDrop')

  If more than one WiFi interface is present, you'll be prompted to
  pick one from a numbered list.

  Once running, the portal is live and status lines print every 5s.
  Ctrl-C   Stop the dead drop and print a final summary. You'll then
           be asked whether to purge all dropped files.

Loot: $CITYPOP_ROOT/loot/DeadDrop/
"""

from payloads._web_input import request_input
import os
import sys
import time
import json
import signal
import threading
import subprocess
import re
import html
import urllib.parse
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces
from payloads._dashboard import DashboardServer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DROP_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'DeadDrop', 'files')
LOG_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'DeadDrop')
CONFIG_PATH = os.path.join(LOG_DIR, "config.json")

HOSTAPD_CONF = "/tmp/rj_deaddrop_hostapd.conf"
DNSMASQ_CONF = "/tmp/rj_deaddrop_dnsmasq.conf"

GATEWAY_IP = "10.0.77.1"
DHCP_START = "10.0.77.10"
DHCP_END = "10.0.77.250"
PORTAL_PORT = 80

MAX_FILE_SIZE = 50 * 1024 * 1024
MAX_FILENAME_LEN = 100
UPLOAD_COOLDOWN = 3

BLOCKED_EXTENSIONS = {
    ".py", ".sh", ".bash", ".zsh", ".exe", ".elf", ".bin", ".so",
    ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".php", ".pl", ".rb",
    ".cgi", ".jsp", ".asp", ".aspx", ".msi", ".deb", ".rpm",
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
_running = True
active = False
status_msg = "Ready"
upload_count = 0
download_count = 0
total_bytes_up = 0
total_bytes_down = 0
connected_ips = set()
_upload_timestamps = {}
_last_event = ""  # last upload/download event text

_hostapd_proc = None
_dnsmasq_proc = None
_http_server = None

ssid = "DeadDrop"
channel = 6
iface = None


def _cleanup_signal(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup_signal)
signal.signal(signal.SIGTERM, _cleanup_signal)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _load_config():
    global ssid
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                cfg = json.load(f)
            ssid = str(cfg.get("ssid", ssid))
        except Exception:
            pass


def _save_config():
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump({"ssid": ssid}, f, indent=2)

# ---------------------------------------------------------------------------
# Filename sanitization
# ---------------------------------------------------------------------------

_SAFE_RE = re.compile(r"[^a-zA-Z0-9._\-]")


def _sanitize_filename(name):
    name = os.path.basename(name)
    name = _SAFE_RE.sub("_", name)
    if not name or name.startswith("."):
        name = "file_" + name
    if len(name) > MAX_FILENAME_LEN:
        base, ext = os.path.splitext(name)
        name = base[:MAX_FILENAME_LEN - len(ext)] + ext
    ext = os.path.splitext(name)[1].lower()
    if ext in BLOCKED_EXTENSIONS:
        name = name + ".blocked"
    return name

# ---------------------------------------------------------------------------
# Service management
# ---------------------------------------------------------------------------

def _start_services(ifc):
    global _hostapd_proc, _dnsmasq_proc, _http_server, status_msg

    for proc_name in ("hostapd", "dnsmasq"):
        subprocess.run(["sudo", "pkill", "-f", f"rj_deaddrop.*{proc_name}"],
                       capture_output=True, timeout=5)

    for cmd in [
        ["sudo", "ip", "link", "set", ifc, "down"],
        ["sudo", "iw", "dev", ifc, "set", "type", "managed"],
        ["sudo", "ip", "link", "set", ifc, "up"],
        ["sudo", "ip", "addr", "flush", "dev", ifc],
        ["sudo", "ip", "addr", "add", f"{GATEWAY_IP}/24", "dev", ifc],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)

    with open(HOSTAPD_CONF, "w") as f:
        f.write(
            f"interface={ifc}\ndriver=nl80211\nssid={ssid}\n"
            f"hw_mode=g\nchannel={channel}\nwmm_enabled=0\n"
            f"auth_algs=1\nwpa=0\nignore_broadcast_ssid=0\n"
        )

    with open(DNSMASQ_CONF, "w") as f:
        f.write(
            f"interface={ifc}\nbind-interfaces\n"
            f"dhcp-range={DHCP_START},{DHCP_END},12h\n"
            f"dhcp-option=6,{GATEWAY_IP}\naddress=/#/{GATEWAY_IP}\n"
            f"no-resolv\n"
        )

    for cmd in [
        ["sudo", "iptables", "-t", "nat", "-F"],
        ["sudo", "iptables", "-F", "FORWARD"],
        ["sudo", "iptables", "-P", "FORWARD", "DROP"],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", ifc,
         "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", str(PORTAL_PORT)],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", ifc,
         "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", str(PORTAL_PORT)],
        ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", ifc,
         "-p", "udp", "--dport", "53", "-j", "DNAT", "--to", f"{GATEWAY_IP}:53"],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)

    _hostapd_proc = subprocess.Popen(
        ["sudo", "hostapd", HOSTAPD_CONF],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(2)

    _dnsmasq_proc = subprocess.Popen(
        ["sudo", "dnsmasq", "-C", DNSMASQ_CONF, "--no-daemon"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1)

    _http_server = _ThreadedHTTPServer((GATEWAY_IP, PORTAL_PORT), _DeadDropHandler)
    threading.Thread(target=_http_server.serve_forever, daemon=True).start()

    with lock:
        status_msg = f"AP '{ssid}' on {ifc}"


def _stop_services():
    global _hostapd_proc, _dnsmasq_proc, _http_server, status_msg

    if _http_server:
        _http_server.shutdown()
        _http_server = None

    for proc in (_hostapd_proc, _dnsmasq_proc):
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    _hostapd_proc = None
    _dnsmasq_proc = None

    for cmd in [
        ["sudo", "iptables", "-t", "nat", "-F"],
        ["sudo", "iptables", "-F", "FORWARD"],
        ["sudo", "iptables", "-P", "FORWARD", "ACCEPT"],
    ]:
        subprocess.run(cmd, capture_output=True, timeout=5)

    subprocess.run(["sudo", "pkill", "-f", "rj_deaddrop"], capture_output=True, timeout=5)
    with lock:
        status_msg = "Stopped"


def _count_clients():
    """Count connected DHCP clients."""
    try:
        r = subprocess.run(["sudo", "cat", "/var/lib/misc/dnsmasq.leases"],
                           capture_output=True, text=True, timeout=3)
        if r.returncode == 0:
            return len([l for l in r.stdout.strip().split("\n") if l.strip()])
    except Exception:
        pass
    return len(connected_ips)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _human_size(size):
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}" if size != int(size) else f"{int(size)} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _list_files():
    files = []
    if os.path.isdir(DROP_DIR):
        for fn in sorted(os.listdir(DROP_DIR)):
            fp = os.path.join(DROP_DIR, fn)
            if os.path.isfile(fp):
                files.append((fn, os.path.getsize(fp)))
    return files

# ---------------------------------------------------------------------------
# HTML portal (multi-file upload)
# ---------------------------------------------------------------------------

_CSS = """
*{box-sizing:border-box}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;
margin:0;padding:15px;min-height:100vh}
.c{max-width:600px;margin:0 auto}
h1{color:#58a6ff;text-align:center;font-size:1.4em;margin:8px 0 2px}
.sub{text-align:center;color:#8b949e;margin-bottom:15px;font-size:0.8em}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;margin:10px 0}
.fl{list-style:none;padding:0;margin:0}
.fl li{padding:7px 10px;border-bottom:1px solid #21262d;display:flex;
justify-content:space-between;align-items:center;font-size:0.9em}
.fl li:last-child{border-bottom:none}
.fl a{color:#58a6ff;text-decoration:none}
.fl a:hover{text-decoration:underline}
.sz{color:#8b949e;font-size:0.8em}
.btn{background:#238636;color:#fff;border:none;padding:10px 16px;border-radius:6px;
cursor:pointer;font-size:0.95em;width:100%}
.btn:hover{background:#2ea043}
input[type=file]{color:#c9d1d9;margin:8px 0;width:100%}
.w{color:#f85149;font-size:0.8em;text-align:center}
.ok{color:#3fb950;font-size:0.8em;text-align:center}
.st{display:flex;justify-content:space-around;text-align:center;color:#8b949e;font-size:0.8em}
.st span{color:#58a6ff;font-weight:bold;display:block;font-size:1.1em}
.prog{width:100%;background:#21262d;border-radius:4px;height:20px;margin:8px 0;overflow:hidden;display:none}
.prog-bar{height:100%;background:#238636;transition:width 0.3s;width:0%}
.prog-text{text-align:center;font-size:0.8em;color:#8b949e;display:none}
"""

_JS = """
document.getElementById('upload-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var files = document.getElementById('file-input').files;
    if (files.length === 0) return;
    var prog = document.getElementById('progress');
    var pbar = document.getElementById('prog-bar');
    var ptxt = document.getElementById('prog-text');
    var results = document.getElementById('results');
    prog.style.display = 'block';
    ptxt.style.display = 'block';
    results.innerHTML = '';
    var done = 0;
    var total = files.length;
    function uploadNext(idx) {
        if (idx >= total) {
            ptxt.textContent = 'All done! Reloading...';
            setTimeout(function(){ location.reload(); }, 1000);
            return;
        }
        var fd = new FormData();
        fd.append('file', files[idx]);
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/upload', true);
        xhr.upload.onprogress = function(ev) {
            if (ev.lengthComputable) {
                var pct = ((done + ev.loaded/ev.total) / total * 100).toFixed(0);
                pbar.style.width = pct + '%';
            }
        };
        xhr.onload = function() {
            done++;
            var pct = (done / total * 100).toFixed(0);
            pbar.style.width = pct + '%';
            ptxt.textContent = done + '/' + total + ' uploaded';
            var color = xhr.status < 300 ? '#3fb950' : '#f85149';
            results.innerHTML += '<div style="color:'+color+';font-size:0.85em">' +
                files[idx].name + ': ' + (xhr.status < 300 ? 'OK' : 'Error ' + xhr.status) + '</div>';
            uploadNext(idx + 1);
        };
        xhr.onerror = function() {
            done++;
            results.innerHTML += '<div style="color:#f85149;font-size:0.85em">' +
                files[idx].name + ': Network error</div>';
            uploadNext(idx + 1);
        };
        xhr.send(fd);
    }
    uploadNext(0);
});
"""


def _build_page(message="", msg_class="ok"):
    files = _list_files()
    total_size = sum(s for _, s in files)

    file_rows = ""
    if files:
        for fn, sz in files:
            safe_name = html.escape(fn)
            encoded = urllib.parse.quote(fn)
            file_rows += (
                f'<li><a href="/download/{encoded}">{safe_name}</a>'
                f'<span class="sz">{_human_size(sz)}</span></li>\n'
            )
    else:
        file_rows = '<li style="color:#8b949e;text-align:center">No files yet</li>'

    msg_html = ""
    if message:
        msg_html = f'<p class="{msg_class}">{html.escape(message)}</p>'

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dead Drop</title><style>{_CSS}</style></head><body>
<div class="c">
<h1>&#x1f4e6; Dead Drop</h1>
<p class="sub">Anonymous file sharing &bull; No logs &bull; No tracking</p>
<div class="card"><div class="st">
<div><span>{len(files)}</span>files</div>
<div><span>{_human_size(total_size)}</span>total</div>
<div><span>{_human_size(MAX_FILE_SIZE)}</span>max/file</div>
</div></div>
{msg_html}
<div class="card">
<h3 style="margin-top:0">&#x1f4e4; Upload files</h3>
<form id="upload-form" method="POST" action="/upload" enctype="multipart/form-data">
<input type="file" id="file-input" name="file" multiple required>
<div class="prog" id="progress"><div class="prog-bar" id="prog-bar"></div></div>
<div class="prog-text" id="prog-text"></div>
<div id="results"></div>
<button type="submit" class="btn">Upload</button>
</form>
<p class="w" style="margin-bottom:0">Blocked: {', '.join(sorted(BLOCKED_EXTENSIONS))}</p>
</div>
<div class="card">
<h3 style="margin-top:0">&#x1f4c1; Files ({len(files)})</h3>
<ul class="fl">{file_rows}</ul>
</div>
<p class="sub" style="margin-top:15px">&#x1f512; Sandboxed &bull; No internet &bull; Local only</p>
</div>
<script>{_JS}</script>
</body></html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _DeadDropHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass

    def _send_html(self, code, body):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        # Track connected client
        with lock:
            connected_ips.add(self.client_address[0])
        if self.path.startswith("/download/"):
            self._handle_download()
        else:
            self._send_html(200, _build_page())

    def do_POST(self):
        with lock:
            connected_ips.add(self.client_address[0])
        if self.path == "/upload":
            self._handle_upload()
        else:
            self._send_html(404, _build_page("Not found", "w"))

    def _handle_download(self):
        global download_count, total_bytes_down, _last_event
        raw_name = urllib.parse.unquote(self.path[len("/download/"):])
        safe_name = os.path.basename(raw_name)

        filepath = os.path.join(DROP_DIR, safe_name)
        real_drop = os.path.realpath(DROP_DIR)
        real_file = os.path.realpath(filepath)
        if not real_file.startswith(real_drop + os.sep):
            self._send_html(403, _build_page("Access denied", "w"))
            return
        if not os.path.isfile(filepath):
            self._send_html(404, _build_page("File not found", "w"))
            return

        try:
            size = os.path.getsize(filepath)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
            self.send_header("Content-Length", str(size))
            self.end_headers()
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            with lock:
                download_count += 1
                total_bytes_down += size
                _last_event = f"DL {safe_name[:14]}"
        except Exception:
            pass

    def _handle_upload(self):
        global upload_count, total_bytes_up, _last_event

        client_ip = self.client_address[0]
        now = time.time()
        with lock:
            last = _upload_timestamps.get(client_ip, 0)
            if now - last < UPLOAD_COOLDOWN:
                self._send_html(429, _build_page(
                    f"Wait {UPLOAD_COOLDOWN}s between uploads", "w"))
                return
            _upload_timestamps[client_ip] = now

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._send_html(400, _build_page("Invalid request", "w"))
            return

        boundary = None
        for part in content_type.split(";"):
            part = part.strip()
            if part.startswith("boundary="):
                boundary = part[9:].strip('"')
                break
        if not boundary:
            self._send_html(400, _build_page("Missing boundary", "w"))
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > MAX_FILE_SIZE + 8192:
            self._send_html(413, _build_page(
                f"Too large (max {_human_size(MAX_FILE_SIZE)})", "w"))
            return

        body = self.rfile.read(content_length)
        boundary_bytes = boundary.encode("utf-8")
        parts = body.split(b"--" + boundary_bytes)

        filename = None
        file_data = None
        for part in parts:
            if b"Content-Disposition" not in part:
                continue
            header_end = part.find(b"\r\n\r\n")
            if header_end < 0:
                continue
            headers_raw = part[:header_end].decode("utf-8", errors="replace")
            if 'name="file"' not in headers_raw:
                continue
            fn_match = re.search(r'filename="([^"]*)"', headers_raw)
            if fn_match:
                filename = fn_match.group(1)
            file_data = part[header_end + 4:]
            if file_data.endswith(b"\r\n"):
                file_data = file_data[:-2]
            break

        if not filename or not file_data:
            self._send_html(400, _build_page("No file received", "w"))
            return

        if len(file_data) > MAX_FILE_SIZE:
            self._send_html(413, _build_page(
                f"Too large (max {_human_size(MAX_FILE_SIZE)})", "w"))
            return

        safe_name = _sanitize_filename(filename)
        if safe_name.endswith(".blocked"):
            self._send_html(403, _build_page(
                f"Blocked: {os.path.splitext(filename)[1]}", "w"))
            return

        dest = os.path.join(DROP_DIR, safe_name)
        real_drop = os.path.realpath(DROP_DIR)
        real_dest = os.path.realpath(dest)
        if not real_dest.startswith(real_drop + os.sep):
            self._send_html(403, _build_page("Invalid filename", "w"))
            return

        if os.path.exists(dest):
            base, ext = os.path.splitext(safe_name)
            counter = 1
            while os.path.exists(dest):
                safe_name = f"{base}_{counter}{ext}"
                dest = os.path.join(DROP_DIR, safe_name)
                counter += 1

        try:
            with open(dest, "wb") as f:
                f.write(file_data)
            os.chmod(dest, 0o644)
            sz = len(file_data)
            with lock:
                upload_count += 1
                total_bytes_up += sz
                _last_event = f"UP {safe_name[:14]}"
            self._send_html(200, _build_page(
                f"OK: {safe_name} ({_human_size(sz)})", "ok"))
        except Exception as exc:
            self._send_html(500, _build_page(f"Error: {exc}", "w"))


# ---------------------------------------------------------------------------
# WiFi interface selection
# ---------------------------------------------------------------------------

def _select_wifi_interface():
    """Detect WiFi interfaces and pick one. Prompts if more than one is found."""
    ifaces = list_interfaces(iface_type="wifi")

    if not ifaces:
        print("No WiFi interface found.", flush=True)
        return None

    if len(ifaces) == 1:
        return ifaces[0]["name"]

    print("Multiple WiFi interfaces found:", flush=True)
    for i, ifc in enumerate(ifaces):
        src = "USB" if not ifc["is_onboard"] else "onboard"
        caps = []
        if ifc["supports_ap"]:
            caps.append("AP")
        if ifc["supports_monitor"]:
            caps.append("mon")
        tag = f"{src} {'+'.join(caps)}" if caps else src
        state = "UP" if ifc["is_up"] else "DOWN"
        print(f"  [{i}] {ifc['name']}  {tag}  {state}", flush=True)

    while True:
        choice = str(request_input("Select AP-capable Wi-Fi interface", input_type="select", choices=[
            {"value": str(i), "label": f"{item['name']} · {'onboard' if item.get('is_onboard') else item.get('bus') or 'external'} · {'AP' if item.get('supports_ap') else 'AP support unknown'} · {'UP' if item.get('is_up') else 'DOWN'}"}
            for i, item in enumerate(ifaces)]))
        if choice.isdigit() and 0 <= int(choice) < len(ifaces):
            return ifaces[int(choice)]["name"]
        print("Invalid selection, try again.", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _usage():
    print(f"Usage: {os.path.basename(__file__)} [ssid]", flush=True)
    print("  ssid   Optional AP name (default: saved config or 'DeadDrop')", flush=True)


def main():
    global _running, active, status_msg, iface, ssid, channel

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0

    _load_config()
    if args:
        ssid = args[0]
    try:
        channel = max(1, min(int(args[1] if len(args) > 1 else "6"), 13))
        duration = max(10, min(int(args[2] if len(args) > 2 else "300"), 3600))
    except ValueError:
        print("Channel and duration must be whole numbers.", flush=True)
        return 2

    os.makedirs(DROP_DIR, exist_ok=True)
    os.chmod(DROP_DIR, 0o700)

    iface = _select_wifi_interface()
    if not iface:
        return 1

    _save_config()

    with lock:
        status_msg = f"Using {iface}"

    print(f"Starting Dead Drop AP '{ssid}' on {iface} ...", flush=True)
    _start_services(iface)
    active = True
    print(f"Portal live at http://{GATEWAY_IP}/  (SSID: {ssid})", flush=True)
    print(f"Dead Drop will run for {duration} seconds. Press Stop to end it early.", flush=True)

    start_time = time.time()
    dashboard = DashboardServer("Wi-Fi Dead Drop", lambda: {
        "status": status_msg,
        "ssid": ssid,
        "interface": iface,
        "channel": channel,
        "portal": f"http://{GATEWAY_IP}/",
        "elapsed_seconds": round(time.time() - start_time, 1),
        "connected_clients": _count_clients(),
        "uploads": upload_count,
        "downloads": download_count,
        "uploaded_bytes": total_bytes_up,
        "downloaded_bytes": total_bytes_down,
        "last_event": _last_event or "none",
        "files": [{"name": name, "bytes": size} for name, size in _list_files()],
    })
    try:
        print(f"Dashboard: {dashboard.start()}", flush=True)
    except OSError as exc:
        print(f"Dashboard unavailable: {exc}", flush=True)
    try:
        while _running and time.time() - start_time < duration:
            time.sleep(5.0)
            with lock:
                ul = upload_count
                dl = download_count
                bup = total_bytes_up
                bdn = total_bytes_down
                evt = _last_event
            clients = _count_clients()
            elapsed = time.time() - start_time
            print(
                f"[{elapsed:6.1f}s] clients={clients} "
                f"uploads={ul} ({_human_size(bup)}) "
                f"downloads={dl} ({_human_size(bdn)}) "
                f"last={evt or '-'}",
                flush=True,
            )
    except KeyboardInterrupt:
        print("\nStopping dead drop...", flush=True)

    _running = False
    _stop_services()
    dashboard.stop()
    active = False

    files = _list_files()
    total_sz = sum(s for _, s in files)
    print("\nFinal summary:", flush=True)
    print(f"  Uploads:       {upload_count} ({_human_size(total_bytes_up)})", flush=True)
    print(f"  Downloads:     {download_count} ({_human_size(total_bytes_down)})", flush=True)
    print(f"  Files in drop: {len(files)} ({_human_size(total_sz)})", flush=True)

    if files:
        try:
            choice = request_input("Purge all dropped files? [y/N]: ").strip().lower()
        except EOFError:
            choice = ""
        if choice == "y":
            for fn, _sz in files:
                fp = os.path.join(DROP_DIR, fn)
                if os.path.isfile(fp):
                    os.remove(fp)
            print("All files purged.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
