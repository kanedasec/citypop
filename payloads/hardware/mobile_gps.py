#!/usr/bin/env python3
# @name: Mobile GPS Receiver
# @desc: Serve a temporary phone geolocation page, print its endpoint, receive browser location updates, and export collected points as CSV.
# @category: hardware
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"seconds","label":"Location page duration","type":"number","default":"300"}]
"""
RaspyJack Payload -- Mobile GPS Receiver
==========================================
Author: 7h30th3r0n3

Starts an HTTPS server that serves a page using the Geolocation API.
User opens the page on their smartphone, which sends GPS coordinates
back to the device periodically.

Setup / Prerequisites
---------------------
- Smartphone and this host on the same network.
- Modern mobile browser with Geolocation API support.

Controls
--------
  Usage: mobile_gps.py [duration_seconds]

  duration_seconds  Optional time to run the server, in seconds. Runs
                     until Ctrl-C if omitted.

  Starts the HTTPS server immediately and prints the URL to open on the
  phone. Each time a position update is received, a status line is
  printed to stdout. Press Ctrl-C to stop the server; any collected
  track points are exported to a CSV file automatically.

Loot: $CITYPOP_ROOT/loot/GPS/
"""

import os
import sys
import time
import json
import ssl
import signal
import threading
import socket
import subprocess
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), "loot", "GPS")
os.makedirs(LOOT_DIR, exist_ok=True)
HTTPS_PORT = 4443
_CERT_DIR = os.path.join(LOOT_DIR, ".certs")
_CERT_FILE = os.path.join(_CERT_DIR, "server.pem")
_KEY_FILE = os.path.join(_CERT_DIR, "server.key")

lock = threading.Lock()
_running = True

# Shared state
_latest_pos = {
    "lat": 0.0, "lon": 0.0, "acc": 0.0,
    "alt": 0.0, "speed": 0.0, "ts": "",
}
_track_log = []  # list of dicts
_server_running = False
_httpd = None


def _stop(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _stop)
signal.signal(signal.SIGTERM, _stop)


HTML_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>RaspyJack GPS</title>
<style>body{font-family:sans-serif;background:#111;color:#0f0;padding:20px;text-align:center}
h2{color:#0cf}#st{color:#fa0}button{font-size:18px;padding:10px 20px;margin:10px}</style>
</head><body>
<h2>RaspyJack GPS</h2><p id="st">Waiting...</p><p id="co"></p>
<script>
var iv=null;
function send(p){
  var x=new XMLHttpRequest();
  x.open("POST","/gps",true);
  x.setRequestHeader("Content-Type","application/json");
  var d={lat:p.coords.latitude,lon:p.coords.longitude,
         acc:p.coords.accuracy||0,alt:p.coords.altitude||0,
         speed:p.coords.speed||0};
  x.send(JSON.stringify(d));
  document.getElementById("st").textContent="Sending...";
  document.getElementById("co").textContent=
    "Lat:"+d.lat.toFixed(6)+" Lon:"+d.lon.toFixed(6);
}
function err(e){document.getElementById("st").textContent="Error: "+e.message;}
if(navigator.geolocation){
  navigator.geolocation.getCurrentPosition(send,err,{enableHighAccuracy:true});
  iv=setInterval(function(){
    navigator.geolocation.getCurrentPosition(send,err,{enableHighAccuracy:true});
  },3000);
}else{document.getElementById("st").textContent="Geolocation not supported";}
</script></body></html>"""


class _GPSHandler(BaseHTTPRequestHandler):
    """Handle GET (serve page) and POST (receive GPS data)."""

    def log_message(self, format, *args):
        pass  # suppress console output

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML_PAGE.encode("utf-8"))

    def do_POST(self):
        global _latest_pos, _track_log
        if self.path != "/gps":
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)
        except (ValueError, json.JSONDecodeError):
            self.send_response(400)
            self.end_headers()
            return

        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        pos = {
            "lat": float(data.get("lat", 0)),
            "lon": float(data.get("lon", 0)),
            "acc": float(data.get("acc", 0)),
            "alt": float(data.get("alt", 0)),
            "speed": float(data.get("speed", 0)),
            "ts": ts,
        }

        with lock:
            _latest_pos = pos
            _track_log = _track_log + [pos]

        print(
            f"Fix at {ts}: lat={pos['lat']:.6f} lon={pos['lon']:.6f} "
            f"acc={pos['acc']:.1f}m alt={pos['alt']:.1f}m speed={pos['speed']:.1f}m/s "
            f"(track: {len(_track_log)} pts)",
            flush=True,
        )

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')


def _get_device_ip():
    """Get the device's local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "0.0.0.0"


def _ensure_self_signed_cert():
    """Generate a self-signed certificate if one does not exist."""
    if os.path.isfile(_CERT_FILE) and os.path.isfile(_KEY_FILE):
        return True
    os.makedirs(_CERT_DIR, exist_ok=True)
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", _KEY_FILE, "-out", _CERT_FILE,
                "-days", "365", "-nodes",
                "-subj", "/CN=RaspyJack GPS",
            ],
            capture_output=True, timeout=30,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return False


def _start_server():
    """Start HTTPS server in a thread with a self-signed certificate."""
    global _httpd, _server_running

    if not _ensure_self_signed_cert():
        print("Certificate generation failed.", flush=True)
        return

    try:
        _httpd = HTTPServer(("0.0.0.0", HTTPS_PORT), _GPSHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=_CERT_FILE, keyfile=_KEY_FILE)
        _httpd.socket = ctx.wrap_socket(_httpd.socket, server_side=True)
        with lock:
            _server_running = True
        ip = _get_device_ip()
        print(f"HTTPS server running. Open on phone: https://{ip}:{HTTPS_PORT}", flush=True)
        _httpd.serve_forever()
    except OSError as exc:
        print(f"Server error: {exc}", flush=True)
        with lock:
            _server_running = False


def _stop_server():
    """Shutdown the HTTP server."""
    global _httpd, _server_running
    if _httpd is not None:
        _httpd.shutdown()
        _httpd = None
    with lock:
        _server_running = False


def _export_track(entries):
    """Export track log to CSV."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fpath = os.path.join(LOOT_DIR, f"track_{ts}.csv")
    try:
        with open(fpath, "w") as fh:
            fh.write("timestamp,latitude,longitude,accuracy,altitude,speed\n")
            for p in entries:
                fh.write(f"{p['ts']},{p['lat']},{p['lon']},{p['acc']},{p['alt']},{p['speed']}\n")
        return f"Saved {len(entries)} pts to {fpath}"
    except OSError as exc:
        return f"Err: {exc}"


def main():
    global _running

    duration = None
    if len(sys.argv) > 1:
        try:
            duration = float(sys.argv[1])
        except ValueError:
            print(f"Usage: {os.path.basename(__file__)} [duration_seconds]", flush=True)
            return 1

    server_thread = threading.Thread(target=_start_server, daemon=True)
    server_thread.start()

    start = time.time()
    try:
        while _running:
            if duration is not None and (time.time() - start) >= duration:
                break
            time.sleep(0.2)
    finally:
        _running = False
        _stop_server()
        with lock:
            final_track = list(_track_log)
        if final_track:
            print(_export_track(final_track), flush=True)
        else:
            print("No track points collected.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
