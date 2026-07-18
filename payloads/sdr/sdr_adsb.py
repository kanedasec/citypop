#!/usr/bin/env python3
# @name: ADS-B Aircraft Tracker
# @desc: Track aircraft via ADS-B (1090 MHz) using RTL-SDR.
# @category: sdr
# @danger: false
# @active: true
"""
RaspyJack Payload -- ADS-B Aircraft Tracker
=============================================
Track aircraft via ADS-B (1090 MHz) using RTL-SDR.
Decodes Mode-S messages: callsign, position, altitude, speed.
Prints a live aircraft summary and can serve a WebUI map on port 8081.

Controls:
  python3 sdr_adsb.py [duration_seconds] [--web]
    duration_seconds : optional; stop tracking after this many seconds.
                        If omitted, tracks until Ctrl-C.
    --web             : also start the WebUI map server on port 8081.
  A periodic aircraft summary is printed to stdout while tracking, and
  a final summary is printed when tracking stops.
"""

import os
import sys
import time
import math
import json
import struct
import subprocess
import threading
from datetime import datetime
import urllib.request
from io import BytesIO
from http.server import SimpleHTTPRequestHandler, HTTPServer

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads.sdr._sdr_core import detect_sdr

LOOT_DIR = "/root/Raspyjack/loot/SDR/adsb"
WEBUI_PORT = 8081

# ADS-B constants
ADSB_FREQ = 1090000000
ADSB_RATE = 2000000
MODES_PREAMBLE = [1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]

# Aircraft database
aircraft = {}
lock = threading.Lock()
_shutdown = threading.Event()


# ---------------------------------------------------------------------------
# Mode-S decoder (pure Python, no pyModeS)
# ---------------------------------------------------------------------------

def _hex_to_bin(hexstr):
    return bin(int(hexstr, 16))[2:].zfill(len(hexstr) * 4)


def _crc(msg_hex):
    """CRC-24 for Mode-S messages."""
    msg_bin = _hex_to_bin(msg_hex)
    n_bits = len(msg_bin)
    gen = 0x1FFF409
    msg_int = int(msg_bin, 2)
    for i in range(n_bits - 24):
        if msg_int & (1 << (n_bits - 1 - i)):
            msg_int ^= gen << (n_bits - 25 - i)
    return msg_int & 0xFFFFFF


def _decode_callsign(msg_hex):
    """Decode aircraft callsign from TC=1-4."""
    chars = "?ABCDEFGHIJKLMNOPQRSTUVWXYZ????? 0123456789??????"
    msg_bin = _hex_to_bin(msg_hex)
    data = msg_bin[40:88]
    cs = ""
    for i in range(8):
        idx = int(data[8 + i * 6:8 + i * 6 + 6], 2)
        if idx < len(chars):
            cs += chars[idx]
    return cs.strip()


def _decode_altitude(msg_hex):
    """Decode altitude from TC=9-18 (airborne position)."""
    msg_bin = _hex_to_bin(msg_hex)
    alt_bits = msg_bin[40:52]
    q_bit = alt_bits[7]
    if q_bit == "1":
        alt_code = alt_bits[:7] + alt_bits[8:]
        alt = int(alt_code, 2) * 25 - 1000
        return alt
    return None


def _decode_cpr_position(msg_hex):
    """Extract CPR latitude/longitude from TC=9-18. Returns (lat_cpr, lon_cpr, odd_flag)."""
    msg_bin = _hex_to_bin(msg_hex)
    flag = int(msg_bin[53])
    lat_cpr = int(msg_bin[54:71], 2) / 131072.0
    lon_cpr = int(msg_bin[71:88], 2) / 131072.0
    return lat_cpr, lon_cpr, flag


def _decode_velocity(msg_hex):
    """Decode velocity from TC=19."""
    msg_bin = _hex_to_bin(msg_hex)
    sub = int(msg_bin[37:40], 2)
    if sub in (1, 2):
        ew_dir = int(msg_bin[45])
        ew_vel = int(msg_bin[46:56], 2) - 1
        ns_dir = int(msg_bin[56])
        ns_vel = int(msg_bin[57:67], 2) - 1
        if ew_dir:
            ew_vel = -ew_vel
        if ns_dir:
            ns_vel = -ns_vel
        speed = int((ew_vel ** 2 + ns_vel ** 2) ** 0.5)
        heading = int(math.degrees(math.atan2(ew_vel, ns_vel)) % 360)
        return speed, heading
    return None, None


def _cpr_global_position(lat0, lon0, lat1, lon1):
    """Decode global position from even (0) and odd (1) CPR frames."""
    dLat0 = 360.0 / 60
    dLat1 = 360.0 / 59
    j = int(math.floor(59 * lat0 - 60 * lat1 + 0.5))
    lat_even = dLat0 * (j % 60 + lat0)
    lat_odd = dLat1 * (j % 59 + lat1)
    if lat_even >= 270:
        lat_even -= 360
    if lat_odd >= 270:
        lat_odd -= 360

    # Use even frame for now
    lat = lat_even
    try:
        nl = max(1, int(math.floor(2 * math.pi / (math.acos(1 - (1 - math.cos(math.pi / 30)) / (math.cos(math.radians(lat)) ** 2))))))
    except (ValueError, ZeroDivisionError):
        nl = 1
    m = int(math.floor(lon0 * (nl - 1) - lon1 * nl + 0.5))
    lon = (360.0 / nl) * (m % nl + lon0)
    if lon > 180:
        lon -= 360
    return lat, lon


def _process_message(msg_hex):
    """Process a Mode-S message. Update aircraft dict."""
    if len(msg_hex) < 28:
        return
    df = int(msg_hex[0:2], 16) >> 3
    if df != 17:
        return
    if _crc(msg_hex) != 0:
        return

    icao = msg_hex[2:8].upper()
    tc = int(_hex_to_bin(msg_hex)[32:37], 2)

    with lock:
        if icao not in aircraft:
            aircraft[icao] = {
                "icao": icao, "callsign": "", "alt": 0, "lat": 0, "lon": 0,
                "speed": 0, "heading": 0, "seen": time.time(),
                "cpr_even": None, "cpr_odd": None, "messages": 0,
            }
        ac = aircraft[icao]
        ac["seen"] = time.time()
        ac["messages"] += 1

        if 1 <= tc <= 4:
            ac["callsign"] = _decode_callsign(msg_hex)
        elif 9 <= tc <= 18:
            alt = _decode_altitude(msg_hex)
            if alt is not None:
                ac["alt"] = alt
            lat_cpr, lon_cpr, flag = _decode_cpr_position(msg_hex)
            if flag == 0:
                ac["cpr_even"] = (lat_cpr, lon_cpr, time.time())
            else:
                ac["cpr_odd"] = (lat_cpr, lon_cpr, time.time())
            if ac["cpr_even"] and ac["cpr_odd"]:
                t0 = ac["cpr_even"][2]
                t1 = ac["cpr_odd"][2]
                if abs(t0 - t1) < 10:
                    lat, lon = _cpr_global_position(
                        ac["cpr_even"][0], ac["cpr_even"][1],
                        ac["cpr_odd"][0], ac["cpr_odd"][1],
                    )
                    if -90 <= lat <= 90 and -180 <= lon <= 180:
                        ac["lat"] = round(lat, 5)
                        ac["lon"] = round(lon, 5)
        elif tc == 19:
            speed, heading = _decode_velocity(msg_hex)
            if speed is not None:
                ac["speed"] = speed
                ac["heading"] = heading




# ---------------------------------------------------------------------------
# RTL-SDR ADS-B receiver thread
# ---------------------------------------------------------------------------

def _adsb_receiver():
    """Capture 1090 MHz using rtl_adsb and decode Mode-S messages."""
    while not _shutdown.is_set():
        try:
            subprocess.run(["pkill", "-9", "rtl_adsb"], capture_output=True)
            time.sleep(0.3)
            proc = subprocess.Popen(
                ["rtl_adsb", "-g", "50"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1,
            )

            for line in proc.stdout:
                if _shutdown.is_set():
                    break
                line = line.strip()
                if not line or not line.startswith("*"):
                    continue
                msg_hex = line.strip("*;").strip()
                if len(msg_hex) >= 28:
                    _process_message(msg_hex)

            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        except Exception:
            pass
        if not _shutdown.is_set():
            time.sleep(1)


# ---------------------------------------------------------------------------
# WebUI server
# ---------------------------------------------------------------------------

_webui_running = False
_webui_server = None

WEBUI_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>RaspyJack ADS-B Radar</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/vendor/leaflet/leaflet.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e14;color:#c8d0dc;font-family:'Segoe UI',system-ui,sans-serif;overflow:hidden;height:100vh}
#map{height:100vh;width:100%;position:absolute;top:0;left:0;z-index:1}
.leaflet-container{background:#0a0e14}
#sidebar{position:absolute;top:0;right:0;width:340px;height:100vh;background:rgba(8,12,20,0.92);
  border-left:1px solid #1a2844;z-index:1000;display:flex;flex-direction:column;backdrop-filter:blur(10px)}
#header{padding:12px 16px;background:rgba(0,20,40,0.8);border-bottom:1px solid #1a2844}
#header h1{font-size:16px;color:#00ccff;font-weight:600;letter-spacing:1px}
#header .sub{font-size:11px;color:#4a6080;margin-top:2px}
#stats{display:flex;gap:8px;padding:8px 16px;border-bottom:1px solid #0d1a2e}
.stat{flex:1;text-align:center;padding:6px;background:rgba(0,40,80,0.3);border-radius:6px;border:1px solid #0d2040}
.stat .val{font-size:20px;font-weight:700;color:#00ff88}
.stat .lbl{font-size:9px;color:#4a6080;text-transform:uppercase;letter-spacing:1px}
#list{flex:1;overflow-y:auto;padding:4px 0}
#list::-webkit-scrollbar{width:4px}
#list::-webkit-scrollbar-thumb{background:#1a3050;border-radius:2px}
.ac{display:flex;align-items:center;padding:8px 16px;cursor:pointer;border-bottom:1px solid #0a1525;transition:background 0.15s}
.ac:hover{background:rgba(0,100,200,0.15)}
.ac.selected{background:rgba(0,150,255,0.2);border-left:3px solid #00ccff}
.ac-icon{font-size:20px;margin-right:10px;transform-origin:center}
.ac-info{flex:1;min-width:0}
.ac-call{font-size:13px;font-weight:600;color:#00ff88}
.ac-icao{font-size:10px;color:#3a5070;margin-left:6px}
.ac-details{font-size:11px;color:#6080a0;margin-top:2px}
.ac-alt{color:#ffaa00}
.ac-spd{color:#00bbff}
.tag-live{display:inline-block;width:6px;height:6px;background:#00ff88;border-radius:50%;margin-right:6px;
  animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
#footer{padding:8px 16px;background:rgba(0,15,30,0.8);border-top:1px solid #1a2844;
  font-size:10px;color:#3a5070;display:flex;justify-content:space-between}
.plane-marker{color:#00ff88;font-size:22px;text-shadow:0 0 8px rgba(0,255,136,0.5);
  transition:transform 0.3s;display:flex;align-items:center;justify-content:center}
.plane-label{position:absolute;left:18px;top:-2px;font-size:10px;color:#00ccff;
  background:rgba(0,20,40,0.8);padding:1px 4px;border-radius:2px;white-space:nowrap;
  border:1px solid #0d2040;font-family:monospace}
@media(max-width:768px){
  #sidebar{width:100%;height:45vh;top:auto;bottom:0;border-left:none;border-top:1px solid #1a2844}
  #map{height:55vh}
}
</style></head><body>
<div id="map"></div>
<div id="sidebar">
  <div id="header"><h1>ADSB RADAR</h1><div class="sub">RaspyJack &bull; 1090 MHz</div></div>
  <div id="stats">
    <div class="stat"><div class="val" id="s-ac">0</div><div class="lbl">Aircraft</div></div>
    <div class="stat"><div class="val" id="s-msg">0</div><div class="lbl">Messages</div></div>
    <div class="stat"><div class="val" id="s-pos">0</div><div class="lbl">Positions</div></div>
  </div>
  <div id="list"></div>
  <div id="footer"><span>Auto-refresh 1.5s</span><span id="clock"></span></div>
</div>
<script src="/vendor/leaflet/leaflet.js"></script>
<script>
const map=L.map('map',{zoomControl:false}).setView([46.8,2.3],6);
L.control.zoom({position:'topleft'}).addTo(map);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{
  maxZoom:18,attribution:'CartoDB'}).addTo(map);
let markers={},trails={},selected=null;
function hdgIcon(h){
  return L.divIcon({className:'',iconSize:[30,30],iconAnchor:[15,15],
    html:`<div class="plane-marker" style="transform:rotate(${h||0}deg)">&#9992;</div>`})}
function refresh(){
  fetch('/api/adsb/aircraft').then(r=>r.json()).then(data=>{
    let html='',totalMsg=0,withPos=0;
    data.forEach(ac=>{
      totalMsg+=ac.messages;
      if(ac.lat&&ac.lon)withPos++;
      const cs=ac.callsign||ac.icao;
      const sel=selected===ac.icao?'selected':'';
      html+=`<div class="ac ${sel}" onclick="selectAc('${ac.icao}',${ac.lat},${ac.lon})">
        <div class="ac-icon" style="transform:rotate(${ac.heading||0}deg)">&#9992;</div>
        <div class="ac-info">
          <div><span class="tag-live"></span><span class="ac-call">${cs}</span><span class="ac-icao">${ac.icao}</span></div>
          <div class="ac-details"><span class="ac-alt">${ac.alt.toLocaleString()}ft</span> &bull;
            <span class="ac-spd">${ac.speed}kt</span> &bull; ${ac.heading}&deg;</div>
        </div></div>`;
      if(ac.lat&&ac.lon){
        if(!markers[ac.icao]){
          markers[ac.icao]=L.marker([ac.lat,ac.lon],{icon:hdgIcon(ac.heading)}).addTo(map);
          trails[ac.icao]=L.polyline([],{color:'#00ff8840',weight:1,dashArray:'4'}).addTo(map);
        }else{
          markers[ac.icao].setLatLng([ac.lat,ac.lon]);
          markers[ac.icao].setIcon(hdgIcon(ac.heading));
          const t=trails[ac.icao].getLatLngs();
          t.push([ac.lat,ac.lon]);
          if(t.length>100)t.shift();
          trails[ac.icao].setLatLngs(t);
        }
        markers[ac.icao].bindPopup(`<div style="font-family:monospace;background:#0a0e14;color:#c8d0dc;padding:8px;border-radius:4px">
          <b style="color:#00ff88;font-size:14px">${cs}</b><br>
          <span style="color:#ffaa00">${ac.alt.toLocaleString()} ft</span><br>
          ${ac.speed} kt &bull; ${ac.heading}&deg;<br>
          <span style="color:#4a6080">${ac.lat.toFixed(4)}, ${ac.lon.toFixed(4)}</span><br>
          <span style="color:#3a5070">${ac.messages} msgs</span></div>`,{className:'dark-popup'});
      }
    });
    document.getElementById('list').innerHTML=html||'<div style="padding:40px;text-align:center;color:#3a5070">Waiting for aircraft...</div>';
    document.getElementById('s-ac').textContent=data.length;
    document.getElementById('s-msg').textContent=totalMsg>999?(totalMsg/1000).toFixed(1)+'k':totalMsg;
    document.getElementById('s-pos').textContent=withPos;
    // Remove stale markers
    const ids=new Set(data.map(a=>a.icao));
    Object.keys(markers).forEach(k=>{if(!ids.has(k)){map.removeLayer(markers[k]);map.removeLayer(trails[k]);delete markers[k];delete trails[k]}});
  }).catch(()=>{});
  document.getElementById('clock').textContent=new Date().toLocaleTimeString();
}
function selectAc(icao,lat,lon){
  selected=icao;
  if(lat&&lon)map.setView([lat,lon],10);
}
setInterval(refresh,1500);refresh();
</script></body></html>"""


class ADSBHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/root/Raspyjack/web", **kwargs)

    def do_GET(self):
        if self.path == "/adsb" or self.path == "/adsb/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(WEBUI_HTML.encode())
        elif self.path == "/api/adsb/aircraft":
            with lock:
                now = time.time()
                active = [ac for ac in aircraft.values() if now - ac["seen"] < 60]
                active.sort(key=lambda a: -a["messages"])
            data = []
            for ac in active:
                data.append({
                    "icao": ac["icao"], "callsign": ac["callsign"],
                    "alt": ac["alt"], "lat": ac["lat"], "lon": ac["lon"],
                    "speed": ac["speed"], "heading": ac["heading"],
                    "messages": ac["messages"],
                    "squawk": ac.get("squawk", ""),
                    "rssi": ac.get("rssi", 0),
                })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        elif self.path.startswith("/vendor/"):
            self.path = self.path
            super().do_GET()
        elif self.path == "/" or self.path == "":
            self.send_response(302)
            self.send_header("Location", "/adsb")
            self.end_headers()
        else:
            super().do_GET()

    def log_message(self, format, *args):
        pass


def _start_webui():
    global _webui_server, _webui_running
    try:
        _webui_server = HTTPServer(("0.0.0.0", WEBUI_PORT), ADSBHandler)
        # directory set in handler __init__
        _webui_running = True
        _webui_server.serve_forever()
    except Exception:
        _webui_running = False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _print_summary(active, total_msg, with_pos):
    print(f"-- {len(active)} aircraft, {total_msg} messages, {with_pos} with position --", flush=True)
    header = f"{'CALL':<8}{'ICAO':<8}{'ALT':>7}{'SPD':>6}{'HDG':>6}{'SQK':>6}  POS"
    print(header, flush=True)
    for ac in active[:15]:
        cs = ac["callsign"] or "-"
        sq = ac.get("squawk", "") or "-"
        pos = "yes" if ac["lat"] != 0 else "no"
        print(
            f"{cs:<8}{ac['icao']:<8}{ac['alt']:>7}{ac['speed']:>6}{ac['heading']:>6}{sq:>6}  {pos}",
            flush=True,
        )


def main():
    found, desc, _backend = detect_sdr()
    if not found:
        print("No RTL-SDR found!", flush=True)
        return 1
    print(f"Found SDR: {desc}", flush=True)

    duration = None
    start_web = False
    for arg in sys.argv[1:]:
        if arg == "--web":
            start_web = True
        else:
            try:
                duration = float(arg)
            except ValueError:
                print("Usage: sdr_adsb.py [duration_seconds] [--web]", flush=True)
                return 1

    webui_thread = None
    if start_web:
        webui_thread = threading.Thread(target=_start_webui, daemon=True)
        webui_thread.start()
        time.sleep(0.5)
        if _webui_running:
            print(f"WebUI map available at http://0.0.0.0:{WEBUI_PORT}/adsb", flush=True)
        else:
            print("WebUI failed to start.", flush=True)

    print("Tracking aircraft on 1090 MHz...", flush=True)
    if duration:
        print(f"Will stop automatically after {duration:.0f}s. Ctrl-C to stop earlier.", flush=True)
    else:
        print("Press Ctrl-C to stop.", flush=True)

    _shutdown.clear()
    receiver_thread = threading.Thread(target=_adsb_receiver, daemon=True)
    receiver_thread.start()

    start_time = time.time()
    try:
        last_status = 0
        while True:
            now = time.time()
            if duration is not None and (now - start_time) >= duration:
                break
            if now - last_status >= 5:
                with lock:
                    active = [ac for ac in aircraft.values() if now - ac["seen"] < 60]
                    active.sort(key=lambda a: -a["messages"])
                    total_msg = sum(ac["messages"] for ac in aircraft.values())
                    with_pos = sum(1 for ac in active if ac["lat"] != 0)
                _print_summary(active, total_msg, with_pos)
                last_status = now
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        _shutdown.set()
        if _webui_server:
            _webui_server.shutdown()

    with lock:
        now = time.time()
        active = [ac for ac in aircraft.values() if now - ac["seen"] < 60]
        total_msg = sum(ac["messages"] for ac in aircraft.values())
        total_seen = len(aircraft)

    print("Tracking stopped.", flush=True)
    print(f"Total aircraft seen: {total_seen}  Messages: {total_msg}", flush=True)
    if active:
        highest = max(active, key=lambda a: a["alt"])
        fastest = max(active, key=lambda a: a["speed"])
        print(f"Highest: {highest['callsign'] or highest['icao']} at {highest['alt']}ft", flush=True)
        print(f"Fastest: {fastest['callsign'] or fastest['icao']} at {fastest['speed']}kt", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
