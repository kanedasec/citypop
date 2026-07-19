"""Tiny authenticated status dashboards for long-running City Pop payloads."""
from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


_PAGE = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>__TITLE__</title><style>
:root{color-scheme:dark;--bg:#08060f;--panel:#120e26;--edge:#35265a;--cyan:#21e6ff;--pink:#ff2e88;--text:#e9e5ff;--dim:#958bad}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(800px 400px at 90% 0,#2c1235,var(--bg) 60%);color:var(--text);font:13px ui-monospace,monospace}main{max-width:900px;margin:auto;padding:18px}h1{font:700 20px system-ui;letter-spacing:2px;color:var(--cyan)}#state{color:var(--dim);margin-bottom:14px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px}.card,section{border:1px solid var(--edge);background:var(--panel);padding:12px}.card b{display:block;color:var(--dim);font-size:10px;text-transform:uppercase}.card span{display:block;margin-top:6px;font-size:18px;color:var(--cyan);overflow-wrap:anywhere}section{margin-top:12px;overflow:auto}h2{font:600 13px system-ui;color:var(--pink);text-transform:uppercase;letter-spacing:1px}table{width:100%;border-collapse:collapse;white-space:nowrap}th,td{text-align:left;padding:6px;border-bottom:1px solid var(--edge)}th{color:var(--cyan)}.error{color:var(--pink)}</style></head>
<body><main><h1>__TITLE__</h1><div id=state>connecting…</div><div id=cards class=cards></div><div id=tables></div></main>
<script>const token=new URLSearchParams(location.search).get('token')||'';const state=document.querySelector('#state'),cards=document.querySelector('#cards'),tables=document.querySelector('#tables');
const label=s=>s.replaceAll('_',' ');function cell(value){if(value===null||value===undefined)return '';if(Array.isArray(value))return value.join(', ');if(typeof value==='object')return JSON.stringify(value);return String(value)}
async function update(){try{const response=await fetch('/api/status?token='+encodeURIComponent(token),{cache:'no-store'});if(!response.ok)throw Error('HTTP '+response.status);const data=await response.json();state.textContent='updated '+new Date().toLocaleTimeString();cards.textContent='';tables.textContent='';for(const [key,value] of Object.entries(data)){if(Array.isArray(value)){const section=document.createElement('section'),heading=document.createElement('h2');heading.textContent=label(key);section.append(heading);if(value.length){const table=document.createElement('table'),head=document.createElement('tr'),keys=[...new Set(value.flatMap(row=>Object.keys(row||{})))];for(const key of keys){const th=document.createElement('th');th.textContent=label(key);head.append(th)}table.append(head);for(const row of value){const tr=document.createElement('tr');for(const key of keys){const td=document.createElement('td');td.textContent=cell(row[key]);tr.append(td)}table.append(tr)}section.append(table)}else section.append('No entries yet.');tables.append(section)}else{const card=document.createElement('div');card.className='card';const name=document.createElement('b'),val=document.createElement('span');name.textContent=label(key);val.textContent=cell(value);card.append(name,val);cards.append(card)}}}catch(error){state.className='error';state.textContent='dashboard unavailable · '+error.message}}update();setInterval(update,2000)</script></body></html>"""


def primary_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("1.1.1.1", 53))
            return sock.getsockname()[0]
    except OSError:
        try:
            output = subprocess.check_output(
                ["ip", "-o", "-4", "addr", "show", "scope", "global"],
                text=True, timeout=3,
            )
            for line in output.splitlines():
                address = line.split()[3].split("/", 1)[0]
                if address:
                    return address
        except (OSError, subprocess.SubprocessError, IndexError):
            pass
        return "127.0.0.1"


_primary_ip = primary_ip


class DashboardServer:
    def __init__(self, title: str, snapshot, port: int | None = None):
        self.title = title
        self.snapshot = snapshot
        self.port = port or int(os.environ.get("CITYPOP_DASHBOARD_PORT", "8092"))
        self.token = secrets.token_urlsafe(12)
        self.httpd = None

    def start(self) -> str:
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urlsplit(self.path)
                if parse_qs(parsed.query).get("token", [""])[0] != owner.token:
                    self.send_error(403)
                    return
                if parsed.path == "/api/status":
                    try:
                        body = json.dumps(owner.snapshot(), default=str).encode()
                    except Exception as exc:
                        body = json.dumps({"error": str(exc)}).encode()
                    content_type = "application/json"
                elif parsed.path == "/":
                    safe_title = owner.title.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    body = _PAGE.replace("__TITLE__", safe_title).encode()
                    content_type = "text/html; charset=utf-8"
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        self.httpd = ThreadingHTTPServer(("0.0.0.0", self.port), Handler)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return f"http://{primary_ip()}:{self.port}/?token={self.token}"

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
