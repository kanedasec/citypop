#!/usr/bin/env python3
# @name: SOCKS5 Pivot Proxy
# @desc: Start an unauthenticated SOCKS5 CONNECT proxy on the Pi for a bounded authorized pivoting session and log proxy activity to loot.
# @category: remote_access
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"port","label":"SOCKS5 listen port","type":"number","default":"1080"},{"name":"seconds","label":"Run duration","type":"number","default":"300"}]
"""
RaspyJack Payload -- SOCKS5 Pivot Proxy
========================================
Author: 7h30th3r0n3

Starts a SOCKS5 proxy server for network pivoting.  Supports the
CONNECT command (TCP tunneling) so remote tools can route through
the Pi into the internal network.

Controls:
  usage: pivot_proxy.py [port] [duration_seconds]
    port              -- Listening port (default 1080)
    duration_seconds  -- Optional run time; omit to run until Ctrl-C

Default port: 1080
"""

import os
import sys
import struct
import socket
import select
import time
import threading
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

BUFFER_SIZE = 4096
DEFAULT_PORT = 1080

# SOCKS5 constants
SOCKS_VERSION = 0x05
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
proxy_active = False
listen_port = DEFAULT_PORT

# Stats
total_clients = 0
bytes_transferred = 0
connections = []    # [{"src", "dst", "bytes", "active"}]

server_sock = None


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _get_ip(iface):
    """Get IPv4 address for an interface."""
    try:
        res = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in res.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("inet "):
                return stripped.split()[1].split("/")[0]
    except Exception:
        pass
    return None


def _get_all_ips():
    """Get IPs for eth0, wlan0, tailscale0."""
    result = {}
    for iface in ["eth0", "wlan0", "tailscale0"]:
        ip = _get_ip(iface)
        if ip:
            result[iface] = ip
    return result


# ---------------------------------------------------------------------------
# SOCKS5 connection handler
# ---------------------------------------------------------------------------

def _handle_client(client_sock, client_addr):
    """Handle a single SOCKS5 client connection."""
    global total_clients, bytes_transferred

    src_label = f"{client_addr[0]}:{client_addr[1]}"
    dst_label = "?"
    conn_entry = {"src": src_label, "dst": dst_label, "bytes": 0, "active": True}

    with lock:
        total_clients += 1
        connections.append(conn_entry)

    remote_sock = None
    try:
        # Greeting: client sends version + auth methods
        greeting = client_sock.recv(256)
        if len(greeting) < 2 or greeting[0] != SOCKS_VERSION:
            return

        # Reply: no auth required
        client_sock.sendall(struct.pack("BB", SOCKS_VERSION, 0x00))

        # Request: version, cmd, rsv, atyp, dst_addr, dst_port
        request = client_sock.recv(256)
        if len(request) < 4:
            return

        version, cmd, _rsv, atyp = request[0], request[1], request[2], request[3]
        if version != SOCKS_VERSION or cmd != CMD_CONNECT:
            # Command not supported
            reply = struct.pack("BBBBIH", SOCKS_VERSION, 0x07, 0, ATYP_IPV4, 0, 0)
            client_sock.sendall(reply)
            return

        # Parse destination
        if atyp == ATYP_IPV4:
            if len(request) < 10:
                return
            dst_ip = socket.inet_ntoa(request[4:8])
            dst_port = struct.unpack("!H", request[8:10])[0]
        elif atyp == ATYP_DOMAIN:
            domain_len = request[4]
            if len(request) < 5 + domain_len + 2:
                return
            domain = request[5:5 + domain_len].decode("utf-8", errors="replace")
            dst_port = struct.unpack("!H", request[5 + domain_len:7 + domain_len])[0]
            try:
                dst_ip = socket.gethostbyname(domain)
            except socket.gaierror:
                reply = struct.pack("BBBBIH", SOCKS_VERSION, 0x04, 0, ATYP_IPV4, 0, 0)
                client_sock.sendall(reply)
                return
        else:
            reply = struct.pack("BBBBIH", SOCKS_VERSION, 0x08, 0, ATYP_IPV4, 0, 0)
            client_sock.sendall(reply)
            return

        dst_label = f"{dst_ip}:{dst_port}"
        with lock:
            conn_entry["dst"] = dst_label

        # Connect to target
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.settimeout(10)
        remote_sock.connect((dst_ip, dst_port))
        remote_sock.settimeout(None)

        # Success reply
        bind_addr = remote_sock.getsockname()
        bind_ip = socket.inet_aton(bind_addr[0])
        bind_port = struct.pack("!H", bind_addr[1])
        reply = struct.pack("BBB", SOCKS_VERSION, 0x00, 0x00)
        reply += struct.pack("B", ATYP_IPV4) + bind_ip + bind_port
        client_sock.sendall(reply)

        # Relay data bidirectionally
        _relay(client_sock, remote_sock, conn_entry)

    except Exception:
        pass
    finally:
        with lock:
            conn_entry["active"] = False
        _safe_close(client_sock)
        _safe_close(remote_sock)


def _relay(client_sock, remote_sock, conn_entry):
    """Bidirectional TCP relay between client and remote."""
    global bytes_transferred

    sockets = [client_sock, remote_sock]
    while running and proxy_active:
        try:
            readable, _, errored = select.select(sockets, [], sockets, 1.0)
        except Exception:
            break

        if errored:
            break

        for sock in readable:
            try:
                data = sock.recv(BUFFER_SIZE)
            except Exception:
                data = b""

            if not data:
                return

            target = remote_sock if sock is client_sock else client_sock
            try:
                target.sendall(data)
            except Exception:
                return

            n = len(data)
            with lock:
                bytes_transferred += n
                conn_entry["bytes"] = conn_entry.get("bytes", 0) + n


def _safe_close(sock):
    """Safely close a socket."""
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Server thread
# ---------------------------------------------------------------------------

def _server_thread(port):
    """SOCKS5 server accept loop."""
    global proxy_active, server_sock

    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.settimeout(1.0)
        server_sock.bind(("0.0.0.0", port))
        server_sock.listen(16)
    except OSError:
        proxy_active = False
        return

    while running and proxy_active:
        try:
            client_sock, client_addr = server_sock.accept()
            threading.Thread(
                target=_handle_client, args=(client_sock, client_addr),
                daemon=True,
            ).start()
        except socket.timeout:
            continue
        except Exception:
            break

    _safe_close(server_sock)
    server_sock = None
    proxy_active = False


# ---------------------------------------------------------------------------
# Status output
# ---------------------------------------------------------------------------

def _format_bytes(n):
    """Format byte count for display."""
    if n < 1024:
        return f"{n}B"
    elif n < 1024 * 1024:
        return f"{n // 1024}K"
    else:
        return f"{n // (1024 * 1024)}M"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, proxy_active, listen_port

    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(f"Usage: {sys.argv[0]} [port] [duration_seconds]", flush=True)
        return 0

    port = DEFAULT_PORT
    duration = None

    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Usage: {sys.argv[0]} [port] [duration_seconds]", flush=True)
            return 1

    if len(sys.argv) > 2:
        try:
            duration = float(sys.argv[2])
        except ValueError:
            print(f"Usage: {sys.argv[0]} [port] [duration_seconds]", flush=True)
            return 1

    listen_port = port

    print("SOCKS5 Pivot Proxy", flush=True)
    ips = _get_all_ips()
    if ips:
        for iface, ip in ips.items():
            print(f"  {iface}: {ip}", flush=True)
    else:
        print("  No interfaces up", flush=True)

    proxy_active = True
    threading.Thread(
        target=_server_thread, args=(listen_port,), daemon=True,
    ).start()
    time.sleep(0.3)

    if not proxy_active:
        print(f"[!] Failed to bind port {listen_port}", flush=True)
        return 1

    print(f"[*] Listening on 0.0.0.0:{listen_port} (SOCKS5, CONNECT only)", flush=True)
    print("[*] Press Ctrl-C to stop", flush=True)

    start = time.time()
    try:
        while running and proxy_active:
            time.sleep(5)
            with lock:
                clients = total_clients
                xfer = bytes_transferred
                active_count = sum(1 for c in connections if c["active"])
            elapsed = int(time.time() - start)
            print(
                f"[{elapsed}s] clients={clients} active={active_count} "
                f"transferred={_format_bytes(xfer)}", flush=True,
            )
            if duration and elapsed >= duration:
                break
    except KeyboardInterrupt:
        print("\n[*] Stopping...", flush=True)
    finally:
        running = False
        proxy_active = False
        _safe_close(server_sock)

    with lock:
        clients = total_clients
        xfer = bytes_transferred
    print(
        f"[*] Stopped. Total clients: {clients}, transferred: {_format_bytes(xfer)}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
