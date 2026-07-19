#!/usr/bin/env python3
# @name: TCP Port Forwarder
# @desc: Forward TCP connections from a chosen local listening port to an authorized remote host and port for a bounded session.
# @category: remote_access
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"rule","label":"Forwarding rule","type":"text","placeholder":"8080:10.0.0.5:80","required":true},{"name":"seconds","label":"Run duration","type":"number","default":"300"}]
"""
RaspyJack Payload -- TCP Port Forwarder
========================================
Author: 7h30th3r0n3

Forward a local port to a remote host:port.  Supports multiple
simultaneous forwarding rules with bidirectional TCP relay.

Controls:
  usage: port_forwarder.py rule [rule ...] [--duration seconds]
    rule -- local_port:remote_host:remote_port, e.g. 8080:192.168.1.1:80
    Omit --duration to run until Ctrl-C.

Loot: none (service tool, no data to loot)
"""

import os
import sys
import socket
import select
import time
import threading
from payloads._dashboard import primary_ip

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

BUFFER_SIZE = 4096

# ---------------------------------------------------------------------------
# Forward rule data structure
# ---------------------------------------------------------------------------
# Each rule: {"local_port", "remote_host", "remote_port", "active",
#             "server_sock", "bytes_fwd", "conn_count"}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True

rules = []          # list of rule dicts


def _new_rule(local_port=8080, remote_host="192.168.1.1", remote_port=80):
    """Create a new forwarding rule."""
    return {
        "local_port": local_port,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "active": False,
        "server_sock": None,
        "bytes_fwd": 0,
        "conn_count": 0,
    }


def _parse_rule_spec(spec):
    """Parse 'local_port:remote_host:remote_port' into a rule dict."""
    parts = spec.split(":")
    if len(parts) != 3:
        raise ValueError(f"bad rule '{spec}', expected local_port:remote_host:remote_port")
    local_port_s, remote_host, remote_port_s = parts
    local_port = int(local_port_s)
    remote_port = int(remote_port_s)
    if not (1 <= local_port <= 65535) or not (1 <= remote_port <= 65535):
        raise ValueError(f"bad rule '{spec}', ports must be 1-65535")
    return _new_rule(local_port, remote_host, remote_port)


# ---------------------------------------------------------------------------
# TCP relay
# ---------------------------------------------------------------------------

def _relay(sock_a, sock_b, rule):
    """Bidirectional relay between two sockets."""
    sockets = [sock_a, sock_b]
    while running and rule["active"]:
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
            target = sock_b if sock is sock_a else sock_a
            try:
                target.sendall(data)
            except Exception:
                return
            with lock:
                rule["bytes_fwd"] = rule.get("bytes_fwd", 0) + len(data)


def _handle_connection(client_sock, rule):
    """Handle a forwarded connection."""
    remote_sock = None
    try:
        with lock:
            rule["conn_count"] = rule.get("conn_count", 0) + 1

        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.settimeout(10)
        remote_sock.connect((rule["remote_host"], rule["remote_port"]))
        remote_sock.settimeout(None)

        _relay(client_sock, remote_sock, rule)
    except Exception:
        pass
    finally:
        _safe_close(client_sock)
        _safe_close(remote_sock)


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
# Server thread (one per rule)
# ---------------------------------------------------------------------------

def _server_thread(rule):
    """Accept loop for a single forwarding rule."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(1.0)
        srv.bind(("0.0.0.0", rule["local_port"]))
        srv.listen(8)
        with lock:
            rule["server_sock"] = srv
    except OSError:
        with lock:
            rule["active"] = False
        return

    while running and rule["active"]:
        try:
            client_sock, _addr = srv.accept()
            threading.Thread(
                target=_handle_connection, args=(client_sock, rule),
                daemon=True,
            ).start()
        except socket.timeout:
            continue
        except Exception:
            break

    _safe_close(srv)
    with lock:
        rule["server_sock"] = None
        rule["active"] = False


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _format_bytes(n):
    """Format byte count for display."""
    if n < 1024:
        return f"{n}B"
    elif n < 1024 * 1024:
        return f"{n // 1024}K"
    else:
        return f"{n // (1024 * 1024)}M"


def _print_status(rule_list):
    """Print a one-line summary of every rule's current counters."""
    for rule in rule_list:
        status = "ACTIVE" if rule["active"] else "STOPPED"
        print(
            f"  :{rule['local_port']} -> {rule['remote_host']}:{rule['remote_port']} "
            f"[{status}] conns={rule['conn_count']} fwd={_format_bytes(rule['bytes_fwd'])}",
            flush=True,
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

USAGE = (
    "Usage: {prog} local_port:remote_host:remote_port "
    "[local_port:remote_host:remote_port ...] [--duration seconds]"
)


def main():
    global running

    args = sys.argv[1:]
    # The web form supplies one rule followed by a plain duration. Preserve
    # the original multi-rule CLI while accepting that web-native shape.
    if len(args) == 2 and args[1].replace(".", "", 1).isdigit():
        args = [args[0], "--duration", args[1]]
    duration = None
    rule_specs = []

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--duration":
            if i + 1 >= len(args):
                print(USAGE.format(prog=sys.argv[0]), flush=True)
                return 1
            try:
                duration = float(args[i + 1])
            except ValueError:
                print(USAGE.format(prog=sys.argv[0]), flush=True)
                return 1
            i += 2
        else:
            rule_specs.append(arg)
            i += 1

    if not rule_specs:
        print(USAGE.format(prog=sys.argv[0]), flush=True)
        return 1

    try:
        for spec in rule_specs:
            rules.append(_parse_rule_spec(spec))
    except ValueError as exc:
        print(f"Error: {exc}", flush=True)
        return 1

    print("TCP Port Forwarder", flush=True)
    listen_ip = primary_ip()
    for rule in rules:
        rule["active"] = True
        threading.Thread(
            target=_server_thread, args=(rule,), daemon=True,
        ).start()
        print(
            f"[*] Endpoint: tcp://{listen_ip}:{rule['local_port']} -> "
            f"{rule['remote_host']}:{rule['remote_port']}", flush=True,
        )
    print("[*] Press Ctrl-C to stop", flush=True)

    start = time.time()
    try:
        while running:
            time.sleep(5)
            with lock:
                rule_list = [dict(r) for r in rules]
            elapsed = int(time.time() - start)
            print(f"[{elapsed}s]", flush=True)
            _print_status(rule_list)
            if not any(r["active"] for r in rule_list):
                break
            if duration and elapsed >= duration:
                break
    except KeyboardInterrupt:
        print("\n[*] Stopping...", flush=True)
    finally:
        running = False
        with lock:
            for rule in rules:
                rule["active"] = False
                srv = rule.get("server_sock")
                if srv:
                    _safe_close(srv)

    with lock:
        rule_list = [dict(r) for r in rules]
    print("[*] Stopped. Final counters:", flush=True)
    _print_status(rule_list)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
