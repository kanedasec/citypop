#!/usr/bin/env python3
# @active: true
# @name: ESP-NOW Receiver (Monitor Mode)
# @desc: Captures ESP-NOW frames over the air using a WiFi adapter in monitor mode.
# @category: wifi
# @danger: true
# @inputs: [{"name":"seconds","label":"Capture duration","type":"number","default":"60"}]

import os
import sys
import time
import signal
import struct
import csv
import subprocess
import threading
from datetime import datetime
from collections import Counter

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces
from payloads._web_input import request_input

try:
    from scapy.all import sniff as scapy_sniff, conf
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ---------------------------------------------------------------------------
# GPS (optional -- auto-detect USB + GPIO via _gps_helper, then use gpsd)
# ---------------------------------------------------------------------------
GPS_OK = False
try:
    from payloads._gps_helper import start_gps, detect_gps
    if start_gps():
        import gpsd as gpsd_module
        gpsd_module.connect()
        GPS_OK = True
except Exception:
    pass

if not GPS_OK:
    try:
        import gpsd as gpsd_module
        gpsd_module.connect()
        GPS_OK = True
    except Exception:
        pass


class GpsReader:
    """Thread-safe GPS reader using gpsd (auto-detects USB + GPIO GPS)."""

    def __init__(self):
        self.lat = 0.0
        self.lon = 0.0
        self.alt = 0.0
        self.speed = 0.0
        self.sats = 0
        self.fix = False
        self._lock = threading.Lock()
        self._running = True
        self._thread = None

    def start(self):
        if not GPS_OK:
            return
        self._thread = threading.Thread(target=self._poll, daemon=True)
        self._thread.start()

    def _poll(self):
        while self._running:
            try:
                pkt = gpsd_module.get_current()
                with self._lock:
                    self.lat = pkt.lat if hasattr(pkt, 'lat') else 0.0
                    self.lon = pkt.lon if hasattr(pkt, 'lon') else 0.0
                    self.alt = pkt.alt if hasattr(pkt, 'alt') else 0.0
                    self.speed = pkt.speed() if hasattr(pkt, 'speed') else 0.0
                    self.sats = pkt.sats if hasattr(pkt, 'sats') else 0
                    self.fix = pkt.mode >= 2 if hasattr(pkt, 'mode') else False
            except Exception:
                pass
            time.sleep(1)

    def get(self):
        with self._lock:
            return {
                "lat": self.lat, "lon": self.lon, "alt": self.alt,
                "speed": self.speed, "sats": self.sats, "fix": self.fix,
            }

    def stop(self):
        self._running = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ["CITYPOP_LOOT"], "ESPNow")
PCAP_DIR = os.path.join(LOOT_DIR, "handshakes")
ESPNOW_CHANNEL = 1
ESPNOW_ELEMENT = b"\x18\xfe\x34\x04"

# struct_message from C5 slave
WARD_STRUCT = struct.Struct("<64s32s16siii")
WARD_STRUCT_SIZE = WARD_STRUCT.size

# wifi_frame_fragment_t header
FRAG_HEADER = struct.Struct("<HBBB")
FRAG_HEADER_SIZE = FRAG_HEADER.size

# Channel lists (matching C5 slave channelsToHop[])
CHANNELS_2G = list(range(1, 14))
CHANNELS_5G = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
               116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
# C5 uses 1-based index into this list as board_id for fragments
ALL_CHANNELS = CHANNELS_2G + CHANNELS_5G
BOARD_ID_TO_CHANNEL = {i + 1: ch for i, ch in enumerate(ALL_CHANNELS)}

_running = True


def _cleanup(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Monitor mode helpers
# ---------------------------------------------------------------------------

def set_monitor_mode(iface, channel=1):
    cmds = [
        ["ip", "link", "set", iface, "down"],
        ["iw", iface, "set", "type", "monitor"],
        ["ip", "link", "set", iface, "up"],
        ["iw", iface, "set", "channel", str(channel)],
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True, timeout=10)
        if r.returncode != 0:
            return False, r.stderr.decode(errors="replace")
    return True, "OK"


def restore_managed_mode(iface):
    subprocess.run(["ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["iw", iface, "set", "type", "managed"],
                   capture_output=True, timeout=5)
    subprocess.run(["ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)


# ---------------------------------------------------------------------------
# ESP-NOW frame parser
# ---------------------------------------------------------------------------

def extract_espnow_payload(pkt):
    """Extract ESP-NOW payload from a raw 802.11 frame.

    ESP-NOW vendor element: 0xDD + Len + OUI(18:FE:34) + Type(0x04) + Ver + Body
    """
    raw_bytes = bytes(pkt)
    idx = raw_bytes.find(ESPNOW_ELEMENT)
    if idx < 0:
        return None
    payload_start = idx + 3 + 1 + 1  # OUI(3) + Type(1) + Version(1)
    if payload_start >= len(raw_bytes):
        return None
    return raw_bytes[payload_start:]


def _is_ward_payload(data):
    """Heuristic: ward payloads are 128 bytes and start with ASCII BSSID (hex:hex:...)."""
    if len(data) < WARD_STRUCT_SIZE:
        return False
    # Ward struct_message is sent as exactly sizeof(struct_message) = 124 bytes
    # ESP-NOW may add up to 4 bytes padding -> expect 124-132
    if not (124 <= len(data) <= 132):
        return False
    # BSSID field starts with printable hex chars (0-9, A-F, a-f, :)
    first = data[0]
    return (0x30 <= first <= 0x39 or  # 0-9
            0x41 <= first <= 0x46 or  # A-F
            0x61 <= first <= 0x66)    # a-f


def parse_ward_payload(data):
    if not _is_ward_payload(data):
        return None
    try:
        bssid_raw, ssid_raw, enc_raw, channel, rssi, board_id = \
            WARD_STRUCT.unpack_from(data)
        bssid = bssid_raw.split(b"\x00", 1)[0].decode(errors="replace")
        ssid = ssid_raw.split(b"\x00", 1)[0].decode(errors="replace")
        enc = enc_raw.split(b"\x00", 1)[0].decode(errors="replace")
        # Sanity check parsed values
        if ":" not in bssid or len(bssid) < 11:
            return None
        if not (-120 <= rssi <= 0):
            return None
        if not (1 <= channel <= 200):
            return None
        return {
            "bssid": bssid, "ssid": ssid, "enc": enc,
            "ap_ch": channel, "rssi": rssi, "board_id": board_id,
            "time": datetime.now().strftime("%H:%M:%S"),
        }
    except Exception:
        return None


def parse_fragment(data):
    if len(data) < FRAG_HEADER_SIZE:
        return None
    try:
        frame_len, frag_num, last_frag, board_id = FRAG_HEADER.unpack_from(data)
        frame_data = data[FRAG_HEADER_SIZE:FRAG_HEADER_SIZE + frame_len]
        return {
            "frame_len": frame_len, "frag_num": frag_num,
            "last": bool(last_frag), "board_id": board_id, "data": frame_data,
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Wigle-compatible CSV Logger
# ---------------------------------------------------------------------------

class WardLogger:
    WIGLE_HEADER = "WigleWifi-1.4,appRelease=RaspyJack,model=RPi,release=1.0,device=ESPNow,display=LCD,board=RPi,brand=RaspyJack"
    COLUMNS = ["MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI",
               "CurrentLatitude", "CurrentLongitude", "AltitudeMeters",
               "AccuracyMeters", "Type"]

    def __init__(self):
        os.makedirs(LOOT_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.csv_path = os.path.join(LOOT_DIR, f"ward_{ts}.csv")
        self._file = open(self.csv_path, "w", newline="")
        self._writer = csv.writer(self._file)
        self._writer.writerow([self.WIGLE_HEADER])
        self._writer.writerow(self.COLUMNS)
        self._count = 0
        self._seen_bssids = set()
        self._enc_counter = Counter()
        self._ch_counter = Counter()
        self._ssid_counter = Counter()

    def log(self, ap, gps_data):
        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        is_new = ap["bssid"] not in self._seen_bssids
        self._writer.writerow([
            ap["bssid"], ap["ssid"], f"[{ap['enc']}]", first_seen,
            ap["ap_ch"], ap["rssi"],
            f"{gps_data['lat']:.8f}" if gps_data["fix"] else "",
            f"{gps_data['lon']:.8f}" if gps_data["fix"] else "",
            f"{gps_data['alt']:.1f}" if gps_data["fix"] else "",
            "", "WIFI",
        ])
        self._file.flush()
        self._count += 1
        self._seen_bssids.add(ap["bssid"])
        self._enc_counter[ap["enc"]] += 1
        self._ch_counter[ap["ap_ch"]] += 1
        if ap["ssid"]:
            self._ssid_counter[ap["ssid"]] += 1
        return is_new

    @property
    def total(self):
        return self._count

    @property
    def unique(self):
        return len(self._seen_bssids)

    def close(self):
        self._file.close()


# ---------------------------------------------------------------------------
# PCAP writer
# ---------------------------------------------------------------------------

class PcapWriter:
    GLOBAL_HEADER = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 0xFFFF, 105)

    def __init__(self):
        os.makedirs(PCAP_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.path = os.path.join(PCAP_DIR, f"hs_{ts}.pcap")
        self._file = open(self.path, "wb")
        self._file.write(self.GLOBAL_HEADER)
        self._count = 0

    def write_frame(self, frame_bytes):
        ts = time.time()
        sec, usec = int(ts), int((ts - int(ts)) * 1_000_000)
        hdr = struct.pack("<IIII", sec, usec, len(frame_bytes), len(frame_bytes))
        self._file.write(hdr + frame_bytes)
        self._file.flush()
        self._count += 1

    @property
    def count(self):
        return self._count

    def close(self):
        self._file.close()


# ---------------------------------------------------------------------------
# Fragment reassembly
# ---------------------------------------------------------------------------

def _extract_ssid_from_beacon(frame_bytes):
    """Extract SSID from a beacon or probe response frame.

    802.11 MAC header (24B) + Fixed params (12B) = 36B, then tagged params.
    Tag 0 = SSID.
    """
    if len(frame_bytes) < 38:
        return ""
    # Check frame type: beacon = type 0 subtype 8, probe resp = type 0 subtype 5
    fc = frame_bytes[0]
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    if ftype != 0 or subtype not in (5, 8):
        return ""
    offset = 36  # after MAC header + fixed params
    while offset + 2 <= len(frame_bytes):
        tag_id = frame_bytes[offset]
        tag_len = frame_bytes[offset + 1]
        if offset + 2 + tag_len > len(frame_bytes):
            break
        if tag_id == 0 and tag_len > 0:
            try:
                return frame_bytes[offset + 2:offset + 2 + tag_len].decode(errors="replace")
            except Exception:
                return ""
        offset += 2 + tag_len
    return ""


class FragmentAssembler:
    def __init__(self, pcap_writer):
        self.pcap = pcap_writer
        self._state = {}
        self.frames_complete = 0
        self.ch_frames = Counter()      # board_id -> frame count
        self.last_ssid = ""             # last SSID extracted from beacon
        self.ch_last_ssid = {}          # board_id -> last SSID

    def feed(self, frag):
        bid = frag["board_id"]
        # Convert 1-based board_id index to actual WiFi channel number
        real_ch = BOARD_ID_TO_CHANNEL.get(bid, bid)
        if bid not in self._state:
            self._state[bid] = {"next": 0, "buf": bytearray()}
        st = self._state[bid]
        if frag["frag_num"] != st["next"]:
            st["next"] = 0
            st["buf"] = bytearray()
            return None
        st["buf"].extend(frag["data"])
        st["next"] += 1
        if frag["last"]:
            frame = bytes(st["buf"])
            st["next"] = 0
            st["buf"] = bytearray()
            self.pcap.write_frame(frame)
            self.frames_complete += 1
            self.ch_frames[real_ch] += 1
            # Try to extract SSID from beacon frames
            ssid = _extract_ssid_from_beacon(frame)
            if ssid:
                self.last_ssid = ssid
                self.ch_last_ssid[real_ch] = ssid
            return frame
        return None


# ---------------------------------------------------------------------------
# Sniffer thread
# ---------------------------------------------------------------------------

class EspNowSniffer:
    def __init__(self, iface, gps_reader):
        self.iface = iface
        self.gps = gps_reader
        self.ward_aps = []
        self.ward_logger = WardLogger()
        self.pcap = PcapWriter()
        self.assembler = FragmentAssembler(self.pcap)
        self.sniff_lines = []
        self._lock = threading.Lock()
        self.packets_total = 0
        self.start_time = time.time()

    def _handle_packet(self, pkt):
        payload = extract_espnow_payload(pkt)
        if payload is None:
            return
        self.packets_total += 1

        ap = parse_ward_payload(payload)
        if ap and ap["bssid"]:
            gps_data = self.gps.get()
            with self._lock:
                ap["lat"] = gps_data["lat"]
                ap["lon"] = gps_data["lon"]
                self.ward_aps.insert(0, ap)
                if len(self.ward_aps) > 1000:
                    self.ward_aps.pop()
                self.ward_logger.log(ap, gps_data)
            return

        frag = parse_fragment(payload)
        if frag and frag["frame_len"] > 0:
            real_ch = BOARD_ID_TO_CHANNEL.get(frag["board_id"], frag["board_id"])
            with self._lock:
                result = self.assembler.feed(frag)
                ts = datetime.now().strftime("%H:%M:%S")
                if result:
                    ssid_tag = ""
                    if self.assembler.last_ssid:
                        ssid_tag = f" {self.assembler.last_ssid[:10]}"
                    self.sniff_lines.insert(0,
                        f"{ts} FRAME ch{real_ch} {len(result)}B{ssid_tag}")
                else:
                    self.sniff_lines.insert(0,
                        f"{ts} frag#{frag['frag_num']} ch{real_ch}")
                if len(self.sniff_lines) > 200:
                    self.sniff_lines = self.sniff_lines[:200]

    def start(self):
        def _run():
            conf.iface = self.iface
            try:
                scapy_sniff(
                    iface=self.iface, prn=self._handle_packet,
                    store=False, stop_filter=lambda _: not _running,
                )
            except Exception as e:
                with self._lock:
                    self.sniff_lines.insert(0, f"ERR: {str(e)[:30]}")
        threading.Thread(target=_run, daemon=True).start()

    def elapsed(self):
        s = int(time.time() - self.start_time)
        return f"{s // 3600}:{(s % 3600) // 60:02d}:{s % 60:02d}"

    def stop(self):
        self.ward_logger.close()
        self.pcap.close()



def main():
    global _running
    if not SCAPY_OK: print("scapy is required",flush=True); return 127
    choices=[{"value":x["name"],"label":x["name"]} for x in list_interfaces("wifi") if x.get("supports_monitor")]
    if not choices: print("No monitor-capable Wi-Fi interface found",flush=True); return 1
    iface=str(request_input("Select Wi-Fi interface",input_type="select",choices=choices)); duration=min(3600,max(5,int(sys.argv[1]) if len(sys.argv)>1 else 60))
    ok,err=set_monitor_mode(iface,ESPNOW_CHANNEL)
    if not ok: print(f"Monitor mode failed: {err}",flush=True); return 1
    gps=GpsReader(); sniffer=EspNowSniffer(iface,gps)
    try:
        gps.start(); sniffer.start(); print(f"Monitoring ESP-NOW for {duration}s",flush=True); end=time.time()+duration
        while time.time()<end: print(f"frames={sniffer.packets_total} devices={len(sniffer.ward_aps)}",flush=True); time.sleep(5)
        return 0
    finally: _running=False; sniffer.stop(); gps.stop(); restore_managed_mode(iface)

if __name__ == "__main__":
    raise SystemExit(main())
