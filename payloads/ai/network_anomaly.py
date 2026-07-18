#!/usr/bin/env python3
# @name: Network Anomaly Detector
# @desc: ML-based network traffic anomaly detection.
# @category: ai
# @danger: false
# @active: true
"""
RaspyJack Payload -- Network Anomaly Detector
===============================================
Author: 7h30th3r0n3

ML-based network traffic anomaly detection.
Learns normal traffic patterns, then alerts on anomalies.
Uses Isolation Forest (sklearn) for unsupervised detection.

Usage:
  network_anomaly.py [duration_seconds] [interface] [--train] [--delete-model]

  duration_seconds  How long to monitor, in seconds. Omit to monitor until
                     Ctrl-C is pressed.
  interface         Network interface to sniff on. If omitted, you will be
                     prompted to choose from the interfaces found on this
                     machine.
  --train           Train a fresh Isolation Forest model on the first ~15s
                     of live traffic before monitoring for anomalies. The
                     trained model is saved and reused on future runs.
  --delete-model    Delete any previously saved model before starting.

If no trained model is available and --train is not given, traffic is
still captured and counted but no anomalies are flagged. Alerts are
printed as they are detected, along with periodic status lines. A
summary is printed on exit (including after Ctrl-C).
"""

from payloads._web_input import request_input
import os
import sys
import time
import signal
import subprocess
import threading
import struct
from datetime import datetime
from collections import deque, Counter

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

MODEL_PATH = "/root/Raspyjack/loot/AI/anomaly_model.pkl"
ALERTS_PATH = "/root/Raspyjack/loot/AI/anomaly_alerts.json"
WINDOW_SEC = 10

_running = True
_monitoring = False
_model = None
_trained = False


def _sig(s, f):
    global _running, _monitoring
    _running = False
    _monitoring = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _ensure_sklearn():
    try:
        from sklearn.ensemble import IsolationForest  # noqa: F401
        return True
    except ImportError:
        pass
    print("Installing sklearn...", flush=True)
    r = subprocess.run(
        ["pip3", "install", "--break-system-packages", "scikit-learn"],
        capture_output=True, timeout=300)
    return r.returncode == 0


class TrafficFeatures:
    """Extract features from network traffic in time windows."""

    def __init__(self):
        self.packets = deque(maxlen=5000)
        self.lock = threading.Lock()

    def add_packet(self, size, proto, src_port, dst_port, flags):
        with self.lock:
            self.packets.append({
                "ts": time.time(),
                "size": size,
                "proto": proto,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags": flags,
            })

    def get_features(self):
        """Extract feature vector for current window."""
        now = time.time()
        with self.lock:
            window = [p for p in self.packets if now - p["ts"] < WINDOW_SEC]

        if len(window) < 5:
            return None

        sizes = [p["size"] for p in window]
        protos = Counter(p["proto"] for p in window)
        ports = Counter(p["dst_port"] for p in window)

        pps = len(window) / WINDOW_SEC
        avg_size = sum(sizes) / len(sizes)
        max_size = max(sizes)
        min_size = min(sizes)
        std_size = (sum((s - avg_size) ** 2 for s in sizes) / len(sizes)) ** 0.5

        tcp_ratio = protos.get(6, 0) / len(window)
        udp_ratio = protos.get(17, 0) / len(window)
        icmp_ratio = protos.get(1, 0) / len(window)

        unique_ports = len(ports)
        top_port_ratio = ports.most_common(1)[0][1] / len(window) if ports else 0

        syn_count = sum(1 for p in window if p["flags"] & 0x02)
        syn_ratio = syn_count / len(window)

        return [
            pps, avg_size, max_size, min_size, std_size,
            tcp_ratio, udp_ratio, icmp_ratio,
            unique_ports, top_port_ratio, syn_ratio,
        ]


_features = TrafficFeatures()
_alerts = deque(maxlen=100)
_stats = {"packets": 0, "anomalies": 0, "last_score": 0.0}


def _sniff_thread(iface):
    """Capture packets using raw socket."""
    import socket
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((iface, 0))
        sock.settimeout(1.0)
    except Exception:
        return

    while _monitoring and _running:
        try:
            raw, _ = sock.recvfrom(65535)
            if len(raw) < 34:
                continue

            eth_proto = struct.unpack("!H", raw[12:14])[0]
            if eth_proto != 0x0800:
                continue

            ip_header = raw[14:34]
            proto = ip_header[9]
            total_len = struct.unpack("!H", ip_header[2:4])[0]

            src_port = dst_port = 0
            flags = 0
            ihl = (ip_header[0] & 0x0F) * 4
            transport = raw[14 + ihl:]

            if proto == 6 and len(transport) >= 14:
                src_port = struct.unpack("!H", transport[0:2])[0]
                dst_port = struct.unpack("!H", transport[2:4])[0]
                flags = transport[13]
            elif proto == 17 and len(transport) >= 8:
                src_port = struct.unpack("!H", transport[0:2])[0]
                dst_port = struct.unpack("!H", transport[2:4])[0]

            _features.add_packet(total_len, proto, src_port, dst_port, flags)
            _stats["packets"] += 1

        except socket.timeout:
            continue
        except Exception:
            continue

    sock.close()


def _detect_thread():
    """Run anomaly detection on feature windows."""
    global _model
    while _monitoring and _running:
        time.sleep(2)
        if not _trained or _model is None:
            continue

        features = _features.get_features()
        if features is None:
            continue

        try:
            import numpy as np
            X = np.array([features])
            score = _model.decision_function(X)[0]
            pred = _model.predict(X)[0]
            _stats["last_score"] = float(score)

            if pred == -1:
                _stats["anomalies"] += 1
                alert = {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "score": f"{score:.3f}",
                    "pps": f"{features[0]:.0f}",
                    "avg_size": f"{features[1]:.0f}",
                    "syn_ratio": f"{features[10]:.2f}",
                    "ports": f"{int(features[8])}",
                }
                _alerts.appendleft(alert)
                print(f"[ALERT {alert['time']}] score={alert['score']} "
                      f"pps={alert['pps']} ports={alert['ports']} syn_ratio={alert['syn_ratio']}",
                      flush=True)
        except Exception:
            pass


def _train_model():
    """Train Isolation Forest on current traffic features."""
    global _model, _trained
    import numpy as np
    from sklearn.ensemble import IsolationForest

    print("Training model on live traffic...", flush=True)
    samples = []
    for _ in range(30):
        f = _features.get_features()
        if f:
            samples.append(f)
        time.sleep(0.5)

    if len(samples) < 10:
        print("Not enough traffic data to train.", flush=True)
        return False

    X = np.array(samples)
    _model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
    )
    _model.fit(X)
    _trained = True

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    try:
        import pickle
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(_model, f)
    except Exception:
        pass

    print(f"Trained on {len(samples)} sample(s).", flush=True)
    return True


def _load_model():
    global _model, _trained
    if not os.path.isfile(MODEL_PATH):
        return False
    try:
        import pickle
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
        _trained = True
        return True
    except Exception:
        return False


def _delete_model():
    global _model, _trained
    _model = None
    _trained = False
    try:
        os.remove(MODEL_PATH)
    except Exception:
        pass


def _list_interfaces():
    """List all network interfaces."""
    ifaces = []
    try:
        for name in os.listdir("/sys/class/net"):
            if name == "lo":
                continue
            ifaces.append(name)
    except Exception:
        ifaces = ["eth0", "wlan0"]
    return sorted(ifaces)


def _get_default_iface():
    """Find default network interface."""
    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                           capture_output=True, text=True, timeout=3)
        parts = r.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    ifaces = _list_interfaces()
    return ifaces[0] if ifaces else "eth0"


def _choose_interface():
    """Prompt the operator to pick an interface from the discovered list."""
    ifaces = _list_interfaces()
    if not ifaces:
        print("No network interfaces found.", flush=True)
        return None

    default_iface = _get_default_iface()
    print("Available interfaces:", flush=True)
    for i, name in enumerate(ifaces, 1):
        marker = " (default)" if name == default_iface else ""
        print(f"  {i}. {name}{marker}", flush=True)

    choice = request_input(f"Select interface [1-{len(ifaces)}] (default: {default_iface}): ").strip()
    if not choice:
        return default_iface
    try:
        idx = int(choice)
        if not (1 <= idx <= len(ifaces)):
            raise ValueError
        return ifaces[idx - 1]
    except ValueError:
        print("Invalid selection.", flush=True)
        return None


def main():
    global _running, _monitoring

    usage = f"Usage: {os.path.basename(__file__)} [duration_seconds] [interface] [--train] [--delete-model]"

    train_flag = "--train" in sys.argv[1:]
    delete_flag = "--delete-model" in sys.argv[1:]
    positional = [a for a in sys.argv[1:] if a not in ("--train", "--delete-model")]

    duration = None
    if len(positional) > 0:
        try:
            duration = float(positional[0])
            if duration <= 0:
                raise ValueError
        except ValueError:
            print(usage, flush=True)
            sys.exit(1)

    iface_arg = positional[1] if len(positional) > 1 else None

    if not _ensure_sklearn():
        print("sklearn install failed!", flush=True)
        return 1

    if delete_flag:
        _delete_model()
        print("Deleted saved model.", flush=True)

    _load_model()

    if iface_arg:
        ifaces = _list_interfaces()
        if iface_arg not in ifaces:
            print(f"Unknown interface '{iface_arg}'. Available: {', '.join(ifaces)}", flush=True)
            sys.exit(1)
        iface = iface_arg
    else:
        iface = _choose_interface()
        if not iface:
            sys.exit(1)

    print(f"Sniffing on {iface}."
          + (f" Duration: {duration:.0f}s." if duration else " Press Ctrl-C to stop."),
          flush=True)

    _monitoring = True
    _stats["packets"] = 0
    sniff_t = threading.Thread(target=_sniff_thread, args=(iface,), daemon=True)
    sniff_t.start()

    if train_flag:
        time.sleep(1)
        _train_model()

    if not _trained:
        print("No trained model - capturing traffic only, no anomaly detection "
              "(use --train to build one).", flush=True)

    detect_t = threading.Thread(target=_detect_thread, daemon=True)
    detect_t.start()

    start = time.time()
    last_report = 0.0
    while _running and _monitoring:
        if duration is not None and time.time() - start >= duration:
            break
        time.sleep(0.5)
        elapsed = time.time() - start
        if elapsed - last_report >= 5:
            last_report = elapsed
            print(f"[{int(elapsed)}s] packets={_stats['packets']} "
                  f"anomalies={_stats['anomalies']} last_score={_stats['last_score']:.3f}",
                  flush=True)

    _monitoring = False
    _running = False
    sniff_t.join(timeout=2)
    detect_t.join(timeout=3)

    print("\n=== Summary ===", flush=True)
    print(f"Interface: {iface}", flush=True)
    print(f"Packets captured: {_stats['packets']}", flush=True)
    print(f"Model trained: {_trained}", flush=True)
    print(f"Anomalies detected: {_stats['anomalies']}", flush=True)
    if _alerts:
        print("Alerts:", flush=True)
        for a in reversed(list(_alerts)):
            print(f"  {a['time']} score={a['score']} pps={a['pps']} "
                  f"ports={a['ports']} syn_ratio={a['syn_ratio']}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
