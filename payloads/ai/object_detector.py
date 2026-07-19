#!/usr/bin/env python3
# @name: Object Detector
# @desc: Run MobileNet SSD TFLite detection from the Pi camera, stream labeled detections, and optionally save annotated screenshots to loot.
# @category: ai
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"seconds","label":"Detection duration","type":"number","default":"60"},{"name":"confidence","label":"Confidence threshold","type":"number","default":"0.5"}]
"""
RaspyJack Payload -- Object Detector
=======================================
Author: 7h30th3r0n3

Real-time object detection using MobileNet SSD TFLite.
Detects 90 COCO classes: persons, cars, animals, etc.

Usage:
  object_detector.py [duration_seconds] [confidence_threshold] [--screenshot]

  duration_seconds      How long to run detection, in seconds. Omit to run
                         until Ctrl-C is pressed.
  confidence_threshold  Minimum detection confidence, between 0.05 and 0.95.
                         Defaults to 0.4.
  --screenshot           Take a single full-resolution photo (via
                         rpicam-still) before detection starts, saved to
                         the loot directory.

Detected objects are printed periodically while running, with a final
summary printed on exit (including after Ctrl-C).
"""

import os
import sys
import time
import signal
import subprocess
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import numpy as np
from PIL import Image

CITYPOP_ROOT = os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
MODEL_DIR = os.path.join(CITYPOP_ROOT, "models", "mobilenet")
MODEL_PATH = os.path.join(MODEL_DIR, "detect.tflite")
LABELS_PATH = os.path.join(MODEL_DIR, "labelmap.txt")
MODEL_URL = "https://storage.googleapis.com/download.tensorflow.org/models/tflite/coco_ssd_mobilenet_v1_1.0_quant_2018_06_29.zip"
LOOT_DIR = os.path.join(CITYPOP_ROOT, "loot", "Camera", "Detections")
INPUT_SIZE = 300
# Camera capture resolution used while detection is running.
CAP_W, CAP_H = 128, 128

_running = True
_detecting = False
_detections = []
_det_lock = threading.Lock()
_fps = 0.0
_conf_threshold = 0.4

COLORS = [
    (255, 50, 50), (50, 255, 50), (50, 50, 255), (255, 255, 50),
    (255, 50, 255), (50, 255, 255), (255, 150, 50), (150, 255, 50),
]


def _sig(s, f):
    global _running, _detecting
    _running = False
    _detecting = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _ensure_model():
    os.makedirs(MODEL_DIR, exist_ok=True)
    if os.path.isfile(MODEL_PATH):
        return True
    print("Downloading model (MobileNet SSD, ~4MB)...", flush=True)
    r = subprocess.run(
        ["wget", "--no-check-certificate", "-q", "-O", "/tmp/ssd.zip", MODEL_URL],
        capture_output=True, timeout=60)
    if r.returncode != 0:
        return False
    subprocess.run(["unzip", "-q", "-o", "/tmp/ssd.zip", "-d", MODEL_DIR],
                   capture_output=True, timeout=30)
    os.remove("/tmp/ssd.zip")
    return os.path.isfile(MODEL_PATH)


def _load_labels():
    if not os.path.isfile(LABELS_PATH):
        return {}
    labels = {}
    with open(LABELS_PATH, "r") as f:
        for i, line in enumerate(f):
            labels[i] = line.strip()
    return labels


def _detect_thread():
    """Capture frames from the camera and run inference on each one."""
    global _detecting, _detections, _fps
    from ai_edge_litert.interpreter import Interpreter

    interp = Interpreter(model_path=MODEL_PATH)
    interp.allocate_tensors()
    inp_detail = interp.get_input_details()[0]
    out_details = interp.get_output_details()
    labels = _load_labels()

    proc = subprocess.Popen(
        ["rpicam-vid", "--width", str(CAP_W), "--height", str(CAP_H),
         "--framerate", "8", "--codec", "yuv420",
         "--rotation", "180", "-t", "0", "--nopreview", "-o", "-"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)

    frame_size = CAP_W * CAP_H * 3 // 2

    frame_count = 0
    t_start = time.time()

    try:
        while _detecting and _running and proc.poll() is None:
            raw = b""
            while len(raw) < frame_size and _detecting:
                chunk = proc.stdout.read(frame_size - len(raw))
                if not chunk:
                    break
                raw += chunk
            if len(raw) < frame_size:
                break

            yuv = np.frombuffer(raw, dtype=np.uint8)
            y_plane = yuv[:CAP_W * CAP_H].reshape(CAP_H, CAP_W)
            u_raw = yuv[CAP_W * CAP_H:CAP_W * CAP_H + CAP_W * CAP_H // 4].reshape(CAP_H // 2, CAP_W // 2)
            v_raw = yuv[CAP_W * CAP_H + CAP_W * CAP_H // 4:].reshape(CAP_H // 2, CAP_W // 2)
            u = np.repeat(np.repeat(u_raw, 2, axis=0), 2, axis=1).astype(np.int16) - 128
            v = np.repeat(np.repeat(v_raw, 2, axis=0), 2, axis=1).astype(np.int16) - 128
            y16 = y_plane.astype(np.int16)

            r = np.clip(y16 + ((359 * v) >> 8), 0, 255).astype(np.uint8)
            g = np.clip(y16 - ((88 * u + 183 * v) >> 8), 0, 255).astype(np.uint8)
            b = np.clip(y16 + ((454 * u) >> 8), 0, 255).astype(np.uint8)

            rgb_frame = np.stack([r, g, b], axis=-1)

            input_img = Image.fromarray(rgb_frame).resize((INPUT_SIZE, INPUT_SIZE))
            input_data = np.expand_dims(np.array(input_img, dtype=np.uint8), axis=0)

            interp.set_tensor(inp_detail["index"], input_data)
            interp.invoke()

            boxes = interp.get_tensor(out_details[0]["index"])[0]
            classes = interp.get_tensor(out_details[1]["index"])[0]
            scores = interp.get_tensor(out_details[2]["index"])[0]

            dets = []
            for i in range(len(scores)):
                if scores[i] >= _conf_threshold:
                    ymin, xmin, ymax, xmax = boxes[i]
                    cls_id = int(classes[i])
                    label = labels.get(cls_id, f"class{cls_id}")
                    dets.append({
                        "label": label,
                        "score": float(scores[i]),
                        "box": (int(xmin * CAP_W), int(ymin * CAP_H), int(xmax * CAP_W), int(ymax * CAP_H)),
                        "color": COLORS[cls_id % len(COLORS)],
                    })

            with _det_lock:
                _detections = dets

            # Flush accumulated frames during inference to stay in sync
            try:
                import select
                while select.select([proc.stdout], [], [], 0)[0]:
                    discard = proc.stdout.read(frame_size)
                    if not discard:
                        break
            except Exception:
                pass

            frame_count += 1
            elapsed = time.time() - t_start
            if elapsed > 0:
                _fps = frame_count / elapsed
    except Exception:
        pass
    finally:
        proc.kill()
        _detecting = False


def main():
    global _running, _detecting, _conf_threshold

    duration = None
    threshold = None
    screenshot = False
    positional = []
    for a in sys.argv[1:]:
        if a == "--screenshot":
            screenshot = True
        else:
            positional.append(a)

    usage = f"Usage: {os.path.basename(__file__)} [duration_seconds] [confidence_threshold] [--screenshot]"

    if len(positional) > 0:
        try:
            duration = float(positional[0])
            if duration <= 0:
                raise ValueError
        except ValueError:
            print(usage, flush=True)
            sys.exit(1)

    if len(positional) > 1:
        try:
            threshold = float(positional[1])
            if not (0.05 <= threshold <= 0.95):
                raise ValueError
        except ValueError:
            print("confidence_threshold must be a number between 0.05 and 0.95", flush=True)
            sys.exit(1)
        _conf_threshold = threshold

    if not _ensure_model():
        print("Model download failed! Check internet.", flush=True)
        return 1

    print("Loading model...", flush=True)
    try:
        from ai_edge_litert.interpreter import Interpreter  # noqa: F401
    except ImportError:
        print("TFLite not installed! Run birdnet.py first.", flush=True)
        return 1

    if screenshot:
        os.makedirs(LOOT_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(LOOT_DIR, f"detect_{ts}.jpg")
        subprocess.run(
            ["rpicam-still", "-o", path, "--width", "1920", "--height", "1080",
             "-t", "300", "--nopreview", "--rotation", "180"],
            capture_output=True, timeout=10)
        print(f"Screenshot saved to {path}", flush=True)

    print(f"Detecting objects (threshold={int(_conf_threshold * 100)}%)."
          + (f" Duration: {duration:.0f}s." if duration else " Press Ctrl-C to stop."),
          flush=True)

    _detecting = True
    det_thread = threading.Thread(target=_detect_thread, daemon=True)
    det_thread.start()

    start = time.time()
    last_report = 0.0
    while _running and _detecting:
        if duration is not None and time.time() - start >= duration:
            break
        time.sleep(0.5)
        elapsed = time.time() - start
        if elapsed - last_report >= 2:
            last_report = elapsed
            with _det_lock:
                dets = list(_detections)
            summary = ", ".join(f"{d['label']}({int(d['score'] * 100)}%)" for d in dets[:5])
            print(f"[{int(elapsed)}s] fps={_fps:.1f} objects={len(dets)} {summary}", flush=True)

    _detecting = False
    _running = False
    det_thread.join(timeout=3)

    with _det_lock:
        dets = list(_detections)
    print(f"\n=== Final detections: {len(dets)} object(s) ===", flush=True)
    for d in dets:
        print(f"  {d['label']}  {int(d['score'] * 100)}%", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
