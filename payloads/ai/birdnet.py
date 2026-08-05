#!/usr/bin/env python3
# @name: BirdNET Live
# @desc: Record audio from the detected ALSA input, run offline BirdNET inference, stream species/confidence detections, and print a session summary.
# @category: ai
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"seconds","label":"Listening duration","type":"number","default":"60"},{"name":"language","label":"Species-name language","type":"text","default":"en"}]
"""
RaspyJack Payload -- BirdNET Live
==================================
Author: 7h30th3r0n3

Real-time bird species detection using BirdNET AI model
and the ES8389 built-in microphone.

Usage:
  birdnet.py [duration_seconds] [lang]

  duration_seconds  How long to listen, in seconds. Omit to listen until
                     Ctrl-C is pressed.
  lang              Language code for common species names (e.g. en, fr,
                     de). Defaults to the last saved language, or "fr".

Detections are printed as they occur, along with periodic status lines.
A summary of all detections is printed on exit (including after Ctrl-C).
"""

import os
import sys
import time
import signal
import subprocess
import struct
import threading
import json
import hashlib
import shutil
import tempfile
import zipfile
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import numpy as np
from payloads._audio_helper import get_audio_card, get_alsa_dev

CITYPOP_ROOT = os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
MODEL_DIR = os.path.join(CITYPOP_ROOT, "models", "birdnet")
MODEL_PATH = os.path.join(MODEL_DIR, "model.tflite")
LABELS_PATH = os.path.join(MODEL_DIR, "labels.txt")
L18N_DIR = os.path.join(MODEL_DIR, "l18n")
LOOT_DIR = os.path.join(CITYPOP_ROOT, "loot", "BirdNET")
SETTINGS_PATH = os.path.join(LOOT_DIR, "settings.json")
RECORD_RATE = 16000
MODEL_RATE = 48000
CHUNK_SECS = 3
CHUNK_SAMPLES = MODEL_RATE * CHUNK_SECS
MIN_CONFIDENCE = 0.25
AVAILABLE_LANGS = [
    "en", "fr", "de", "es", "it", "pt", "nl", "pl", "ru", "ja",
    "ko", "zh_CN", "ar", "tr", "sv", "da", "no", "fi", "cs", "hu",
]

_running = True
_listening = False
_alsa_dev = "default"
_interpreter = None
_labels = []
_lang_map = {}
_lang = "fr"
_detections = []
_detections_lock = threading.Lock()
_current_status = "Ready"
_status_lock = threading.Lock()


def _sig(s, f):
    global _running, _listening
    _running = False
    _listening = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _detect_alsa_dev():
    global _alsa_dev
    try:
        r = subprocess.run(["aplay", "-l"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.split("\n"):
            if "card" in line.lower() and ":" in line:
                card_num = line.split(":")[0].replace("card", "").strip()
                if any(k in line.upper() for k in ["ES8388", "ES8389", "ES8390"]):
                    _alsa_dev = f"plughw:{card_num},0"
                    return
                elif "HDMI" not in line.upper():
                    _alsa_dev = f"plughw:{card_num},0"
    except Exception:
        pass


def _enable_mic():
    subprocess.run(
        ["i2cset", "-f", "-y", "1", "0x4f", "0x06", "0x01"],
        capture_output=True, timeout=2)
    subprocess.run(
        ["amixer", "-c", get_audio_card(), "cset", "name=ADC MUX", "0"],
        capture_output=True, timeout=2)
    subprocess.run(
        ["amixer", "-c", get_audio_card(), "cset", "name=ADCL PGA Volume", "12"],
        capture_output=True, timeout=2)
    subprocess.run(
        ["amixer", "-c", get_audio_card(), "cset", "name=ADCL Capture Volume", "220"],
        capture_output=True, timeout=2)


def _disable_mic():
    subprocess.run(
        ["i2cset", "-f", "-y", "1", "0x4f", "0x06", "0x03"],
        capture_output=True, timeout=2)


def _load_settings():
    global _lang
    os.makedirs(LOOT_DIR, exist_ok=True)
    if os.path.isfile(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r") as f:
                s = json.load(f)
            _lang = s.get("lang", "fr")
        except Exception:
            pass


def _save_settings():
    os.makedirs(LOOT_DIR, exist_ok=True)
    try:
        with open(SETTINGS_PATH, "w") as f:
            json.dump({"lang": _lang}, f)
    except Exception:
        pass


def _load_lang_map():
    global _lang_map
    path = os.path.join(L18N_DIR, f"labels_{_lang}.json")
    if os.path.isfile(path):
        try:
            with open(path, "r") as f:
                _lang_map = json.load(f)
        except Exception:
            _lang_map = {}
    else:
        _lang_map = {}


def _get_common_name(sci_name):
    if _lang_map and sci_name in _lang_map:
        return _lang_map[sci_name]
    return sci_name


def _load_model():
    global _interpreter, _labels
    try:
        from ai_edge_litert.interpreter import Interpreter
    except ImportError:
        return False
    if not os.path.isfile(MODEL_PATH) or not os.path.isfile(LABELS_PATH):
        return False
    try:
        _interpreter = Interpreter(model_path=MODEL_PATH)
        _interpreter.allocate_tensors()
        with open(LABELS_PATH, "r", encoding="utf-8") as f:
            _labels = [line.strip() for line in f if line.strip()]
    except (OSError, ValueError, RuntimeError) as error:
        _interpreter = None
        _labels = []
        print(f"Model load failed: {error}", flush=True)
        print("The verified files were retained; check ai-edge-litert compatibility on this device.", flush=True)
        return False
    _load_settings()
    _load_lang_map()
    return True


def _resample_16k_to_48k(samples_16k):
    n = len(samples_16k)
    indices = np.arange(n * 3) / 3.0
    indices = np.clip(indices, 0, n - 1)
    idx_floor = indices.astype(np.int32)
    idx_ceil = np.minimum(idx_floor + 1, n - 1)
    frac = indices - idx_floor
    return samples_16k[idx_floor] * (1.0 - frac) + samples_16k[idx_ceil] * frac


def _sigmoid(x):
    return 1.0 / (1.0 + np.exp(-np.clip(x, -15, 15)))


def _analyze_chunk(audio_48k):
    if _interpreter is None:
        return []
    inp_details = _interpreter.get_input_details()[0]
    out_details = _interpreter.get_output_details()[0]

    chunk = np.zeros(CHUNK_SAMPLES, dtype=np.float32)
    n = min(len(audio_48k), CHUNK_SAMPLES)
    chunk[:n] = audio_48k[:n]

    _interpreter.set_tensor(inp_details["index"], chunk.reshape(1, -1))
    _interpreter.invoke()
    logits = _interpreter.get_tensor(out_details["index"])[0]
    preds = _sigmoid(logits)

    results = []
    top_indices = np.argsort(preds)[::-1][:5]
    for idx in top_indices:
        conf = float(preds[idx])
        if conf >= MIN_CONFIDENCE and idx < len(_labels):
            label = _labels[idx]
            sci_name = label.split("_")[0]
            common_name = _get_common_name(sci_name)
            results.append({
                "species": common_name,
                "scientific": sci_name,
                "confidence": conf,
                "time": datetime.now().strftime("%H:%M"),
            })
    return results


def _set_status(msg):
    global _current_status
    with _status_lock:
        _current_status = msg


def _get_status():
    with _status_lock:
        return _current_status


def _listen_thread():
    global _listening
    _enable_mic()
    time.sleep(0.3)

    rec_proc = subprocess.Popen(
        ["arecord", "-D", _alsa_dev, "-f", "S16_LE", "-r", str(RECORD_RATE),
         "-c", "1", "-t", "raw"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    chunk_bytes = RECORD_RATE * 2 * CHUNK_SECS
    try:
        while _listening and _running:
            _set_status("Listening...")
            raw = b""
            while len(raw) < chunk_bytes and _listening and _running:
                piece = rec_proc.stdout.read(chunk_bytes - len(raw))
                if not piece:
                    break
                raw += piece

            if len(raw) < chunk_bytes // 2:
                break

            _set_status("Analyzing...")
            n_samples = len(raw) // 2
            samples_16k = np.array(
                struct.unpack(f"<{n_samples}h", raw),
                dtype=np.float32) / 32768.0

            audio_48k = _resample_16k_to_48k(samples_16k)

            results = _analyze_chunk(audio_48k)
            if results:
                with _detections_lock:
                    for r in results:
                        _detections.insert(0, r)
                    if len(_detections) > 50:
                        _detections[:] = _detections[:50]
                for r in results:
                    print(f"[{r['time']}] {r['species']} ({r['scientific']}) "
                          f"{int(r['confidence'] * 100)}%", flush=True)
                _save_detections(results)
    except Exception:
        pass
    finally:
        if rec_proc.poll() is None:
            rec_proc.kill()
        _disable_mic()
        _listening = False
        _set_status("Stopped")


def _save_detections(results):
    os.makedirs(LOOT_DIR, exist_ok=True)
    log_path = os.path.join(LOOT_DIR, f"detections_{datetime.now().strftime('%Y%m%d')}.json")
    entries = []
    if os.path.isfile(log_path):
        try:
            with open(log_path, "r") as f:
                entries = json.load(f)
        except Exception:
            entries = []
    for r in results:
        entries.append({
            "species": r["species"],
            "scientific": r["scientific"],
            "confidence": r["confidence"],
            "time": r["time"],
            "date": datetime.now().strftime("%Y-%m-%d"),
        })
    try:
        with open(log_path, "w") as f:
            json.dump(entries, f, indent=2)
    except Exception:
        pass


MODEL_BUNDLE_URL = "https://zenodo.org/records/15050749/files/BirdNET_v2.4_tflite_fp16.zip"
MODEL_BUNDLE_SIZE = 53_025_528
MODEL_BUNDLE_SHA256 = "55369cc3804b3b23b877375f2b7d6bea2dbe95879a1c9d31cb79d377dcb4e6da"
MODEL_SIZE = 25_932_528
MODEL_SHA256 = "5c64ba3ffab264ccbfafe784896392051a86be63b0cc507e7683db7df114546b"
MODEL_MEMBER = "audio-model-fp16.tflite"
LABEL_COUNT = 6522
LANG_MEMBERS = {lang: ("en_us" if lang == "en" else "zh" if lang == "zh_CN" else lang) for lang in AVAILABLE_LANGS}
DOWNLOAD_STALL_SECONDS = 60
DOWNLOAD_TOTAL_SECONDS = 300
DOWNLOAD_REPORT_SECONDS = 10


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _valid_model(path=None):
    path = path or MODEL_PATH
    try:
        if os.path.getsize(path) != MODEL_SIZE or _sha256(path) != MODEL_SHA256:
            return False
        with open(path, "rb") as handle:
            return handle.read(8)[4:8] == b"TFL3"
    except OSError:
        return False


def _valid_labels(path=None):
    path = path or LABELS_PATH
    try:
        with open(path, "r", encoding="utf-8") as handle:
            labels = [line.strip() for line in handle if line.strip()]
        return len(labels) == LABEL_COUNT and all("_" in label for label in labels)
    except (OSError, UnicodeError):
        return False


def _valid_model_bundle():
    return (
        _valid_model()
        and _valid_labels()
        and all(os.path.isfile(os.path.join(L18N_DIR, f"labels_{lang}.json")) for lang in AVAILABLE_LANGS)
    )


def _mapping_from_labels(content):
    mapping = {}
    for line in content.decode("utf-8").splitlines():
        parts = line.strip().split("_", 1)
        if len(parts) == 2:
            mapping[parts[0]] = parts[1]
    return mapping


def _stop_process(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _download_model_archive(archive_path):
    """Download with visible progress and bounded total/inactivity waits."""
    process = subprocess.Popen(
        [
            "wget", "--no-verbose", "--dns-timeout=15", "--connect-timeout=15",
            "--read-timeout=30", "--tries=3", "-O", archive_path,
            MODEL_BUNDLE_URL,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    started = time.monotonic()
    last_data = started
    last_report = started - DOWNLOAD_REPORT_SECONDS
    previous_size = 0
    failure = ""
    try:
        while process.poll() is None:
            now = time.monotonic()
            try:
                size = os.path.getsize(archive_path)
            except OSError:
                size = 0
            if size != previous_size:
                previous_size = size
                last_data = now
            if now - last_report >= DOWNLOAD_REPORT_SECONDS:
                percent = min(100.0, size * 100.0 / MODEL_BUNDLE_SIZE)
                idle = int(now - last_data)
                print(
                    f"BirdNET download: {size / 1_048_576:.1f}/"
                    f"{MODEL_BUNDLE_SIZE / 1_048_576:.1f} MiB "
                    f"({percent:.1f}%) · no new data for {idle}s",
                    flush=True,
                )
                last_report = now
            if not _running:
                failure = "cancelled by operator"
                _stop_process(process)
                break
            if now - last_data >= DOWNLOAD_STALL_SECONDS:
                failure = f"no data received for {DOWNLOAD_STALL_SECONDS}s"
                _stop_process(process)
                break
            if now - started >= DOWNLOAD_TOTAL_SECONDS:
                failure = f"download exceeded {DOWNLOAD_TOTAL_SECONDS}s"
                _stop_process(process)
                break
            time.sleep(1)
        _stdout, stderr = process.communicate(timeout=5)
    except (OSError, subprocess.SubprocessError) as error:
        _stop_process(process)
        return False, str(error)

    if failure:
        return False, failure
    if process.returncode != 0:
        detail = (stderr or "").strip().splitlines()
        return False, detail[-1] if detail else f"wget exit {process.returncode}"
    print(
        f"BirdNET download complete: {os.path.getsize(archive_path) / 1_048_576:.1f} MiB; verifying SHA-256...",
        flush=True,
    )
    return True, ""


def _install_model_bundle():
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(L18N_DIR, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix=".birdnet-download-", dir=MODEL_DIR) as temporary:
            archive_path = os.path.join(temporary, "birdnet.zip")
            downloaded, detail = _download_model_archive(archive_path)
            if not downloaded:
                print(f"Download failed: BirdNET model bundle · {detail}", flush=True)
                return False
            if os.path.getsize(archive_path) != MODEL_BUNDLE_SIZE or _sha256(archive_path) != MODEL_BUNDLE_SHA256:
                print("Download failed: BirdNET model bundle did not pass size/checksum validation.", flush=True)
                return False

            with zipfile.ZipFile(archive_path) as archive:
                if archive.testzip() is not None:
                    print("Download failed: BirdNET model bundle is corrupt.", flush=True)
                    return False
                model_tmp = os.path.join(temporary, "model.tflite")
                with archive.open(MODEL_MEMBER) as source, open(model_tmp, "wb") as destination:
                    shutil.copyfileobj(source, destination)
                if not _valid_model(model_tmp):
                    print("Download failed: extracted BirdNET model did not pass validation.", flush=True)
                    return False

                labels_by_lang = {}
                for lang, archive_lang in LANG_MEMBERS.items():
                    member = f"labels/{archive_lang}.txt"
                    labels_by_lang[lang] = archive.read(member)
                labels_tmp = os.path.join(temporary, "labels.txt")
                with open(labels_tmp, "wb") as handle:
                    handle.write(labels_by_lang["en"])
                if not _valid_labels(labels_tmp):
                    print("Download failed: BirdNET labels did not pass validation.", flush=True)
                    return False

                for lang, content in labels_by_lang.items():
                    mapping = _mapping_from_labels(content)
                    if len(mapping) < LABEL_COUNT - 1:
                        print(f"Download failed: BirdNET {lang} labels are incomplete.", flush=True)
                        return False
                    lang_tmp = os.path.join(temporary, f"labels_{lang}.json")
                    with open(lang_tmp, "w", encoding="utf-8") as handle:
                        json.dump(mapping, handle, ensure_ascii=False)
                    os.replace(lang_tmp, os.path.join(L18N_DIR, f"labels_{lang}.json"))

                os.replace(labels_tmp, LABELS_PATH)
                os.replace(model_tmp, MODEL_PATH)
    except (OSError, KeyError, zipfile.BadZipFile, subprocess.TimeoutExpired) as error:
        print(f"Download failed: BirdNET model bundle · {error}", flush=True)
        return False
    print("BirdNET model and labels installed and verified.", flush=True)
    return True


def _ensure_deps():
    try:
        from ai_edge_litert.interpreter import Interpreter  # noqa: F401
        return True
    except ImportError:
        pass
    print("Installing TFLite...", flush=True)
    r = subprocess.run(
        ["pip3", "install", "--break-system-packages", "ai-edge-litert"],
        capture_output=True, timeout=300)
    if r.returncode != 0:
        print("Install failed: ai-edge-litert", flush=True)
        return False
    return True


def _ensure_model():
    if _valid_model_bundle():
        return True
    print("Downloading verified BirdNET model bundle (51MB)...", flush=True)
    return _install_model_bundle() and _valid_model_bundle()


def _ensure_lang_labels(lang):
    path = os.path.join(L18N_DIR, f"labels_{lang}.json")
    return os.path.isfile(path)


def main():
    global _running, _listening, _lang

    duration = None
    if len(sys.argv) > 1:
        try:
            duration = float(sys.argv[1])
            if duration <= 0:
                raise ValueError
        except ValueError:
            print(f"Usage: {os.path.basename(__file__)} [duration_seconds] [lang]", flush=True)
            print(f"  lang: one of {', '.join(AVAILABLE_LANGS)}", flush=True)
            sys.exit(1)

    _load_settings()
    if len(sys.argv) > 2:
        requested_lang = sys.argv[2]
        if requested_lang not in AVAILABLE_LANGS:
            print(f"Unknown language '{requested_lang}'. Available: {', '.join(AVAILABLE_LANGS)}", flush=True)
            sys.exit(1)
        _lang = requested_lang
        _save_settings()

    _detect_alsa_dev()

    if not _ensure_deps():
        return 1

    print("Checking model...", flush=True)
    if not _ensure_model():
        return 1

    print("Loading model...", flush=True)
    if not _load_model():
        return 1

    _ensure_lang_labels(_lang)
    _load_lang_map()

    print(f"Listening for birds (lang={_lang})."
          + (f" Duration: {duration:.0f}s." if duration else " Press Ctrl-C to stop."),
          flush=True)

    _listening = True
    listen_thread = threading.Thread(target=_listen_thread, daemon=True)
    listen_thread.start()

    start = time.time()
    last_report = 0.0
    while _running and _listening:
        if duration is not None and time.time() - start >= duration:
            break
        time.sleep(0.5)
        elapsed = time.time() - start
        if elapsed - last_report >= 5:
            last_report = elapsed
            with _detections_lock:
                n = len(_detections)
            print(f"[{int(elapsed)}s] status={_get_status()} total_detections={n}", flush=True)

    _listening = False
    _running = False
    listen_thread.join(timeout=5)
    _disable_mic()

    with _detections_lock:
        dets = list(_detections)
    print(f"\n=== Summary: {len(dets)} detection(s) ===", flush=True)
    for d in dets:
        print(f"  {d['time']}  {d['species']} ({d['scientific']})  {int(d['confidence'] * 100)}%", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
