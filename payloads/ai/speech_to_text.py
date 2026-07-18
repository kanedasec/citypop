#!/usr/bin/env python3
# @name: Speech to Text
# @desc: Offline speech recognition using Vosk.
# @category: ai
# @danger: false
# @active: true
"""
RaspyJack Payload -- Speech to Text
=====================================
Author: 7h30th3r0n3

Offline speech recognition using Vosk.
Records from microphone and transcribes in real-time.
Supports multiple languages.

Usage:
  speech_to_text.py [duration_seconds] [lang]

  duration_seconds  How long to record, in seconds. Omit to record until
                     Ctrl-C is pressed.
  lang              Language code to transcribe in. One of: en, fr, de,
                     es, it. Defaults to "fr". The model is downloaded
                     automatically the first time a language is used.

Transcribed lines are printed as they are recognized. On exit (including
after Ctrl-C) the full transcript is saved under the loot directory and
its path is printed.
"""

import os
import sys
import time
import signal
import subprocess
import threading
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._audio_helper import get_audio_card, get_alsa_dev

MODEL_DIR = "/root/Raspyjack/models/vosk"
LOOT_DIR = "/root/Raspyjack/loot/AI/transcripts"
SAMPLE_RATE = 16000

LANGUAGES = {
    "en": {"name": "English", "model": "vosk-model-small-en-us-0.15", "url": "https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip"},
    "fr": {"name": "Francais", "model": "vosk-model-small-fr-0.22", "url": "https://alphacephei.com/vosk/models/vosk-model-small-fr-0.22.zip"},
    "de": {"name": "Deutsch", "model": "vosk-model-small-de-0.15", "url": "https://alphacephei.com/vosk/models/vosk-model-small-de-0.15.zip"},
    "es": {"name": "Espanol", "model": "vosk-model-small-es-0.42", "url": "https://alphacephei.com/vosk/models/vosk-model-small-es-0.42.zip"},
    "it": {"name": "Italiano", "model": "vosk-model-small-it-0.22", "url": "https://alphacephei.com/vosk/models/vosk-model-small-it-0.22.zip"},
}

_running = True
_recording = False
_lang = "fr"
_transcript = []
_partial = ""
_lock = threading.Lock()
_alsa_dev = "default"


def _sig(s, f):
    global _running, _recording
    _running = False
    _recording = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


def _ensure_vosk():
    try:
        import vosk  # noqa: F401
        return True
    except ImportError:
        pass
    print("Installing vosk...", flush=True)
    r = subprocess.run(
        ["pip3", "install", "--break-system-packages", "vosk"],
        capture_output=True, timeout=300)
    return r.returncode == 0


def _ensure_model(lang):
    """Download and extract Vosk model if missing."""
    if lang not in LANGUAGES:
        return None
    info = LANGUAGES[lang]
    model_path = os.path.join(MODEL_DIR, info["model"])
    if os.path.isdir(model_path):
        return model_path

    os.makedirs(MODEL_DIR, exist_ok=True)
    zip_path = os.path.join(MODEL_DIR, f"{info['model']}.zip")

    print(f"Downloading {info['name']} model...", flush=True)
    r = subprocess.run(
        ["wget", "--no-check-certificate", "-q", "-O", zip_path, info["url"]],
        capture_output=True, timeout=300)
    if r.returncode != 0:
        print("Download failed!", flush=True)
        return None

    print("Extracting model...", flush=True)
    subprocess.run(["unzip", "-q", "-o", zip_path, "-d", MODEL_DIR],
                   capture_output=True, timeout=120)
    try:
        os.remove(zip_path)
    except Exception:
        pass

    return model_path if os.path.isdir(model_path) else None


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
    except Exception:
        pass


_vosk_model = None
_vosk_rec = None


def _load_vosk_model(model_path):
    global _vosk_model, _vosk_rec
    import vosk
    vosk.SetLogLevel(-1)
    _vosk_model = vosk.Model(model_path)
    _vosk_rec = vosk.KaldiRecognizer(_vosk_model, SAMPLE_RATE)


def _recognition_thread(model_path):
    """Record audio and run Vosk recognition."""
    global _recording, _partial, _vosk_rec
    import vosk

    if _vosk_rec is None:
        _load_vosk_model(model_path)

    _vosk_rec = vosk.KaldiRecognizer(_vosk_model, SAMPLE_RATE)

    _enable_mic()
    time.sleep(0.5)

    proc = subprocess.Popen(
        ["arecord", "-D", _alsa_dev, "-f", "S16_LE", "-r", str(SAMPLE_RATE),
         "-c", "1", "-t", "raw"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    chunk_size = SAMPLE_RATE * 2 // 5
    try:
        while _recording and _running:
            raw = proc.stdout.read(chunk_size)
            if not raw:
                break

            if _vosk_rec.AcceptWaveform(raw):
                result = json.loads(_vosk_rec.Result())
                text = result.get("text", "").strip()
                if text:
                    with _lock:
                        _transcript.append(text)
                        _partial = ""
                    print(f"> {text}", flush=True)
            else:
                partial = json.loads(_vosk_rec.PartialResult())
                with _lock:
                    _partial = partial.get("partial", "")
    except Exception:
        pass
    finally:
        proc.kill()
        _disable_mic()
        final = json.loads(_vosk_rec.FinalResult())
        text = final.get("text", "").strip()
        if text:
            with _lock:
                _transcript.append(text)
            print(f"> {text}", flush=True)
        _recording = False


def _save_transcript():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"transcript_{ts}.txt")
    with _lock:
        text = "\n".join(_transcript)
    with open(path, "w") as f:
        f.write(text)
    return path


def main():
    global _running, _recording, _lang

    duration = None
    if len(sys.argv) > 1:
        try:
            duration = float(sys.argv[1])
            if duration <= 0:
                raise ValueError
        except ValueError:
            print(f"Usage: {os.path.basename(__file__)} [duration_seconds] [lang]", flush=True)
            print(f"  lang: one of {', '.join(LANGUAGES)}", flush=True)
            sys.exit(1)

    if len(sys.argv) > 2:
        requested_lang = sys.argv[2]
        if requested_lang not in LANGUAGES:
            print(f"Unknown language '{requested_lang}'. Available: {', '.join(LANGUAGES)}", flush=True)
            sys.exit(1)
        _lang = requested_lang

    _detect_alsa_dev()

    if not _ensure_vosk():
        print("Vosk install failed!", flush=True)
        return 1

    model_path = _ensure_model(_lang)
    if not model_path:
        return 1

    print("Loading model...", flush=True)
    _load_vosk_model(model_path)

    print(f"Recording ({LANGUAGES[_lang]['name']})."
          + (f" Duration: {duration:.0f}s." if duration else " Press Ctrl-C to stop."),
          flush=True)

    _recording = True
    rec_thread = threading.Thread(target=_recognition_thread, args=(model_path,), daemon=True)
    rec_thread.start()

    start = time.time()
    last_report = 0.0
    while _running and _recording:
        if duration is not None and time.time() - start >= duration:
            break
        time.sleep(0.5)
        elapsed = time.time() - start
        if elapsed - last_report >= 5:
            last_report = elapsed
            with _lock:
                n = len(_transcript)
            print(f"[{int(elapsed)}s] recording... {n} line(s) so far", flush=True)

    _recording = False
    _running = False
    rec_thread.join(timeout=3)
    _disable_mic()

    with _lock:
        has_transcript = bool(_transcript)

    print("\n=== Transcript ===", flush=True)
    with _lock:
        for line in _transcript:
            print(f"  {line}", flush=True)

    if has_transcript:
        path = _save_transcript()
        print(f"\nSaved to {path}", flush=True)
    else:
        print("\nNothing transcribed.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
