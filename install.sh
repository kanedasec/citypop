#!/usr/bin/env bash
set -euo pipefail
BASE="$(cd "$(dirname "$0")" && pwd)"
ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
OS_ID="$(. /etc/os-release 2>/dev/null && printf '%s' "${ID:-unknown}")"
IS_ARM=false
case "$ARCH" in
  arm64|armhf|aarch64|armv7l) IS_ARM=true ;;
esac

if $IS_ARM; then
  echo "ARM target detected ($ARCH, OS: $OS_ID); enabling Pi Zero 2 W-friendly dependency installation."
  if [ "$OS_ID" = "kali" ]; then
    echo "Kali ARM Pi-Tail environment detected (phone-controlled, no RaspyJack UI drivers)."
  fi
  if [ -r /proc/meminfo ]; then
    MEM_KB="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
    if [ -n "$MEM_KB" ] && [ "$MEM_KB" -lt 700000 ]; then
      echo "Low-memory device detected; heavy Python packages will use OS binaries instead of source builds."
    fi
  fi
fi

if [ "$(id -u)" = 0 ]; then
  INSTALL_DIR=/opt/city-pop

  # Payloads also call native radio, networking, GPS, audio, and hardware
  # utilities. Package availability varies between Debian/Raspberry Pi OS
  # releases, so install every package that exists in the configured repos.
  # A broken unrelated third-party repository must not prevent City Pop from
  # using the indexes that APT did refresh successfully. apt-get install below
  # will still fail normally if a required package cannot actually be fetched.
  if ! apt-get update; then
    echo "WARNING: apt-get update reported one or more repository errors." >&2
    echo "Continuing with the package indexes that are available." >&2
  fi
  SYSTEM_PACKAGES=(
    python3 python3-venv python3-dev python3-rpi.gpio python3-gpiozero
    python3-lgpio python3-spidev python3-smbus gpiod
    python3-soapysdr build-essential pkg-config
    python3-numpy python3-scipy python3-sklearn python3-opencv python3-pil
    python3-turbojpeg
    python3-cryptography python3-serial python3-requests python3-scapy
    python3-bleak python3-pyudev python3-pyzbar python3-qrcode python3-evdev
    libbluetooth-dev libffi-dev libglib2.0-dev libnfc-dev libusb-1.0-0-dev
    nmap iw iproute2 iputils-ping iperf3 whois curl openssl nginx wget unzip usbutils avahi-utils
    bluez wireless-tools rfkill aircrack-ng hostapd dnsmasq
    gpsd gpsd-clients rtl-sdr rtl-433 multimon-ng i2c-tools alsa-utils
    modemmanager sshpass hydra john hashcat gobuster reaver hcxtools hping3 dsniff
    tcpdump tshark tcpreplay ethtool bridge-utils vlan macchanger smbclient ldap-utils
    udisks2
    snmp ffmpeg zbar-tools libturbojpeg0
  )
  AVAILABLE_PACKAGES=()
  for package in "${SYSTEM_PACKAGES[@]}"; do
    if apt-cache show "$package" >/dev/null 2>&1; then
      AVAILABLE_PACKAGES+=("$package")
    else
      echo "Skipping unavailable system package: $package"
    fi
  done
  apt-get install -y "${AVAILABLE_PACKAGES[@]}"
  if [ "$BASE" != "$INSTALL_DIR" ]; then
    for catalog in payloads templates; do
      if [ ! -d "$BASE/$catalog" ]; then
        echo "Refusing to deploy: repository catalog is missing: $BASE/$catalog" >&2
        exit 1
      fi
    done
    install -d "$INSTALL_DIR"
    rm -rf "$INSTALL_DIR/.venv"
    # payloads/ and templates/ are deployed catalogs, not runtime state.
    # Replace them instead of overlaying files so entries removed or renamed
    # in the repository do not survive in an installation. Loot and the
    # generated config remain untouched.
    rm -rf "$INSTALL_DIR/payloads"
    rm -rf "$INSTALL_DIR/templates"
    # Stream only runtime files into /opt. Avoid temporarily duplicating a
    # potentially huge venv or copying Git history, caches, source migration
    # material, and collected loot on a small Pi SD card.
    tar -C "$BASE" \
      --exclude='./.venv' --exclude='./.git' --exclude='./__pycache__' \
      --exclude='*/__pycache__' --exclude='./misc' --exclude='./tools' \
      --exclude='./loot' --exclude='./state' --exclude='./config.json' \
      -cf - . | tar -C "$INSTALL_DIR" -xf -
  fi
else
  INSTALL_DIR="$BASE"
fi

# System site packages expose hardware bindings supplied by Raspberry Pi OS
# (notably SoapySDR, SMBus, and GPIO) while pip packages remain isolated in
# City Pop's own environment.
python3 -m venv --system-site-packages "$INSTALL_DIR/.venv"
VENV_PYTHON="$INSTALL_DIR/.venv/bin/python"
"$VENV_PYTHON" -m pip install --upgrade --no-cache-dir pip setuptools wheel
"$VENV_PYTHON" -m pip install --no-cache-dir --require-hashes \
  -r "$INSTALL_DIR/requirements-core.lock"

if $IS_ARM; then
  # Debian-family ARM distributions, including Kali and Raspberry Pi OS,
  # supply these large/native modules as binary packages. Asking pip for
  # differently named distributions (notably
  # opencv-python-headless) would compile them locally on armhf and can exhaust
  # a Zero 2 W's 512 MB RAM. Keep the remaining lightweight/ARM-wheel packages
  # in the City Pop venv.
  PI_REQUIREMENTS="$(mktemp)"
  trap 'rm -f "$PI_REQUIREMENTS"' EXIT
  # Repair previous installs that allowed LiteRT/OpenCV to place a NumPy 2.x
  # stack inside the venv. Once removed, --system-site-packages exposes Kali's
  # mutually compatible NumPy/SciPy/scikit-learn/OpenCV packages again.
  "$VENV_PYTHON" -m pip uninstall -y numpy opencv-python opencv-python-headless ai-edge-litert >/dev/null 2>&1 || true
  awk '
    BEGIN { IGNORECASE=1 }
    /^[[:space:]]*(Pillow|PyTurboJPEG|ai-edge-litert|cryptography|numpy|opencv-python-headless|pyserial|pyudev|pyzbar|qrcode|requests|scapy|scikit-learn|evdev)([<>=;[:space:]\[]|$)/ { next }
    { print }
  ' "$INSTALL_DIR/requirements.txt" > "$PI_REQUIREMENTS"
  if [ "$ARCH" = "armhf" ] || [ "$ARCH" = "armv7l" ]; then
    # Vosk and LiteRT currently publish ARM64 wheels, but not dependable
    # armhf wheels. Do not attempt a large source build on a 512 MB board.
    sed -i '/^[[:space:]]*vosk\([<>=;[:space:]]\|$\)/Id' "$PI_REQUIREMENTS"
    echo "NOTE: AI speech/inference payloads require 64-bit Raspberry Pi OS."
  fi
  if ! "$VENV_PYTHON" -m pip install --prefer-binary --no-cache-dir \
      -c "$INSTALL_DIR/constraints-arm.txt" -r "$PI_REQUIREMENTS"; then
    echo "WARNING: One or more optional payload packages were unavailable for $ARCH." >&2
    echo "The City Pop web core is installed; affected payloads will report their missing dependency." >&2
  fi
  # PyTurboJPEG is pure Python, but its package metadata asks pip to resolve
  # NumPy. On armhf/Python 3.13 that resolution downloads the NumPy source and
  # starts a multi-hour local compile. Kali's binary python3-numpy is already
  # visible through --system-site-packages, so install only this package.
  if ! "$VENV_PYTHON" -m pip install --no-deps --prefer-binary --no-cache-dir PyTurboJPEG; then
    echo "WARNING: PyTurboJPEG is unavailable; camera payloads can still use Kali's OpenCV package." >&2
  fi
else
  "$VENV_PYTHON" -m pip install --prefer-binary --no-cache-dir -r "$INSTALL_DIR/requirements.txt"
fi

"$VENV_PYTHON" - <<'PY'
import importlib

required = ("flask", "flask_socketio", "gunicorn", "simple_websocket")
for module in required:
    importlib.import_module(module)
print("City Pop web runtime imports: OK")

optional = (
    "PIL", "bleak", "cryptography", "cv2", "evdev", "gpsd", "nfc",
    "numpy", "pyftpdlib", "pyudev", "pyzbar", "qrcode", "requests",
    "scapy", "serial", "sklearn", "smbus2", "vosk",
)
missing = []
for module in optional:
    try:
        importlib.import_module(module)
    except Exception:
        missing.append(module)
if missing:
    print("Optional payload imports unavailable: " + ", ".join(missing))
else:
    print("Optional payload imports: OK")
PY

if [ ! -f "$INSTALL_DIR/config.json" ]; then
  cp "$INSTALL_DIR/config.example.json" "$INSTALL_DIR/config.json"
fi
"$INSTALL_DIR/.venv/bin/python" - "$INSTALL_DIR/config.json" <<'PY'
import json,secrets,sys
p=sys.argv[1]; c=json.load(open(p));
c.pop('auth_token', None)
if c.get('session_secret') in ('CHANGE_ME_ON_INSTALL','',None): c['session_secret']=secrets.token_urlsafe(48)
c.setdefault('tls', {'enabled': True, 'certfile': 'state/tls/cert.pem', 'keyfile': 'state/tls/key.pem'})
json.dump(c,open(p,'w'),indent=2); open(p,'a').write('\n')
print('Authentication: create the administrator account on first access.')
PY
install -d -m 700 "$INSTALL_DIR/state" "$INSTALL_DIR/loot"
chmod 600 "$INSTALL_DIR/config.json"
chmod 700 "$INSTALL_DIR/state" "$INSTALL_DIR/loot"

SOCKETIO_ASSET="$INSTALL_DIR/static/vendor/socket.io.min.js"
SOCKETIO_SHA256="b0e735814f8dcfecd6cdb8a7ce95a297a7e1e5f2727a29e6f5901801d52fa0c5"
if [ ! -f "$SOCKETIO_ASSET" ] || \
   [ "$(sha256sum "$SOCKETIO_ASSET" | awk '{print $1}')" != "$SOCKETIO_SHA256" ]; then
  echo "Refusing to install: bundled Socket.IO asset failed SHA-256 verification." >&2
  exit 1
fi

PAIRING_CODE="$("$VENV_PYTHON" - "$INSTALL_DIR/state/auth.json" "$INSTALL_DIR/state/setup.json" <<'PY'
import json
import os
import secrets
import sys
from pathlib import Path
from werkzeug.security import generate_password_hash

auth_path, setup_path = map(Path, sys.argv[1:])
if auth_path.is_file():
    setup_path.unlink(missing_ok=True)
elif not setup_path.is_file():
    code = "-".join(secrets.token_hex(3).upper() for _ in range(3))
    setup_path.write_text(json.dumps({
        "code_hash": generate_password_hash(code, method="scrypt"),
    }, indent=2) + "\n", encoding="utf-8")
    os.chmod(setup_path, 0o600)
    print(code)
PY
)"
if [ -n "$PAIRING_CODE" ]; then
  echo "ONE-TIME FIRST-ACCESS PAIRING CODE: $PAIRING_CODE"
  echo "This code is shown once and expires when the administrator account is created."
elif [ ! -f "$INSTALL_DIR/state/auth.json" ]; then
  echo "First-access pairing is pending. The existing one-time code remains valid."
  echo "If it was lost, remove state/setup.json over SSH and rerun install.sh."
fi
CITYPOP_PORT="$($VENV_PYTHON -c 'import json,sys; print(int(json.load(open(sys.argv[1]))["port"]))' "$INSTALL_DIR/config.json")"
TLS_DIR="$INSTALL_DIR/state/tls"
install -d -m 700 "$TLS_DIR"
if [ ! -s "$TLS_DIR/cert.pem" ] || [ ! -s "$TLS_DIR/key.pem" ]; then
  TLS_SAN="DNS:city-pop.local,DNS:localhost,IP:127.0.0.1"
  while IFS= read -r address; do
    [ -n "$address" ] && TLS_SAN="$TLS_SAN,IP:$address"
  done <<EOF
$(ip -o -4 addr show scope global 2>/dev/null | awk '{split($4, address, "/"); print address[1]}')
EOF
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 825 \
    -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" \
    -subj "/CN=city-pop.local/O=City Pop Authorized Lab" \
    -addext "subjectAltName=$TLS_SAN"
  chmod 600 "$TLS_DIR/key.pem"
  chmod 644 "$TLS_DIR/cert.pem"
fi
if [ "$(id -u)" = 0 ]; then
  NGINX_DEFAULT=/etc/nginx/sites-enabled/default
  if [ -L "$NGINX_DEFAULT" ] && \
      [ "$(readlink -f "$NGINX_DEFAULT")" = "/etc/nginx/sites-available/default" ]; then
    unlink "$NGINX_DEFAULT"
    echo "Disabled nginx's packaged default site so ports 80/443 remain available to payload-managed services."
  fi
  sed \
    -e "s|__CITYPOP_PORT__|$CITYPOP_PORT|g" \
    -e "s|__CITYPOP_CERT__|$TLS_DIR/cert.pem|g" \
    -e "s|__CITYPOP_KEY__|$TLS_DIR/key.pem|g" \
    "$INSTALL_DIR/city-pop.nginx.conf" > /etc/nginx/conf.d/city-pop.conf
  nginx -t
  systemctl stop city-pop.service 2>/dev/null || true
  systemctl enable nginx.service
  systemctl restart nginx.service
  sed 's/^User=.*/User=root/' "$INSTALL_DIR/city-pop.service" > /etc/systemd/system/city-pop.service
  systemctl daemon-reload
  systemctl enable city-pop.service
  systemctl restart city-pop.service
  echo "City Pop enabled: nginx TLS on port $CITYPOP_PORT → Gunicorn on 127.0.0.1:18080"
else
  echo "The venv is ready, but no server was started."
  echo "Run now: $INSTALL_DIR/.venv/bin/python $INSTALL_DIR/app.py"
  echo "For boot startup, rerun: sudo $BASE/install.sh"
fi
PRIMARY_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}')"
ALL_IPS="$(ip -o -4 addr show scope global 2>/dev/null | awk '{split($4, address, "/"); print address[1]}')"
if [ -n "$PRIMARY_IP" ]; then
  echo "Primary URL: https://${PRIMARY_IP}:${CITYPOP_PORT}"
fi
if [ -n "$ALL_IPS" ]; then
  echo "Available URLs:"
  while IFS= read -r address; do
    [ -n "$address" ] && echo "  https://${address}:${CITYPOP_PORT}"
  done <<EOF
$ALL_IPS
EOF
else
  echo "URL: https://192.168.43.254:${CITYPOP_PORT} (fallback; verify the Pi address with: ip -4 addr)"
fi
echo "Authentication: open City Pop to create or use the local administrator account."
echo "Internal session-signing secret: stored privately in $INSTALL_DIR/config.json (not a login credential)."
