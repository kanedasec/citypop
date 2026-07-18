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
    nmap iw iproute2 iputils-ping iperf3 whois curl openssl wget unzip usbutils avahi-utils
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
    install -d "$INSTALL_DIR"
    rm -rf "$INSTALL_DIR/.venv"
    # payloads/ is a deployed catalog, not runtime state. Replace it instead
    # of overlaying files so payloads removed or renamed in the repository do
    # not survive as stale, disabled cards in the web interface. Loot and the
    # generated config remain untouched.
    rm -rf "$INSTALL_DIR/payloads"
    # Stream only runtime files into /opt. Avoid temporarily duplicating a
    # potentially huge venv or copying Git history, caches, source migration
    # material, and collected loot on a small Pi SD card.
    tar -C "$BASE" \
      --exclude='./.venv' --exclude='./.git' --exclude='./__pycache__' \
      --exclude='*/__pycache__' --exclude='./misc' --exclude='./tools' \
      --exclude='./loot' -cf - . | tar -C "$INSTALL_DIR" -xf -
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
"$VENV_PYTHON" -m pip install --no-cache-dir -r "$INSTALL_DIR/requirements-core.txt"

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

required = ("flask", "flask_socketio", "simple_websocket")
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
if c.get('auth_token') in ('CHANGE_ME_ON_INSTALL',''): c['auth_token']=secrets.token_urlsafe(24)
json.dump(c,open(p,'w'),indent=2); open(p,'a').write('\n'); print('City Pop token:',c['auth_token'])
PY
if [ "$(id -u)" = 0 ]; then
  sed 's/^User=.*/User=root/' "$INSTALL_DIR/city-pop.service" > /etc/systemd/system/city-pop.service
  systemctl daemon-reload
  systemctl enable city-pop.service
  systemctl restart city-pop.service
  echo "City Pop service enabled and started as root"
else
  echo "The venv is ready, but no server was started."
  echo "Run now: $INSTALL_DIR/.venv/bin/python $INSTALL_DIR/app.py"
  echo "For boot startup, rerun: sudo $BASE/install.sh"
fi
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$HOST_IP" ] || HOST_IP="192.168.43.254"
echo "URL: http://${HOST_IP}:8080"
[ "$(id -u)" = 0 ] && echo "Token file: $INSTALL_DIR/config.json" || echo "Token file: $BASE/config.json"
