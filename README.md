<p align="center">
  <img src="https://img.shields.io/badge/platform-Kali%20Pi--Tail-557C94?style=flat-square&logo=kali-linux&logoColor=white" alt="Platform: Kali Pi-Tail">
  <img src="https://img.shields.io/badge/hardware-Raspberry%20Pi%20Zero%202%20W-C51A4A?style=flat-square&logo=raspberry-pi&logoColor=white" alt="Hardware: Raspberry Pi Zero 2 W">
  <img src="https://img.shields.io/badge/code-Python%203-FFD43B?style=flat-square&logo=python&logoColor=3776AB" alt="Code: Python 3">
  <img src="https://img.shields.io/badge/interface-phone--first%20web-21E6FF?style=flat-square" alt="Interface: phone-first web">
  <img src="https://img.shields.io/badge/payloads-161-FF2E88?style=flat-square" alt="Payloads: 161">
  <img src="https://img.shields.io/badge/license-MIT-3DFFB0?style=flat-square" alt="License: MIT">
  <img src="https://img.shields.io/badge/usage-authorized%20testing%20only-3DFFB0?style=flat-square" alt="Usage: authorized testing only">
</p>

<p align="center">
  <img src="static/citypop-icon.png" alt="City Pop icon" width="700">
</p>

# CITY POP // Pi-Tail Deck



> A phone-first field interface for Kali Pi-Tail—inspired by RaspyJack, rebuilt for a Raspberry Pi Zero 2 W that lives in your pocket instead of behind an LCD HAT.

```text
       ┌──────────────────────────────┐
       │  CITY POP // PI-TAIL DECK   │
       │  PHONE ── USB ── ZERO 2 W   │
       │  161 WEB-NATIVE PAYLOADS    │
       └──────────────────────────────┘
```

City Pop turns a Kali Pi-Tail into a compact, browser-operated security deck. The phone supplies power and tethering, displays the interface, stores the access token, and provides the primary controls. The Pi runs the tools, talks to attached radios and boards, and saves results into a central loot directory.

This is an independent web adaptation of [7h30th3r0n3/Raspyjack](https://github.com/7h30th3r0n3/Raspyjack). RaspyJack is an LCD-driven portable offensive toolkit; City Pop preserves much of its payload spirit while replacing joystick, button, and display flows with phone-friendly forms and live web prompts. It is not an official RaspyJack or Kali Linux project.

## Why Pi-Tail?

[Kali Pi-Tail for the Raspberry Pi Zero 2 W](https://www.kali.org/docs/arm/raspberry-pi-zero-2-w-pi-tail/) is designed around smartphone tethering. Kali describes the phone as the Pi-Tail's power supply, screen, keyboard, and mouse. City Pop takes that idea literally: no Waveshare LCD is required, and the web app becomes the device interface.

The Zero 2 W has only 512 MB of RAM, so installation favors Kali/Debian binary packages for heavy native dependencies and uses a project virtual environment for the web runtime and lighter Python packages.

## Highlights

- Phone-first, responsive web interface
- Token-authenticated HTTP and WebSocket control
- 161 active payloads across Wi-Fi, Bluetooth, network, NFC/RFID, SDR, hardware, reconnaissance, credentials, USB, AI, and utility categories
- Structured launch forms and dynamic adapter/target selectors
- Live output, cancellation, and runtime input prompts
- Engagement name, date, and authorized-scope tracking in the browser
- Central loot browser with preview and download support
- Isolated Python environment at `/opt/city-pop/.venv`
- Hardware bindings inherited from Kali through `--system-site-packages`
- Root systemd service for payloads that require radio, packet, GPIO, or device access
- ARM-aware dependency handling for the Pi Zero 2 W

## Intended build

### Required

- Raspberry Pi Zero 2 W
- A microSD card with the official Kali Pi-Tail image
- A smartphone with USB OTG support
- A data-capable USB cable and appropriate OTG adapter
- Internet access during installation

### Strongly recommended

- A powered OTG hub when using USB radios, SDRs, storage, or multiple adapters
- A separate monitor-mode/injection-capable Wi-Fi adapter for Wi-Fi assessment payloads
- A tested recovery path over SSH, USB Ethernet, or a second interface

### Optional payload hardware

- Bluetooth adapter
- GPS receiver
- NFC reader
- RTL-SDR or supported SoapySDR device
- USB serial, LTE, I²C, SPI, GPIO, and other supported boards

Not every payload works with every adapter or Pi-Tail image. A payload will report a missing command, package, capability, or device when its optional hardware is unavailable.

## Installation

### 1. Prepare Kali Pi-Tail

Download and flash the official [Raspberry Pi-Tail Zero 2 W image](https://www.kali.org/docs/arm/raspberry-pi-zero-2-w-pi-tail/). Configure USB, Wi-Fi, or Bluetooth tethering according to the Kali documentation, boot the Pi, and connect to it from your phone.

Change all default Kali/Pi-Tail credentials before placing the device on any network.

### 2. Clone City Pop

From an SSH session on the Pi:

```bash
sudo apt update
sudo apt install -y git
git clone https://github.com/kanedasec/citypop.git
cd city-pop
chmod +x install.sh
sudo ./install.sh
```

The installer:

1. Detects Kali and the ARM architecture.
2. Installs available system tools and board/radio bindings.
3. Copies runtime files to `/opt/city-pop`.
4. Creates `/opt/city-pop/.venv` with access to Kali's system Python packages.
5. Installs Python dependencies without attempting large ARM source builds where avoidable.
6. Generates a random City Pop authentication token.
7. Enables and starts `city-pop.service` as root.
8. Prints the primary and all available IPv4 web URLs plus the token location.

An unrelated broken APT repository may cause `apt update` to warn. The installer continues using indexes that did refresh, but required package installation can still fail if Kali cannot fetch them.

### 3. Open the deck

On the tethered phone, browse to the URL printed by the installer:

```text
http://<pi-tail-ip>:8080
```

The Pi-Tail default is often `192.168.43.254`, but hotspot vendors and USB tethering modes may assign another address.

Enter the token printed during installation. You can retrieve it later over SSH:

```bash
sudo python3 -c 'import json; print(json.load(open("/opt/city-pop/config.json"))["auth_token"])'
```

## Usage

1. Authenticate with the City Pop token.
2. Read and accept the authorized-use notice.
3. Select **+ Engagement**.
4. Give the engagement a name and date.
5. Enter the exact authorized scope: lab name, IPs, CIDRs, domains, SSIDs, device addresses, or other target context.
6. Choose a payload category and payload.
7. Review every option, interface, adapter, and target before running it.
8. Watch output in the live terminal. Use **Stop** if the result is unexpected.
9. Open **Loot** to preview or download generated artifacts.
10. End the engagement when testing is finished.

Only one payload or command runs at a time. Disconnecting the controlling browser stops its current process.

### Service management

```bash
sudo systemctl status city-pop
sudo systemctl restart city-pop
sudo journalctl -u city-pop -f
```

Runtime files are installed under `/opt/city-pop`. Payload output is stored under `/opt/city-pop/loot`.

### Updating

From the cloned repository:

```bash
git pull
sudo ./install.sh
```

Back up loot and any local payload edits before reinstalling. `config.json`, loot, logs, captures, credentials, and local virtual environments are intentionally excluded from Git.

## Network and power safety

### Preserve the phone control path

Do not place the phone-tether interface into monitor mode, disable it, bridge it, change its address, or use it for a disruptive Layer-2 workflow unless another tested management path is active. If that interface drops, the browser loses its connection and cannot send **Stop**.

Use a separate USB Wi-Fi or Ethernet adapter for assessment traffic whenever possible.

### Radio and physical safety

- Monitor mode, injection, beaconing, jamming-like traffic, and rogue services can affect nearby systems beyond the intended target.
- Use shielding, attenuators, isolated lab networks, or RF test enclosures where appropriate.
- Verify frequency, channel, transmit-power, and regional regulatory requirements.
- Treat NFC/RFID write, replay, cloning, and fuzzing operations as potentially destructive.
- Do not replay unknown SDR captures; transmitting may be illegal and could interfere with safety-critical services.
- Never connect unknown USB, serial, GPIO, I²C, or SPI hardware without confirming voltage and pinout.

## Web security

City Pop is a privileged administration surface, not a hardened internet service.

- The service runs payloads as root.
- The optional command bar executes shell commands as root.
- The default server uses plain HTTP; the token is not protected by transport encryption.
- Keep port `8080` on a trusted, private phone-to-Pi link.
- Do not expose it through public Wi-Fi, router forwarding, cloud tunnels, or an untrusted VPN.
- Treat the token like a root password and rotate it if it is disclosed.
- Do not commit `/opt/city-pop/config.json`, loot, logs, captures, or credentials.
- Review third-party payload behavior and dependencies before use.

To rotate the token:

```bash
sudo python3 - <<'PY'
import json, secrets
path = "/opt/city-pop/config.json"
with open(path, encoding="utf-8") as source:
    config = json.load(source)
config["auth_token"] = secrets.token_urlsafe(24)
with open(path, "w", encoding="utf-8") as destination:
    json.dump(config, destination, indent=2)
    destination.write("\n")
print(config["auth_token"])
PY
sudo systemctl restart city-pop
```

## Legal and ethical use

City Pop is intended only for:

- Systems and networks you own
- Environments for which you have explicit written authorization
- Controlled education, research, CTF, and lab exercises
- Defensive validation performed within an agreed scope

Authorization must define the targets, techniques, time window, data-handling rules, and permitted impact. A device being reachable, discoverable, or physically nearby is not permission to test it.

You are responsible for complying with applicable computer-misuse, privacy, interception, radio, telecommunications, access-control, and data-protection laws. Some payloads can interrupt service, collect credentials or traffic, alter network behavior, write physical media, or create remote-access material. The engagement prompts are reminders—not a substitute for authorization, technical review, supervision, or professional judgment.

The maintainers and upstream authors are not responsible for misuse, damage, data loss, service interruption, regulatory violations, or unauthorized access.

## Project layout

```text
app.py                  Flask + Socket.IO web application
payload_runner.py       payload discovery, execution, prompts, logs, stopping
payloads/               web-native payload catalog and shared helpers
static/                 phone UI, styles, PWA manifest, client logic
install.sh              Kali/ARM-aware installer
city-pop.service        systemd service template
requirements-core.txt   required web runtime
requirements.txt        optional payload Python dependencies
constraints-arm.txt     ARM dependency compatibility constraints
config.example.json     safe configuration template
misc/                   development documentation (not installed)
tools/                  local migration tooling (not installed or committed)
```

## License

City Pop is released under the [MIT License](LICENSE).

The MIT License applies to this project's original code and contributions. Adapted, bundled, or externally invoked components remain subject to their respective licenses and notices. When redistributing the project, retain the City Pop license, applicable upstream attribution, and any third-party license material required by those components.

## Credits and provenance

- [RaspyJack](https://github.com/7h30th3r0n3/Raspyjack) by `7h30th3r0n3`—the upstream project and payload inspiration. RaspyJack describes itself as a portable Raspberry Pi offensive toolkit with LCD control, a payload launcher, WebUI, and payload IDE.
- [Kali Linux Raspberry Pi-Tail](https://www.kali.org/docs/arm/raspberry-pi-zero-2-w-pi-tail/)—the phone-powered and phone-controlled platform this adaptation targets.
- The maintainers and authors of the individual tools invoked by the payload catalog.

RaspyJack is also published under the MIT License. This repository retains its upstream attribution, and redistribution must continue to comply with the licenses of copied, adapted, bundled, and externally invoked components.

---

**Carry a lab in your pocket. Keep the scope in your hand.**
