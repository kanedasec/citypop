<p align="center">
  <img src="static/citypop-icon.png" alt="City Pop — phone-first Kali Pi-Tail payload deck" width="760">
</p>

<p align="center">
  <strong>Turn a phone-powered Raspberry Pi Zero 2 W into a browser-operated security field deck.</strong>
</p>

<p align="center">
  <a href="https://github.com/kanedasec/citypop/actions/workflows/ci.yml"><img src="https://github.com/kanedasec/citypop/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://github.com/kanedasec/citypop/commits"><img src="https://img.shields.io/github/last-commit/kanedasec/citypop?style=flat-square&color=39e7ef" alt="Last commit"></a>
  <a href="https://github.com/kanedasec/citypop/issues"><img src="https://img.shields.io/github/issues/kanedasec/citypop?style=flat-square&color=ff4f9a" alt="Open issues"></a>
  <img src="https://img.shields.io/github/repo-size/kanedasec/citypop?style=flat-square&color=8cf7f7" alt="Repository size">
  <img src="https://img.shields.io/badge/platform-Kali%20Pi--Tail-557C94?style=flat-square&logo=kali-linux&logoColor=white" alt="Platform: Kali Pi-Tail">
  <img src="https://img.shields.io/badge/hardware-Pi%20Zero%202%20W-C51A4A?style=flat-square&logo=raspberry-pi&logoColor=white" alt="Hardware: Raspberry Pi Zero 2 W">
  <img src="https://img.shields.io/badge/payloads-153-ff4f9a?style=flat-square" alt="153 payloads">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-55e6a5?style=flat-square" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/use-authorized%20testing%20only-ffc45c?style=flat-square" alt="Authorized testing only">
</p>

# CITY POP // Pi-Tail Deck

> A phone-first field interface for Kali Pi-Tail—inspired by RaspyJack, rebuilt for a Raspberry Pi Zero 2 W that lives in your pocket instead of behind an LCD HAT.

City Pop turns a Kali Pi-Tail into a compact, browser-operated security deck. The phone supplies power and tethering, displays the interface, and provides the primary controls. The Pi runs the tools, talks to attached radios and boards, and saves results into a central loot directory.

This is an independent web adaptation of [7h30th3r0n3/Raspyjack](https://github.com/7h30th3r0n3/Raspyjack). RaspyJack is an LCD-driven portable offensive toolkit; City Pop preserves much of its payload spirit while replacing joystick, button, and display flows with phone-friendly forms and live web prompts. It is not an official RaspyJack or Kali Linux project.

> [!CAUTION]
> City Pop launches privileged security tooling. Use it only on systems, devices, radio environments, and networks you own or have explicit permission to test. Keep the web service on a private phone-to-Pi link.

## Contents

- [Why Pi-Tail?](#why-pi-tail)
- [Feature tour](#feature-tour)
- [Quick start](#quick-start)
- [Hardware](#intended-build)
- [Installation](#installation)
- [Usage](#usage)
- [Practical examples](#practical-examples)
- [Troubleshooting](#troubleshooting)
- [Security and safety](#web-security)
- [Project layout](#project-layout)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Why Pi-Tail?

[Kali Pi-Tail for the Raspberry Pi Zero 2 W](https://www.kali.org/docs/arm/raspberry-pi-zero-2-w-pi-tail/) is designed around smartphone tethering. Kali describes the phone as the Pi-Tail's power supply, screen, keyboard, and mouse. City Pop takes that idea literally: no Waveshare LCD is required, and the web app becomes the device interface.

The Zero 2 W has only 512 MB of RAM, so installation favors Kali/Debian binary packages for heavy native dependencies and uses a project virtual environment for the web runtime and lighter Python packages.

## Highlights

- Phone-first, responsive web interface
- Administrator-authenticated HTTP and WebSocket control
- 153 active payloads across Wi-Fi, Bluetooth, network, NFC/RFID, SDR, hardware, reconnaissance, credentials, USB, AI, and utility categories
- Structured launch forms and dynamic adapter/target selectors
- Payload preflight checks, protected-route warnings, and live hardware/interface status
- All-payload catalog with toggleable categories, search, impact/capability filters, and favorites
- Category-filtered guided launch workflow for every payload
- Recoverable live output, cancellation, runtime prompts, and endpoint/artifact cards
- Engagement-scoped run history, logs, loot, and Markdown reports with artifact hashes
- Server-persisted engagement manager for reopening, editing, and securely deleting an engagement with all associated data
- Installable phone app shell with offline UI fallback
- Isolated Python environment at `/opt/city-pop/.venv`
- Hardware bindings inherited from Kali through `--system-site-packages`
- Root systemd service for payloads that require radio, packet, GPIO, or device access
- ARM-aware dependency handling for the Pi Zero 2 W

## Feature tour

| On your phone | On the Pi-Tail |
|---|---|
| Create an engagement with mandatory name, date, and authorized scope | Keep logs and artifacts separated by engagement |
| Browse all payloads or toggle categories, search, filter, and favorite tools | Discover 153 web-enabled payloads from their metadata |
| Follow a guided launch flow for any payload | Check commands, radios, adapters, and protected routes before launch |
| Choose targets, interfaces, modes, and durations through web prompts | Run one privileged operation at a time inside the City Pop environment |
| Watch a searchable, pausable terminal and open live dashboard links | Stream output and preserve it across temporary phone disconnects |
| Preview loot, revisit runs, and generate a report | Produce engagement reports with artifact sizes and SHA-256 hashes |

The interface is installable as a phone web app. Its shell remains available without internet access, while payload execution still requires a live connection to the Pi.

## Quick start

Already running Kali Pi-Tail? The shortest supported installation path is:

```bash
sudo apt update
sudo apt install -y git
git clone https://github.com/kanedasec/citypop.git
cd citypop
sudo ./install.sh
```

When installation finishes, keep the one-time pairing code shown in the
terminal and open one of the printed URLs on the connected phone. On first
access, enter that code and create the local administrator account:

```text
https://<pi-tail-address>:8080
```

For hardware preparation, installer behavior, updates, and account recovery, continue to [Installation](#installation).

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
cd citypop
chmod +x install.sh
sudo ./install.sh
```

The installer:

1. Detects Kali and the ARM architecture.
2. Installs available system tools and board/radio bindings.
3. Copies runtime files to `/opt/city-pop`.
4. Creates `/opt/city-pop/.venv` with access to Kali's system Python packages.
5. Installs Python dependencies without attempting large ARM source builds where avoidable.
6. Generates a private session-signing secret and a one-time first-access
   pairing code. Only the pairing-code hash is retained.
7. Configures nginx for management TLS/WebSockets on port `8080`, with no nginx
   listener on ports `80` or `443`, and proxies to one threaded Gunicorn worker
   bound only to `127.0.0.1:18080`.
8. Enables and starts `nginx.service` and `city-pop.service` as root.
9. Prints the one-time pairing code and all available management HTTPS URLs.

An unrelated broken APT repository may cause `apt update` to warn. The installer continues using indexes that did refresh, but required package installation can still fail if Kali cannot fetch them.

### 3. Open the deck

On the tethered phone, browse to the URL printed by the installer:

```text
https://<pi-tail-ip>:8080
```

The Pi-Tail default is often `192.168.43.254`, but hotspot vendors and USB tethering modes may assign another address.

On first access, City Pop asks you to create its local administrator username
and password using the one-time code printed by `install.sh`. Passwords must
contain at least 15 characters. Password and pairing-code material is stored
only as salted scrypt hashes; the pairing record is deleted after successful
setup.

## Usage

1. Sign in with the City Pop administrator account.
2. Read and accept the authorized-use notice.
3. Select **+ Engagement**.
4. Give the engagement a name and date.
5. Enter the exact authorized scope: lab name, IPs, CIDRs, domains, SSIDs, device addresses, or other target context.
6. Choose a payload category and payload.
7. Review every option, interface, adapter, and target before running it.
8. Watch output in the live terminal. Use **Stop** if the result is unexpected.
9. Open **Loot** to preview or download generated artifacts.
10. End the engagement when testing is finished.

Only one payload or command runs at a time. A temporary phone or radio disconnect does not stop it: reconnecting restores the running-operation state, buffered terminal output, and any pending prompt. Use **Stop** explicitly when an operation should end.

## Practical examples

### Survey Wi-Fi from a separate adapter

1. Create an engagement such as `homelab` and enter the exact authorized SSIDs/devices in its scope.
2. Open **Hardware** and identify the interface marked as the protected City Pop route.
3. Connect a separate monitor-capable USB Wi-Fi adapter through a powered OTG hub.
4. Select **Wi-Fi → WiFi Recon Survey** or find it through the guided workflow picker.
5. Review the preflight, choose the separate adapter, and set the survey duration.
6. Follow the printed dashboard endpoint or watch the terminal; download the resulting JSON from **Loot**.

Never switch the phone tether or current default-route interface into monitor mode. A monitor-capable driver does not guarantee that an adapter switched successfully; verify the preflight and terminal output.

### Run a scoped network check

1. Record the authorized host or CIDR in the engagement scope.
2. Search for a reconnaissance payload such as **Nmap Target** or **TCP Banner**.
3. Confirm the exact target again in the payload form.
4. Review the impact warning, run the payload, and retain the engagement log with the result.

### Generate the engagement handoff

After testing, choose **Report**, add operator notes and limitations, then generate the Markdown report. City Pop includes the execution timeline and SHA-256 inventory of files stored under that engagement.

## Troubleshooting

### The printed address is not my current Wi-Fi or hotspot address

IP addresses can change when moving between home Wi-Fi, USB tethering, and phone hotspots. On the Pi, list current IPv4 addresses with:

```bash
ip -br -4 address
```

Open the HTTPS address reachable from the phone with port `8080`. The service listens independently of the installer’s original address. The installer creates a self-signed certificate, so the browser will require you to inspect and explicitly accept its warning.

### A Wi-Fi survey reports `Network is down`

The selected adapter did not remain operational for monitor capture. Check that it is not the management interface, that its driver supports monitor mode, and that NetworkManager or `wpa_supplicant` did not reclaim it:

```bash
ip link show <interface>
iw dev <interface> info
rfkill list
journalctl -k --since "5 minutes ago" | tail -100
```

### Installation appears stuck while building NumPy

On the Pi Zero 2 W, compiling NumPy can take a long time and exhaust memory. The installer is designed to prefer Kali/Debian binary packages and compatible wheels. Confirm that you are using the current installer and a supported Kali Pi-Tail image before retrying.

### The service does not open

```bash
sudo systemctl status city-pop --no-pager
sudo systemctl status nginx --no-pager
sudo journalctl -u city-pop -n 100 --no-pager
sudo nginx -t
sudo ss -lntp | grep 8080
```

## Service management and updates

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

## Web security

City Pop is a privileged administration surface, not a hardened internet service.

- The service runs payloads as root.
- The optional command bar executes shell commands as root.
- The installer enables HTTPS with a locally generated self-signed certificate. Nginx terminates TLS and WebSockets, then proxies only to Gunicorn on `127.0.0.1:18080`. Verify the certificate fingerprint before trusting it on a management device.
- Nginx does not listen on ports 80 or 443. While a DNS Spoof template is
  active, the payload itself temporarily owns port 80 for HTTP redirects and
  port 443 for its self-signed HTTPS template server. Both are released during
  payload cleanup.
- Keep port `8080` on a trusted, private phone-to-Pi link.
- Do not expose it through public Wi-Fi, router forwarding, cloud tunnels, or an untrusted VPN.
- Use a unique administrator passphrase and change it from **Account** if it is disclosed.
- Password or username changes invalidate every existing browser and WebSocket
  session. Login and first-access attempts are rate-limited.
- The management UI uses a locally bundled, checksum-verified Socket.IO client,
  CSRF/origin validation, and a restrictive Content Security Policy.
- Do not commit `/opt/city-pop/config.json`, loot, logs, captures, or credentials.
- Review third-party payload behavior and dependencies before use.

To recover access when the administrator password is lost, reset the local
account over SSH. This preserves the old account file as a backup and returns
the web interface to first-access setup:

```bash
sudo systemctl stop city-pop
sudo mv /opt/city-pop/state/auth.json /opt/city-pop/state/auth.json.backup
cd ~/citypop
sudo ./install.sh
```

The installer prints a new one-time pairing code. It preserves the backed-up
account file until you remove it deliberately.

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
auth_store.py           scrypt credentials, auth generations, one-time pairing
payload_runner.py       payload discovery, persistent execution, prompts, history
payloads/               web-native payload catalog and shared helpers
static/                 phone UI, service worker, and verified local Socket.IO client
docs/                   architecture and payload-authoring references
tests/                  catalog-contract and authenticated API tests
.github/                CI, issue forms, and pull-request template
state/                  local execution history (generated, excluded from Git)
install.sh              Kali/ARM-aware installer
city-pop.service        systemd service template
city-pop.nginx.conf     TLS, WebSocket, CSP, headers, limits, and proxy template
requirements-core.txt   required web runtime
requirements-core.lock  exact, SHA-256-locked web dependency closure
requirements.txt        optional payload Python dependencies
constraints-arm.txt     ARM dependency compatibility constraints
constraints-web.txt     human-readable exact web dependency versions
config.example.json     safe configuration template
misc/                   development documentation (not installed)
tools/                  local migration tooling (not installed or committed)
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — runtime components, data flow, environment contract, trust boundaries, and Pi-Tail constraints.
- [Payload authoring](docs/PAYLOAD_AUTHORING.md) — metadata, phone prompts, output, loot, dashboards, dependencies, safety, and verification.
- [Security policy](SECURITY.md) — supported version, private vulnerability reporting, and deployment expectations.
- [Code of Conduct](CODE_OF_CONDUCT.md) — behavior expected in project spaces.

## Contributing

Contributions that improve phone usability, Pi Zero 2 W reliability, hardware detection, documentation, and safe web-native payload behavior are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), which documents architecture boundaries, the payload contract, local setup, validation, safety expectations, and the pull-request checklist.

The baseline validation is:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile app.py payload_runner.py
node --check static/app.js
node --check static/input.js
node --check static/sw.js
bash -n install.sh
git diff --check
```

Good entry points include documentation fixes, clearer payload output, adapter compatibility reports, and issues labeled [`good first issue`](https://github.com/kanedasec/citypop/labels/good%20first%20issue) or [`help wanted`](https://github.com/kanedasec/citypop/labels/help%20wanted).

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
