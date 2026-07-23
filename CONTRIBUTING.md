# Contributing to City Pop

Thank you for helping make City Pop safer and more useful on Kali Pi-Tail. Contributions are welcome for the web interface, payload adaptations, hardware support, installer reliability, tests, and documentation.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md) and to work only with authorized test systems and data.

## Start here

1. Search [existing issues](https://github.com/kanedasec/citypop/issues).
2. Open an issue before changing architecture, installation behavior, the payload contract, or privileged execution.
3. Fork the repository and create a focused branch.
4. Keep a pull request limited to one coherent change.
5. Describe the Pi/Kali image, adapters, and validation environment in the pull request.

Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not the public issue tracker.

## Architecture boundaries

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before changing execution or authentication.

- `app.py` owns authenticated HTTP and Socket.IO APIs.
- nginx owns public management TLS on configured port `8080`; Gunicorn owns
  only `127.0.0.1:18080`. Nginx must not claim ports `80` or `443`.
- `payload_runner.py` owns discovery, one-at-a-time execution, logs, history, prompts, and reconnect recovery.
- `static/` is the phone-first client. Keep controls usable at narrow mobile widths and with touch.
- `payloads/` contains web-native scripts and shared helpers.
- `install.sh` must remain suitable for Kali Pi-Tail on a 32-bit ARM Raspberry Pi Zero 2 W with 512 MB RAM.
- Generated secrets, state, logs, loot, captures, and virtual environments must never enter Git.

Do not add LCD, joystick, desktop-window, or attached-keyboard dependencies. Do not silently change the default route, phone tether, or management interface.

## Local setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-core.lock
cp config.example.json config.json
# For the direct development server only, set bind to 127.0.0.1 and
# tls.enabled to false in the ignored config.json.
python app.py
```

Open `http://127.0.0.1:8080`. Direct Flask execution is a loopback-only
development fallback; installed deployments must use nginx TLS and Gunicorn.
The installer creates first-access pairing state, so local authentication tests
should use isolated test stores or explicitly generate development pairing
state. Use only synthetic or authorized test data. Many payload dependencies
are intentionally optional and are normally supplied by Kali or attached
hardware.

## Payload contract

Read the complete [payload authoring guide](docs/PAYLOAD_AUTHORING.md). Every discoverable payload needs valid metadata within its first 30 lines:

```python
#!/usr/bin/env python3
# @active: true
# @name: Interface Status
# @desc: List available network interfaces, addresses, drivers, modes, and route-safety information in the web terminal.
# @category: utilities
# @danger: false
# @web: true
# @inputs: []
```

Required behavior:

- Set `@active: true` and `@web: true` only when the complete phone workflow works.
- Make `@desc` describe actual behavior and output. Do not mention LCD controls or unsupported capabilities.
- Use static `@inputs` for launch arguments and `payloads._web_input.request_input()` for runtime choices.
- Present discovered adapters and targets as choices instead of asking users to guess identifiers.
- Print actionable progress, failures, output paths, and full dashboard URLs to stdout.
- Store artifacts below `CITYPOP_LOOT`; never write credentials or captures into the repository.
- Use `@danger: true` for disruptive, modifying, transmitting, credential-handling, or service-impacting behavior.
- Restore interfaces and services in `finally` blocks where practical.
- Never assume an interface name such as `wlan0`, `mon0`, or `hci0` without discovery or an explicit user choice.

## Web interface changes

- Preserve administrator session authentication and engagement requirements.
- Preserve authentication-generation checks, CSRF/origin validation,
  per-event Socket.IO reauthorization, login/setup throttling, and one-time
  pairing.
- Keep browser dependencies local and compatible with the nginx CSP; do not add
  runtime CDN scripts or inline JavaScript.
- Do not remove, add, or materially relocate controls without explaining the UX reason.
- Keep touch targets at least 44 px and preserve keyboard focus indicators.
- Escape untrusted payload and loot text before inserting it into HTML.
- Test at a phone viewport near 390 × 844 and at a desktop width.
- Preserve reconnect recovery, explicit stopping, terminal scrolling, and pending runtime prompts.
- Update the service-worker cache name when changing cached frontend assets.

## Installer changes

The Pi Zero 2 W should not compile large scientific packages when a compatible Kali package or wheel is available. Installer changes must:

- remain noninteractive after `sudo ./install.sh` starts;
- tolerate unrelated broken APT sources where safe;
- prefer binary packages and compatible wheels on ARM;
- retain board/radio system bindings through the project virtual environment;
- remain safe to rerun;
- install nginx as the TLS/WebSocket proxy on the configured management port;
- keep Gunicorn loopback-only on `127.0.0.1:18080`;
- leave ports `80` and `443` free for payload-managed services; and
- print all reachable management HTTPS URLs and explain first-access account setup; and
- preserve one-time pairing, hardened runtime permissions, the verified local
  Socket.IO asset, and exact web dependency constraints.

## Validation

Run the baseline checks:

```bash
python -m unittest discover -s tests -v
python -m py_compile app.py payload_runner.py
node --check static/app.js
node --check static/input.js
node --check static/sw.js
bash -n install.sh
git diff --check
```

For payload changes, also run the script through the web UI and verify:

1. engagement and scope gating;
2. preflight output;
3. every static and runtime prompt;
4. terminal progress and useful errors;
5. stop/cleanup behavior;
6. dashboard endpoint output, when applicable; and
7. engagement-scoped logs and artifacts.

## Pull request checklist

- Explain the problem and the chosen solution.
- Link the issue when one exists.
- List validation commands and real hardware used.
- Include phone screenshots for visible UI changes.
- Note safety, privilege, RF, data-handling, or management-route implications.
- Update README/docs when behavior or user expectations change.
- Do not include secrets, targets, personal data, loot, or generated captures.

Maintainers may ask that broad submissions be split into smaller changes. Review focuses on phone usability, truthful behavior, Pi-Tail compatibility, safe failure, and maintainability.
