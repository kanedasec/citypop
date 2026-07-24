# City Pop Architecture

City Pop separates the privileged Pi runtime from a phone-first browser client while keeping one explicit operation active at a time.

```text
Phone browser
  │ HTTPS + WebSocket :8080 (default)
  ▼
nginx (TLS termination; no listener on :80 or :443)
  │ HTTP + WebSocket proxy
  ▼
Gunicorn gthread · 127.0.0.1:18080 · one worker
  │
Flask + Socket.IO · app.py
  ├─ authenticated REST ───── payload catalog, preflight, hardware, loot, reports
  └─ authenticated Socket.IO ─ output, prompts, stop, artifacts, live endpoints
                                  │
                             PayloadRunner
                           ┌──────┴────────┐
                      payload process  state/history
                           │                 │
                   Kali tools + boards  engagement loot
```

The installed management path is always `browser → nginx → Gunicorn`; it does
not use Flask's development server. Nginx listens with TLS on the configured
City Pop port (`8080` by default), proxies to loopback-only Gunicorn, and
carries Socket.IO WebSocket upgrades.

Nginx intentionally does not own ports `80` or `443`. When
`network/dns_spoofing.py` runs with a selected template, that payload
temporarily starts its own HTTP redirect server on `0.0.0.0:80` and HTTPS
template server on `0.0.0.0:443`. Port 80 redirects to the same spoofed
hostname and path on port 443. Both listeners stop during payload cleanup; the
management UI remains on nginx at port 8080.

`wifi/captive_portal.py` owns its isolated AP address on port 80 while active.
At launch, the operator chooses either a repository template from
`templates/dns/` or a previously validated image uploaded by the launch form.
Templates share the DNS-spoof server's UTF-8 handling and declared,
non-sensitive submission-field allowlist. Image mode creates a temporary,
responsive display-only site and accepts no form submissions. Portal requests
and permitted awareness responses use one engagement-scoped JSONL event log.
Uploaded source images are stored with opaque names and mode `0600` beneath
the mode-`0700` `state/uploads/` directory.

## Runtime components

### `app.py`

The Flask application serves static assets, authenticates administrator sessions, exposes hardware and preflight information, manages loot/report generation, listing, preview, download, and deletion APIs, and validates authorization context before starting work.

The systemd service launches one threaded Gunicorn worker bound only to
`127.0.0.1:18080`. Nginx is the sole public management listener.

First access requires the one-time pairing code printed by the installer.
Passwords and pairing codes are stored only as salted scrypt hashes, and the
pairing record is consumed after account creation. Every session carries the
current authentication version and a CSRF token. Account changes increment the
version, immediately invalidating older HTTP and Socket.IO sessions. Login and
setup attempts are limited by nginx and a bounded application limiter.

### `payload_runner.py`

The runner discovers metadata, resolves payload paths safely, launches Python or shell processes, injects City Pop environment variables, maintains a bounded terminal buffer, persists execution history, and detects dashboard links and new artifacts. It deliberately permits only one active payload or command.

Payload processes survive temporary browser disconnects. An authenticated browser retrieves the runtime snapshot and pending prompt after reconnecting.

### `payload_analysis.py`

The static capability analyzer derives launch/runtime input counts, referenced executables, required and optional Python modules, system services, device/data paths, hardware classes, dashboard support, and loot behavior. The catalog uses these capabilities to construct truthful per-payload guide stages, while preflight resolves them against the running Pi.

### `engagement_store.py`

The engagement registry persists names, dates, and authorized scopes in `state/engagements.json`, allowing engagements to be reopened or edited from another browser. Existing execution history is surfaced as recovered engagements until its missing scope is supplied; arbitrary payload output directories are never interpreted as engagements. Permanent engagement deletion removes its registry entry, execution history, reports, logs, and loot after exact typed confirmation.

### `static/`

The vanilla HTML/CSS/JavaScript client is optimized for a phone. It owns engagement information stored in browser storage, catalog filtering, guide/preflight dialogs, terminal presentation, live prompts, loot controls, and report actions. Socket.IO is bundled locally and checksum-verified during installation. The service worker caches only the application shell and local client assets; APIs are never cached.

### `payloads/`

Payloads are independently executable scripts with comment metadata. Shared helpers provide web prompts, dashboards, interface discovery, GPS, audio, and other integrations. Payloads communicate through stdout, stdin JSON prompt responses, environment variables, and the engagement loot directory.

## Environment contract

The runner supplies:

| Variable | Meaning |
|---|---|
| `CITYPOP_ROOT` | Installed application directory |
| `CITYPOP_LOOT` | Current engagement’s artifact directory |
| `CITYPOP_ENGAGEMENT` | Operator-provided engagement name |
| `CITYPOP_ENGAGEMENT_SLUG` | Filesystem-safe engagement identifier |
| `CITYPOP_INTERACTIVE=1` | Enables structured web runtime prompts |
| `PYTHONUNBUFFERED=1` | Streams terminal output immediately |

## Trust boundaries

- The web service runs as root because payloads need packet, radio, GPIO, and device access.
- The administrator session protects a root-capable interface. Passwords are
  salted scrypt hashes; an internal signing secret protects HTTP-only, Secure,
  SameSite session cookies.
- State-changing HTTP requests require same-origin CSRF validation. Privileged
  Socket.IO events revalidate both the session generation and CSRF token.
- Nginx applies a restrictive CSP, framing/content-type/referrer/permissions
  headers, a 1 MiB request limit, and authentication endpoint rate limits.
- Core web dependencies are exact-version and SHA-256 locked. The locally
  bundled Socket.IO client is also checksum-verified by the installer.
- Nginx provides management TLS on port 8080 using a locally generated
  self-signed certificate. The DNS-spoof template server reuses that
  certificate on port 443, so browsers should expect a trust warning.
- Ports 80 and 443 are payload-owned only while a DNS-spoof template is active;
  nginx must not listen on either port.
- Engagement scope is operator-provided context, not an automatic authorization system.
- Payload subprocesses and third-party tools remain privileged and must be reviewed.
- Loot may contain sensitive information and stays outside Git.

## Design constraints

- Raspberry Pi Zero 2 W: 32-bit ARM and 512 MB RAM.
- Kali Pi-Tail: phone supplies power, network path, and primary screen/input.
- The management interface must remain available whenever possible.
- Payload UI must work without LCD, joystick, desktop environment, or physical keyboard.
- Installation should prefer system packages and binary wheels over native compilation.
