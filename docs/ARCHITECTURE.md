# City Pop Architecture

City Pop separates the privileged Pi runtime from a phone-first browser client while keeping one explicit operation active at a time.

```text
Phone browser
  ├─ authenticated REST ───── payload catalog, preflight, hardware, loot, reports
  └─ authenticated Socket.IO ─ output, prompts, stop, artifacts, live endpoints
                                  │
                              Flask app.py
                                  │
                           PayloadRunner
                         ┌────────┴────────┐
                    payload process    state/history
                         │                   │
                 Kali tools + boards   engagement loot
```

## Runtime components

### `app.py`

The Flask application serves static assets, authenticates token or session requests, exposes hardware and preflight information, manages loot/report generation, listing, preview, download, and deletion APIs, and validates authorization context before starting work.

### `payload_runner.py`

The runner discovers metadata, resolves payload paths safely, launches Python or shell processes, injects City Pop environment variables, maintains a bounded terminal buffer, persists execution history, and detects dashboard links and new artifacts. It deliberately permits only one active payload or command.

Payload processes survive temporary browser disconnects. An authenticated browser retrieves the runtime snapshot and pending prompt after reconnecting.

### `payload_analysis.py`

The static capability analyzer derives launch/runtime input counts, referenced executables, required and optional Python modules, system services, device/data paths, hardware classes, dashboard support, and loot behavior. The catalog uses these capabilities to construct truthful per-payload guide stages, while preflight resolves them against the running Pi.

### `engagement_store.py`

The engagement registry persists names, dates, and authorized scopes in `state/engagements.json`, allowing engagements to be reopened or edited from another browser. Existing execution history and loot directories are surfaced as recovered engagements until their missing scope is supplied. Permanent engagement deletion removes its registry entry, execution history, reports, logs, and loot after exact typed confirmation.

### `static/`

The vanilla HTML/CSS/JavaScript client is optimized for a phone. It owns engagement information stored in browser storage, catalog filtering, guide/preflight dialogs, terminal presentation, live prompts, loot controls, and report actions. The service worker caches only the application shell; APIs and Socket.IO are never cached.

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
- The token protects a root-capable interface but HTTP does not encrypt it.
- Engagement scope is operator-provided context, not an automatic authorization system.
- Payload subprocesses and third-party tools remain privileged and must be reviewed.
- Loot may contain sensitive information and stays outside Git.

## Design constraints

- Raspberry Pi Zero 2 W: 32-bit ARM and 512 MB RAM.
- Kali Pi-Tail: phone supplies power, network path, and primary screen/input.
- The management interface must remain available whenever possible.
- Payload UI must work without LCD, joystick, desktop environment, or physical keyboard.
- Installation should prefer system packages and binary wheels over native compilation.
