# Web-Native Payload Authoring

This guide defines how a City Pop payload participates in discovery, phone prompts, execution, dashboards, and engagement output.

## File placement and metadata

Place a script in `payloads/<category>/`. Its `@category` must match the directory. Metadata must appear within the first 30 lines.

```python
#!/usr/bin/env python3
# @active: true
# @name: Example Survey
# @desc: Survey authorized targets for 60 seconds, print live counts, expose a temporary dashboard, and save JSON results to engagement loot.
# @category: reconnaissance
# @danger: false
# @web: true
# @inputs: [{"name":"seconds","label":"Duration","type":"number","default":"60"}]
```

Supported static input types are `text`, `password`, `number`, and `select`. A select input requires a nonempty `choices` array. Arguments are passed to the script in metadata order.

## Runtime choices

Use a runtime prompt when choices must be discovered after launch:

```python
from payloads._web_input import request_input

interface = request_input(
    "Select assessment interface",
    input_type="select",
    choices=[{"value": row["name"], "label": row["label"]} for row in adapters],
)
```

Prefer select controls for interfaces, Bluetooth adapters, targets found by a scan, modes, and known-safe options. Validate the returned value against the discovered set.

Do not use terminal `input()`, `curses`, Tk, LCD menus, or an attached keyboard for the primary workflow.

## Output contract

stdout and stderr are streamed into the phone terminal and engagement log. Output should answer:

- what is starting;
- which operator-selected interface or target is in use;
- where a service or dashboard can be opened;
- periodic progress for long operations;
- why an operation cannot continue;
- where results were saved; and
- whether cleanup succeeded.

Print complete endpoints, including scheme, host, port, path, and token when applicable:

```python
print(f"Dashboard: {dashboard.start()}", flush=True)
```

Avoid tight-loop output. City Pop collapses identical consecutive lines, but payloads should still report at a useful interval.

## Loot and reports

Write only beneath the current engagement directory:

```python
from pathlib import Path
import os

loot = Path(os.environ["CITYPOP_LOOT"]) / "ExampleSurvey"
loot.mkdir(parents=True, exist_ok=True)
result = loot / "results.json"
```

Do not hardcode `/opt/city-pop/loot`, write into the source tree, or reuse another engagement’s directory. City Pop detects newly created files and exposes them to the phone.

## Interface safety

- Discover interfaces at runtime.
- Clearly identify the default route and onboard interface.
- Warn before touching the management route.
- Prefer a separate USB assessment adapter.
- Check command return codes when changing mode or link state.
- Print captured stderr on failure.
- Restore mode, addresses, routes, and stopped services in a `finally` block.

A driver advertising monitor or AP capability does not prove that a transition succeeded. Verify the resulting mode and link state before capture.

## Dashboards

Use `payloads._dashboard.DashboardServer` for small read-only live views. Bind only as broadly as required, use its tokenized endpoint, print the returned URL, and stop the server during cleanup. Dashboard state should be a snapshot and must not replace essential terminal output or saved results.

## Dependency behavior

Check optional commands, Python modules, services, and devices before destructive setup. Fail with a direct terminal message and a meaningful nonzero exit code. Avoid downloading or installing packages from a payload; dependencies belong in the installer and requirement files.

## Danger classification

Use `@danger: true` when a payload transmits disruptive traffic, modifies a target or medium, handles credentials, changes network behavior, performs replay/injection, creates access material, or can interrupt service. Passive local status and read-only inspection can normally use `false`.

The danger flag communicates expected impact; it is not a substitute for validation, scope, cleanup, or safe defaults.

## Verification checklist

- Metadata parses and matches the category directory.
- Description matches real behavior and output.
- Static and runtime inputs work from a phone.
- Invalid and missing selections fail clearly.
- The protected route remains visible and recoverable.
- Stop terminates child processes and cleanup restores state.
- Dashboard URL opens from the phone.
- Artifacts appear under the correct engagement.
- Secrets do not appear in source, history arguments, or Git.
- The script behaves acceptably on a Pi Zero 2 W.
