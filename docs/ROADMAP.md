# City Pop Progress and Roadmap

City Pop is currently in the **payload evaluation and fixing phase**. The web
platform, deployment architecture, authentication baseline, and repository
structure are established; current work focuses on validating each payload
through its complete phone-controlled workflow and correcting failures found
on representative hardware.

## Project phases

| Phase | Status | Outcome |
|---|---|---|
| 1. Web platform foundation | Complete | Phone-first UI, engagements, execution, prompts, history, loot, and reports |
| 2. Deployment and authentication baseline | Complete | nginx TLS proxy, loopback Gunicorn, local account setup, session controls, and installer integration |
| 3. Hardware and network controls | Complete | Interface inventory, protected-route safeguards, mode/link controls, and safe poweroff |
| 4. Repository and documentation organization | Complete | Application, deployment, configuration, tests, templates, and documentation separated by purpose |
| **5. Payload evaluation and fixing** | **In progress** | Exercise every payload, repair its web workflow, and assign evidence-based maturity |
| 6. Cross-device and hardware validation | Planned | Validate supported adapters, Pi images, phone browsers, cleanup, and recovery paths |
| 7. Release hardening | Planned | Resolve release blockers, refresh compatibility documentation, and prepare a stable release |

Status meanings:

- **Complete** means the phase's baseline outcome is implemented. It does not
  mean that the area will never receive another improvement.
- **In progress** means it is the current primary development phase.
- **Planned** means it follows the current phase and may still change based on
  validation findings.

## Payload validation snapshot

Snapshot taken on 2026-07-24:

| Maturity | Payloads | Meaning |
|---|---:|---|
| Functional | 4 | Complete supported workflow validated |
| Limited | 1 | Primary workflow works, but coverage or compatibility is limited |
| Not tested | 149 | Complete City Pop workflow has not yet been evidenced |
| **Total** | **154** | Discoverable web payload catalog |

Payloads with either `functional` or `limited` evidence currently represent
**5 of 154 payloads (3.2%)**. This percentage measures catalog validation
coverage only; it is not the completion percentage of the City Pop platform.
Payloads without an explicit `@maturity` tag are counted as `not tested`.

## Current-phase workflow

Each payload should move through the following checks:

1. Confirm metadata, category, description, inputs, danger level, and maturity.
2. Launch it from the phone interface under an authorized test engagement.
3. Verify preflight checks and every static or runtime prompt.
4. Exercise expected success and common failure paths on relevant hardware.
5. Confirm live output, stop behavior, child-process cleanup, and interface restoration.
6. Verify that logs and artifacts appear under the correct engagement.
7. Fix discovered problems and add a regression test where practical.
8. Set `@maturity` to `limited` or `functional` only when evidence supports it.

The detailed payload contract and maturity definitions are in
[Payload authoring](PAYLOAD_AUTHORING.md).

## Maintaining this page

Update the snapshot whenever a meaningful batch of payloads changes maturity.
The catalog totals can be checked from the repository root with:

```bash
python3 - <<'PY'
from collections import Counter
from pathlib import Path
from citypop.payload_runner import discover

payloads = discover(Path("payloads"))
print(f"Total: {len(payloads)}")
print(Counter(payload["maturity"] for payload in payloads))
PY
```

When advancing a project phase, record the outcome that was actually achieved,
move the next phase to **In progress**, and adjust later phases if validation
findings changed the plan.
