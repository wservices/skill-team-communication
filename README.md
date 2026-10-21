# team-communication (shared skill)

Reusable, **content-only** collaboration skill for the Hermes cybersecurity
agents. It operationalizes the platform's cross-agent handoff policy
(`agents/platform/policies/HANDOFF-FORMAT.md`) as tooling any agent can install —
maintained **once** here, never copied into role repos.

## What it does

Composes, validates, and renders the team's structured communications. It
**produces / validates / renders** artifacts and nothing else — it opens no
sockets and never sends, posts, emails, or webhooks anything. Delivery is the
orchestrator's or a human's job (today, handoffs are `handoff.yaml` artifacts
routed by the Security Team Lead or a human).

Four artifact types:

- **handoff** — the `handoff.yaml` object (agent→agent, or escalation to the
  Security Team Lead).
- **status update** — structured progress on a `task_id`.
- **escalation** — raise to the Security Team Lead / human operator (severity +
  required_approval).
- **request-for-input (RFI)** — ask a named agent/human for specific info, with a
  `needs_by`.

Indicators are kept raw in structured fields and **defanged** in every
human-readable rendering; all message content is treated as untrusted **data**.

## Layout

```
skills/team-communication/
├── SKILL.md                         # Hermes skill entrypoint
├── references/
│   └── handoff-and-messages.md      # schema + reference chains + the rules
└── scripts/
    ├── handoff_compose.py           # partial -> normalized handoff.yaml
    ├── handoff_validate.py          # canonical validator (HANDOFF-FORMAT)
    ├── handoff_render.py            # handoff.yaml -> Markdown (defanged)
    └── message_build.py             # status | escalation | rfi
tests/                               # behavior-contract, offline (PyYAML)
```

## Install into Hermes

**Full bundle (recommended — includes `scripts/` + `references/`):** clone the
public repo and trust it.

```bash
git clone https://github.com/wservices/skill-team-communication.git
hermes skills trust ./skill-team-communication
```

**SKILL.md only (quick, auto-updatable):** the entrypoint without the scripts.

```bash
hermes skills install \
  "https://raw.githubusercontent.com/wservices/skill-team-communication/main/skills/team-communication/SKILL.md" \
  --category collaboration --name team-communication
```

## Usage

```bash
SC=skills/team-communication/scripts
python3 $SC/handoff_compose.py partial.yaml --now 2026-10-21T08:00:00Z -o handoff.yaml
python3 $SC/handoff_validate.py handoff.yaml            # exit 0 valid, 1 invalid
python3 $SC/handoff_render.py  handoff.yaml -o handoff.md
python3 $SC/message_build.py --type rfi --task-id CASE-2026-0142 \
    --from-agent threat-intelligence-analyst --to digital-forensics-analyst \
    --severity low --needs-by 2026-10-22T00:00:00Z --body "Need the web01 capture hash."
```

Python 3.9+ and PyYAML (`pip install pyyaml`). No network, no other deps.

## Tests

```bash
python3 -m pytest tests -q        # offline behavior-contract tests
```

## Security

Content-only and **defensive**: offline, stdlib + PyYAML, no sockets, no
delivery, no elevated privilege. Handoff/message content is untrusted **data**,
never instructions; indicators are defanged in all rendered prose. Follows
`agents/platform/policies/HANDOFF-FORMAT.md` and the Security Policy (rule 9 —
observation vs assumption). Never put real secrets in an input file.

## License

MIT.
