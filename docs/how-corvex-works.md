# How Corvex works (plain English)

Corvex is a **multi-host campaign correlator**. It watches weak signals on many machines and tries to stitch them into one attack story — then optionally proposes (or, in the lab, enforces) isolation. It does **not** replace a SIEM or EDR, and it does **not** claim to stop APTs.

## The one-sentence version

Same stolen account logging into three hosts, or the same small data drip leaving two hosts toward one external IP, is often more important than any single alert — Corvex’s job is to notice that **across** hosts.

## Pieces

1. **Events** — signed envelopes (`auth`, `net_conn`, `dns`) with HMAC from local enrollment (`~/.corvex/enrollment.json`). No cloud API keys. No LLM.
2. **Detectors** — pure functions that raise weak signals: lateral auth, micro-exfil, recon fanout.
3. **Correlator** — fuses overlapping signals into **campaigns** (host sets + stages). Detector-only mode keeps alerts per key and does **not** merge across keys; fusion does.
4. **Reconstruction** — rebuilds a readable timeline + coarse ATT&CK tags from campaigns. If evidence is thin, status is `partial` or `insufficient_evidence`. It will **not** invent hops, CVEs, or malware names.
5. **Quarantine** — three honest modes:
   - `dry_run` — log `IsolateHost` proposals only (`CORVEX_CONTAIN=0`)
   - `lab_flag` — write sandbox flag files virtual lab hosts check before `/auth`
   - `blocked` — refuse and say so when live contain is requested but no real executor exists
6. **Dashboard** — shows campaigns, reconstruction status/gaps, and quarantine capability without pretending live contain is on.

## What “isolate” means today

| Context | What happens |
|---------|----------------|
| Product default | Dry-run log only |
| Live / break-test lab | Flag file → virtual host returns 403 on auth |
| Real Windows firewall / EDR / VLAN | **Not implemented** — Corvex says so |

## Typical commands

```bash
corvex replay train/train-lateral.jsonl
corvex reconstruct runs/replay
corvex quarantine-status
corvex quarantine host-a,host-b --rationale "lab mid-chain cut"
corvex dash
```

## Claim hygiene

- Sealed eval numbers are **lab / synthetic** until non-author + stranger + real-N FCR gates pass.
- Reconstruction exports (`to_manifest` / pack GT shape) are for **regression scoring**, not red-team playbooks.
- Live contain stays locked until Security L1 checklist is evidenced **and** a real executor exists.

For interview-depth physics of the design, see the Corvex deep-dive study doc.
