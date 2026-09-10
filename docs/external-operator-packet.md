# External operator packet (~45 minutes)

Someone **other than the author** runs this. The author does not sit on the call
or type commands. Do not retune the correlator. Pick **one rung**. Return the
artifact below.

Jack's signed `reports/stranger_dry_run.json` is a **different** file. Do not
overwrite it. Write `reports/operator_replication.json` (from the template).

Author HMAC and agent/Cursor runs do not count. `attestation_kind` must be
`human`.

Standing claim stays: research correlator on synthetic fleets; not field
validated. Completing a rung does not flip `claim_allowed` by itself (S2 live
second host is a separate gate).

## Return artifact

1. `reports/operator_replication.json` filled from
   [`reports/operator_replication.TEMPLATE.json`](../reports/operator_replication.TEMPLATE.json)
2. SHA-256 of `runs/<your-run>/events.jsonl` (or the scorer report for rung 2)
3. One paragraph: what broke, what looked incomplete, reconstruction status
   (`complete` / `partial` / `insufficient_evidence`)
4. Optional: redacted screenshot of the dash reconstruction panel (gaps listed,
   not invented)

Sign if you can hold a key the author does not have:

```bash
corvex stranger-keygen
# keep reports/.stranger_ed25519_private.pem; do not send it
```

If Jack already holds the stranger key, a second operator may leave the JSON
unsigned and still count as **replication evidence**. Unsigned JSON still does
**not** unlock `claim_allowed`.

---

## Rung 1 — fixture replay (weak, easiest)

Proves install + honest reconstruction gaps. **Not** their telemetry.

```bash
git clone https://github.com/Siddarthb07/corvex.git
cd corvex
python -m pip install -e ".[dev]"

corvex byo-windows fixtures/windows_security_sample.json \
  --host-map fixtures/windows_host_map.json \
  --out-dir runs/operator-rung1

corvex dash --run-dir runs/operator-rung1 --build
```

Confirm the dash shows a multi-host timeline **or** lists reconstruction gaps
instead of inventing completeness. Hash `runs/operator-rung1/events.jsonl`.

Set `"rung": 1` in the attestation.

---

## Rung 2 — public OTRF corpus (medium, replication)

Same public Mordor slice the author already used. Call this **replication**, not
field validation. Mixed attack+ambient: gate stays `INCOMPLETE` by design.

```bash
python scripts/fetch_otrf_corpus.py
python scripts/run_benign_baseline.py \
  --corpus labs/benign/otrf-empire-psexec \
  --adapter otrf
```

Hash `reports/benign_baseline_otrf-empire-psexec.json` if present, else the
console report path printed by the scorer. Do not retune bars in
`future-plans.md`.

Set `"rung": 2`.

---

## Rung 3 — their logs (the one that counts)

Export **their** multi-host Windows Security 4624 JSON (or Sysmon JSON the
adapter accepts). They keep the raw files. No retune.

```bash
corvex byo-windows path/to/their_4624.json \
  --host-map path/to/their_host_map.json \
  --out-dir runs/operator-rung3

corvex dash --run-dir runs/operator-rung3 --build
```

`their_host_map.json` maps Computer names to `host-a` / `host-b` / … enrolled
ids (see `fixtures/windows_host_map.json`). Prefer two or more real computers.

Set `"rung": 3`. Do not email raw EVTX to the author unless they asked.

---

## Habit-loop (optional +15 min)

Scripted purple path without author help: [`docs/habit-loop.md`](habit-loop.md).
Fills `reports/habit_loop.json`. Stage B quality only; not a stranger substitute.

## After you send the artifact

Author writes `reports/external_replication.md` (who, rung, hashes, what broke)
and leaves public README claim language unchanged until S5 benign PASS.
