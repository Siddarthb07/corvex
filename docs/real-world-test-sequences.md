# Real-world test sequences

Operator runbook that chains Corvex’s real-world gates in order. Reuses existing
CLIs and scripts — no new scoring harness.

**Bar source of truth:** [`future-plans.md`](../future-plans.md) (do not fork
numbers here). Deep runbooks: [`stranger-checklist.md`](stranger-checklist.md),
[`os-wide-sensor.md`](os-wide-sensor.md),
[`labs/benign/README.md`](../labs/benign/README.md),
[`labs/benign/home-lab-capture/README.md`](../labs/benign/home-lab-capture/README.md).

## Standing public claim

Until **S5** primary + secondary PASS (hub GAP called out if residual), nothing
about Corvex is described publicly as more than:

> Research correlator — holds up against synthetic ATT&CK-shaped fleets; not yet
> validated against real telemetry or benign baselines.

## Sequence map

```text
S0 Preflight ──► S1 Stranger BYO ──┐
              └► S2 Second host ───┼──► S6 Claim gates
S3 Live sensor ──► S4 Fuse ──► S5 Benign ──┘
```

S1 and S2 can run in parallel (both block `claim_allowed`). S5 is the
highest-leverage gate and may take days/weeks of capture before scoring.
**Do not peek or curate mid-window on S5. Do not hand-craft benign noise.**

## Prerequisites

| Need | Notes |
|------|--------|
| Python 3.9+ | `pip install -e ".[dev]"` |
| Enrollment | `corvex init` or auto on first replay → `~/.corvex/enrollment.json` |
| Windows elevation | Security channel via wevtutil; Sysmon preferred |
| Second physical PC | Required for S2 — not Docker, not fixture |
| Human outsider | Required for S1 (Jack or equivalent); author cannot self-attest |
| Docker | Optional — live/breaktest labs are regression only, not real-world proof |

---

## S0 — Preflight (synthetic regression)

**Goal:** Refuse real-world work on a broken checkout.  
**Owner:** Author. **Duration:** same day.

| Step | Command / check | Pass |
|------|-----------------|------|
| Install | `pip install -e ".[dev]"` | import works |
| Unit | `pytest tests -q` | all green |
| Replay smoke | `corvex replay train/train-lateral.jsonl --out-dir runs/rw-preflight` | campaigns written |
| CDN control | `python scripts/run_cdn_bridge_safe.py` | report ok |
| Claim honesty | `corvex claim-gates` | expect `claim_allowed=false` today |

**Anti-patterns:** Running T3 fleets “to prove readiness.” T2 is already cleared;
more synthetic HELD is not real-world validation.

**Evidence:** none under `reports/` required beyond existing synthetic reports.

---

## S1 — Stranger Windows BYO

**Goal:** Independent human completes Windows export → `byo-windows` → dash.  
**Owner:** Jack (or any non-author human). Author must **not** write `pass: true`.

Full rule set: [`stranger-checklist.md`](stranger-checklist.md).

1. Clone + install; do **not** retune the correlator.
2. Prefer a real multi-host 4624 export. Fixture is rehearsal only:

```bash
corvex byo-windows fixtures/windows_security_sample.json \
  --host-map fixtures/windows_host_map.json \
  --out-dir runs/stranger-wedge
corvex dash --run-dir runs/stranger-wedge --build
```

3. Confirm a multi-host campaign and honest reconstruction gaps (not invented
   completeness).
4. Write `reports/stranger_dry_run.json`:

```json
{
  "pass": true,
  "operator": "NAME",
  "attestation_kind": "human",
  "date": "YYYY-MM-DD",
  "note": "Completed Windows export → byo-windows → timeline without author help.",
  "run_dir": "runs/stranger-wedge"
}
```

5. Jack-only key custody (author `--hmac` does **not** unlock claims):

```bash
corvex stranger-keygen
corvex sign-stranger-attestation
```

**Pass:** signed human attestation; private key at
`reports/.stranger_ed25519_private.pem` (gitignored), held by the stranger.  
**Fail:** agent / `attestation_kind≠human`; author self-attest; treating unsigned
JSON as claim unlock.

**Evidence:** `reports/stranger_dry_run.json` (+ signature fields after sign).

---

## S2 — Second physical Windows host

**Goal:** Elevated live wevtutil on a **second physical** PC.  
**Owner:** Author on that machine (not Docker, not fixture).

```bash
corvex sensor-windows --follow --require-live --run-dir runs/live-host-2 \
  --channels security,sysmon,firewall,powershell \
  --host-id host-pc-2 --producer prod-pc-2

python scripts/record_live_host_evidence.py --run-dir runs/live-host-2
```

Sensor ops: [`os-wide-sensor.md`](os-wide-sensor.md). Stage B may need
`corvex stage-b-lab-unlock --reason "…"` for local sensor work — that does
**not** flip `claim_allowed`.

**Pass:** `reports/live_second_host.json` present with a live wevtutil path (not
`offline_lab_replay` / Docker).  
**Fail:** faking from lab JSONL or writing the JSON by hand.

**Evidence:** `reports/live_second_host.json`.

---

## S3 — Live OS-wide sensor path

**Goal:** Prove live channel readiness on each Windows host that will feed S5.  
**Owner:** Author. Not a claim unlock by itself.

On each enrolled host:

1. Elevated Security channel; Sysmon preferred; Firewall/PowerShell as available.
2. Run until bookmarks advance under `<run-dir>/sensor_bookmarks.json`:

```bash
corvex sensor-windows --follow --require-live --run-dir runs/os-wide-live \
  --channels security,sysmon,firewall,powershell \
  --host-id host-pc --producer prod-pc
```

3. If Sysmon is missing, degrade honestly — document channel status; do not invent
   events.

**Pass:** non-zero live hits on Security (or elevation failure documented and
fixed before S5).  
**Anti-patterns:** Using `--fixture` and calling it live evidence.

---

## S4 — Multi-host offline fuse

**Goal:** Merge one lab JSONL stream with one PC sensor stream honestly.  
**Owner:** Author.

```bash
corvex fuse-run \
  --lab labs/breaktest/shared/events.jsonl \
  --pc runs/os-wide-live \
  --out-dir runs/pc-and-lab

corvex dash --run-dir runs/pc-and-lab
```

`fuse-run` mode is `offline_lab_replay` — file merge + correlator, **not**
JetStream / not a concurrent product bus.

**Pass:** fuse completes; dash shows campaigns spanning both sources;
reconstruction lists real gaps.  
**Anti-patterns:** Claiming live multi-writer bus validation. JetStream remains
stub — out of scope for these sequences.

---

## S5 — Pure-benign baseline (highest priority)

**Goal:** Score ≥72 host-hours of passive home-lab capture against locked FP bars.  
**Owner:** Author. Protocol:
[`labs/benign/home-lab-capture/README.md`](../labs/benign/home-lab-capture/README.md).

Bars locked **2026-07-25** in `future-plans.md` — decide PASS/FAIL against them
**before** looking at the number.

### S5a — Start capture (day 0)

1. Create `labs/benign/home-lab-<date>/` with empty `raw/` and draft
   `manifest.json` (`corpus_kind: home_lab_capture`, `bars_locked: "2026-07-25"`).
2. Enable Sysmon JSON (and optional Security) on **≥3 hosts**; include a
   jump/management host so hub is not GAP by construction.
3. Start logging **before** deciding what “interesting” admin work is.
4. Record `capture_start_utc` in the manifest.

### S5b — Routine window

- Routine admin only: RDP, patches, AD joins, browser, IDE.
- **No** red-team / ART in this corpus.
- **Do not peek or curate** mid-window.
- Stop only when host-hours ≥ **72** **and** distinct hosts ≥ **3**
  (sum over hosts of each host’s time span).

### S5c — Close, convert, score

1. Set `capture_end_utc`; drop exports under `raw/`; fill `host_map` / `roles`.
2. Score:

```bash
python scripts/run_benign_baseline.py \
  --corpus labs/benign/home-lab-<date> \
  --adapter os_wide
```

3. Report under `reports/benign_baseline_<corpus>.{json,md}` must quote bars
   verbatim:

| Bar | PASS |
|-----|------|
| Size | ≥72 host-hours, ≥3 hosts, kind `pure_benign` or `home_lab_capture` |
| Primary | `FP_iso / H ≤ 1/1000` |
| Secondary | `FP_seal / H ≤ 1/100` |
| Hub | Per-host degree stats; if no hub-shaped host → `hub_coverage: GAP` (gate incomplete for fix #9 — not a silent PASS) |

**Forbidden:** treating OTRF mixed smoke as PASS (`corpus_kind: mixed` →
INCOMPLETE); hand-crafted SCCM/RDP noise; retuning thresholds after FAIL;
deciding PASS after seeing the number.

OTRF fetch remains adapter smoke only:

```bash
python scripts/fetch_otrf_corpus.py
python scripts/run_benign_baseline.py \
  --corpus labs/benign/otrf-empire-psexec --adapter otrf
```

**Evidence:** `reports/benign_baseline_<corpus>.json` + `.md`.

---

## S6 — Claim gates closeout

**Goal:** Flip `claim_allowed` only when all code gates are green.  
**Owner:** Author after S1 + S2 (and S5 before softening public claim language).

```bash
# After human stranger PASS only — create empty marker (do not invent attestation):
#   reports/stage-b-allowed

corvex stage-b-check
corvex claim-gates
```

Writes `reports/claim_gates.json`. Exit 0 only when `claim_allowed=true`
([`corvex/eval/claim_gates.py`](../corvex/eval/claim_gates.py): held-out benign
FCR, stranger Ed25519, live second host, integrity, etc.).

**Still locked after claim:** live OS quarantine (`contain/live.py`), incomplete
L1 checklist, JetStream bus.

Public README / portfolio copy may soften the standing claim sentence only after
**S5 primary + secondary PASS** (hub GAP residual called out explicitly).

---

## Evidence checklist

| Gate | Artifact | Who writes it | Unlocks |
|------|----------|---------------|---------|
| S1 Stranger | `reports/stranger_dry_run.json` (+ Ed25519 sig) | Human outsider (Jack) | Part of `claim_allowed`; Stage B honest path |
| S1 Key | `reports/.stranger_ed25519_private.pem` | Stranger only (gitignored) | Signature custody — not author |
| S2 Second host | `reports/live_second_host.json` | Author on 2nd physical PC | Part of `claim_allowed` |
| S5 Benign | `reports/benign_baseline_<corpus>.{json,md}` | Author after capture window | Soften public claim; FP honesty |
| S6 Stage B marker | `reports/stage-b-allowed` (empty file) | Author **after** stranger PASS | `stage-b-check` allowed |
| S6 Claim snapshot | `reports/claim_gates.json` | `corvex claim-gates` | Machine-readable `claim_allowed` |

Templates (if present): `reports/live_second_host.TEMPLATE.json`,
`reports/habit_loop.TEMPLATE.json`. Habit-loop is Stage B quality evidence only
— **not** a stranger substitute.

---

## Explicitly out of these sequences

- T3 fleets / more synthetic HELD to “prove” readiness
- Live IsolateHost / EDR / VLAN actuators
- Author minting stranger keys or Docker-faking `live_second_host`
- Habit-loop as stranger substitute
- Hand-crafted “looks like SCCM” benign JSONL
- Softening the standing public claim before S5 PASS
