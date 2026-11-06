# S5 via AWS — three-host pure-benign window

*Locked bars (2026-07-25) do not change for cloud VMs.*

## Can two AWS instances alone pass S5?

**No.** The corpus floor is **≥3 distinct hosts** and **≥72 host-hours**.
Two EC2 Windows boxes can never PASS, no matter how long they run.

## Layout that can PASS (recommended)

| Role | Host | Notes |
|------|------|--------|
| Hub / jump | `cyborg_1` (existing lab PC) or a 3rd EC2 | Prefer a management-shaped host so `hub_coverage` is not GAP by construction |
| Worker A | AWS EC2 Windows Server (t3.medium+) | Sysmon + Security; routine admin only |
| Worker B | AWS EC2 Windows Server (t3.medium+) | Same |

**Minimum wall clock:** 72 / 3 = **24 hours** if all three log continuously.
Longer is safer (idle gaps shrink per-host span).

Alternatives: **3× AWS Windows** (no local hub), or **2× AWS + author PC** (not Cyborg if Cyborg is already counted elsewhere — any three distinct enrolled host_ids).

## Honesty rules (unchanged)

- `corpus_kind`: `home_lab_capture` (or `pure_benign`).
- **No** Atomic / ART / red-team in this window.
- **Do not peek or curate** mid-window.
- Score once after close with `scripts/run_benign_baseline.py`.
- Decide PASS/FAIL against locked bars **before** reading the number.

## Prerequisites

1. AWS CLI configured (`aws sts get-caller-identity` must succeed).
2. Key pair + security group allowing RDP from your IP only.
3. Corvex checkout on a fuse host (author PC) with enrollment secrets.
4. Sysmon installed on each Windows host (SwiftOnSecurity or vendor config is fine).

## Provision (2 EC2 + use Cyborg as host-3)

```powershell
# From author PC after: aws configure
cd C:\Users\siddu\Projects\corvex
powershell -ExecutionPolicy Bypass -File scripts\s5_aws_provision.ps1 `
  -KeyName YOUR_KEY `
  -AllowCidr "YOUR.PUBLIC.IP.0/32"
```

Script writes instance ids / public DNS under `labs/benign/aws-s5-<date>/aws_inventory.json`.
It does **not** start the capture clock until you run the bootstrap on each host.

## Capture start (S5a) — same day on all three

On **each** of the three hosts (elevated PowerShell), after copying Corvex or a sensor stub:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\s5_host_capture_start.ps1 `
  -CorpusName aws-s5-2026-11-06 `
  -HostId <stable-slug>
```

Record `capture_start_utc` in `labs/benign/aws-s5-<date>/manifest.json` only after all three sensors are up.

## Routine window (S5b)

- RDP, patches, browser, IDE, file shares between the three.
- No red-team.
- Do not score mid-window.
- Stop when sum of per-host time spans ≥ 72 **and** distinct hosts ≥ 3.

## Close + score (S5c)

1. On each host: `scripts\s5_host_capture_export.ps1` → drop JSONL under `raw/<host_id>/`.
2. On fuse host:

```bash
python scripts/run_benign_baseline.py \
  --corpus labs/benign/aws-s5-<date> \
  --adapter os_wide
```

3. Commit `reports/benign_baseline_aws-s5-<date>.{json,md}` — PASS, FAIL, or GAP (hub) as written.
4. Tear down EC2 when exports are hashed (`scripts\s5_aws_teardown.ps1`).

## Cost ballpark

Two t3.medium Windows (~$0.05–0.08/hr each) × 24–48 h ≈ **$5–15** plus EBS, before the third host if it is also EC2.
Cyborg as host-3 avoids a third instance charge.

## What this does **not** unlock

- Completing S5 does not flip enterprise EDR parity.
- It only closes the pure-benign multi-host bar named in the TETC draft.
- Adaptive retune after FAIL is forbidden without a new locked bar date.
