# 30-day GitHub commit cadence (honest)

**Goal:** a public trail of real evaluation and Stage D progress — not empty daily commits.

## Rule

Commit **only when there is a real delta**: code, docs, or a freshly regenerated audit/report that differs from HEAD.  
Forbidden: empty commits, whitespace churn, flipping checklist bits without evidence, metaphor-only README edits.

## Cadence (next ~30 days from 2026-07-22)

| Days | Focus | Expected commits/week |
|------|--------|------------------------|
| 1–7 | Public-repo hygiene: README/RESULTS, dashboard, CI green, first push | 3–5 real |
| 8–14 | Stage D evidence work (typed authz design, nonce durability, tests) — checklist stays false until proven | 3–5 |
| 15–21 | Stage B sensor path realism (one OS export fixture, mTLS doc) — no fake retention | 2–4 |
| 22–30 | Hardening + disclosure polish; freeze a “decision-ready” RESULTS snapshot | 2–4 |

Optional **daily** automation: run `scripts/daily_audit.ps1`. It regenerates reports and commits **only if `git status` is dirty**.

## Commands

```powershell
# Manual honest day
cd C:\Users\siddu\Projects\campaignfuse
.\scripts\daily_audit.ps1

# First-time remote (once)
gh repo create campaignfuse --private --source=. --remote=origin
# or --public when ready; do not claim OSS traction until retention met
git push -u origin HEAD
```

## Windows Task Scheduler (optional)

1. Action: `powershell.exe -File C:\Users\siddu\Projects\campaignfuse\scripts\daily_audit.ps1`
2. Trigger: daily ~18:00 local
3. Start in: `C:\Users\siddu\Projects\campaignfuse`
4. If the script prints `NO_CHANGES`, that day has **no commit** — correct behavior.

## What “good” looks like on GitHub in 30 days

- Green CI running seal + train smoke + pytest
- `reports/RESULTS.md` updated when metrics change
- `reports/dashboard/` regenerable via `cfuse dash --build`
- Stage D checklist still honest (mostly false) unless items are evidenced
- Commit messages describe *why* (eval refresh, dry-run fix, disclosure) — not “day 12”
