# Corvex — future plans

Where Corvex is today: observe/correlate ready, contain locked, sealed eval honest but synthetic. Held-out still ties Corvex to detector-only (both F1 1.0) — that’s the soft spot.

**Build status (scaffolded, eval not re-run yet):** fusion_chain family + honest per-key detector-only ablation; 5-host break-test lab + attack-repo manifests; Windows auth → BYO adapter; break-point reporter. Next action: `corvex seal-day0 --force` then sealed eval / breaktest scoring.

## 1. Make the correlator premise undeniable

- Add sealed packs where **single-host / detector-only fail** and **cross-host fusion wins**
- Keep publishing P+R, benign FCR, vs B1, per-family — if fusion lift is real, it’ll show up as a gap, not a story
- **Scaffolded:** `fusion_chain` family in `feeder.py`; detector-only now groups per alert key (user / dst / host) without cross-key merge; `seal-day0` registers `train-fusion-chain` + `held-fusion-chain` (5 hosts). Re-seal + eval still needed to publish numbers.

## 2. Hard break-testing: 4–5 hosts + real attack repos

Synthetic packs are too clean. Stress where Corvex actually fails:

- Spin a lab of **4–5 hosts** (not the current 2–3 hop theatre)
- Drive campaigns from **public GitHub attack / red-team repos** (known TTPs, not hand-authored JSONL) — adapted into Corvex’s event schema / BYO ingest
- Score the same bars: P+R, benign FCR, vs B1 / detector-only, time-to-correlate, dry-run false-isolate
- **Publish the break points** — missed hops, over-merged campaigns, timing windows that collapse, hosts that never fuse — not just the wins
- Treat this as the honesty gate before claiming sensor or network-deploy readiness
- **Scaffolded:** `labs/breaktest/` (5-host compose), ART-style sequential manifests
  (`art_lateral_chain`, `art_cred_hop`, `art_slow_drip`, `art_recon_pivot`,
  `art_recon_exfil_split`), manifest-driven attacker, `corvex build-breaktest`,
  `scripts/record_art_breaktest.py` (score + live record + video).

## 3. One real sensor path (not more demos)

- One OS export → JSONL → correlator on a lab machine (Windows Event / auth logs is enough)
- Document the exact pipeline strangers can copy
- This is the unlock before JetStream/mTLS theater
- **Scaffolded:** `corvex adapt-windows`, `corvex/adapters/windows_security.py`, `docs/sensor-windows.md`, `fixtures/windows_security_sample.json`. Stage B live sensors stay gated.

## 4. Deploy shape for a stranger’s network

- Harden the “admin box that can *see* events” story: bind, enrollment, BYO ingest, dash
- Optional: systemd/docker compose for correlator+dash only (no contain)
- Keep live isolate clearly off

## 5. Containment evidence, not toggle theater

Only flip L1 checklist bits when evidenced:

- Typed authz ≠ HMAC
- Durable anti-replay
- Blast-radius caps with tests
- Then: dry-run isolate **false-isolate rate** on a larger set — publish nonzero if that’s the truth

## 6. External check (cheap, high signal)

- One person outside you runs sealed/blind timeline scoring (`stranger_dry_run`)
- If they shrug, don’t unlock sensors/“share” claims

## What not to do next

- More GIFs / pitch polish
- Claiming commercial-tool parity
- Arming `CORVEX_CONTAIN` without an executor + hostile-bus tests
- Another Stage letter roadmap doc

## If only one thing

Harden the eval so cross-host correlation beats detector-only on held-out — then prove it still holds (or document where it breaks) on a 4–5 host lab driven by real public attack repos. Everything else (sensors, network deploy, contain) reads stronger once that gap is real.
