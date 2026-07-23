# Corvex — future plans

Where Corvex is today: observe/correlate ready; **reconstruction + quarantine honesty shipped**; contain live executor still locked; sealed eval honest but synthetic. Held-out still ties Corvex to detector-only on some packs (both F1 1.0) — that’s the soft spot.

**Just shipped:** `corvex reconstruct` / `corvex quarantine` (+ status); replay writes `reconstruction.json`; dashboard Reconstruction + Quarantine panels; [`docs/how-corvex-works.md`](docs/how-corvex-works.md); deep-dive at `portfolio-study/Corvex_DEEP_DIVE.md`.

## 1. Make the correlator premise undeniable

- Add sealed packs where **single-host / detector-only fail** and **cross-host fusion wins**
- Keep publishing P+R, benign FCR, vs B1, per-family — if fusion lift is real, it’ll show up as a gap, not a story
- **Scaffolded:** `fusion_chain` family; detector-only per-key (no cross-key merge); `seal-day0` registers fusion-chain packs. **Next:** `corvex seal-day0 --force` then publish numbers.

## 2. Hard break-testing: 4–5 hosts + real attack repos

- 5-host break-test lab + ART-style manifests already scaffolded under `labs/breaktest/`
- Score P+R, FCR, dry-run false-isolate; **publish break points**
- Reconstruction manifests round-trip as regression only (not weaponized packs)

## 3. One real sensor path

- Windows Security → `corvex adapt-windows` → BYO → correlator → dash/reconstruct
- Harden [`docs/sensor-windows.md`](docs/sensor-windows.md) until a stranger can follow it

## 4. Deploy shape (observe + honest quarantine status)

- Admin-box correlator + dash; quarantine panel shows dry-run / lab_flag / blocked
- Keep live isolate clearly off until P4

## 5. Containment — isolate stays on the roadmap

Attempt quarantine always; enforce only when mode allows:

| Mode | Meaning |
|------|---------|
| `dry_run` | Log IsolateHost only |
| `lab_flag` | Sandbox flag files (virtual hosts) |
| `blocked` | Refuse — say cannot quarantine real hosts |

Live OS/EDR/VLAN executor only after L1 evidenced + hostile-bus + published false-isolate rates. **Never bullshit success.**

## 6. External check

- Stranger dry-run of Windows → timeline / reconstruct
- If they shrug, don’t unlock “useful on real attacks”

## What not to do next

- More pitch polish / GIFs
- Claiming commercial-tool parity
- Arming `CORVEX_CONTAIN` without an executor + hostile-bus tests
- Inventing reconstruction hops or CVEs when status is partial/insufficient

## If only one thing

Re-seal and publish fusion lift (or the honest lack of it) on held-out + break-test — then harden the Windows BYO path so reconstruction + quarantine honesty show up on stranger logs.
