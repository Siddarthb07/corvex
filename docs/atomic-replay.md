# Atomic Red Team playbook replay (lab only)

*Updated: 2026-09-08*

Corvex can **re-run the same ATT&CK chain** on an authorized Windows lab host by
orchestrating an operator-installed [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
via `Invoke-AtomicRedTeam`. This is the real-host recreation path.

Synthetic breaktest manifests (`build-breaktest` / Docker `art_attack`) stay for
offline scoring. **`corvex reconstruct` remains narrative** — playbooks are the
reusable attack.

## Honesty

| Is | Isn't |
|----|--------|
| Lab purple-team orchestrator | Vendored malware / Atomic YAML in-repo |
| Same playbook → same technique order | Proof Corvex “works on real attacks” |
| Observe-only sensor capture | Live quarantine / claim unlock |
| Curated technique → test_number map | Red-team kit for third parties |

**`claim_allowed` does not flip** because you ran Atomic tests. Standing public
claim stays synthetic-fleet research until stranger + second-host gates pass.

## Gates (all required)

1. `CORVEX_ATOMIC=1` in the shell
2. `--i-authorize-lab-ttp` on the CLI
3. Stage B unlock: `corvex stage-b-lab-unlock --reason 'atomic lab replay …'`
   (or full Stage B marker path)

Missing any gate → refuse closed.

## Install Atomic Red Team (operator machine)

Corvex does **not** ship atomics. On the lab Windows host:

1. Install [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam)
2. Clone or download atomics; set `ATOMICS_PATH` to the `atomics` folder
3. Confirm: `Get-Command Invoke-AtomicTest`

## Playbook flow

```text
breaktest manifest ──► corvex atomic-bind ──► *.atomic.json
                                              │
                     ┌── sketch (unchanged) ──┘
                     │   build-breaktest / Docker art_attack
                     │
                     └── atomic (this path)
                         sensor-windows --follow
                         corvex atomic-run --role host-a …
                         correlate / reconstruct
```

### Bind

```bash
corvex atomic-bind labs/breaktest/manifests/art_lateral_chain.json \
  --out labs/breaktest/manifests/art_lateral_chain.atomic.json
```

Fills curated defaults for `T1078`, `T1021` / `T1021.001`, `T1041`, `T1046`,
`T1071.004`, `T1110`, `T1190`. Unlisted techniques get `atomic: null` and an
`atomic_gaps` entry (honest).

Seeded playbook: [`labs/breaktest/manifests/art_lateral_chain.atomic.json`](../labs/breaktest/manifests/art_lateral_chain.atomic.json).

### Why these test numbers

Bindings use **test_number: 1** as a low-friction default per technique. Verify
against your local atomics folder before a live run — ART test indices change
across releases. Prefer tests that create observable auth / net / DNS telemetry
without destructive wipe. Override per step:

```json
"atomic": {
  "technique": "T1041",
  "test_number": 2,
  "get_prereqs": true,
  "cleanup": true,
  "input_args": {}
}
```

### Run one host role

Multi-host chains: each PC runs only its `--role`. MVP does not WinRM-spray.

```powershell
$env:CORVEX_ATOMIC = "1"
corvex stage-b-lab-unlock --reason "atomic lab replay on host-a"
corvex atomic-run labs/breaktest/manifests/art_lateral_chain.atomic.json `
  --role host-a `
  --run-dir runs/atomic/lateral-a `
  --i-authorize-lab-ttp
```

`--dry-run` journals planned calls (hashes only) without invoking ART.

### Capture + correlate (helper)

```powershell
# From repo root — starts sensor follow, runs atomic-run, stops sensor, reconstructs
.\scripts\run_atomic_playbook.ps1 `
  -Playbook labs\breaktest\manifests\art_lateral_chain.atomic.json `
  -Role host-a `
  -RunDir runs\atomic\lateral-a
```

Or fixture CI path (no live wevtutil):

```bash
corvex atomic-lab labs/breaktest/manifests/art_lateral_chain.atomic.json \
  --role host-a \
  --fixture fixtures/os_wide/multi_channel.jsonl \
  --i-authorize-lab-ttp \
  --dry-run
```

Reports: `reports/atomic_run_<campaign_id>.json` — evidence only, **no claim upgrade**.

## Journal

`runs/.../atomic_exec.jsonl` stores technique, test #, phase, return codes, and
**stdout/stderr SHA-256** — not payload bodies.

## Related

- [`labs/breaktest/README.md`](../labs/breaktest/README.md) — sketch vs atomic
- [`docs/sensor-windows.md`](sensor-windows.md) — observe-only capture
- [`future-plans.md`](../future-plans.md) — claim_allowed gates
