# Stranger checklist (P3 claim gate)

Someone **other than the author** must complete this and write `reports/stranger_dry_run.json`.

## Steps

1. Clone the repo; install (`pip install -e .`).
2. Run `corvex seal-day0` only if needed for local enrollment — do **not** retune correlator.
3. Export Windows Security 4624 JSON from a multi-host lab (or use `fixtures/windows_security_sample.json`).
4. Run:

```bash
corvex byo-windows fixtures/windows_security_sample.json \
  --host-map fixtures/windows_host_map.json \
  --out-dir runs/stranger-wedge
corvex dash --run-dir runs/stranger-wedge --build
```

5. Confirm the dashboard shows a multi-host campaign and a reconstruction status that is not invented (gaps listed if partial).
6. Write attestation:

```json
{
  "pass": true,
  "operator": "NAME",
  "date": "YYYY-MM-DD",
  "note": "Completed Windows export → byo-windows → timeline without author help.",
  "run_dir": "runs/stranger-wedge"
}
```

Save as `reports/stranger_dry_run.json`.

## After stranger PASS — Stage B marker

```bash
# Author (or CI) only after stranger_dry_run.json has pass:true:
# Create an empty marker file — do not invent the attestation.
#   reports/stage-b-allowed

corvex stage-b-check   # allowed:true only if Stage A PASS + stranger pass + marker
corvex claim-gates     # claim_allowed still needs all P3 gates
```

**Lab override (not for claims):** `CORVEX_STAGE_B=1` unlocks Stage B stubs locally without stranger attestation.

After Stage B unlock, OS-wide collection: see [`docs/os-wide-sensor.md`](os-wide-sensor.md).

## Rules

- Author may not write `pass: true` for themselves.
- Shrugging / cannot finish → leave file absent or `"pass": false`.
- File present with `"pass": false` does **not** count as stranger success.
- This gate alone does not unlock live contain.
