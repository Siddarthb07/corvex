# S2 — second physical Windows host

`claim_allowed` stays false until `reports/live_second_host.json` exists with
`source: wevtutil` from a **second physical** Windows PC. This machine
(`cyborg_1` / `host-win`) already counts as host-1 for Phase 0 capture. Do not
record S2 from it.

Do not copy `reports/live_second_host.TEMPLATE.json` by hand. Do not use Docker,
fixtures, or `offline_lab_replay`.

## On PC-2 (elevated PowerShell)

Clone or copy the same git checkout, then use the copy-paste list in
[`s2-pc2-commands.md`](s2-pc2-commands.md), or:

```powershell
cd <repo>
powershell -ExecutionPolicy Bypass -File scripts\run_s2_second_host.ps1
```

The script:

1. Refuses to run if the hostname is `cyborg_1` (host-1).
2. Unlocks Stage B locally (`stage-b-lab-unlock`). That does **not** flip
   `claim_allowed`.
3. Runs `corvex sensor-windows --require-live --once` into `runs/live-host-2`.
4. Calls `python scripts/record_live_host_evidence.py --run-dir runs/live-host-2`.

Copy `reports/live_second_host.json` back to the author checkout if PC-2 is a
separate clone, then:

```bash
python -m corvex claim-gates
```

Expect `live_second_host.pass=true` only when `sensor_status.source=wevtutil`
and Security/channel events were seen. Then keep the same host in the home-lab
capture window (see `labs/benign/home-lab-2026-08-13/README.md` Phase 1) so S5
can reach three hosts.
