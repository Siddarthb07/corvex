# Home-lab capture protocol

Passive Sysmon (and optional Security / Firewall) capture for the **pure-benign**
gate. This is the preferred path to a PASS-eligible corpus.

## Rules

1. **Start capture first** — enable Sysmon logging to JSON/EVTX→JSON before you
   decide what “interesting” admin work looks like.
2. **Do not peek to curate** — do not skim events mid-window and drop noisy hosts
   or quiet the stream so Corvex “behaves.” Close the window, then convert.
3. **Routine work only** — RDP to lab VMs, patch installs, AD joins, SCCM-like
   management if you have it, browser, IDE. No red-team scripts in this corpus.
4. **Prefer a hub role** — if you can, include a jump box / DC / management host
   so `hub_coverage` is not GAP by construction.
5. **Minimum for the gate** — ≥ 3 enrolled hosts and ≥ 72 host-hours
   (sum over hosts of each host’s time span).

## Manifest template

Copy to `labs/benign/home-lab-<date>/manifest.json` when the window closes:

```json
{
  "name": "home-lab-<date>",
  "corpus_kind": "home_lab_capture",
  "source": {
    "project": "local-home-lab",
    "capture_start_utc": "YYYY-MM-DDThh:mm:ssZ",
    "capture_end_utc": "YYYY-MM-DDThh:mm:ssZ",
    "note": "Passive Sysmon; not inspected until window closed."
  },
  "raw_glob": "raw/*.jsonl",
  "host_map": {},
  "attack_windows": [],
  "roles": {},
  "bars_locked": "2026-07-25"
}
```

## Convert + score

Drop exports under `raw/`, then:

```bash
python scripts/run_benign_baseline.py --corpus labs/benign/home-lab-<date> --adapter os_wide
```

Standing public claim stays until gate is **PASS** (and hub GAP is closed or
explicitly residual).
