# Open-source attack corpora (external authorship)

Primary independence stress for Corvex: **OTRF / Security-Datasets** captures
(and MITRE ATT&CK Evals Round 1 APT3 via Caldera), **not** Corvex-authored
`fleet20` / `fleet-limits` / `fleet-intensive` manifests.

| Is | Isn't |
|----|--------|
| Telemetry someone else captured | Author-tuned synthetic fleets |
| Legible public provenance + URL | Enterprise estate validation |
| Observational multi-host / fusion metrics | Ground-truth F1 we wrote ourselves |

`claim_allowed` stays **false**.

## Catalog

[`catalog.json`](catalog.json) lists zip/tar.gz paths under
https://github.com/OTRF/Security-Datasets

## Run

```bash
python scripts/fetch_opensource_corpora.py
python scripts/run_opensource_attack_eval.py
```

Optional larger Empire APT3 compound:

```bash
python scripts/fetch_opensource_corpora.py --full --only otrf-empire-apt3
python scripts/run_opensource_attack_eval.py --only otrf-empire-apt3
```

Reports: `reports/opensource_attack_eval.md`

## vs author fleets

Author fleets remain useful as **engineering probes** (known break shapes).
They are **secondary** for any claim about independence or “how capable is it.”
Lead with this open-source scoreboard instead.

## Windows Defender note

Raw Empire/Covenant JSON dumps are often quarantined as PUA. Fetch writes
`*.sanitized.jsonl` (drops `CommandLine` / `ScriptBlockText`, keeps auth/net/dns
fields). Re-fetch with `--force` if AV deleted a prior raw extract.
