# otrf-empire-psexec

Public OTRF/Security-Datasets slice (captured telemetry — not hand-authored).

- **corpus_kind:** `mixed` (attack + ambient). Cannot PASS the pure-benign gate.
- **Source:** https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip
- **Raw:** `raw/` (gitignored). Re-fetch: `python scripts/fetch_otrf_corpus.py --name otrf-empire-psexec`

See `labs/benign/README.md` and `future-plans.md` § Benign corpus plan.
