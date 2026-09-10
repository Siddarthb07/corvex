# Habit-loop (~15 minutes)

External operator produces a correct timeline from a **scripted** pack without
author help. This is Stage B quality evidence. It does **not** flip
`claim_allowed` and does **not** replace `stranger_dry_run.json` or
`operator_replication.json`.

No Atomic Red Team payloads are vendored. Do not download malware.

## Commands

```bash
git clone https://github.com/Siddarthb07/corvex.git
cd corvex
python -m pip install -e ".[dev]"

corvex replay train/train-lateral.jsonl --out-dir runs/habit-loop
corvex dash --run-dir runs/habit-loop --build
```

Pass: dash shows a multi-host campaign for the lateral pack; reconstruction is
not invented (`complete` or `partial` with listed gaps).

Copy [`reports/habit_loop.TEMPLATE.json`](../reports/habit_loop.TEMPLATE.json) to
`reports/habit_loop.json` (gitignored if present; send the JSON to the author):

```json
{
  "habit_loop_pass": true,
  "operator": "NAME",
  "date": "YYYY-MM-DD",
  "run_dir": "runs/habit-loop",
  "note": "Replay train-lateral.jsonl; timeline matched pack without author help."
}
```

`habit_loop_pass` must be written by the operator. Author may not set `true`
for themselves.
