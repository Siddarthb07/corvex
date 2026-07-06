# Stage C — OSS

Public install:

```bash
pip install -e .
cfuse --help
```

Gates before calling it a public OSS release:
- `stage_c_ready()["no_destructive_verbs"]` is true
- Retention: >=3 external labs × 2 unprompted runs in `reports/oss_retention.json`
- SECURITY.md present; drafts/actions not installed

Until retention is met: stay private.
