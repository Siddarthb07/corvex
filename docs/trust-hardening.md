# Trust hardening (council residual → close)

Closes the 2026-07-25 council fatal findings that kept Corvex ~2.4/5.

| Finding | Fix |
|---------|-----|
| Overclaimed `claim_allowed` / “useful on real attacks” | `claim_allowed=false` until signed stranger + all gates; `lab_verified` for sealed/breaktest |
| Dash LAN token bypass via embedded `index.html` / `snapshot.json` | API-only boot; token on **all** routes; delete served `snapshot.json` |
| BYO `resign_events` theatrical HMAC | Verify-first; else tag `_corvex_provenance=locally_stamped` |
| `Correlator.ingest` skipped verify | Enrollment-aware HMAC verify + audit `hmac_reject` |
| Forgeable stranger JSON | Require `attestation_hmac` (`corvex sign-stranger-attestation`) |
| Offline fuse sold as live multi-host | Unchanged honesty: `mode: offline_lab_replay`; 2nd physical host still open |

## Verify

```bash
python -m pytest tests/ -q
python -m corvex claim-gates          # expect lab_verified=true, claim_allowed=false
python scripts/run_cdn_bridge_safe.py # expect pass=true
```

## Still open (not claimed closed)

- Second physical Windows host + elevated wevtutil Security hits (`reports/live_second_host.json`)
- JetStream / live quarantine deferred

## Stranger signing (independent custody)

```bash
corvex stranger-keygen          # writes reports/.stranger_ed25519_private.pem (gitignored)
# fill reports/stranger_dry_run.json (human operator)
corvex sign-stranger-attestation   # Ed25519 self-sign; author never needs the private key
corvex claim-gates
```

Author-held HMAC (`--hmac`) is advisory and does **not** unlock `claim_allowed`.
