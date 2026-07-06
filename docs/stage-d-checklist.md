# Stage D — Contain checklist (REJECT until 100%)

Do **not** merge actuator executors until every item is demonstrated.

- [ ] mTLS (or equivalent mutual auth) between components
- [ ] Per-component identities (sensor ≠ correlator ≠ contain ≠ oversight)
- [ ] Typed commands only — no free-form shell
- [ ] Authorization policy independent of signature
- [ ] Anti-replay + command expiry + idempotency keys
- [ ] Dual-control for destructive actions
- [ ] Fail-closed defaults
- [ ] Contain agent least privilege; no shared fleet private key
- [ ] Immutable audit of who ordered what
- [ ] Oversight off data-plane and separately authorized
- [ ] Blast-radius caps (max N hosts / T minutes)
- [ ] Supply chain: pinned deps, SBOM, signed releases

Until then: `CFUSE_CONTAIN=0` and no `campaignfuse/actuators/` package.
