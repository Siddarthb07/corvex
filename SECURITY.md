# Security

Corvex is **L0 observe-only** through Stage C.

- No host isolation, process kill, or firewall mutation in the installable package.
- Destructive action vocabulary (if any) lives under `drafts/actions/` and is **not** packaged.
- Per-producer HMAC secrets; shared/default secrets are rejected.
- Any local eval keys or enrollment files belong **outside** the repository (developer machine only). Do not commit keys, enrollment JSON, or sealed held-out ciphertext.

## Dual-use

Do not treat schemas in `drafts/` as a remote-control toolkit. Public packages omit actuator executors.

## Reporting

See `docs/threat-model.md` and `docs/stage-d-checklist.md`.
