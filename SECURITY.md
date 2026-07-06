# Security

Corvex is **L0 observe-only** through Stage C.

- No host isolation, process kill, or firewall mutation in the installable package.
- Destructive action vocabulary (if any) lives under `drafts/actions/` and is **not** packaged.
- Per-producer HMAC secrets; shared/default secrets are rejected.
- Held-out unlock key is outside the repository (`%USERPROFILE%\.campaignfuse\heldout.key`). Solo key custody is tamper-evident, not peek-proof.

## Dual-use

Do not treat sealed coordination schemas in `drafts/` as a remote-control toolkit. Public wheels omit actuator executors.

## Reporting

See `docs/threat-model.md` and `docs/stage-d-checklist.md`.
