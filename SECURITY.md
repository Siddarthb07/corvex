# Security

Corvex ships as **observe-only** by default.

- No host isolation, process kill, or firewall mutation in the installable package.
- Destructive action vocabulary lives under `drafts/actions/` and is **not** packaged.
- Per-producer HMAC secrets; shared/default secrets are rejected.
- Eval keys and enrollment files belong **outside** the repository (`~/.corvex/` by default). Do not commit keys, enrollment JSON, or sealed held-out ciphertext.

## Dual-use

Do not treat schemas in `drafts/` as a remote-control toolkit. Public packages omit actuator executors.

## Reporting

See [`THREAT_MODEL.md`](THREAT_MODEL.md) and [`corvex/contain/CHECKLIST.md`](corvex/contain/CHECKLIST.md).
