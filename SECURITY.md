# Security

Corvex ships **observe-only by default** (`CORVEX_CONTAIN=0`).

- Dry-run proposals do not mutate hosts.
- A gated Windows Firewall self-isolate executor is in the package (`corvex.contain.windows_firewall`). It does not run unless `CORVEX_CONTAIN!=0`, the Security L1 checklist is complete, `corvex hostile-bus-test` has passed, and `CORVEX_CONTAIN_AUTHZ` is a unique secret. It applies a named firewall rule on the **local** host_id only. It is not EDR, VLAN, or enterprise quarantine. SSH fanout and the contain-agent inbox can carry the same typed envelope to peers; both stay behind those gates and default to dry-run.
- Free-form shell and process kill are not live executors. Unknown verbs refuse.
- Per-producer HMAC secrets; shared/default secrets are rejected.
- Eval keys and enrollment files belong **outside** the repository (`~/.corvex/` by default). Do not commit keys, enrollment JSON, or sealed held-out ciphertext.
- S5 pure-benign evidence and the paper are deferred. Do not cite this repo as production EDR.

## Dual-use

Do not treat action envelopes as a remote-control toolkit. Live enforce stays fail-closed. The dashboard isolate panel is read-only and does not call the OS.

## Reporting

See [`THREAT_MODEL.md`](THREAT_MODEL.md) and [`corvex/contain/CHECKLIST.md`](corvex/contain/CHECKLIST.md).
