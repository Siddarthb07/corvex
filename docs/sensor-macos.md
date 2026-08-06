# macOS network-wide sensor (Stage B)

Observe-only collector for Mac hosts. Same Stage B gate and envelope contract as
[`sensor-windows`](sensor-windows.md) / [`os-wide-sensor.md`](os-wide-sensor.md).
Emits HMAC-signed Corvex envelopes into a run directory so multi-Mac fleets can
fuse with Windows sensors and lab JSONL.

| | |
|--|--|
| **CLI** | `corvex sensor-macos` |
| **Adapter** | `corvex/adapters/macos.py` |
| **Collector** | `corvex/sensors/macos_os.py` |
| **Fixtures** | `fixtures/os_wide_macos/` |
| **Tests** | `tests/test_macos_sensor.py` |
| **Mode** | Offline lab / observe-only — not a live streaming product bus |
| **Claim impact** | Does **not** unlock `claim_allowed` |

---

## What this is / isn't

| Is | Isn't |
|----|--------|
| Observe-only Mac exporter (gated Stage B) | EndpointSecurity / Network Extension kernel sensor |
| Live `lsof` TCP established flows (per-user visibility) | Full-system netmon for every process as root |
| Fixture CI without admin rights | Proof of real-attack usefulness |
| Multi-host exporter into one `run_dir` | JetStream / mTLS bus (still stub) |
| Same `auth` / `net_conn` / `dns` / `process` payload types as Windows | Live OS quarantine / pf mutation |
| Honest degrade reasons in `sensor_status.json` | Silent inventing of missing channel data |

---

## Architecture

```text
  ┌─────────────────────────────────────────────────────────┐
  │  Mac host A / B / C                                     │
  │                                                         │
  │  live: lsof (net) │ log show (auth/dns) │ ps │ pfctl   │
  │            │              │                │      │     │
  │            └──────────────┴────────────────┴──────┘     │
  │                           │                             │
  │              adapt_macos_records()                      │
  │                           │                             │
  │              sign_unsigned() + enrollment HMAC          │
  │                           │                             │
  │              append → <run-dir>/events.jsonl            │
  │              bookmark → sensor_bookmarks.json           │
  │              status → sensor_status.json                │
  │              recompute → timeline.json + campaigns      │
  └───────────────────────────┬─────────────────────────────┘
                              │  (share / scp / fuse-run)
                              ▼
                    corvex dash --run-dir …
```

Pipeline per cycle (mirrors Windows):

1. **Source** — fixture JSONL **or** live channel pollers.
2. **Dedupe** — bookmark keys per exporter identity (`host_id`).
3. **Adapt** — Mac records → unsigned envelope dicts (`payload_type` + payload).
4. **Rate limit** — soft envelopes/sec cap (default 50).
5. **Sign** — enrollment secret for `(producer_id, host_id)`.
6. **Append** — `events.jsonl`.
7. **Recompute** — HMAC verify + correlator → `timeline.json` / `campaigns.jsonl`.

---

## Channels (detailed)

| Channel | CLI name | Live source | `payload_type` | Allowlisted kinds (default) |
|---------|----------|-------------|----------------|-----------------------------|
| Network | `net` | `lsof -iTCP -sTCP:ESTABLISHED -n -P` | `net_conn` | `tcp_established`, `udp_flow`, `tcp_listen` |
| Auth | `auth` | `log show` (sshd / loginwindow predicates) | `auth` | `ssh_accept`, `ssh_fail`, `login_success`, `login_fail`, `sudo` |
| DNS | `dns` | `log show` (mDNSResponder + Query) | `dns` | `query` |
| Process | `process` | `ps -axo user=,pid=,comm=,args=` | `process` | `exec`, `sample` |
| Packet filter | `pf` | `pfctl -s info` | `net_conn` (+ `blocked`) | `pass`, `block` |

Default allowlist: `fixtures/os_wide_macos/channels.json`.

### `net` (primary live channel)

- Parses `lsof` NAME fields like `10.0.0.2:5555->198.51.100.40:443 (ESTABLISHED)`.
- Skips loopback (`127.0.0.1` / `::1`) by default to cut noise.
- Payload fields: `dst_ip`, `dst_port`, `bytes`, `egress`, optional `image` / `pid`.
- **Coverage honesty:** sees connections visible to the calling user (and often
  many system processes). It is **not** a kernel Network Extension with
  guaranteed global coverage. `netstat` on modern macOS often returns
  `Operation not permitted` without elevation — the sensor prefers `lsof` and
  degrades if neither works.

### `auth`

- Best-effort unified log predicates for SSH accept/fail and loginwindow.
- Common degrade reasons: `sandboxed`, `permission_denied`, `no_log`, `zero_hits`.
- Payload: `user`, `result` (`success`|`failure`), optional `src`, `macos_event`.

### `dns`

- Best-effort extraction of query names from mDNSResponder log lines.
- Payload: `query`, `qtype` (default `A`) — correlator/detectors expect
  **`payload_type: "dns"`** (not `dns_query`).
- Often empty under TCC / sandbox; that is a degrade, not a crash.

### `process`

- Periodic `ps` sample — **not** EndpointSecurity `exec` streaming.
- Long script bodies are hashed (`script_sha256_16`) when present; raw script
  text is not stored from fixtures that supply `script`.
- Useful for dash richness; do not treat as forensic process provenance.

### `pf`

- `pfctl -s info` usually needs root and does not yield per-flow events by
  itself. Expect `pf_info_only_no_flow_events` or `permission_denied`.
- Fixture path can still emit `block` / `pass` shaped records for CI.

---

## Payload contract (shared with Windows)

Unsigned then signed envelopes use the same schema:

```json
{
  "schema_ver": "1",
  "event_id": "mac0-net-tcp_established-0",
  "producer_id": "prod-mac",
  "host_id": "host-mac",
  "ts_utc": "2026-08-06T12:36:40Z",
  "nonce": "…",
  "payload_type": "net_conn",
  "payload": {
    "dst_ip": "198.51.100.40",
    "dst_port": 443,
    "bytes": 1500,
    "egress": true,
    "macos_event": "tcp_established",
    "channel": "net"
  },
  "hmac": "…"
}
```

| `payload_type` | Required payload fields |
|----------------|-------------------------|
| `auth` | `user`, `result`, optional `src` |
| `net_conn` | `dst_ip`, `dst_port`, `bytes`, `egress` (bool); optional `blocked` |
| `dns` | `query`, `qtype` |
| `process` | `image`, `command_line`, `user` |

---

## Stage B gate

`require_stage_b()` — identical to Windows:

**Allowed if either:**

1. **Honest unlock:** Stage A PASS + human `reports/stranger_dry_run.json` + empty
   `reports/stage-b-allowed`
2. **Lab unlock:** `corvex stage-b-lab-unlock --reason '…'` (min 8 chars) →
   `reports/stage-b-lab-override.json`

`CORVEX_STAGE_B=1` / `CFUSE_STAGE_B=1` are **ignored**. Lab unlock does **not**
flip `claim_allowed`.

```bash
corvex stage-b-lab-unlock --reason "local macos fixture CI"
corvex stage-b-check   # shows allowed / why
```

---

## Quick start

### Fixture / CI (no admin)

```bash
git clone https://github.com/Siddarthb07/corvex.git
cd corvex
python -m pip install -e ".[dev]"

corvex stage-b-lab-unlock --reason "local macos fixture CI"
corvex sensor-macos \
  --fixture fixtures/os_wide_macos/multi_channel.jsonl \
  --allowlist fixtures/os_wide_macos/channels.json \
  --host-map fixtures/os_wide_macos/host_map.json \
  --run-dir runs/os-wide-macos \
  --once

corvex dash --run-dir runs/os-wide-macos --build --no-open
# or: corvex dash --run-dir runs/os-wide-macos
```

### Live Mac (this machine)

Enrollment auto-merges `host-mac` → `prod-mac` (and any `--host-id` /
`--producer` you pass).

```bash
corvex stage-b-lab-unlock --reason "live macos net poll"

# Recommended first live pass: net + process
corvex sensor-macos --run-dir runs/os-wide-macos-live --once \
  --channels net,process \
  --host-id host-mac --producer prod-mac

# Fail CI/local if nothing live published:
corvex sensor-macos --run-dir runs/os-wide-macos-live --once \
  --channels net --require-live \
  --host-id host-mac --producer prod-mac

# Continuous poll (Ctrl-C to stop; use --max-cycles in tests):
corvex sensor-macos --run-dir runs/os-wide-macos-live --follow \
  --channels net \
  --poll-seconds 3 \
  --host-id host-mac --producer prod-mac
```

### CLI options (summary)

| Option | Default | Purpose |
|--------|---------|---------|
| `--run-dir` | `runs/os-wide-macos` | Events, bookmarks, timeline |
| `--channels` | `net,auth,dns,process` | Comma-separated channel list |
| `--fixture` | _(none)_ | JSON/JSONL export; omit for live |
| `--allowlist` | `fixtures/os_wide_macos/channels.json` | Kind allowlist |
| `--host-map` | _(built-in + file)_ | hostname → enrolled `host_id` |
| `--host-id` / `--producer` | `host-mac` / `prod-mac` | Multi-host exporter identity |
| `--once` / `--follow` | once | Single drain vs continuous |
| `--max-per-sec` | `50` | Soft publish rate cap |
| `--poll-seconds` | `2` | Follow interval |
| `--max-cycles` | _(none)_ | Bound follow (tests) |
| `--require-live` | off | Exit 1 if no live hits (incompatible with `--fixture`) |

---

## Run directory layout

| File | Purpose |
|------|---------|
| `events.jsonl` | Appended signed envelopes |
| `sensor_bookmarks.json` | Per-channel cursors + `seen_by_exporter` dedupe |
| `sensor_audit.jsonl` | Rate-limit audits |
| `sensor_status.json` | Cycle stats, `channel_health`, honesty note |
| `timeline.json` | After recompute (`sensor: macos-os-wide+network`) |
| `campaigns.jsonl` | Correlator store |
| `audit.jsonl` | Correlator audit |
| `reconstruction.json` | Best-effort reconstruction |

### `channel_health` reasons

| Reason | Meaning |
|--------|---------|
| `ok` + hits | Channel produced records |
| `zero_hits` | Source ok but nothing matched |
| `not_macos` | Running on non-Darwin (fixture still works) |
| `sandboxed` | `log show` refused (common in restricted environments) |
| `permission_denied` | TCC / root / sysctl denial |
| `no_lsof` / `no_log` / `no_pfctl` / `no_ps` | Binary missing from PATH |
| `no_net_source` | Neither lsof nor usable netstat |
| `pf_info_only_no_flow_events` | pfctl info returned; no flow rows |
| `unknown_channel` | Typo in `--channels` |
| `timeout` | Subprocess exceeded timeout |

Degraded channels are listed under `sensor_status.json` → `degraded` without
aborting the whole run (unless `--require-live` and nothing published).

---

## Multi-host (network-wide fleet)

Same exporter shape as Windows: one process per Mac, shared `run_dir`
(network share, sync, or scp-merge of `events.jsonl`).

```bash
# Mac A
corvex sensor-macos --host-id host-a --producer prod-a \
  --run-dir /shared/runs/fleet-mac --channels net,auth --once

# Mac B
corvex sensor-macos --host-id host-b --producer prod-b \
  --run-dir /shared/runs/fleet-mac --channels net,auth --once

corvex dash --run-dir /shared/runs/fleet-mac
```

Enrollment (`~/.corvex/enrollment.json` or `CORVEX_ENROLLMENT`) must include each
`(producer, host)` pair. The CLI merges `--host-id`/`--producer` and
`host-mac`/`prod-mac` into the lab enrollment on first use.

Fixture multi-host map: `fixtures/os_wide_macos/host_map.json`.

---

## Fuse with lab / Windows

```bash
# Mac live + breaktest lab JSONL
corvex fuse-run \
  --lab labs/breaktest/shared/events.jsonl \
  --pc runs/os-wide-macos-live \
  --out-dir runs/pc-and-lab-macos \
  --once

# Mac + Windows PC sensor dirs (merge via fuse or shared events.jsonl)
corvex fuse-run \
  --lab runs/os-wide \
  --pc runs/os-wide-macos-live \
  --out-dir runs/win-and-mac \
  --once

corvex dash --run-dir runs/pc-and-lab-macos
```

Mode is **`offline_lab_replay`** — file merge + HMAC verify + correlator.
Not JetStream; not a concurrency-safe product bus.

---

## Fixture record format

JSONL (one object per line). Required-ish fields vary by channel:

```json
{"channel": "net", "EventID": "tcp_established", "Computer": "host-mac-a.local",
 "TimeCreated": "2026-08-06T12:01:00Z", "dst_ip": "198.51.100.40", "dst_port": 443,
 "bytes": 4200, "egress": true, "image": "curl", "pid": 4242}

{"channel": "auth", "EventID": "ssh_accept", "Computer": "host-mac-b.local",
 "TimeCreated": "2026-08-06T12:00:20Z", "user": "ops", "src": "10.0.0.8", "result": "success"}

{"channel": "dns", "EventID": "query", "Computer": "host-mac-b.local",
 "TimeCreated": "2026-08-06T12:01:45Z", "query": "cdn-sync-updates.example", "qtype": "A"}
```

Unknown / non-allowlisted `EventID` kinds are **skipped** (counted in stats),
same noise-control pattern as Windows OS-wide.

Sample pack: `fixtures/os_wide_macos/multi_channel.jsonl`.

---

## Testing

```bash
pytest tests/test_macos_sensor.py -q
# covers: adapt skip unknown kinds, lsof parse, fixture once → timeline,
#         multi-host exporter shape into one run_dir
```

Live smoke (Darwin only):

```bash
corvex stage-b-lab-unlock --reason "live macos net poll"
corvex sensor-macos --run-dir runs/os-wide-macos-live --once \
  --channels net --require-live --host-id host-mac --producer prod-mac
```

---

## Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| Exit 2, Stage B message | Gate locked | `corvex stage-b-lab-unlock --reason '…'` or honest stranger path |
| `published: 0`, `require_live_failed` | No live net/auth hits | Check `channel_health`; try `--channels net` only; confirm Darwin + `lsof` |
| `sandboxed` / `permission_denied` on auth/dns | Unified log restricted | Expected in many environments; use fixture or net-only |
| `rate_limited` high | Busy host / low cap | Raise `--max-per-sec` or narrow `--channels` |
| `hmac_rejected` on recompute | Wrong enrollment / tampered rows | Re-run with same `CORVEX_ENROLLMENT`; do not hand-edit `events.jsonl` |
| Campaigns empty after live net | Benign egress only, no multi-host auth chain | Expected — correlator needs multi-host weak signals; use fixture pack or fuse with lab attack JSONL |

---

## Safety & honesty

- Observe-only — **no** pf enable/disable, no quarantine, no host mutation.
- Fixture path is **CI-only** — never describe fixture output as live evidence.
- Missing channels **degrade**; they do not invent events.
- Does not satisfy S2 “second physical Windows host” or pure-benign S5 gates.
- Standing public claim stays locked until `corvex claim-gates` →
  `claim_allowed=true` (see [`real-world-test-sequences.md`](real-world-test-sequences.md)).

Related: [`sensor-windows.md`](sensor-windows.md) · [`os-wide-sensor.md`](os-wide-sensor.md) ·
[`reports/local_stress_break_results.md`](../reports/local_stress_break_results.md).
