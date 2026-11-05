# Intensive multi-factor capability matrix

Synthetic ATT&CK-shaped sketches across **domain × container × sequence × style**.
Not enterprise telemetry. `claim_allowed` stays false.

## Scoring

Same HELD / HELD,fragile / PARTIAL / BROKE bar as fleet-limits (Jaccard ≥ 0.9, no merge-FQ, ambiguity margin < 0.2 ⇒ fragile).

- Cells: **28** | Intensity: **2** | Wall: **44.869s**
- HELD: **23** (fragile: **5**) | PARTIAL: **2** | BROKE: **3** | ERROR: **0**

## Where it breaks (BROKE / PARTIAL first)

| Campaign | Verdict | J | Margin | Missed | Over-merge | Factors |
|----------|---------|---|--------|--------|------------|---------|
| `mf-single-bare-burst-exfil_bury` | **BROKE** | 0.6667 | 0.9 | corp-ws03 | - | `single/bare/burst/exfil_bury` |
| `mf-single-bare-slow-exfil_bury` | **BROKE** | 0.6667 | 0.9 | corp-ws03 | - | `single/bare/slow/exfil_bury` |
| `mf-single-docker-ooo-exfil_bury` | **BROKE** | 0.6667 | 0.9 | ctr-ws03-db | - | `single/docker/ooo/exfil_bury` |
| `mf-cross-bare-slow-dns_c2` | **PARTIAL** | 0.6667 | 0.0 | - | - | `cross/bare/slow/dns_c2` |
| `mf-forest-mixed-concurrent-exfil_bury` | **PARTIAL** | 0.8333 | 0.0 | finance-ws01 | - | `forest/mixed/concurrent/exfil_bury` |
| `mf-cross-docker-concurrent-helpdesk_overlap` | **HELD, fragile** | 1.0 | -0.1 | - | - | `cross/docker/concurrent/helpdesk_overlap` |
| `mf-cross-docker-slow-helpdesk_overlap` | **HELD, fragile** | 1.0 | 0.1 | - | - | `cross/docker/slow/helpdesk_overlap` |
| `mf-forest-bare-concurrent-helpdesk_overlap` | **HELD, fragile** | 1.0 | -0.1 | - | - | `forest/bare/concurrent/helpdesk_overlap` |
| `mf-forest-docker-ooo-helpdesk_overlap` | **HELD, fragile** | 1.0 | 0.0 | - | - | `forest/docker/ooo/helpdesk_overlap` |
| `mf-single-bare-burst-helpdesk_overlap` | **HELD, fragile** | 1.0 | 0.0 | - | - | `single/bare/burst/helpdesk_overlap` |

## Factor pivots

### domain

| Level | HELD | fragile | PARTIAL | BROKE | ERROR |
|-------|------|---------|---------|-------|-------|
| `cross` | 4 | 2 | 1 | 0 | 0 |
| `forest` | 4 | 2 | 1 | 0 | 0 |
| `single` | 10 | 1 | 0 | 3 | 0 |

### container

| Level | HELD | fragile | PARTIAL | BROKE | ERROR |
|-------|------|---------|---------|-------|-------|
| `bare` | 9 | 2 | 1 | 2 | 0 |
| `docker` | 4 | 3 | 0 | 1 | 0 |
| `mixed` | 5 | 0 | 1 | 0 | 0 |

### sequence

| Level | HELD | fragile | PARTIAL | BROKE | ERROR |
|-------|------|---------|---------|-------|-------|
| `burst` | 10 | 1 | 0 | 1 | 0 |
| `concurrent` | 2 | 2 | 1 | 0 | 0 |
| `ooo` | 3 | 1 | 0 | 1 | 0 |
| `slow` | 3 | 1 | 1 | 1 | 0 |

### style

| Level | HELD | fragile | PARTIAL | BROKE | ERROR |
|-------|------|---------|---------|-------|-------|
| `dns_c2` | 4 | 0 | 1 | 0 | 0 |
| `exfil_bury` | 0 | 0 | 1 | 3 | 0 |
| `helpdesk_overlap` | 0 | 5 | 0 | 0 | 0 |
| `pth_lateral` | 10 | 0 | 0 | 0 | 0 |
| `spray` | 4 | 0 | 0 | 0 | 0 |

## Full scoreboard

| # | Campaign | Verdict | J | Margin | Domain | Container | Sequence | Style |
|---|----------|---------|---|--------|--------|-----------|----------|-------|
| 1 | `mf-single-bare-burst-pth_lateral` | **HELD** | 1.0 | 1.0 | single | bare | burst | pth_lateral |
| 2 | `mf-cross-bare-burst-pth_lateral` | **HELD** | 1.0 | 1.0 | cross | bare | burst | pth_lateral |
| 3 | `mf-forest-bare-burst-pth_lateral` | **HELD** | 1.0 | 1.0 | forest | bare | burst | pth_lateral |
| 4 | `mf-single-docker-burst-pth_lateral` | **HELD** | 1.0 | 1.0 | single | docker | burst | pth_lateral |
| 5 | `mf-single-mixed-burst-pth_lateral` | **HELD** | 1.0 | 1.0 | single | mixed | burst | pth_lateral |
| 6 | `mf-single-bare-slow-pth_lateral` | **HELD** | 1.0 | 1.0 | single | bare | slow | pth_lateral |
| 7 | `mf-single-bare-ooo-pth_lateral` | **HELD** | 1.0 | 1.0 | single | bare | ooo | pth_lateral |
| 8 | `mf-single-bare-concurrent-pth_lateral` | **HELD** | 1.0 | 0.9 | single | bare | concurrent | pth_lateral |
| 9 | `mf-single-bare-burst-dns_c2` | **HELD** | 1.0 | 1.0 | single | bare | burst | dns_c2 |
| 10 | `mf-single-bare-burst-spray` | **HELD** | 1.0 | 1.0 | single | bare | burst | spray |
| 11 | `mf-single-bare-burst-exfil_bury` | **BROKE** | 0.6667 | 0.9 | single | bare | burst | exfil_bury |
| 12 | `mf-single-bare-burst-helpdesk_overlap` | **HELD, fragile** | 1.0 | 0.0 | single | bare | burst | helpdesk_overlap |
| 13 | `mf-cross-docker-concurrent-helpdesk_overlap` | **HELD, fragile** | 1.0 | -0.1 | cross | docker | concurrent | helpdesk_overlap |
| 14 | `mf-cross-mixed-ooo-pth_lateral` | **HELD** | 1.0 | 1.0 | cross | mixed | ooo | pth_lateral |
| 15 | `mf-forest-bare-slow-pth_lateral` | **HELD** | 1.0 | 1.0 | forest | bare | slow | pth_lateral |
| 16 | `mf-forest-docker-burst-dns_c2` | **HELD** | 1.0 | 1.0 | forest | docker | burst | dns_c2 |
| 17 | `mf-forest-mixed-concurrent-exfil_bury` | **PARTIAL** | 0.8333 | 0.0 | forest | mixed | concurrent | exfil_bury |
| 18 | `mf-cross-bare-slow-dns_c2` | **PARTIAL** | 0.6667 | 0.0 | cross | bare | slow | dns_c2 |
| 19 | `mf-single-docker-ooo-exfil_bury` | **BROKE** | 0.6667 | 0.9 | single | docker | ooo | exfil_bury |
| 20 | `mf-cross-docker-burst-spray` | **HELD** | 1.0 | 1.0 | cross | docker | burst | spray |
| 21 | `mf-forest-bare-concurrent-helpdesk_overlap` | **HELD, fragile** | 1.0 | -0.1 | forest | bare | concurrent | helpdesk_overlap |
| 22 | `mf-single-mixed-slow-spray` | **HELD** | 1.0 | 1.0 | single | mixed | slow | spray |
| 23 | `mf-cross-mixed-burst-dns_c2` | **HELD** | 1.0 | 1.0 | cross | mixed | burst | dns_c2 |
| 24 | `mf-forest-docker-ooo-helpdesk_overlap` | **HELD, fragile** | 1.0 | 0.0 | forest | docker | ooo | helpdesk_overlap |
| 25 | `mf-single-bare-slow-exfil_bury` | **BROKE** | 0.6667 | 0.9 | single | bare | slow | exfil_bury |
| 26 | `mf-cross-docker-slow-helpdesk_overlap` | **HELD, fragile** | 1.0 | 0.1 | cross | docker | slow | helpdesk_overlap |
| 27 | `mf-forest-mixed-ooo-spray` | **HELD** | 1.0 | 1.0 | forest | mixed | ooo | spray |
| 28 | `mf-single-docker-concurrent-dns_c2` | **HELD** | 1.0 | 1.0 | single | docker | concurrent | dns_c2 |

## Honesty

- Author-built factor cells; not an independent red team.
- Domain/container labels are host_id namespaces — not live AD/K8s.
- DNS-only cells probe correlator fusion of `dns` payloads; OS DNS channel may still be GAP.

