"""Benign-baseline scoring — pre-committed bars (do not retune after a run).

See future-plans.md § Benign corpus plan. Absolute FP rates, not post-hoc
anchoring. Gate is INCOMPLETE until corpus size + kind requirements are met.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

# --- Pre-committed bars (locked 2026-07-25; quote verbatim in reports) ---
MIN_HOST_HOURS = 72.0
MIN_DISTINCT_HOSTS = 3
MAX_FP_ISO_PER_HOST_HOUR = 1.0 / 1000.0  # IsolateHost proposals
MAX_FP_SEAL_PER_HOST_HOUR = 1.0 / 100.0  # correlator campaigns on pure-benign

PURE_KINDS = frozenset({"pure_benign", "home_lab_capture"})


def parse_ts(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(float(raw), tz=timezone.utc)
    text = str(raw).strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def host_hours_from_events(events: Sequence[Mapping[str, Any]]) -> Tuple[float, Dict[str, float]]:
    """Sum over hosts of (max_ts − min_ts) in hours. Returns (total, per_host)."""
    spans: Dict[str, List[datetime]] = defaultdict(list)
    for ev in events:
        host = str(ev.get("host_id") or "")
        ts = parse_ts(ev.get("ts_utc"))
        if not host or ts is None:
            continue
        spans[host].append(ts)
    per: Dict[str, float] = {}
    for host, times in spans.items():
        if len(times) == 1:
            per[host] = 0.0
            continue
        delta = (max(times) - min(times)).total_seconds() / 3600.0
        per[host] = max(0.0, delta)
    return round(sum(per.values()), 6), {k: round(v, 6) for k, v in sorted(per.items())}


def auth_hop_degrees(events: Sequence[Mapping[str, Any]]) -> Dict[str, int]:
    """Undirected peer degree from auth hops where src looks like a host id."""
    hop: Dict[str, Set[str]] = defaultdict(set)
    for ev in events:
        if ev.get("payload_type") != "auth":
            continue
        host = str(ev.get("host_id") or "")
        src = str((ev.get("payload") or {}).get("src") or "")
        if not host:
            continue
        # Correlator only counts host-* style lateral; also accept short names
        # without dots when they look like enrolled peers (not IPs).
        peer = None
        if src.startswith("host-") and src != host:
            peer = src
        elif src and src != host and "." not in src and not _looks_like_ip(src):
            peer = src
        if peer:
            hop[host].add(peer)
            hop[peer].add(host)
    return {h: len(peers) for h, peers in sorted(hop.items())}


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return True
    return ":" in s  # v6-ish


def hub_bar_for_fleet(n_hosts: int, configured: Optional[int] = None) -> int:
    if configured is not None:
        return int(configured)
    return max(2, n_hosts // 2)


def hub_coverage(
    degrees: Mapping[str, int],
    *,
    n_hosts: int,
    configured_bar: Optional[int] = None,
) -> Dict[str, Any]:
    bar = hub_bar_for_fleet(n_hosts, configured_bar)
    hubs = sorted(h for h, d in degrees.items() if d >= bar)
    return {
        "hub_degree_bar": bar,
        "degrees": dict(degrees),
        "hubs_at_or_above_bar": hubs,
        "hub_coverage": "OK" if hubs else "GAP",
        "note": (
            None
            if hubs
            else (
                "No host meets hub-degree bar on this corpus; synthetic hub tests "
                "remain unvalidated by this run."
            )
        ),
    }


def count_isolate_proposals(reconstruction: Mapping[str, Any]) -> Tuple[int, List[str]]:
    """FP_iso = hosts proposed for IsolateHost across campaign reconstructions."""
    hosts: Set[str] = set()
    for item in reconstruction.get("campaign_reconstructions") or []:
        if not isinstance(item, Mapping):
            continue
        qq = item.get("quarantine") or {}
        if not isinstance(qq, Mapping):
            continue
        if str(qq.get("verb") or "") != "IsolateHost":
            continue
        for h in qq.get("host_ids") or []:
            if h:
                hosts.add(str(h))
    return len(hosts), sorted(hosts)


def count_false_campaigns(
    campaigns: Sequence[Mapping[str, Any]],
    *,
    excluded_hosts: Optional[Set[str]] = None,
) -> Tuple[int, List[str]]:
    """FP_seal = correlator campaigns not wholly inside an excluded attack set.

    On pure-benign corpora excluded_hosts is empty → every campaign counts.
    """
    excluded = excluded_hosts or set()
    ids: List[str] = []
    for c in campaigns:
        if not isinstance(c, Mapping):
            continue
        hosts = {str(h) for h in (c.get("host_ids") or c.get("hosts") or [])}
        if hosts and hosts <= excluded:
            continue
        cid = str(c.get("campaign_id") or "")
        ids.append(cid or f"camp-{len(ids)}")
    return len(ids), ids


def score_benign_baseline(
    *,
    corpus_kind: str,
    host_hours: float,
    n_hosts: int,
    fp_iso: int,
    fp_seal: int,
    hub: Mapping[str, Any],
) -> Dict[str, Any]:
    """Apply pre-committed bars. Returns gate + rates; never mutates bars."""
    kind = str(corpus_kind or "").strip()
    eligible_kind = kind in PURE_KINDS
    size_ok = host_hours >= MIN_HOST_HOURS and n_hosts >= MIN_DISTINCT_HOSTS

    rate_iso = (fp_iso / host_hours) if host_hours > 0 else (float("inf") if fp_iso else 0.0)
    rate_seal = (fp_seal / host_hours) if host_hours > 0 else (float("inf") if fp_seal else 0.0)

    bars = {
        "min_host_hours": MIN_HOST_HOURS,
        "min_distinct_hosts": MIN_DISTINCT_HOSTS,
        "max_fp_iso_per_host_hour": MAX_FP_ISO_PER_HOST_HOUR,
        "max_fp_seal_per_host_hour": MAX_FP_SEAL_PER_HOST_HOUR,
        "locked": "2026-07-25",
    }

    reasons: List[str] = []
    if not eligible_kind:
        reasons.append(
            f"corpus_kind={kind!r} is not pure_benign/home_lab_capture — "
            "dirty/mixed replay may be reported but cannot PASS the benign gate"
        )
    if not size_ok:
        reasons.append(
            f"corpus below minimum size (host_hours={host_hours}, hosts={n_hosts}; "
            f"need ≥{MIN_HOST_HOURS} host-hours and ≥{MIN_DISTINCT_HOSTS} hosts)"
        )

    if not eligible_kind or not size_ok:
        gate = "INCOMPLETE"
    else:
        fail = False
        if rate_iso > MAX_FP_ISO_PER_HOST_HOUR:
            fail = True
            reasons.append(
                f"FP_iso rate {rate_iso:.6g} > {MAX_FP_ISO_PER_HOST_HOUR} per host-hour"
            )
        if rate_seal > MAX_FP_SEAL_PER_HOST_HOUR:
            fail = True
            reasons.append(
                f"FP_seal rate {rate_seal:.6g} > {MAX_FP_SEAL_PER_HOST_HOUR} per host-hour"
            )
        gate = "FAIL" if fail else "PASS"
        if gate == "PASS":
            reasons.append("primary and secondary bars met on eligible pure-benign corpus")

    return {
        "gate": gate,
        "bars": bars,
        "corpus_kind": kind,
        "eligible_for_gate": eligible_kind and size_ok,
        "host_hours": host_hours,
        "n_hosts": n_hosts,
        "fp_iso": fp_iso,
        "fp_seal": fp_seal,
        "fp_iso_per_host_hour": None if host_hours <= 0 else round(rate_iso, 8),
        "fp_seal_per_host_hour": None if host_hours <= 0 else round(rate_seal, 8),
        "hub_coverage": hub.get("hub_coverage"),
        "hub": dict(hub),
        "reasons": reasons,
        "claim_sentence_still_applies": gate != "PASS",
    }
