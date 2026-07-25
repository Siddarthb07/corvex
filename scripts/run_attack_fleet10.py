#!/usr/bin/env python3
"""Generate + run a 10-attack black-box fleet against Corvex (full intensity).

Attacks are purple-team *event sketches* adapted from public GitHub ATT&CK/Atomic
Red Team technique IDs, plus original correlator breakers. No malware is executed
or vendored. The fleet is written with zero knowledge of Corvex internals in the
manifest narratives — scoring reveals where fusion holds or breaks.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
FLEET_DIR = ROOT / "labs" / "breaktest" / "manifests" / "fleet20"
RUN = ROOT / "runs" / "attack-fleet20"
REPORT_JSON = ROOT / "reports" / "attack_fleet20.json"
REPORT_MD = ROOT / "reports" / "attack_fleet20.md"

HOSTS = ["host-a", "host-b", "host-c", "host-d", "host-e"]
PRODUCERS = {h: f"prod-{h[-1]}" for h in HOSTS}
ART = "https://github.com/redcanaryco/atomic-red-team"


def base_man(
    campaign_id: str,
    *,
    family: str,
    truth: List[str],
    techniques: List[str],
    source_note: str,
    origin: str,
    narrative: List[str],
    steps: List[Dict[str, Any]],
    break_intent: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return {
        "campaign_id": campaign_id,
        "family": family,
        "ood": True,
        "hosts": HOSTS,
        "truth_hosts": truth,
        "producers": PRODUCERS,
        "base_time_utc": "2026-07-25T14:00:00Z",
        "fleet_origin": origin,  # github_art | original
        "source": {
            "style": "Black-box fleet — ATT&CK/Atomic-style telemetry sketches",
            "repo": ART if origin == "github_art" else "https://github.com/Siddarthb07/corvex",
            "techniques": techniques,
            "note": source_note,
        },
        "narrative": narrative,
        "break_intent": break_intent
        or {
            "name": campaign_id,
            "success_criteria_defender": ["matched truth_hosts", "empty over_merged_hosts"],
        },
        "steps": steps,
    }


def fleet_manifests() -> List[Dict[str, Any]]:
    """10 attacks. Narratives assume no Corvex knowledge — just 'break the network'."""
    out: List[Dict[str, Any]] = []

    # 1 — GitHub ART: credential dump + pass-the-hash style lateral (T1003 / T1550.002)
    out.append(
        base_man(
            "fleet01-art-cred-dump-pth",
            family="attack_repo",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1003.001", "T1550.002", "T1021", "T1041"],
            origin="github_art",
            source_note="Adapted from Atomic Red Team OS Credential Dumping + pass-the-hash lateral patterns.",
            narrative=[
                "Dump creds on the beachhead, reuse the hash everywhere that accepts it, pull data out.",
                "No regard for defender tooling — spray until something works.",
            ],
            steps=[
                {"kind": "auth", "host": "host-a", "user": "Administrator", "src": "203.0.113.10", "offset_seconds": 0, "technique": "T1003.001"},
                {"kind": "auth", "host": "host-a", "user": "Administrator", "src": "203.0.113.10", "offset_seconds": 3, "technique": "T1003.001"},
                {"kind": "auth", "host": "host-b", "user": "Administrator", "src": "host-a", "offset_seconds": 8, "technique": "T1550.002"},
                {"kind": "auth", "host": "host-b", "user": "Administrator", "src": "host-a", "offset_seconds": 11, "technique": "T1550.002"},
                {"kind": "auth", "host": "host-c", "user": "Administrator", "src": "host-b", "offset_seconds": 16, "technique": "T1021"},
                {"kind": "auth", "host": "host-c", "user": "Administrator", "src": "host-b", "offset_seconds": 19, "technique": "T1021"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.20", "bytes": 24000, "offset_seconds": 28, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.20", "bytes": 18000, "offset_seconds": 32, "technique": "T1041"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.20", "bytes": 16000, "offset_seconds": 36, "technique": "T1041"},
            ],
        )
    )

    # 2 — GitHub ART: PowerShell / scripting interpreter chain (T1059.001)
    out.append(
        base_man(
            "fleet02-art-powershell-chain",
            family="attack_repo",
            truth=["host-a", "host-b", "host-d"],
            techniques=["T1059.001", "T1078", "T1041"],
            origin="github_art",
            source_note="Atomic-style PowerShell execution → interactive user → egress.",
            narrative=[
                "Encoded PowerShell foothold, steal an interactive session, move, exfil.",
            ],
            steps=[
                {"kind": "recon", "host": "host-a", "dst_ips": [f"10.40.1.{i}" for i in range(1, 9)], "dst_port": 5985, "dst_step": 1, "offset_seconds": 0, "technique": "T1059.001"},
                {"kind": "auth", "host": "host-a", "user": "ps-operator", "src": "203.0.113.33", "offset_seconds": 12, "technique": "T1059.001"},
                {"kind": "auth", "host": "host-b", "user": "ps-operator", "src": "host-a", "offset_seconds": 18, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "ps-operator", "src": "host-a", "offset_seconds": 21, "technique": "T1078"},
                {"kind": "auth", "host": "host-d", "user": "ps-operator", "src": "host-b", "offset_seconds": 28, "technique": "T1078"},
                {"kind": "exfil", "host": "host-d", "dst_ip": "198.51.100.30", "bytes": 20000, "offset_seconds": 40, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.30", "bytes": 14000, "offset_seconds": 44, "technique": "T1041"},
                {"kind": "exfil", "host": "host-d", "dst_ip": "198.51.100.30", "bytes": 12000, "offset_seconds": 48, "technique": "T1041"},
            ],
        )
    )

    # 3 — GitHub ART: SMB / remote services lateral (T1021.002)
    out.append(
        base_man(
            "fleet03-art-smb-admin-shares",
            family="attack_repo",
            truth=["host-a", "host-b", "host-c", "host-d"],
            techniques=["T1021.002", "T1078", "T1041"],
            origin="github_art",
            source_note="Atomic Red Team remote services / admin share hop chain.",
            narrative=[
                "Walk admin$ / C$ style remoting across the segment as fast as auth allows.",
            ],
            steps=[
                {"kind": "recon", "host": "host-a", "dst_ips": ["10.50.0.11", "10.50.0.12", "10.50.0.13", "10.50.0.14", "10.50.0.15", "10.50.0.16"], "dst_port": 445, "dst_step": 1, "offset_seconds": 0, "technique": "T1021.002"},
                {"kind": "auth", "host": "host-a", "user": "svc-deploy", "src": "10.50.0.9", "offset_seconds": 10, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "svc-deploy", "src": "host-a", "offset_seconds": 14, "technique": "T1021.002"},
                {"kind": "auth", "host": "host-c", "user": "svc-deploy", "src": "host-b", "offset_seconds": 18, "technique": "T1021.002"},
                {"kind": "auth", "host": "host-d", "user": "svc-deploy", "src": "host-c", "offset_seconds": 22, "technique": "T1021.002"},
                {"kind": "auth", "host": "host-d", "user": "svc-deploy", "src": "host-c", "offset_seconds": 25, "technique": "T1021.002"},
                {"kind": "exfil", "host": "host-d", "dst_ip": "198.51.100.40", "bytes": 30000, "offset_seconds": 35, "technique": "T1041"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.40", "bytes": 22000, "offset_seconds": 38, "technique": "T1041"},
            ],
        )
    )

    # 4 — GitHub ART: network discovery then exfil (T1046 / T1048)
    out.append(
        base_man(
            "fleet04-art-recon-exfil",
            family="attack_repo",
            truth=["host-b", "host-c"],
            techniques=["T1046", "T1048", "T1078"],
            origin="github_art",
            source_note="Atomic network service discovery then alternate protocol exfil.",
            narrative=[
                "Map the segment hard, then push loot over an alternate channel.",
            ],
            steps=[
                {"kind": "recon", "host": "host-b", "dst_ips": [f"10.60.{i}.1" for i in range(1, 12)], "dst_port": 22, "dst_step": 1, "offset_seconds": 0, "technique": "T1046"},
                {"kind": "recon", "host": "host-c", "dst_ips": [f"10.60.{i}.2" for i in range(1, 10)], "dst_port": 22, "dst_step": 1, "offset_seconds": 15, "technique": "T1046"},
                {"kind": "auth", "host": "host-b", "user": "scanbot", "src": "203.0.113.70", "offset_seconds": 30, "technique": "T1078"},
                {"kind": "auth", "host": "host-c", "user": "scanbot", "src": "host-b", "offset_seconds": 36, "technique": "T1078"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.50", "dst_port": 8443, "bytes": 26000, "offset_seconds": 50, "technique": "T1048"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.50", "dst_port": 8443, "bytes": 19000, "offset_seconds": 55, "technique": "T1048"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.50", "dst_port": 8443, "bytes": 15000, "offset_seconds": 60, "technique": "T1048"},
            ],
        )
    )

    # 5 — GitHub ART: DNS C2 only (T1071.004) — known Corvex blind channel
    out.append(
        base_man(
            "fleet05-art-dns-c2-only",
            family="genuine_vuln_breaker",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1071.004", "T1078"],
            origin="github_art",
            source_note="Atomic application-layer DNS C2 — no auth/exfil detectors should fire on DNS alone.",
            narrative=[
                "Beacon and exfil exclusively over DNS. Avoid classic ports.",
            ],
            break_intent={
                "name": "DNS-only fleet",
                "expected_break_points": {"both_missed": True, "invisible_to_fusion": ["dns"]},
                "success_criteria_attacker": ["correlator misses truth hosts"],
            },
            steps=[
                {"kind": "dns", "host": "host-a", "query": "a1.c2.evil.test", "offset_seconds": 0, "technique": "T1071.004"},
                {"kind": "dns", "host": "host-a", "query": "a2.c2.evil.test", "offset_seconds": 5, "technique": "T1071.004"},
                {"kind": "dns", "host": "host-b", "query": "b1.c2.evil.test", "offset_seconds": 10, "technique": "T1071.004"},
                {"kind": "dns", "host": "host-b", "query": "b2.c2.evil.test", "offset_seconds": 15, "technique": "T1071.004"},
                {"kind": "dns", "host": "host-c", "query": "c1.c2.evil.test", "offset_seconds": 20, "technique": "T1071.004"},
                {"kind": "dns", "host": "host-c", "query": "payload.c2.evil.test", "offset_seconds": 25, "technique": "T1071.004"},
                # tiny auth noise that does NOT span 2 hosts with same user
                {"kind": "auth", "host": "host-a", "user": "dns-only-a", "src": "203.0.113.1", "offset_seconds": 30, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "dns-only-b", "src": "203.0.113.2", "offset_seconds": 35, "technique": "T1078"},
            ],
        )
    )

    # 6 — GitHub ART: password spray intensity (T1110)
    out.append(
        base_man(
            "fleet06-art-password-spray",
            family="attack_repo",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1110.003", "T1078", "T1041"],
            origin="github_art",
            source_note="Atomic password spraying — many users/hosts then one hit pivots.",
            narrative=[
                "Spray every box. When one cred works, burn lateral and leave.",
            ],
            steps=[
                # spray noise — distinct users (should NOT fuse as one lateral)
                *[{"kind": "auth", "host": h, "user": f"spray-{i}", "src": "203.0.113.99", "offset_seconds": i, "technique": "T1110.003"}
                  for i, h in enumerate(["host-a", "host-b", "host-c", "host-d", "host-e", "host-a", "host-b", "host-c"])],
                # success user
                {"kind": "auth", "host": "host-a", "user": "jdoe", "src": "203.0.113.99", "offset_seconds": 20, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "jdoe", "src": "host-a", "offset_seconds": 24, "technique": "T1078"},
                {"kind": "auth", "host": "host-c", "user": "jdoe", "src": "host-b", "offset_seconds": 28, "technique": "T1078"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.60", "bytes": 21000, "offset_seconds": 40, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.60", "bytes": 17000, "offset_seconds": 44, "technique": "T1041"},
            ],
        )
    )

    # 7 — ORIGINAL: IP-only src lateral (no host-* ) — defeats src attribution
    out.append(
        base_man(
            "fleet07-orig-ip-src-lateral",
            family="genuine_vuln_breaker",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1021", "T1078", "T1041"],
            origin="original",
            source_note="Original breaker: lateral auth only carries raw IPs as src — never host-*.",
            narrative=[
                "Move with source IPs only. Never leave hostnames in auth logs.",
            ],
            break_intent={
                "name": "IP-src blindness",
                "expected_break_points": {"missed_hosts": ["host-a"]},
                "success_criteria_attacker": ["entry host-a absent from correlator campaign"],
            },
            steps=[
                {"kind": "auth", "host": "host-a", "user": "ops", "src": "203.0.113.200", "offset_seconds": 0, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "ops", "src": "10.1.0.11", "offset_seconds": 8, "technique": "T1021"},
                {"kind": "auth", "host": "host-b", "user": "ops", "src": "10.1.0.11", "offset_seconds": 11, "technique": "T1021"},
                {"kind": "auth", "host": "host-c", "user": "ops", "src": "10.1.0.12", "offset_seconds": 18, "technique": "T1021"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.70", "bytes": 19000, "offset_seconds": 30, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.70", "bytes": 16000, "offset_seconds": 34, "technique": "T1041"},
            ],
        )
    )

    # 8 — ORIGINAL: under-ceiling chunked exfil + benign CDN on innocents
    out.append(
        base_man(
            "fleet08-orig-chunked-cdn-bait",
            family="genuine_vuln_breaker",
            truth=["host-a", "host-b"],
            techniques=["T1041", "T1105", "T1078"],
            origin="original",
            source_note="Original: stay under micro_exfil byte ceiling; pollute with org CDN on d/e.",
            narrative=[
                "Chunk loot under detector thresholds. Make everyone look like Windows Update.",
            ],
            steps=[
                {"kind": "exfil", "host": "host-a", "dst_ip": "104.18.32.7", "bytes": 8200, "offset_seconds": 0, "technique": "T1105"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "104.18.32.7", "bytes": 8100, "offset_seconds": 5, "technique": "T1105"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "104.18.32.7", "bytes": 8000, "offset_seconds": 10, "technique": "T1105"},
                {"kind": "exfil", "host": "host-d", "dst_ip": "104.18.32.7", "bytes": 7900, "offset_seconds": 15, "technique": "T1105"},
                {"kind": "exfil", "host": "host-e", "dst_ip": "104.18.32.7", "bytes": 7800, "offset_seconds": 20, "technique": "T1105"},
                {"kind": "auth", "host": "host-a", "user": "chunker", "src": "203.0.113.8", "offset_seconds": 40, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "chunker", "src": "host-a", "offset_seconds": 45, "technique": "T1078"},
                # real loot under 50KB ceiling, same dst across APT only
                {"kind": "exfil", "host": "host-a", "dst_ip": "198.51.100.80", "bytes": 9000, "offset_seconds": 55, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.80", "bytes": 9000, "offset_seconds": 58, "technique": "T1041"},
                {"kind": "exfil", "host": "host-a", "dst_ip": "198.51.100.80", "bytes": 9000, "offset_seconds": 61, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.80", "bytes": 9000, "offset_seconds": 64, "technique": "T1041"},
            ],
        )
    )

    # 9 — ORIGINAL: window boundary — second wave at +601s (outside default 600s window)
    out.append(
        base_man(
            "fleet09-orig-window-gap",
            family="genuine_vuln_breaker",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1078", "T1041"],
            origin="original",
            source_note="Original: split campaign across correlator window_seconds=600 boundary.",
            narrative=[
                "Hit hard, go quiet past ten minutes, finish the job on the same hosts.",
            ],
            break_intent={
                "name": "window gap",
                "expected_break_points": {"fragmented_campaigns": True},
                "success_criteria_attacker": ["single campaign does not cover full truth"],
            },
            steps=[
                {"kind": "auth", "host": "host-a", "user": "sleeper", "src": "203.0.113.55", "offset_seconds": 0, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "sleeper", "src": "host-a", "offset_seconds": 20, "technique": "T1078"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.90", "bytes": 12000, "offset_seconds": 40, "technique": "T1041"},
                # resume after window (gap from last wave-1 event at t=40 must exceed 600s)
                # resume after window — same user, IP srcs (resume_window re-links)
                {"kind": "auth", "host": "host-b", "user": "sleeper", "src": "10.1.0.50", "offset_seconds": 700, "technique": "T1078"},
                {"kind": "auth", "host": "host-c", "user": "sleeper", "src": "10.1.0.51", "offset_seconds": 720, "technique": "T1078"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.91", "bytes": 15000, "offset_seconds": 740, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.91", "bytes": 11000, "offset_seconds": 750, "technique": "T1041"},
            ],
        )
    )

    # 10 — ORIGINAL: ransomware mass-auth + buried APT user + shared backup account fanout
    out.append(
        base_man(
            "fleet10-orig-ransom-fanout-bury",
            family="genuine_vuln_breaker",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1486", "T1078", "T1041"],
            origin="original",
            source_note="Original: fleet-wide backup account fanout (poison bait) while real APT uses buried user.",
            narrative=[
                "Encryptor prep: authenticate as backup everywhere. Real operator uses a quiet account underneath.",
            ],
            steps=[
                # fleet-wide shared account — should be poisoned
                *[{"kind": "auth", "host": h, "user": "backup$", "src": "10.0.0.5", "offset_seconds": i * 2, "technique": "T1486"}
                  for i, h in enumerate(HOSTS)],
                *[{"kind": "auth", "host": h, "user": "backup$", "src": "10.0.0.5", "offset_seconds": 20 + i * 2, "technique": "T1486"}
                  for i, h in enumerate(HOSTS)],
                # buried APT
                {"kind": "auth", "host": "host-a", "user": "quiet-op", "src": "203.0.113.77", "offset_seconds": 40, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "quiet-op", "src": "host-a", "offset_seconds": 46, "technique": "T1078"},
                {"kind": "auth", "host": "host-c", "user": "quiet-op", "src": "host-b", "offset_seconds": 52, "technique": "T1078"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.100", "bytes": 25000, "offset_seconds": 65, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.100", "bytes": 20000, "offset_seconds": 70, "technique": "T1041"},
            ],
        )
    )

    # 11 — GitHub ART: scheduled task / persistence lateral (T1053)
    out.append(
        base_man(
            "fleet11-art-scheduled-task",
            family="attack_repo",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1053.005", "T1078", "T1041"],
            origin="github_art",
            source_note="Atomic scheduled task persistence then hop.",
            narrative=["Plant tasks, reuse the service identity, pull data."],
            steps=[
                {"kind": "auth", "host": "host-a", "user": "tasksvc", "src": "203.0.113.12", "offset_seconds": 0, "technique": "T1053.005"},
                {"kind": "auth", "host": "host-b", "user": "tasksvc", "src": "host-a", "offset_seconds": 10, "technique": "T1078"},
                {"kind": "auth", "host": "host-c", "user": "tasksvc", "src": "host-b", "offset_seconds": 20, "technique": "T1078"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.110", "bytes": 17000, "offset_seconds": 35, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.110", "bytes": 14000, "offset_seconds": 40, "technique": "T1041"},
            ],
        )
    )

    # 12 — GitHub ART: WMI remote (T1047)
    out.append(
        base_man(
            "fleet12-art-wmi-remote",
            family="attack_repo",
            truth=["host-a", "host-b", "host-d"],
            techniques=["T1047", "T1021", "T1041"],
            origin="github_art",
            source_note="Atomic WMI remote execution hop chain.",
            narrative=["WMI remoting across the segment; dump and leave."],
            steps=[
                {"kind": "auth", "host": "host-a", "user": "wmi-ops", "src": "203.0.113.13", "offset_seconds": 0, "technique": "T1047"},
                {"kind": "auth", "host": "host-b", "user": "wmi-ops", "src": "host-a", "offset_seconds": 8, "technique": "T1021"},
                {"kind": "auth", "host": "host-d", "user": "wmi-ops", "src": "host-b", "offset_seconds": 16, "technique": "T1021"},
                {"kind": "exfil", "host": "host-d", "dst_ip": "198.51.100.120", "bytes": 21000, "offset_seconds": 30, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.120", "bytes": 16000, "offset_seconds": 34, "technique": "T1041"},
            ],
        )
    )

    # 13 — GitHub ART: cloud/metadata-ish egress (T1552) + lateral
    out.append(
        base_man(
            "fleet13-art-cloud-cred-egress",
            family="attack_repo",
            truth=["host-b", "host-c"],
            techniques=["T1552.005", "T1078", "T1041"],
            origin="github_art",
            source_note="Atomic cloud credential access style egress + pivot.",
            narrative=["Grab cloud tokens, pivot, exfil to attacker bucket."],
            steps=[
                {"kind": "auth", "host": "host-b", "user": "cloud-role", "src": "203.0.113.14", "offset_seconds": 0, "technique": "T1552.005"},
                {"kind": "auth", "host": "host-c", "user": "cloud-role", "src": "host-b", "offset_seconds": 12, "technique": "T1078"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.130", "bytes": 28000, "offset_seconds": 25, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.130", "bytes": 19000, "offset_seconds": 30, "technique": "T1041"},
            ],
        )
    )

    # 14 — GitHub ART: remote desktop / interactive (T1021.001)
    out.append(
        base_man(
            "fleet14-art-rdp-hop",
            family="attack_repo",
            truth=["host-a", "host-c", "host-e"],
            techniques=["T1021.001", "T1078", "T1041"],
            origin="github_art",
            source_note="Atomic RDP interactive hop.",
            narrative=["RDP hop a→c→e then pull files."],
            steps=[
                {"kind": "auth", "host": "host-a", "user": "rdp-user", "src": "203.0.113.15", "offset_seconds": 0, "technique": "T1021.001"},
                {"kind": "auth", "host": "host-c", "user": "rdp-user", "src": "host-a", "offset_seconds": 15, "technique": "T1021.001"},
                {"kind": "auth", "host": "host-e", "user": "rdp-user", "src": "host-c", "offset_seconds": 30, "technique": "T1021.001"},
                {"kind": "exfil", "host": "host-e", "dst_ip": "198.51.100.140", "bytes": 23000, "offset_seconds": 45, "technique": "T1041"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.140", "bytes": 15000, "offset_seconds": 50, "technique": "T1041"},
            ],
        )
    )

    # 15 — GitHub ART: email collection style multi-host (T1114)
    out.append(
        base_man(
            "fleet15-art-mail-collect",
            family="attack_repo",
            truth=["host-a", "host-b"],
            techniques=["T1114", "T1078", "T1041"],
            origin="github_art",
            source_note="Atomic email collection then dual-host egress.",
            narrative=["Mailbox access on two mail roles, sync out."],
            steps=[
                {"kind": "auth", "host": "host-a", "user": "mailadmin", "src": "203.0.113.16", "offset_seconds": 0, "technique": "T1114"},
                {"kind": "auth", "host": "host-b", "user": "mailadmin", "src": "host-a", "offset_seconds": 10, "technique": "T1078"},
                {"kind": "exfil", "host": "host-a", "dst_ip": "198.51.100.150", "bytes": 32000, "offset_seconds": 25, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.150", "bytes": 27000, "offset_seconds": 30, "technique": "T1041"},
            ],
        )
    )

    # 16 — ORIGINAL: dual-user meet-in-middle (needs auth↔exfil bridge)
    out.append(
        base_man(
            "fleet16-orig-dual-user-bridge",
            family="attack_repo",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1078", "T1041"],
            origin="original",
            source_note="Original: two users meet on host-b with shared exfil.",
            narrative=["Operator A and B hand off on the jump box."],
            steps=[
                {"kind": "auth", "host": "host-a", "user": "op-a", "src": "203.0.113.17", "offset_seconds": 0, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "op-a", "src": "host-a", "offset_seconds": 10, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "op-b", "src": "203.0.113.18", "offset_seconds": 20, "technique": "T1078"},
                {"kind": "auth", "host": "host-c", "user": "op-b", "src": "host-b", "offset_seconds": 30, "technique": "T1078"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.160", "bytes": 18000, "offset_seconds": 40, "technique": "T1041"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.160", "bytes": 16000, "offset_seconds": 45, "technique": "T1041"},
            ],
        )
    )

    # 17 — ORIGINAL: DNS + auth hybrid (dns should fuse with lateral)
    out.append(
        base_man(
            "fleet17-orig-dns-plus-lateral",
            family="attack_repo",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1071.004", "T1078", "T1041"],
            origin="original",
            source_note="Original: DNS beacon plus short lateral — should fuse.",
            narrative=["Beacon over DNS while hopping with a real account."],
            steps=[
                {"kind": "dns", "host": "host-a", "query": "1.beacon.evil.test", "offset_seconds": 0, "technique": "T1071.004"},
                {"kind": "dns", "host": "host-b", "query": "2.beacon.evil.test", "offset_seconds": 5, "technique": "T1071.004"},
                {"kind": "auth", "host": "host-a", "user": "hybrid", "src": "203.0.113.19", "offset_seconds": 10, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "hybrid", "src": "host-a", "offset_seconds": 15, "technique": "T1078"},
                {"kind": "auth", "host": "host-c", "user": "hybrid", "src": "host-b", "offset_seconds": 20, "technique": "T1078"},
                {"kind": "dns", "host": "host-c", "query": "3.beacon.evil.test", "offset_seconds": 25, "technique": "T1071.004"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.170", "bytes": 14000, "offset_seconds": 35, "technique": "T1041"},
            ],
        )
    )

    # 18 — ORIGINAL: rapid burst intensity (many retries same chain)
    out.append(
        base_man(
            "fleet18-orig-burst-retries",
            family="attack_repo",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1110", "T1078", "T1041"],
            origin="original",
            source_note="Original: high-intensity retry storm then pivot.",
            narrative=["Hammer auth, then the working cred flies."],
            steps=[
                *[{"kind": "auth", "host": "host-a", "user": "burst", "src": "203.0.113.20", "offset_seconds": i, "technique": "T1110"} for i in range(0, 10)],
                {"kind": "auth", "host": "host-b", "user": "burst", "src": "host-a", "offset_seconds": 12, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "burst", "src": "host-a", "offset_seconds": 13, "technique": "T1078"},
                {"kind": "auth", "host": "host-c", "user": "burst", "src": "host-b", "offset_seconds": 16, "technique": "T1078"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.180", "bytes": 20000, "offset_seconds": 25, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.180", "bytes": 15000, "offset_seconds": 28, "technique": "T1041"},
            ],
        )
    )

    # 19 — ORIGINAL: benign helpdesk + APT share jump (anti-jumpbox must hold)
    out.append(
        base_man(
            "fleet19-orig-helpdesk-vs-apt",
            family="genuine_vuln_breaker",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1078", "T1041"],
            origin="original",
            source_note="Original: helpdesk on c↔d must not glue to APT a↔b↔c.",
            narrative=["APT on a-b-c. Helpdesk also on c-d same minute."],
            break_intent={
                "name": "anti-jumpbox",
                "success_criteria_defender": ["empty over_merged_hosts", "matched truth"],
            },
            steps=[
                {"kind": "auth", "host": "host-a", "user": "apt-user", "src": "203.0.113.21", "offset_seconds": 0, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "apt-user", "src": "host-a", "offset_seconds": 10, "technique": "T1078"},
                {"kind": "auth", "host": "host-c", "user": "apt-user", "src": "host-b", "offset_seconds": 20, "technique": "T1078"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.190", "bytes": 16000, "offset_seconds": 30, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.190", "bytes": 14000, "offset_seconds": 35, "technique": "T1041"},
                {"kind": "auth", "host": "host-c", "user": "helpdesk", "src": "10.30.0.9", "offset_seconds": 25, "technique": "T1078"},
                {"kind": "auth", "host": "host-d", "user": "helpdesk", "src": "host-c", "offset_seconds": 32, "technique": "T1078"},
            ],
        )
    )

    # 20 — ORIGINAL: mixed CDN poison + real APT (CDN must stay poisoned)
    out.append(
        base_man(
            "fleet20-orig-cdn-plus-apt",
            family="genuine_vuln_breaker",
            truth=["host-a", "host-b", "host-c"],
            techniques=["T1105", "T1078", "T1041"],
            origin="original",
            source_note="Original: fleet CDN then APT — innocents must stay saved.",
            narrative=["Everyone hits CDN. APT still moves underneath."],
            steps=[
                *[{"kind": "exfil", "host": h, "dst_ip": "104.18.32.7", "bytes": 7500, "offset_seconds": i * 3, "technique": "T1105"} for i, h in enumerate(HOSTS)],
                {"kind": "auth", "host": "host-a", "user": "under", "src": "203.0.113.22", "offset_seconds": 40, "technique": "T1078"},
                {"kind": "auth", "host": "host-b", "user": "under", "src": "host-a", "offset_seconds": 48, "technique": "T1078"},
                {"kind": "auth", "host": "host-c", "user": "under", "src": "host-b", "offset_seconds": 56, "technique": "T1078"},
                {"kind": "exfil", "host": "host-c", "dst_ip": "198.51.100.200", "bytes": 19000, "offset_seconds": 70, "technique": "T1041"},
                {"kind": "exfil", "host": "host-b", "dst_ip": "198.51.100.200", "bytes": 15000, "offset_seconds": 75, "technique": "T1041"},
            ],
        )
    )

    return out


def write_manifests() -> List[Path]:
    if FLEET_DIR.exists():
        shutil.rmtree(FLEET_DIR)
    FLEET_DIR.mkdir(parents=True)
    paths = []
    for man in fleet_manifests():
        path = FLEET_DIR / f"{man['campaign_id']}.json"
        path.write_text(json.dumps(man, indent=2) + "\n", encoding="utf-8")
        paths.append(path)
    return paths


def score_one(path: Path, intensity_rounds: int = 3) -> Dict[str, Any]:
    """Full intensity: build-breaktest + replay rounds; take worst/best honesty stats."""
    stem = path.stem
    rounds = []
    t0 = time.perf_counter()
    for r in range(1, intensity_rounds + 1):
        out_dir = RUN / stem / f"r{r}"
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True)
        pack = out_dir / "pack.jsonl"
        breaks = out_dir / "breaks.json"
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "corvex",
                "build-breaktest",
                str(path),
                "--out",
                str(pack),
                "--report",
                str(breaks),
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        row: Dict[str, Any] = {"round": r, "build_ok": proc.returncode == 0}
        if breaks.is_file():
            br = json.loads(breaks.read_text(encoding="utf-8"))
            bp = br.get("break_points") or {}
            corr = br.get("correlator") or {}
            det = br.get("detector_only") or {}
            row.update(
                {
                    "corr_matched": corr.get("matched"),
                    "corr_jaccard": corr.get("best_jaccard"),
                    "det_matched": det.get("matched"),
                    "det_jaccard": det.get("best_jaccard"),
                    "missed_hosts": bp.get("missed_hosts") or [],
                    "over_merged_hosts": bp.get("over_merged_hosts") or [],
                    "fusion_lift": bp.get("fusion_lift"),
                    "both_missed": bp.get("both_missed"),
                    "corr_hosts": corr.get("hosts_union") or [],
                }
            )
            # quarantine dry-run via replay
            replay = out_dir / "replay"
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "corvex",
                    "replay",
                    str(pack),
                    "--out-dir",
                    str(replay),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
            )
            q = set()
            recon_path = replay / "reconstruction.json"
            if recon_path.is_file():
                recon = json.loads(recon_path.read_text(encoding="utf-8"))
                for item in recon.get("campaign_reconstructions") or []:
                    qq = item.get("quarantine") or {}
                    # Empty host_ids [] means contain gate refused — do not use campaign hosts.
                    if "host_ids" in qq:
                        q.update(str(h) for h in (qq.get("host_ids") or []))
                    else:
                        q.update(str(h) for h in (item.get("host_ids") or []))
            row["quarantine_proposed"] = sorted(q)
        else:
            row["error"] = (proc.stderr or proc.stdout or "")[-500:]
        rounds.append(row)
    wall = round(time.perf_counter() - t0, 4)
    man = json.loads(path.read_text(encoding="utf-8"))
    truth = set(man.get("truth_hosts") or [])
    last = rounds[-1] if rounds else {}
    flagged = set(last.get("corr_hosts") or [])
    qprop = set(last.get("quarantine_proposed") or [])
    innocents = set(HOSTS) - truth
    saved = sorted(h for h in innocents if h not in qprop)
    false_q = sorted(h for h in innocents if h in qprop)
    verdict = "HELD"
    j = float(last.get("corr_jaccard") or 0.0)
    missed = list(last.get("missed_hosts") or [])
    over = list(last.get("over_merged_hosts") or [])
    if last.get("both_missed") or j <= 0.0:
        verdict = "BROKE"
    elif missed or over or j < 0.99:
        verdict = "PARTIAL"
    return {
        "campaign_id": man["campaign_id"],
        "origin": man.get("fleet_origin"),
        "techniques": (man.get("source") or {}).get("techniques"),
        "truth_hosts": sorted(truth),
        "verdict": verdict,
        "intensity_rounds": intensity_rounds,
        "wall_seconds": wall,
        "corr_jaccard": last.get("corr_jaccard"),
        "corr_matched": last.get("corr_matched"),
        "det_jaccard": last.get("det_jaccard"),
        "missed_hosts": missed,
        "over_merged_hosts": over,
        "quarantine_proposed": sorted(qprop),
        "hosts_saved": saved,
        "false_quarantine": false_q,
        "fusion_lift": last.get("fusion_lift"),
        "rounds": rounds,
        "narrative": (man.get("narrative") or [""])[0],
    }


def markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Attack fleet 20 — full-intensity black-box benchmark",
        "",
        "Purple-team **event sketches** only. Sources cite "
        f"[Atomic Red Team]({ART}) technique IDs where marked `github_art`. "
        "No malware executed. Quarantine = dry-run proposals.",
        "",
        f"- Attacks: **{report['n']}** | Intensity rounds/attack: **{report['intensity_rounds']}**",
        f"- Wall: **{report['total_wall_seconds']}s**",
        f"- HELD: **{report['counts']['HELD']}** | PARTIAL: **{report['counts']['PARTIAL']}** | BROKE: **{report['counts']['BROKE']}**",
        "",
        "## Fleet scoreboard",
        "",
        "| # | Campaign | Origin | Verdict | Jaccard | Missed | Over-merged | Saved | False Q |",
        "|---|----------|--------|---------|---------|--------|-------------|-------|---------|",
    ]
    for i, a in enumerate(report["attacks"], 1):
        lines.append(
            "| {i} | {cid} | {o} | **{v}** | {j} | {m} | {om} | {s} | {fq} |".format(
                i=i,
                cid=a["campaign_id"],
                o=a["origin"],
                v=a["verdict"],
                j=a.get("corr_jaccard"),
                m=", ".join(a.get("missed_hosts") or []) or "-",
                om=", ".join(a.get("over_merged_hosts") or []) or "-",
                s=", ".join(a.get("hosts_saved") or []) or "-",
                fq=", ".join(a.get("false_quarantine") or []) or "-",
            )
        )
    lines.extend(["", "## Where it broke", ""])
    broke = [a for a in report["attacks"] if a["verdict"] != "HELD"]
    if not broke:
        lines.append("No stable breaks — all attacks matched truth without over-merge.")
    for a in broke:
        lines.append(
            f"- **{a['campaign_id']}** ({a['origin']}, {a['verdict']}): "
            f"missed={a['missed_hosts']} over_merged={a['over_merged_hosts']} "
            f"— {a['narrative']}"
        )
    lines.extend(
        [
            "",
            "## Per-attack detail",
            "",
        ]
    )
    for a in report["attacks"]:
        lines.extend(
            [
                f"### {a['campaign_id']}",
                "",
                f"- Origin: `{a['origin']}` | Techniques: {', '.join(a.get('techniques') or [])}",
                f"- Truth: {', '.join(a['truth_hosts'])}",
                f"- Verdict: **{a['verdict']}** | Jaccard={a.get('corr_jaccard')} | fusion_lift={a.get('fusion_lift')}",
                f"- Quarantine dry-run: {', '.join(a.get('quarantine_proposed') or []) or '-'}",
                f"- Saved: {', '.join(a.get('hosts_saved') or []) or '-'} | False Q: {', '.join(a.get('false_quarantine') or []) or '-'}",
                "",
            ]
        )
    lines.extend(
        [
            "## Honesty",
            "",
            "- Black-box narratives; scoring uses Corvex break-point machinery.",
            "- DNS-only and window-gap packs are intentional stress cases.",
            "- Live OS quarantine remains unimplemented.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    intensity = 3
    if len(sys.argv) > 1:
        intensity = max(1, int(sys.argv[1]))
    paths = write_manifests()
    if RUN.exists():
        shutil.rmtree(RUN)
    RUN.mkdir(parents=True)
    wall0 = time.perf_counter()
    attacks = []
    for path in paths:
        print(f"=== {path.name} ===", flush=True)
        row = score_one(path, intensity_rounds=intensity)
        attacks.append(row)
        print(json.dumps({k: row[k] for k in ("campaign_id", "verdict", "corr_jaccard", "missed_hosts", "over_merged_hosts", "hosts_saved")}, indent=2), flush=True)
    counts = {k: sum(1 for a in attacks if a["verdict"] == k) for k in ("HELD", "PARTIAL", "BROKE")}
    report = {
        "test": "Attack fleet 20 — full intensity black-box benchmark",
        "n": len(attacks),
        "intensity_rounds": intensity,
        "total_wall_seconds": round(time.perf_counter() - wall0, 4),
        "counts": counts,
        "attacks": attacks,
        "honesty": (
            "Event sketches from public ATT&CK/Atomic technique IDs + original breakers. "
            "No live exploitation."
        ),
    }
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    text = markdown(report)
    REPORT_MD.write_text(text, encoding="utf-8")
    try:
        print(text)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(text.encode("utf-8", errors="replace"))
    print(f"\nJSON: {REPORT_JSON}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
