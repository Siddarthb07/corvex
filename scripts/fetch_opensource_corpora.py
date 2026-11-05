#!/usr/bin/env python3
"""Fetch open-source attack corpora (OTRF/Security-Datasets) into labs/opensource/.

These are **externally authored** captures — not Corvex-written breaktest manifests.
Does not flip claim_allowed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, List  # Dict used by sanitize helpers

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "labs" / "opensource" / "catalog.json"
OUT_ROOT = ROOT / "labs" / "opensource"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# Fields kept after sanitize — enough for Corvex auth/net/dns adapt; drops
# CommandLine/ScriptBlockText that Windows Defender often flags as PUA.
_KEEP_KEYS = {
    "@timestamp",
    "UtcTime",
    "EventTime",
    "Channel",
    "channel",
    "EventID",
    "event_id",
    "Hostname",
    "Computer",
    "hostname",
    "DestinationIp",
    "DestinationPort",
    "SourceIp",
    "SourcePort",
    "QueryName",
    "QueryType",
    "TargetUserName",
    "SubjectUserName",
    "IpAddress",
    "DestAddress",
    "DestPort",
    "User",
    "AccountName",
    "AccountType",
    "Image",  # process path only; still useful, rarely the AV trigger alone
    # Lateral hop signal — required for correlator peer edges on OTRF
    "WorkstationName",
    "TargetServerName",
    "ClientName",
    "ServiceName",
    "TargetUserSid",
    "LogonType",
}


def _sanitize_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: rec[k] for k in _KEEP_KEYS if k in rec}
    # Winlogbeat ECS: keep structural winlog fields without script bodies
    if isinstance(rec.get("winlog"), dict):
        wl = rec["winlog"]
        ed = wl.get("event_data") if isinstance(wl.get("event_data"), dict) else {}
        ed_keep = {
            k: v
            for k, v in ed.items()
            if k
            in {
                "DestinationIp",
                "DestinationPort",
                "SourceIp",
                "SourcePort",
                "QueryName",
                "TargetUserName",
                "SubjectUserName",
                "IpAddress",
                "DestAddress",
                "DestPort",
                "User",
                "Image",
                "WorkstationName",
                "TargetServerName",
                "ClientName",
                "ServiceName",
                "LogonType",
            }
        }
        out["winlog"] = {
            "channel": wl.get("channel"),
            "event_id": wl.get("event_id"),
            "computer_name": wl.get("computer_name"),
            "event_data": ed_keep,
        }
    if isinstance(rec.get("host"), dict):
        out["host"] = {
            "hostname": rec["host"].get("hostname"),
            "name": rec["host"].get("name"),
        }
    if isinstance(rec.get("event"), dict):
        out["event"] = {
            "code": rec["event"].get("code"),
            "id": rec["event"].get("id"),
            "provider": rec["event"].get("provider"),
            "created": rec["event"].get("created"),
        }
    return out


def _iter_json_records_from_text(text: str):
    """Yield dict records from JSONL or a top-level JSON array (streaming-friendly for arrays)."""
    s = text.lstrip("\ufeff").lstrip()
    if not s:
        return
    if s[0] == "[":
        dec = json.JSONDecoder()
        i = 1
        n = len(s)
        while i < n:
            while i < n and s[i] in " \t\r\n,":
                i += 1
            if i < n and s[i] == "]":
                break
            if i >= n:
                break
            try:
                obj, end = dec.raw_decode(s, i)
            except json.JSONDecodeError:
                break
            if isinstance(obj, dict):
                yield obj
            i = end
        return
    for line in s.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict):
            yield rec


def _sanitize_json_bytes(raw: bytes) -> bytes:
    """Rewrite JSONL/array to drop AV-triggering script fields."""
    text = raw.decode("utf-8", errors="replace")
    lines_out: List[str] = [
        json.dumps(_sanitize_record(rec), separators=(",", ":"))
        for rec in _iter_json_records_from_text(text)
    ]
    return ("\n".join(lines_out) + ("\n" if lines_out else "")).encode("utf-8")


def _sanitize_stream_to_path(src, target: Path, *, chunk: int = 1 << 20) -> int:
    """Stream-sanitize a binary fileobj into sanitized JSONL. Returns record count.

    Avoids loading multi-hundred-MB APT29 captures fully twice when possible:
    small/medium files still go through bytes path; huge streams use incremental
    JSONL or chunked array decode after a full read only when needed.
    """
    # Prefer size hint when available (ZipExtFile / BufferedReader).
    size_hint = getattr(src, "seek", None) and getattr(src, "tell", None)
    data = src.read()
    if not data:
        target.write_bytes(b"")
        return 0
    # For very large payloads, still one read (zip already compressed in mem on extract
    # of member) — write line-by-line so peak is ~1× raw rather than 2× string+list.
    text = data.decode("utf-8", errors="replace")
    del data
    n = 0
    with target.open("w", encoding="utf-8", newline="\n") as out:
        for rec in _iter_json_records_from_text(text):
            out.write(json.dumps(_sanitize_record(rec), separators=(",", ":")))
            out.write("\n")
            n += 1
    del text
    return n


def _extract_zip(archive: Path, dest: Path) -> List[str]:
    names: List[str] = []
    with zipfile.ZipFile(archive, "r") as zf:
        for name in zf.namelist():
            if name.endswith("/"):
                continue
            low = name.lower()
            target = dest / Path(name).name
            if low.endswith(".json") or low.endswith(".jsonl"):
                # Always write .jsonl sanitized — avoids Defender PUA on Empire/Covenant CLIs
                if not target.name.endswith(".jsonl"):
                    target = dest / (Path(name).stem + ".sanitized.jsonl")
                with zf.open(name) as src:
                    _sanitize_stream_to_path(src, target)
            else:
                # Skip pcaps / binaries — Corvex host adapter only
                if low.endswith((".pcap", ".pcapng", ".zeek", ".log")):
                    continue
                target.write_bytes(zf.read(name))
            names.append(target.name)
    return names


def _extract_targz(archive: Path, dest: Path) -> List[str]:
    names: List[str] = []
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            low = member.name.lower()
            if not (low.endswith(".json") or low.endswith(".jsonl") or low.endswith(".log")):
                continue
            raw_f = tf.extractfile(member)
            if raw_f is None:
                continue
            flat = Path(member.name).name
            target = dest / flat
            if target.exists():
                parent = Path(member.name).parts[-2] if len(Path(member.name).parts) > 1 else "x"
                target = dest / f"{parent}_{flat}"
            if low.endswith(".json") or low.endswith(".jsonl"):
                target = dest / (target.stem + ".sanitized.jsonl")
                _sanitize_stream_to_path(raw_f, target)
            else:
                target.write_bytes(raw_f.read())
            names.append(target.name)
    return names


def fetch_one(entry: Dict[str, Any], *, base_url: str, force: bool) -> Dict[str, Any]:
    cid = str(entry["id"])
    corpus = OUT_ROOT / cid
    raw = corpus / "raw"
    meta_path = raw / "fetch_meta.json"
    if meta_path.is_file() and not force:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        return {"id": cid, "skipped": True, "corpus": str(corpus), "meta": meta}

    if corpus.exists() and force:
        shutil.rmtree(corpus)
    raw.mkdir(parents=True, exist_ok=True)
    (raw / ".gitkeep").touch()

    url = base_url.rstrip("/") + "/" + str(entry["path"]).lstrip("/")
    fmt = str(entry.get("format") or "zip")
    archive = raw / ("download.tar.gz" if fmt == "tar.gz" else "download.zip")
    print(f"GET {url}", flush=True)
    # APT29 day2 ~43MB compressed; allow long transfers
    with urllib.request.urlopen(url, timeout=900) as resp:
        archive.write_bytes(resp.read())

    if fmt == "tar.gz":
        extracted = _extract_targz(archive, raw)
    else:
        extracted = _extract_zip(archive, raw)
    meta = {
        "source_url": url,
        "archive_sha256": _sha256(archive),
        "format": fmt,
        "extracted": extracted,
        "family": entry.get("family"),
        "note": entry.get("note"),
        "license_note": "OTRF Security-Datasets — see upstream LICENSE (GPL-3.0).",
        "authorship": "external — OTRF / MITRE ATT&CK Evals capture, not Corvex authors",
    }
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    archive.unlink(missing_ok=True)

    man = {
        "name": cid,
        "corpus_kind": "opensource_attack_capture",
        "source": {
            "project": "OTRF/Security-Datasets",
            "url": url,
            "family": entry.get("family"),
            "tool": entry.get("tool"),
            "attack": entry.get("attack") or entry.get("note"),
            "techniques": entry.get("techniques") or [],
            "note": entry.get("note") or entry.get("attack"),
            "authorship": "external",
        },
        "raw_glob": "raw/*.sanitized.jsonl",
        "host_map": {},
        "fetch": meta,
    }
    (corpus / "manifest.json").write_text(json.dumps(man, indent=2) + "\n", encoding="utf-8")
    (corpus / "README.md").write_text(
        f"""# {cid}

Externally authored capture from [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets).

- **Family:** `{entry.get('family')}`
- **Note:** {entry.get('note')}
- **Authorship:** OTRF / upstream — **not** written by Corvex authors
- **Source:** `{url}`
- **Raw:** `raw/` (gitignored). Re-fetch: `python scripts/fetch_opensource_corpora.py --only {cid}`

Still a lab purple-team capture. Does **not** unlock `claim_allowed`.
""",
        encoding="utf-8",
    )
    return {"id": cid, "skipped": False, "corpus": str(corpus), "extracted": extracted}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--catalog", type=Path, default=CATALOG)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--full", action="store_true", help="Include optional_full corpora")
    ap.add_argument(
        "--aggressive",
        action="store_true",
        help="Only fetch corpora marked aggressive (APT29/APT3/LSASS/Log4Shell/GoldenSAML)",
    )
    ap.add_argument(
        "--live-stress",
        action="store_true",
        help="Only fetch corpora marked live_stress (laptop live correlator battery)",
    )
    ap.add_argument("--only", action="append", default=[], help="Fetch only these ids")
    args = ap.parse_args()

    cat = json.loads(Path(args.catalog).read_text(encoding="utf-8"))
    base = str(cat.get("base_url") or "")
    only = set(args.only or [])
    rows = []
    for entry in cat.get("corpora") or []:
        if only and entry["id"] not in only:
            continue
        if args.live_stress and not entry.get("live_stress") and not only:
            continue
        if args.aggressive and not entry.get("aggressive") and not only:
            continue
        if (
            entry.get("optional_full")
            and not args.full
            and not args.aggressive
            and not args.live_stress
            and not only
        ):
            print(
                f"skip optional_full {entry['id']} (pass --full / --aggressive / --live-stress)",
                flush=True,
            )
            continue
        try:
            rows.append(fetch_one(entry, base_url=base, force=bool(args.force)))
        except Exception as exc:  # noqa: BLE001
            # Windows Defender often blocks Empire/Covenant zips mid-write (Errno 22).
            print(f"FAIL {entry['id']}: {exc}", flush=True)
            rows.append({"id": entry["id"], "skipped": False, "error": str(exc)})
    ok = [r for r in rows if not r.get("error")]
    print(
        json.dumps(
            {
                "fetched": len(ok),
                "failed": sum(1 for r in rows if r.get("error")),
                "rows": [
                    {
                        "id": r["id"],
                        "skipped": r.get("skipped"),
                        **({"error": r["error"]} if r.get("error") else {}),
                    }
                    for r in rows
                ],
            },
            indent=2,
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
