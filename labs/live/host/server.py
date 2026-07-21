"""Virtual host sensor — accepts auth attempts; respects Corvex isolate flag."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HOST_ID = os.environ.get("HOST_ID", "host-a")
ROLE = os.environ.get("HOST_ROLE", "workstation")
LAB = Path(os.environ.get("LAB_DIR", "/lab"))
EVENTS = LAB / "events.jsonl"
ISOLATED = LAB / "isolated" / f"{HOST_ID}.flag"
STATE = LAB / "hosts" / f"{HOST_ID}.json"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def append_event(rec: dict) -> None:
    EVENTS.parent.mkdir(parents=True, exist_ok=True)
    with EVENTS.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, separators=(",", ":")) + "\n")


def write_state(**extra) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "host_id": HOST_ID,
        "role": ROLE,
        "isolated": ISOLATED.exists(),
        "ts": now(),
        **extra,
    }
    STATE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        print(f"[{HOST_ID}] " + (fmt % args), flush=True)

    def _json(self, code: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/health", "/"):
            self._json(
                200,
                {
                    "host_id": HOST_ID,
                    "role": ROLE,
                    "isolated": ISOLATED.exists(),
                    "status": "isolated" if ISOLATED.exists() else "open",
                },
            )
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "bad json"})
            return

        if path != "/auth":
            self._json(404, {"error": "not found"})
            return

        user = str(data.get("user") or "")
        src = str(data.get("src") or self.client_address[0])
        isolated = ISOLATED.exists()

        if isolated:
            append_event(
                {
                    "kind": "auth_blocked",
                    "host_id": HOST_ID,
                    "role": ROLE,
                    "ts_utc": now(),
                    "user": user,
                    "src": src,
                    "result": "blocked_by_corvex",
                    "isolated": True,
                }
            )
            write_state(last_auth="blocked", user=user, src=src)
            self._json(
                403,
                {
                    "ok": False,
                    "host_id": HOST_ID,
                    "result": "blocked_by_corvex",
                    "message": f"{HOST_ID} isolated by Corvex — auth refused",
                },
            )
            print(f"[{HOST_ID}] BLOCKED auth user={user} src={src}", flush=True)
            return

        append_event(
            {
                "kind": "auth",
                "host_id": HOST_ID,
                "role": ROLE,
                "ts_utc": now(),
                "user": user,
                "src": src,
                "result": "success",
                "isolated": False,
            }
        )
        write_state(last_auth="success", user=user, src=src)
        self._json(
            200,
            {
                "ok": True,
                "host_id": HOST_ID,
                "result": "success",
                "message": f"welcome {user}@{HOST_ID}",
            },
        )
        print(f"[{HOST_ID}] AUTH OK user={user} src={src}", flush=True)


def main() -> None:
    LAB.mkdir(parents=True, exist_ok=True)
    (LAB / "isolated").mkdir(parents=True, exist_ok=True)
    (LAB / "hosts").mkdir(parents=True, exist_ok=True)
    write_state(boot=True)
    port = int(os.environ.get("PORT", "8080"))
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"[{HOST_ID}] listening on :{port} role={ROLE}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
