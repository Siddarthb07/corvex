"""Monitor HTTP server — static HTML + read-only snapshot API.

Council rebuild rules:
- GET /api/snapshot returns JSON only (does not rewrite HTML)
- No POST mutation endpoints on this server
- No prevention-log page
- Non-localhost bind requires a bearer / query token
"""

from __future__ import annotations

import json
import secrets
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional, Type
from urllib.parse import parse_qs, urlparse

from corvex.dashboard import collect_snapshot, write_dashboard


def make_handler(
    repo_root: Path,
    dash_dir: Path,
    *,
    access_token: Optional[str] = None,
) -> Type[SimpleHTTPRequestHandler]:
    root = Path(repo_root)
    directory = str(Path(dash_dir))
    token = access_token

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory, **kwargs)

        def log_message(self, fmt: str, *args) -> None:
            return

        def _json(self, code: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            if not token:
                return True
            auth = self.headers.get("Authorization") or ""
            if auth.lower().startswith("bearer ") and auth[7:].strip() == token:
                return True
            qs = parse_qs(urlparse(self.path).query)
            got = (qs.get("token") or [None])[0]
            return got == token

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/api/snapshot":
                if not self._authorized():
                    self._json(401, {"ok": False, "error": "unauthorized — pass Bearer or ?token="})
                    return
                self._json(200, collect_snapshot(root))
                return
            if path in ("/api/checklist", "/api/prevention"):
                self._json(
                    410,
                    {
                        "ok": False,
                        "error": "removed — monitor is read-only; use CLI for checklist evidence",
                    },
                )
                return
            super().do_GET()

        def do_POST(self) -> None:  # noqa: N802
            self._json(
                405,
                {
                    "ok": False,
                    "error": "monitor is read-only — no dashboard mutations",
                },
            )

    return Handler


def serve(
    repo_root: Path,
    port: int = 8765,
    host: str = "127.0.0.1",
    *,
    access_token: Optional[str] = None,
) -> ThreadingHTTPServer:
    if host in ("0.0.0.0", "::", "[::]") and not access_token:
        raise ValueError(
            "non-localhost dash bind requires an access token "
            "(pass --token or let CLI generate one)"
        )
    out = write_dashboard(repo_root)
    handler = make_handler(repo_root, out.parent, access_token=access_token)
    ThreadingHTTPServer.allow_reuse_address = True
    httpd = ThreadingHTTPServer((host, port), handler)
    return httpd


def new_access_token() -> str:
    return secrets.token_urlsafe(24)
