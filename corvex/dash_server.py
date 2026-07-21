"""Monitor HTTP server (static dashboard + checklist API)."""

from __future__ import annotations

import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Type
from urllib.parse import urlparse

from corvex.contain import L1_ITEMS, set_checklist_item
from corvex.dashboard import collect_snapshot, write_dashboard
from corvex.logs_page import write_logs_page
from corvex.prevention_log import load_prevention_log


def make_handler(repo_root: Path, dash_dir: Path) -> Type[SimpleHTTPRequestHandler]:
    root = Path(repo_root)
    directory = str(Path(dash_dir))

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

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            if not raw:
                return {}
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("expected JSON object")
            return data

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/api/snapshot":
                snap = collect_snapshot(root)
                write_dashboard(root, out=Path(directory) / "index.html")
                self._json(200, snap)
                return
            if path == "/api/prevention":
                write_logs_page(root, out_dir=Path(directory))
                self._json(200, {"entries": load_prevention_log(root)})
                return
            super().do_GET()

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path != "/api/checklist":
                self.send_error(404, "not found")
                return
            # Refuse remote checklist mutations (LAN bind is view-only).
            peer = self.client_address[0] if self.client_address else ""
            if peer not in ("127.0.0.1", "::1", "localhost"):
                self._json(403, {"ok": False, "error": "checklist toggles are loopback-only"})
                return
            try:
                data = self._read_json()
                key = str(data.get("key") or "")
                if key not in L1_ITEMS:
                    self._json(400, {"ok": False, "error": f"unknown key: {key}"})
                    return
                if "enabled" not in data:
                    self._json(400, {"ok": False, "error": "enabled required"})
                    return
                enabled = bool(data["enabled"])
                items = set_checklist_item(key, enabled, root=root, source="dashboard")
                snap = collect_snapshot(root)
                write_dashboard(root, out=Path(directory) / "index.html")
                self._json(
                    200,
                    {
                        "ok": True,
                        "key": key,
                        "enabled": enabled,
                        "items": items,
                        "snap": snap,
                    },
                )
            except Exception as exc:  # noqa: BLE001 — surface to UI
                self._json(500, {"ok": False, "error": str(exc)})

    return Handler


def serve(repo_root: Path, port: int = 8765, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    out = write_dashboard(repo_root)
    handler = make_handler(repo_root, out.parent)
    ThreadingHTTPServer.allow_reuse_address = True
    httpd = ThreadingHTTPServer((host, port), handler)
    return httpd
