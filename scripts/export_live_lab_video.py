#!/usr/bin/env python3
"""Export a HTML replay page to GIF + MP4 via Playwright."""

from __future__ import annotations

import http.server
import socketserver
import threading
import time
from io import BytesIO
from pathlib import Path

import imageio.v2 as imageio
import numpy as np
from PIL import Image
from playwright.sync_api import sync_playwright

FPS = 6
DURATION_S = 14.0
VIEWPORT = {"width": 1280, "height": 800}


def _serve(directory: Path):
    handler = type(
        "Handler",
        (http.server.SimpleHTTPRequestHandler,),
        {
            "__init__": lambda self, *a, **k: http.server.SimpleHTTPRequestHandler.__init__(
                self, *a, directory=str(directory), **k
            ),
            "log_message": lambda *a, **k: None,
        },
    )
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    httpd.allow_reuse_address = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def export_replay(html_path: Path, gif_path: Path, mp4_path: Path) -> None:
    html_path = Path(html_path)
    directory = html_path.parent
    httpd = _serve(directory)
    host, port = httpd.server_address
    url = f"http://{host}:{port}/{html_path.name}"
    frames: list[Image.Image] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport=VIEWPORT)
            page.goto(url, wait_until="networkidle")
            page.wait_for_timeout(400)
            start = time.time()
            interval = 1.0 / FPS
            next_t = start
            while time.time() - start < DURATION_S:
                png = page.screenshot(type="png")
                frames.append(Image.open(BytesIO(png)).convert("RGB"))
                next_t += interval
                delay = next_t - time.time()
                if delay > 0:
                    time.sleep(delay)
            browser.close()
    finally:
        httpd.shutdown()
        httpd.server_close()

    if not frames:
        raise RuntimeError("no frames captured")

    scaled = [f.resize((960, 600), Image.Resampling.LANCZOS) for f in frames]
    scaled[0].save(
        gif_path,
        save_all=True,
        append_images=scaled[1:],
        duration=int(1000 / FPS),
        loop=0,
    )

    writer = imageio.get_writer(
        mp4_path,
        fps=FPS,
        codec="libx264",
        quality=8,
        pixelformat="yuv420p",
        macro_block_size=None,
    )
    try:
        for frame in frames:
            arr = np.asarray(frame)
            h, w = arr.shape[:2]
            if h % 2 or w % 2:
                arr = arr[: h - h % 2, : w - w % 2]
            writer.append_data(arr)
    finally:
        writer.close()

    print(f"wrote {gif_path} ({gif_path.stat().st_size // 1024} KB)")
    print(f"wrote {mp4_path} ({mp4_path.stat().st_size // 1024} KB)")
