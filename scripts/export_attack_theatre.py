#!/usr/bin/env python3
"""Capture Corvex attack theatre to GIF + MP4."""

from __future__ import annotations

import http.server
import socketserver
import threading
import time
from pathlib import Path

import imageio.v2 as imageio
import numpy as np
from PIL import Image
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / ".sandbox" / "demo"
OUT_GIF = DEMO / "corvex-attack-theatre.gif"
OUT_MP4 = DEMO / "corvex-attack-theatre.mp4"
URL_PATH = "/attack-theatre.html"
FPS = 8
DURATION_S = 11.0
VIEWPORT = {"width": 1280, "height": 800}


def _serve(directory: Path, port: int = 0):
    handler = type(
        "Handler",
        (http.server.SimpleHTTPRequestHandler,),
        {
            "__init__": lambda self, *a, **k: http.server.SimpleHTTPRequestHandler.__init__(
                self, *a, directory=str(directory), **k
            ),
            "log_message": lambda self, *a: None,
        },
    )
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", port), handler)
    httpd.allow_reuse_address = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def capture_frames(url: str) -> list[Image.Image]:
    frames: list[Image.Image] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport=VIEWPORT, device_scale_factor=1)
        page.goto(url, wait_until="networkidle")
        page.wait_for_selector("#play")
        # settle fonts
        page.wait_for_timeout(400)
        page.click("#play")
        start = time.time()
        interval = 1.0 / FPS
        next_t = start
        while time.time() - start < DURATION_S:
            png = page.screenshot(type="png", full_page=False)
            frames.append(Image.open(__import__("io").BytesIO(png)).convert("RGB"))
            next_t += interval
            sleep_for = next_t - time.time()
            if sleep_for > 0:
                time.sleep(sleep_for)
        browser.close()
    return frames


def write_gif(frames: list[Image.Image], path: Path) -> None:
    # Slightly smaller for GIF weight
    scaled = [f.resize((960, 600), Image.Resampling.LANCZOS) for f in frames]
    scaled[0].save(
        path,
        save_all=True,
        append_images=scaled[1:],
        duration=int(1000 / FPS),
        loop=0,
        optimize=False,
    )


def write_mp4(frames: list[Image.Image], path: Path) -> None:
    arrs = [np.asarray(f) for f in frames]
    # imageio-ffmpeg writer
    writer = imageio.get_writer(
        path,
        fps=FPS,
        codec="libx264",
        quality=8,
        pixelformat="yuv420p",
        macro_block_size=None,
    )
    try:
        for arr in arrs:
            # ensure even dimensions for yuv420p
            h, w = arr.shape[:2]
            if h % 2 or w % 2:
                arr = arr[: h - (h % 2), : w - (w % 2)]
            writer.append_data(arr)
    finally:
        writer.close()


def main() -> int:
    DEMO.mkdir(parents=True, exist_ok=True)
    if not (DEMO / "attack-theatre.html").exists():
        raise SystemExit(f"missing {DEMO / 'attack-theatre.html'}")

    httpd = _serve(DEMO, port=0)
    host, port = httpd.server_address
    url = f"http://{host}:{port}{URL_PATH}"
    print(f"recording {url}")
    try:
        frames = capture_frames(url)
    finally:
        httpd.shutdown()
        httpd.server_close()

    print(f"captured {len(frames)} frames")
    write_gif(frames, OUT_GIF)
    print(f"wrote {OUT_GIF} ({OUT_GIF.stat().st_size // 1024} KB)")
    write_mp4(frames, OUT_MP4)
    print(f"wrote {OUT_MP4} ({OUT_MP4.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
