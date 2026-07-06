#!/usr/bin/env python3
"""Export the narrated 30s Corvex pitch demo to MP4 + GIF and install on the dash."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / ".sandbox" / "demo"
HTML = DEMO / "pitch-30s.html"
OUT_MP4 = DEMO / "corvex-pitch-30s.mp4"
OUT_GIF = DEMO / "corvex-pitch-30s.gif"
DASH_MEDIA = ROOT / "reports" / "dashboard" / "media"


def main() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from export_live_lab_video import export_replay

    # Patch exporter timing via monkey values — call a local capture for exact 30s
    import http.server
    import socketserver
    import threading
    import time
    from io import BytesIO

    import imageio.v2 as imageio
    import numpy as np
    from PIL import Image
    from playwright.sync_api import sync_playwright

    FPS = 8
    DURATION_S = 30.0
    VIEWPORT = {"width": 1280, "height": 720}

    handler = type(
        "Handler",
        (http.server.SimpleHTTPRequestHandler,),
        {
            "__init__": lambda self, *a, **k: http.server.SimpleHTTPRequestHandler.__init__(
                self, *a, directory=str(DEMO), **k
            ),
            "log_message": lambda *a, **k: None,
        },
    )
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    host, port = httpd.server_address
    url = f"http://{host}:{port}/pitch-30s.html"
    print(f"recording {url} for {DURATION_S:.0f}s @ {FPS}fps")

    frames: list[Image.Image] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport=VIEWPORT, device_scale_factor=1)
            page.goto(url, wait_until="networkidle")
            page.wait_for_timeout(300)
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

    print(f"captured {len(frames)} frames")
    # GIF (scaled)
    scaled = [f.resize((960, 540), Image.Resampling.LANCZOS) for f in frames]
    # subsample gif to keep size sane (~4fps)
    gif_frames = scaled[::2]
    gif_frames[0].save(
        OUT_GIF,
        save_all=True,
        append_images=gif_frames[1:],
        duration=int(1000 / (FPS / 2)),
        loop=0,
    )

    writer = imageio.get_writer(
        OUT_MP4,
        fps=FPS,
        codec="libx264",
        quality=7,
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

    DASH_MEDIA.mkdir(parents=True, exist_ok=True)
    shutil.copy2(OUT_MP4, DASH_MEDIA / "corvex-pitch-30s.mp4")
    shutil.copy2(OUT_GIF, DASH_MEDIA / "corvex-pitch-30s.gif")
    shutil.copy2(HTML, DASH_MEDIA / "pitch-30s.html")

    # Copy live lab summary for dash panel
    for name in ("live-corvex_state.json", "live-attacker.jsonl"):
        src = DEMO / name
        if src.exists():
            shutil.copy2(src, DASH_MEDIA / name)

    print(f"wrote {OUT_MP4} ({OUT_MP4.stat().st_size // 1024} KB)")
    print(f"wrote {OUT_GIF} ({OUT_GIF.stat().st_size // 1024} KB)")
    print(f"installed into {DASH_MEDIA}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
