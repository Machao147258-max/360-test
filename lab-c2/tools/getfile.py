#!/usr/bin/env python3
"""getfile.py - capture a file download with the locally installed Chrome and save it.

Why: the Huorong download page starts a download directly. Playwright then reports
"Page.goto: Download is starting" as a navigation failure (measured 2026-10-04), so the
link can neither be read from the DOM nor fetched by guessing. Capturing the download
event gets both the file and the resolved URL.

usage:
  python tools/getfile.py <page-url> <out-dir>
"""
import os
import sys

from playwright.sync_api import sync_playwright

url = sys.argv[1]
outdir = sys.argv[2] if len(sys.argv) > 2 else "."
os.makedirs(outdir, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True)
    ctx = browser.new_context(accept_downloads=True)
    page = ctx.new_page()
    try:
        with page.expect_download(timeout=60000) as dl_info:
            page.goto(url, timeout=30000, wait_until="commit")
        dl = dl_info.value
        name = dl.suggested_filename or "download.bin"
        path = os.path.join(outdir, name)
        dl.save_as(path)
        print("SAVED:", path)
        print("SIZE:", os.path.getsize(path))
        print("RESOLVED_URL:", dl.url)
    except Exception as e:  # noqa: BLE001
        print("CAPTURE_FAILED:", type(e).__name__, str(e)[:300])
    browser.close()
