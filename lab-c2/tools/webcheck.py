#!/usr/bin/env python3
"""webcheck.py - verify the browser-automation channel on THIS host (Windows).

Probes the available channels in order and reports the first one that works, so the
answer to "can you log into a page yourself" is measured, not assumed.

usage:
  python tools/webcheck.py                        # default https://example.com
  python tools/webcheck.py https://www.baidu.com
  python tools/webcheck.py URL --persist <dir>    # keep a profile for login-state reuse
"""
import sys

from playwright.sync_api import sync_playwright

url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
persist = None
if "--persist" in sys.argv:
    persist = sys.argv[sys.argv.index("--persist") + 1]

# channel=None -> playwright's bundled chromium (needs "playwright install chromium")
# channel="chrome"/"msedge" -> the ALREADY INSTALLED browsers on this host, no download
SPECS = [(None, "bundled-chromium"), ("chrome", "installed-chrome"), ("msedge", "installed-edge")]
ok = False

with sync_playwright() as p:
    for channel, name in SPECS:
        try:
            kw = {"headless": True}
            if channel:
                kw["channel"] = channel
            if persist:
                kw["args"] = [f"--user-data-dir={persist}"]
            browser = p.chromium.launch(**kw)
            page = browser.new_page()
            page.goto(url, timeout=25000)
            title = page.title()
            body = page.inner_text("body")[:300].replace("\n", " | ")
            print(f"[ok]   channel={name}  title={title!r}")
            print(f"[body] {body}")
            browser.close()
            ok = True
            break
        except Exception as e:  # noqa: BLE001 - report and try the next channel
            print(f"[fail] channel={name}: {type(e).__name__}: {str(e)[:220]}")

sys.exit(0 if ok else 1)
