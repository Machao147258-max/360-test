#!/usr/bin/env python3
"""pagelinks.py - open a page in the locally installed Chrome and dump download candidates.

Why: the Huorong download page renders its link client-side, so static HTML/HEAD probes
find nothing (three guessed URLs returned 404 on 2026-10-04). Reading the DOM after JS
runs is the only reliable way.

usage:
  python tools/pagelinks.py <url> [regex]        # default regex matches .exe/.zip/.msi
"""
import re
import sys

from playwright.sync_api import sync_playwright

url = sys.argv[1] if len(sys.argv) > 1 else "https://www.huorong.cn/person5.html"
pat = re.compile(
    sys.argv[2] if len(sys.argv) > 2 else r'https?://[^"\'<>\s]+\.(?:exe|zip|msi)', re.I
)

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True)
    page = browser.new_page()
    page.goto(url, timeout=30000, wait_until="load")
    page.wait_for_timeout(3500)
    html = page.content()
    print("TITLE:", page.title())
    hits = sorted(set(pat.findall(html)))
    print(f"REGEX_HITS={len(hits)}")
    for h in hits[:30]:
        print("URL:", h)
    try:
        hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        for h in hrefs:
            if re.search(r"exe|down|download|setup", h, re.I):
                print("A:", h)
    except Exception as e:  # noqa: BLE001
        print("href-dump failed:", e)
    browser.close()
