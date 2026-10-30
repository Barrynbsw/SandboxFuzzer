#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
diag_slot_leak.py —— 量化 LightFTP 的会话槽泄漏速率，并找出触发泄漏的交互
==========================================================================

现象（diag_wedge.sh 实测）：fuzz 跑 ~15k 次后靶机【永久】回
`MAXIMUM ALLOWED USERS CONNECTED`，且此时 fftp 只剩 2 个线程（= 槽被不存在的
线程占着）。把 conf 的 maxusers 从 10 提到 1024【没有】救回来，所以
"槽太少"这个解释是错的 —— 要么泄漏速率远高于估计，要么 maxusers 根本没生效
（`g_cfg.MaxUsers` 解析失败时回退成 1，见 main.c:113）。

这个脚本把变量拆干净：起一个 fftp，用【已知】交互模式反复开会话，
看第几次撞上 NOSLOTS。三种模式各测一次：

  noop   连上 → NOOP → 关闭                          （基线，应该不漏）
  drop   连上 → PASV → LIST → 立刻关                  （数据连接没建立就跑）
  half   连上 → 只发半行（不带 \\n）→ 关闭            （服务器停在"等完整一行"）

撞上 NOSLOTS 的会话序号 ≈ 泄漏速率的倒数 × maxusers。
同时打印 LightFTP 启动横幅里的 `Max users : N`（用 stdbuf 抓，否则 printf
块缓冲、进程被杀时全丢），确认 conf 的 maxusers 到底生效没有。

用法（宿主机跑不动 fftp，必须进容器，挂【包根】）：
  cd SandboxFuzzer
  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/sbfpkg \
      --workdir /sbfpkg/ECSSandbox --entrypoint bash sbf-node \
      -lc 'python3 diag_slot_leak.py'
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAUNCHER = os.path.join(HERE, "targets", "lightftp.sh")
PORT = 9501
MAX_SESS = 4000


def start_target(maxusers: int, logpath: str):
    """起一个 fftp，返回 Popen。maxusers 经 SBF_FTP_MAXUSERS 传给适配器。"""
    env = dict(os.environ, SBF_FTP_MAXUSERS=str(maxusers))
    log = open(logpath, "wb")
    # stdbuf -o0：否则 LightFTP 的 printf 全缓冲，启动横幅永远看不到
    p = subprocess.Popen(["stdbuf", "-o0", "-e0", LAUNCHER, str(PORT)],
                         env=env, stdout=log, stderr=subprocess.STDOUT)
    # 等它真的开始服务
    for _ in range(100):
        try:
            s = socket.create_connection(("127.0.0.1", PORT), 0.3)
            s.close()
            return p, log
        except OSError:
            time.sleep(0.05)
    p.kill()
    log.close()
    raise RuntimeError("靶机起不来，见 %s" % logpath)


def banner(port: int, timeout=1.0) -> bytes:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        return s.recv(128)
    finally:
        s.close()


def run_pattern(name: str, talk, maxusers: int) -> dict:
    logpath = os.path.join(HERE, "run", "slot_leak_%s.log" % name)
    os.makedirs(os.path.dirname(logpath), exist_ok=True)
    p, log = start_target(maxusers, logpath)
    try:
        # 先确认头几次是健康的
        first = banner(PORT)
        if not first.startswith(b"220"):
            return {"name": name, "err": "起手就不是 220: %r" % first}

        sat = None
        t0 = time.time()
        for i in range(1, MAX_SESS + 1):
            s = socket.socket()
            s.settimeout(1.0)
            try:
                s.connect(("127.0.0.1", PORT))
                b = s.recv(128)
            except OSError as e:
                sat = i
                first = b"CONN_FAIL:%s" % str(e).encode()
                s.close()
                break
            if not b.startswith(b"220"):
                sat = i
                first = b
                s.close()
                break
            try:
                talk(s)
            except OSError:
                pass
            s.close()
            if i % 500 == 0:
                print("    %s: %d 会话完，%.1fs" % (name, i, time.time() - t0))
        return {"name": name, "saturated_at": sat, "first_bad": first,
                "elapsed": round(time.time() - t0, 1)}
    finally:
        p.kill()
        p.wait()
        log.close()


def talk_noop(s):
    s.sendall(b"NOOP\r\n")
    s.recv(128)


def talk_drop(s):
    # PASV 打开数据监听，LIST 起 worker 线程去 accept 数据连接；
    # 我们不连数据口就走人 → create_datasocket() 的 accept() 无超时，见 ftpserv.c:284
    s.sendall(b"PASV\r\n")
    s.recv(128)
    s.sendall(b"LIST\r\n")
    # 不等应答就关


def talk_half(s):
    # 不带 \n 的半行：recvcmd 会一直等"完整的一行"
    s.sendall(b"USER admi")


PATTERNS = [("noop", talk_noop), ("drop", talk_drop), ("half", talk_half)]


def read_banner_from_log(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            txt = f.read()
    except OSError:
        return "(读不到)"
    m = re.search(r"Max users\s*:\s*(\d+)", txt)
    return m.group(1) if m else "(横幅里没有 Max users；前 200 字=%r)" % txt[:200]


def main() -> int:
    if not os.path.isfile(LAUNCHER):
        print("[!] 找不到 %s" % LAUNCHER)
        return 2

    for maxusers in (int(x) for x in (sys.argv[1:] or ["1024"])):
        print()
        print("=" * 60)
        print("  maxusers 请求值 = %d" % maxusers)
        print("=" * 60)
        for name, talk in PATTERNS:
            print("  -- 模式 %s" % name)
            r = run_pattern(name, talk, maxusers)
            log = os.path.join(HERE, "run", "slot_leak_%s.log" % name)
            print("     %s" % r)
            print("     启动横幅 Max users = %s" % read_banner_from_log(log))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
