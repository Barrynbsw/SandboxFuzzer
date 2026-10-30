#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_seedhub_bootstrap.py —— bootstrap 崩溃分类的真靶机验收
=============================================================
（审查 F1 残留③④ 的验收：崩溃样本全部归档、正常样本零误判）

拿 stateful_server 两个已知崩溃（S1 "PASS CRASH" / S2 "STOR BUG"）所在
fixture 的【全部】crashes/ 与 benign/ 样本，逐个走 probe_crash() 判定链：

    crashes/* → 必须全部判死（漏一个 = 漏报，崩溃样本再没人找回）
    benign/*  → 必须全部判活（错一个 = 假 crash 淹掉真发现）

每个样本一台干净靶机（同 replay_judge 的隔离法），互不干扰；
前缀按状态 fixture 发（USER / USER+PASS），走 send_prefix 逐条口径。

跑法（先由 run_tests.sh 编好 tests/bin/stateful_server）:
    python3 tests/test_seedhub_bootstrap.py
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from local_seedhub import LocalSeedHub  # noqa: E402

SRV = os.path.join(HERE, "bin", "stateful_server")
STATES = ("state_1_user", "state_2_auth")

PASS, FAIL = 0, 0


def check(cond, label, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {label}")
    else:
        FAIL += 1
        print(f"  ✗ {label}" + (f"\n      {detail}" if detail else ""))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def classify(seed_path, prefix):
    """单样本判定：一台干净靶机 + probe_crash()。返回 True/False/None（起不来）。"""
    port = free_port()
    srv = subprocess.Popen([SRV, str(port)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        hub = LocalSeedHub.__new__(LocalSeedHub)   # 只用判定链，无需池目录
        hub.probe_host, hub.probe_port = "127.0.0.1", port
        hub.banner_lines = 0                        # stateful_server 无 banner
        if not hub._wait_target(tries=40, interval=0.05):
            return None
        with open(seed_path, "rb") as f:
            blob = f.read()
        return hub.probe_crash(blob, prefix)
    finally:
        if srv.poll() is None:
            srv.kill()
            srv.wait()


def main() -> int:
    if not os.path.isfile(SRV):
        print(f"[!] 找不到 {SRV}，先跑 ./run_tests.sh 编译")
        return 2

    print("=" * 70)
    print("bootstrap 崩溃分类真靶机验收（对照 sandbox_harness.c 判定口径）")
    print("=" * 70)
    for state in STATES:
        fix = os.path.join(HERE, "fixtures", state)
        if not os.path.isdir(fix):
            print(f"[skip] {state}: 无 fixture")
            continue
        with open(os.path.join(fix, "prefix.raw"), "rb") as f:
            prefix = f.read()

        for kind, expect in (("crashes", True), ("benign", False)):
            d = os.path.join(fix, kind)
            names = sorted(n for n in os.listdir(d)
                           if os.path.isfile(os.path.join(d, n)))
            print(f"── {state}/{kind}  预期判{'死' if expect else '活'}"
                  f"  × {len(names)} ──")
            for n in names:
                got = classify(os.path.join(d, n), prefix)
                if got is None:
                    check(False, f"{n}: 靶机起不来（无法判定）")
                    continue
                ok = (got == expect)
                check(ok, f"{n} → {'崩溃' if got else '存活'}",
                      f"预期 {'崩溃' if expect else '存活'}，实得 "
                      f"{'崩溃' if got else '存活'}")

    print("-" * 70)
    print(f"  通过 {PASS}   失败 {FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
