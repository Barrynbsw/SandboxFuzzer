#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""诊断 3：复刻 build_dependency_matrix 的【分批跑法】，看 base 批与 drop 批
之间有没有系统性漂移 —— 那正是 0.0625 假依赖的来源。

算法的实际跑法：
    base_runs = [run(FULL) for _ in range(repeats)]        # 5 次连跑
    for x in 0..n-1:
        drop_runs = [run(FULL minus x) for _ in range(repeats)]
        ...
base 批在最前面，x=2 的 drop 批排在 x=0、x=1 的 10 次实验之后 —— 中间隔了
十几条会话。若 fftp 常驻进程随存活时间漂 1 条边，两批配对就会全部是 0.0625，
中位数 0.0625 > δ=0.02，被判成"依赖"。

对照跑法：把 base 和 drop【交替】跑（每做一次 drop 就重测一次 base），
漂移对两边同时生效，配对差应该回到 0。
"""
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALGO_DIR = os.path.join(os.path.dirname(HERE), "PrefixMsgs algorithm")
sys.path.insert(0, ALGO_DIR)

from tcp_shm_oracle import TcpShmOracle  # noqa: E402

PORT = int(os.environ.get("PROBE_PORT", "9859"))
MSGS = [b"USER admin\r\n", b"PASS 123456\r\n", b"PWD\r\n",
        b"CWD /\r\n", b"NOOP\r\n", b"TYPE I\r\n"]
LABEL = ["USER", "PASS", "PWD", "CWD", "NOOP", "TYPE"]


def diff(a, b):
    if not a and not b:
        return 0.0
    u = len(a | b)
    return len(a ^ b) / u if u else 0.0


def main() -> int:
    launcher = os.path.join(HERE, "targets", "lightftp.sh")
    with TcpShmOracle([launcher, str(PORT)], port=PORT, banner_lines=1,
                      settle=0.02, start_timeout=6.0) as o:
        # ── 跑法 A：复刻算法的分批法 ──────────────────────────────
        print("跑法 A：base 批连跑 5 次，再逐个 x 各跑 5 次（复刻算法）")
        base = [o.run_sequence(MSGS) for _ in range(5)]
        for x in (2, 3, 4):
            left = [m for i, m in enumerate(MSGS) if i != x]
            drop = [o.run_sequence(left) for _ in range(5)]
            ds = [diff(base[a][-1], drop[b][-1])
                  for a in range(5) for b in range(5)]
            uniq = {tuple(sorted(base[a][-1])) for a in range(5)}
            uniq |= {tuple(sorted(drop[b][-1])) for b in range(5)}
            print(f"  删 M{x}({LABEL[x]:4s}) TYPE: DIFF 中位={statistics.median(ds):.4f} "
                  f"最大={max(ds):.4f}  出现过 {len(uniq)} 种边集")

        # ── 跑法 B：交替法，每做一次 drop 就重测一次 base ─────────
        print("\n跑法 B：base / drop 交替跑（漂移同时作用于两边）")
        for x in (2, 3, 4):
            left = [m for i, m in enumerate(MSGS) if i != x]
            ds = []
            for _ in range(5):
                b = o.run_sequence(MSGS)[-1]
                d = o.run_sequence(left)[-1]
                ds.append(diff(b, d))
            print(f"  删 M{x}({LABEL[x]:4s}) TYPE: DIFF 中位={statistics.median(ds):.4f} "
                  f"最大={max(ds):.4f}")

        # ── 跑法 C：测漂移本身 ───────────────────────────────────
        print("\n跑法 C：隔 20 条会话前后各测一次 TYPE 边集")
        before = o.run_sequence(MSGS)[-1]
        for i in range(20):
            o.run_sequence(MSGS)
        after = o.run_sequence(MSGS)[-1]
        print(f"  前 {len(before)} 边 / 后 {len(after)} 边  "
              f"对称差 = {sorted(before ^ after)}")

        print("\n跑法 D：USER(M0) 自身覆盖的抖动来源（10 次）")
        hist = {}
        for i in range(10):
            c = o.run_sequence(MSGS)[0]
            hist.setdefault(tuple(sorted(c)), []).append(i)
        for k, v in hist.items():
            print(f"  {len(k)} 边 次数={len(v)} 边={k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
