#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""诊断 2：0.0625 那条边是「批次间系统性漂移」还是「单次抖动」。

build_dependency_matrix 把 base 批和 drop 批分开跑，各 repeats 次，再两两
配对取中位数。若两批的 TYPE 自身覆盖各在其内部稳定、但批与批之间差 1 条边，
25 个配对会全部是 0.0625 —— 中位数 0.0625，看起来像"稳定依赖"，其实是
fftp 常驻进程随存活时间漂移。

本脚本交替跑 base / drop 两种序列各若干次，把 TYPE 的边集逐次打出来，
看它到底在不在漂、什么时候漂。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALGO_DIR = os.path.join(os.path.dirname(HERE), "PrefixMsgs algorithm")
sys.path.insert(0, ALGO_DIR)

from tcp_shm_oracle import TcpShmOracle  # noqa: E402

PORT = int(os.environ.get("PROBE_PORT", "9858"))
MSGS = [b"USER admin\r\n", b"PASS 123456\r\n", b"PWD\r\n",
        b"CWD /\r\n", b"NOOP\r\n", b"TYPE I\r\n"]
LABEL = ["USER", "PASS", "PWD", "CWD", "NOOP", "TYPE"]


def sig(cov):
    return ",".join(str(e) for e in sorted(cov))


def main() -> int:
    launcher = os.path.join(HERE, "targets", "lightftp.sh")
    n_rep = int(os.environ.get("PROBE_REPS", "6"))
    with TcpShmOracle([launcher, str(PORT)], port=PORT, banner_lines=1,
                      settle=0.02, start_timeout=6.0) as o:
        print("交替跑 4 种序列，各条自身覆盖边集（只看每条最后一次的稳定形态）\n")
        variants = {
            "FULL   ": list(range(6)),
            "dropPWD": [0, 1, 3, 4, 5],
            "dropCWD": [0, 1, 2, 4, 5],
            "dropNOP": [0, 1, 2, 3, 5],
        }
        seen = {k: {} for k in variants}
        for r in range(n_rep):
            for name, idx in variants.items():
                cov = o.run_sequence([MSGS[i] for i in idx])
                key = sig(cov[-1])
                seen[name].setdefault(key, []).append(r)

        print("各变体的 TYPE 自身覆盖出现过的边集（按出现轮次）:")
        for name, d in seen.items():
            for key, rounds in d.items():
                edges = key.split(",")
                print(f"  {name}  {len(edges):2d} 边  出现轮次 {rounds}  边={key}")

        # 连续 20 次只跑 FULL，看同一条序列自身覆盖稳不稳
        print("\n同一条 FULL 序列连跑 20 次（看单序列内部稳不稳）:")
        hist = {}
        for i in range(20):
            cov = o.run_sequence(MSGS)
            hist.setdefault(sig(cov[-1]), []).append(i)
        for key, rounds in hist.items():
            print(f"  {len(key.split(',')):2d} 边  次数={len(rounds)}  首现={rounds[0]}  边={key}")

        # 每条消息都看，不只 TYPE
        print("\nFULL 序列连跑 10 次，逐条统计边集是否唯一:")
        per = [set() for _ in range(6)]
        for i in range(10):
            cov = o.run_sequence(MSGS)
            for k, c in enumerate(cov):
                per[k].add(sig(c))
        for k in range(6):
            print(f"  M{k} {LABEL[k]:5s} 出现过 {len(per[k])} 种不同边集")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
