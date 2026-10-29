#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""诊断 4：定位那条杂散边，看它在重复实验里怎么分布。

跑法 A/B 的中位数都是 0，但偶尔 1/25 配对会是 0.0625 —— 说明杂散边是
**成簇**出现的（某一批里多数 run 有，另一批里没有），中位数去不掉。
把每条 run 的 TYPE 边集逐个打出来，就能定用什么统计量能压住它：
  只在少数 run 出现  → 取交集/多数票能去掉
  在整批里出现      → 只能靠提高 δ，或者改成交替配对
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALGO_DIR = os.path.join(os.path.dirname(HERE), "PrefixMsgs algorithm")
sys.path.insert(0, ALGO_DIR)

from tcp_shm_oracle import TcpShmOracle  # noqa: E402

PORT = int(os.environ.get("PROBE_PORT", "9861"))
MSGS = [b"USER admin\r\n", b"PASS 123456\r\n", b"PWD\r\n",
        b"CWD /\r\n", b"NOOP\r\n", b"TYPE I\r\n"]
LABEL = ["USER", "PASS", "PWD", "CWD", "NOOP", "TYPE"]


def main() -> int:
    launcher = os.path.join(HERE, "targets", "lightftp.sh")
    with TcpShmOracle([launcher, str(PORT)], port=PORT, banner_lines=1,
                      settle=0.02, start_timeout=6.0) as o:
        # 逐条消息都看：每种条件跑 8 次，记录每条边出现次数
        conds = {
            "FULL   ": list(range(6)),
            "dropPWD": [0, 1, 3, 4, 5],
        }
        for rep in range(2):
            print(f"\n===== 第 {rep} 批（每种条件各 8 次）=====")
            for name, idx in conds.items():
                runs = [set(o.run_sequence([MSGS[i] for i in idx])[-1])
                        for _ in range(8)]
                all_edges = sorted(set().union(*runs))
                print(f"  {name} TYPE 自身覆盖（8 次）:")
                for e in all_edges:
                    cnt = sum(1 for r in runs if e in r)
                    flag = "  ← 杂散" if cnt < 8 else ""
                    print(f"      边 {e:4d}  出现 {cnt}/8{flag}")
                sizes = sorted({len(r) for r in runs})
                print(f"      边数取值 {sizes}")

        # 每条消息各自抖不抖（FULL 条件，8 次）
        print("\n===== 逐条消息抖动统计（FULL，8 次）=====")
        runs = [o.run_sequence(MSGS) for _ in range(8)]
        for k in range(6):
            sets = [set(r[k]) for r in runs]
            union = set().union(*sets)
            inter = set.intersection(*sets)
            print(f"  M{k} {LABEL[k]:5s} 并={len(union)} 交={len(inter)} "
                  f"杂散={sorted(union - inter)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
