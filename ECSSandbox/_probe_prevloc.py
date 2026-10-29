#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""诊断：依赖矩阵里那条恰好 0.0625 的边是真依赖还是采集伪影。

0.0625 = 1/16，正好是「16 条边里差 1 条」。AFL++ 插桩写边是
    map[cur ^ prev_loc]++; prev_loc = cur;
清零 SHM **不会** 重置 TLS 里的 __afl_prev_loc，于是每条消息的【第一条】边
取决于前一条消息的最后一条边 —— 删掉中间消息会移动前驱，这条边就变了。
这是确定性的、可复现的伪影，不是噪声（噪声地板才 0.0000）。

本脚本把 TYPE 的自身覆盖在「删/不删某条」两种会话下打出来，
看差异边到底是不是只有 1 条、是不是首条。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALGO_DIR = os.path.join(os.path.dirname(HERE), "PrefixMsgs algorithm")
sys.path.insert(0, ALGO_DIR)

from tcp_shm_oracle import TcpShmOracle  # noqa: E402

PORT = int(os.environ.get("PROBE_PORT", "9857"))
MSGS = [b"USER admin\r\n", b"PASS 123456\r\n", b"PWD\r\n",
        b"CWD /\r\n", b"NOOP\r\n", b"TYPE I\r\n"]
LABEL = ["USER", "PASS", "PWD", "CWD", "NOOP", "TYPE"]


def main() -> int:
    launcher = os.path.join(HERE, "targets", "lightftp.sh")
    with TcpShmOracle([launcher, str(PORT)], port=PORT, banner_lines=1,
                      settle=0.02, start_timeout=6.0) as o:
        full = o.run_sequence(MSGS)
        print("完整会话 [USER,PASS,PWD,CWD,NOOP,TYPE] 各条自身覆盖边数:")
        for i, c in enumerate(full):
            print(f"  M{i} {LABEL[i]:5s} {len(c):3d} 边")

        print("\n逐条移除，看 TYPE(M5) 的自身覆盖差在哪:")
        for x in range(5):
            left = [m for i, m in enumerate(MSGS) if i != x]
            cov = o.run_sequence(left)
            cur = cov[-1]                 # TYPE 是最后一条
            base = full[5]
            only_base = sorted(base - cur)
            only_cur = sorted(cur - base)
            print(f"  删 M{x}({LABEL[x]:5s}): "
                  f"|base|={len(base)} |cur|={len(cur)} "
                  f"base\\cur={only_base} cur\\base={only_cur}")

        print("\n对照：只改【位置】不删任何消息（把 NOOP 挪到最前）")
        perm = [4, 0, 1, 2, 3, 5]
        cov = o.run_sequence([MSGS[i] for i in perm])
        cur = cov[-1]
        print(f"  TYPE 自身覆盖 |cur|={len(cur)} "
              f"base\\cur={sorted(full[5] - cur)} cur\\base={sorted(cur - full[5])}")

        print("\n对照：同一会话里连发两次 TYPE，看第二次是否受前一条影响")
        two = o.run_sequence([b"USER admin\r\n", b"PASS 123456\r\n",
                              b"PWD\r\n", b"CWD /\r\n", b"NOOP\r\n",
                              b"TYPE I\r\n", b"TYPE I\r\n"])
        print(f"  第一次 TYPE={len(two[5])} 边   第二次 TYPE={len(two[6])} 边  "
              f"差={sorted(two[5] ^ two[6])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
