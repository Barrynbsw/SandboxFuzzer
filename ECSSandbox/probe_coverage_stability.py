#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_coverage_stability.py — 覆盖率采集的确定性回归探针
=========================================================

会话前缀重建的依赖矩阵建立在「同一条消息的自身覆盖是确定性的」之上：
    i 是 j 的前置  ⟺  移除 i 后 j 的自身覆盖【真的】变了
一旦采集本身会随机多出/少掉边，这个判据就没有基准可言。

踩过的坑（2026-10-29 查实，本探针就是守它）：
    LightFTP 每条连接起一个线程。`sock.close()` 只关 socket，服务端线程还要
    走退出路径，而那条路径的覆盖是【写进同一个 SHM】的 —— 下一次测量清零
    SHM 之后它才落笔，于是凭空多出 1~2 条边（实测是 834 这类）。

    这不是噪声，是**跨会话污染**，而且成簇出现（取决于线程退出时机）：
    它让依赖矩阵的 DIFF 恰好等于 1/16 = 0.0625，看起来像一条稳定的弱依赖。
    实测后果：会话级前置集从 [USER, PASS] 被撑成 5 条假阳性，
    而且重跑一次又变回 [USER, PASS] —— 输出不可复现。

    两道防线，都在 tcp_shm_oracle.TcpShmOracle 里：
      1. _quiesce()          每条会话结束后清零 SHM，轮询到连续静默再开下一条。
                             这能吃掉【退出线程】的残留。
      2. _sample_background() 采一份「会话簿记边集」（accept / 建线程 / 发
                             banner / 收 EOF / 线程退出），每次快照自动减掉。
                             这吃掉【常驻监听线程】的污染 —— 那是活线程在跑，
                             _quiesce 等不掉。注意纯空转采样大概率采不到它
                             （它只在有连接进出时才走），所以采样必须自带
                             「连接抖动」阶段。

    为什么减掉是安全的：base 与 drop 两次测量减的是同一个集合，所以
    cov_diff 的分子 |a\b| 不受影响（簿记边本来就在两边都出现，是样板代码），
    只有分母 |a∪b| 略缩，信号比只会【变大】不会变小 —— 等于顺手把
    recv/send/accept 这类每条消息都有的样板边去掉，判别力更集中。

本探针做三件事：
    A. 同一条序列连跑 K 次，每条消息的自身覆盖必须【完全一致】
    B. 交替跑 FULL / 删一条 两种序列，同一条件下边集必须一致
    C. 隔 M 条会话前后各测一次，不得漂移

跑法（宿主机编不动 fftp，进容器）：
    cd SandboxFuzzer
    docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/sbfpkg \\
        --workdir /sbfpkg/ECSSandbox --entrypoint python3 sbf-node \\
        /sbfpkg/ECSSandbox/probe_coverage_stability.py
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALGO_DIR = os.environ.get("SBF_ALGO_DIR") or os.path.join(
    os.path.dirname(HERE), "PrefixMsgs algorithm")
sys.path.insert(0, ALGO_DIR)

from tcp_shm_oracle import TcpShmOracle  # noqa: E402

PORT = int(os.environ.get("PROBE_PORT", "9863"))
MSGS = [b"USER admin\r\n", b"PASS 123456\r\n", b"PWD\r\n",
        b"CWD /\r\n", b"NOOP\r\n", b"TYPE I\r\n"]
LABEL = ["USER", "PASS", "PWD", "CWD", "NOOP", "TYPE"]
REPEATS = int(os.environ.get("PROBE_REPS", "6"))


def main() -> int:
    launcher = os.path.join(HERE, "targets", "lightftp.sh")
    fftp = os.path.join(HERE, "third_party", "lightftp", "fftp")
    if not os.access(fftp, os.X_OK):
        print(f"[!] fftp 不可执行: {fftp}", file=sys.stderr)
        return 2

    fails = []
    with TcpShmOracle([launcher, str(PORT)], port=PORT, banner_lines=1,
                      settle=0.02, start_timeout=6.0) as o:
        # ── A. 同一条序列连跑，逐条消息边集必须唯一 ────────────────
        print(f"[A] 同一条 FULL 序列连跑 {REPEATS} 次，逐条消息边集唯一性")
        runs = [o.run_sequence(MSGS) for _ in range(REPEATS)]
        for k in range(len(MSGS)):
            uniq = {tuple(sorted(r[k])) for r in runs}
            sizes = sorted({len(r[k]) for r in runs})
            ok = len(uniq) == 1
            print(f"    M{k} {LABEL[k]:5s} {sizes} 边  "
                  f"出现过 {len(uniq)} 种边集  {'OK' if ok else 'FAIL'}")
            if not ok:
                # 打出到底哪条边时有时无 —— 杂散边的 ID 是定位污染源的钥匙
                from collections import Counter
                cnt = Counter(e for u in uniq for e in u)
                flaky = sorted(e for e, c in cnt.items() if c < len(uniq))
                print(f"          杂散边 = {flaky}  "
                      f"(出现次数 {[cnt[e] for e in flaky]}/{len(uniq)})")
                fails.append(f"A: M{k} {LABEL[k]} 有 {len(uniq)} 种边集"
                             f"（杂散边 {flaky}）")

        # ── B. 交替跑两种序列，同一条件下边集必须一致 ──────────────
        print(f"\n[B] FULL / 删一条 交替跑，同一条件内边集唯一性")
        for x in (0, 2, 4):
            left = [m for i, m in enumerate(MSGS) if i != x]
            full_sets, drop_sets = set(), set()
            for _ in range(REPEATS):
                full_sets.add(tuple(sorted(o.run_sequence(MSGS)[-1])))
                drop_sets.add(tuple(sorted(o.run_sequence(left)[-1])))
            ok = len(full_sets) == 1 and len(drop_sets) == 1
            same = full_sets == drop_sets
            print(f"    删 M{x}({LABEL[x]:4s}) 末条 TYPE: "
                  f"FULL {len(full_sets)} 种 / DROP {len(drop_sets)} 种  "
                  f"两者{'相同' if same else '不同'}  {'OK' if ok else 'FAIL'}")
            if not ok:
                fails.append(f"B: 删 M{x} 后边集不唯一")

        # ── C. 隔 20 条会话前后各测一次，不得漂移 ─────────────────
        print(f"\n[C] 隔 20 条会话前后各测一次，不得漂移")
        before = o.run_sequence(MSGS)[-1]
        for _ in range(20):
            o.run_sequence(MSGS)
        after = o.run_sequence(MSGS)[-1]
        sym = sorted(before ^ after)
        print(f"    前 {len(before)} 边 / 后 {len(after)} 边  "
              f"对称差={sym or '空'}  {'OK' if not sym else 'FAIL'}")
        if sym:
            fails.append(f"C: 漂移了 {sym}")

    print(f"\n{'=' * 60}")
    if fails:
        print("采集确定性: FAIL")
        for f in fails:
            print(f"  ✗ {f}")
        print("\n  → 覆盖率采集被污染，依赖矩阵的结论不可信。")
        print("    先查 TcpShmOracle：_quiesce() 是否还在每条会话后调用，")
        print("    以及 _sample_background() 采出的会话簿记边集是否被 _snap() 减掉。")
        return 1
    print("采集确定性: PASS —— 依赖矩阵的基准是干净的")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
