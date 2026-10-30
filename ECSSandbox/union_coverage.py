#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
union_coverage.py —— 量出各臂【并集】边覆盖，替代 Σedges 那个上界
===================================================================

主实验（run_state_sweep.sh）里 ISO 是 K 个配置各跑一遍，MIX 是 1 个配置跑满
全程。汇总时只能把 K 个配置的 edges_found 加起来 —— 可那是个**上界**：
三个配置跑的是同一个 fftp 核心，命令分发、应答发送这些样板边每个配置各算一次。
Σ=362 里有多少是真的新增、多少是重复计数，fuzzer_stats 说不出来。

这里把话说死：拿**同一个**位图，把各配置的语料按**它自己的前缀**逐条会话回放，
读出来的就是并集。两边都这么量，比的就是集合本身：

    |⋃ ISO|          按状态隔离摸到的边（精确，非上界）
    |MIX|            不隔离摸到的边（精确）
    |⋃ ISO − MIX|    【只有隔离才摸得到】的边 ← 论点的直接证据
    |MIX − ⋃ ISO|    反向，要如实报

判定口径与 reachability_probe.py / sandbox_harness.c 一致：
    连上 → 读 banner → 【逐条报文】发前缀（每条等一条应答）→ 发种子 → 读应答
逐条发是硬要求：LightFTP 把一次 recv 的整个缓冲当一条命令。

去污染（见 [[sbf-coverage-measurement-determinism]]）：多线程靶机往同一个 SHM
落笔，所以每个快照都减掉 `TcpShmOracle` 启动时采到的「会话簿记边集」`_bg`。
两趟分开量：先逐配置量各自的边集（趟间清零），再一趟量并集（全程不清零）。

用法：
    python3 union_coverage.py --fixture sweep --pool-root corpus \\
        --group ISO=ISO_0_3567275f,ISO_1_5185be6d,ISO_2_5616cc54 \\
        --group MIX=MIX_global \\
        --json run/union_coverage.json

前置：run_state_sweep.sh 已经跑完（要它的 corpus/<cfg>/ 语料）。
宿主机编不动 fftp，必须进容器，挂【包根】。
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ALGO_DIR = os.environ.get("SBF_ALGO_DIR") or os.path.join(
    os.path.dirname(HERE), "PrefixMsgs algorithm")
sys.path.insert(0, ALGO_DIR)
sys.path.insert(0, HERE)

from tcp_shm_oracle import TcpShmOracle            # noqa: E402
from verify_prefix import split_lines              # noqa: E402

PORT = int(os.environ.get("UNION_PORT", "9871"))


def load_cfg(fixture: str, pool_root: str, name: str, suffix: str = ".raw"):
    """一个配置 = (自己的前缀消息列表, 自己池里的种子列表)。

    suffix='' 表示目录下【所有】常规文件都要 —— 回放 AFL++ 的 queue/ 时用得上，
    那里的文件名是 `id:000000,src:...`，没有后缀。
    """
    pre_path = os.path.join(fixture, name, "prefix.raw")
    if not os.path.isfile(pre_path):
        raise SystemExit(f"[!] 缺前缀: {pre_path}")
    with open(pre_path, "rb") as f:
        prefix = f.read()
    pool = os.path.join(pool_root, name)
    if not os.path.isdir(pool):
        raise SystemExit(f"[!] 缺语料池: {pool}")
    blobs = []
    for fn in sorted(os.listdir(pool)):
        p = os.path.join(pool, fn)
        if not os.path.isfile(p) or not fn.endswith(suffix):
            continue
        with open(p, "rb") as f:
            blobs.append(f.read())
    if not blobs:
        raise SystemExit(f"[!] {pool} 里没有种子（suffix={suffix!r}）")
    return split_lines(prefix), blobs


def respawn(oracle: TcpShmOracle) -> None:
    """靶机死了就换一个，但【沿用同一个 SHM】—— 并集就存在那个位图里。

    绝不能重调 start()：它会新建 SHM，把前面累计的边全丢掉。
    """
    if oracle._proc is not None:
        oracle._proc.kill()
        oracle._proc.wait()
    env = os.environ.copy()
    env["__AFL_SHM_ID"] = str(oracle._shm.id)
    env["AFL_NO_FORKSRV"] = "1"
    oracle._proc = subprocess.Popen(
        oracle.target_cmd, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + oracle.start_timeout
    while time.time() < deadline:
        try:
            s = socket.socket()
            s.settimeout(0.2)
            s.connect((oracle.host, oracle.port))
            s.close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"靶机起不来: {oracle.target_cmd}")


def replay(oracle: TcpShmOracle, cfgs) -> frozenset:
    """把 cfgs 里每个配置的语料按自己的前缀逐条会话回放，返回点亮的边集。

    【开头清一次零，配置之间不清零】—— 读到的就是这一批配置的并集。
    每次调用都是一趟独立测量：传一个配置得"它自己摸到的"，传一批得"这批的并集"。

    早先这里有个 `accumulate` 开关想区分两种语义，结果第二趟没清零、
    直接叠在第一趟剩下的位图上，"并集"算成了 甲∪乙∪丙∪丁，还倒过来
    报出「ISO∩MIX = 141 > |MIX| = 130」这种自相矛盾的数。清零是每趟的
    起手式，不是可选项。
    """
    oracle.reset()
    n = 0
    for name, msgs, blobs in cfgs:
        for blob in blobs:
            if oracle._proc.poll() is not None:
                print(f"    [!] 靶机退出（第 {n} 条会话后），换新的续跑", flush=True)
                respawn(oracle)
            s = oracle._connect()
            try:
                for m in msgs:                 # 前缀逐条发，每条等一条应答
                    s.sendall(m)
                    oracle._drain_collect(s)
                s.sendall(blob)
                oracle._drain_collect(s)
            finally:
                s.close()
            n += 1
    # 等最后几条会话的线程退出路径把笔落完；这里【不清零】，落下来就是它的
    time.sleep(0.4)
    return frozenset(oracle._shm.snapshot() - oracle._bg)


def main() -> int:
    ap = argparse.ArgumentParser(description="量各臂的并集边覆盖（精确，非 Σ 上界）")
    ap.add_argument("--fixture", default="sweep", help="fixture 根（含 <cfg>/prefix.raw）")
    ap.add_argument("--pool-root", default="corpus", help="语料池根（含 <cfg>/*.raw）")
    ap.add_argument("--pool-suffix", default=".raw",
                    help="种子文件后缀；传空串 = 目录下所有文件（回放 queue/ 用）")
    ap.add_argument("--group", action="append", required=True,
                    help="臂名=cfg1,cfg2,...（可重复）")
    ap.add_argument("--launcher", default="targets/lightftp.sh")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--banner-lines", type=int, default=1)
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    groups = []
    for spec in args.group:
        head, _, cfgs = spec.partition("=")
        groups.append((head.strip(), [c.strip() for c in cfgs.split(",") if c.strip()]))
    if len(groups) < 2:
        print("[!] 至少要两个臂才能比")
        return 2

    cfg_names = [c for _, cs in groups for c in cs]
    data = {}
    for name in cfg_names:
        msgs, blobs = load_cfg(args.fixture, args.pool_root, name, args.pool_suffix)
        data[name] = (name, msgs, blobs)
        print(f"  [CFG] {name}: 前缀 {len(msgs)} 条报文，池 {len(blobs)} 条种子")

    launcher = os.path.join(HERE, args.launcher)
    with TcpShmOracle([launcher, str(args.port)], port=args.port,
                      banner_lines=args.banner_lines, settle=0.08,
                      start_timeout=6.0) as oracle:
        # 趟一：逐配置量各自的边集（趟间清零，读的是"这个配置自己摸到的"）
        own = {}
        for name in cfg_names:
            own[name] = replay(oracle, [data[name]])
            print(f"    自身覆盖  {name:22s} {len(own[name]):4d} 条边")

        # 趟二：每臂一趟 → 并集
        unions = {}
        for gname, cs in groups:
            unions[gname] = replay(oracle, [data[c] for c in cs])
            sigma = sum(len(own[c]) for c in cs)
            print(f"    并集      {gname:22s} {len(unions[gname]):4d} 条边"
                  f"   （Σ=上界 {sigma}，虚高 {(sigma - len(unions[gname])) / max(sigma, 1) * 100:.1f}%）")

    print()
    print("### 并集边覆盖（精确）")
    print()
    print("| 臂 | 配置数 | Σ 上界 | **并集** | 虚高 |")
    print("|---|---|---|---|---|")
    for gname, cs in groups:
        sigma = sum(len(own[c]) for c in cs)
        u = len(unions[gname])
        print(f"| {gname} | {len(cs)} | {sigma} | **{u}** | "
              f"{(sigma - u) / max(sigma, 1) * 100:.1f}% |")

    print()
    print("各配置自身的边集（看重叠结构）：")
    names = cfg_names
    print("| | " + " | ".join(names) + " |")
    print("|---" * (len(names) + 1) + "|")
    for a in names:
        row = [f"| **{a}**"]
        for b in names:
            row.append(f" {len(own[a] & own[b])} ")
        print("".join(row) + "|")

    print()
    g0, g1 = groups[0][0], groups[1][0]
    u0, u1 = unions[g0], unions[g1]
    only0, only1 = u0 - u1, u1 - u0

    # 集合恒等式自检。上面那个"第二趟没清零"的 bug 就是靠这类检查现形的 ——
    # 它会安静地报出 |ISO∩MIX| > |MIX| 的荒唐结果，不自检就直接进论文了。
    for gn, cs in groups:
        u = unions[gn]
        lo = max(len(own[c]) for c in cs)
        hi = sum(len(own[c]) for c in cs)
        assert lo <= len(u) <= hi, f"{gn} 并集 {len(u)} 越界 [{lo}, {hi}]"
    assert len(u0 & u1) <= min(len(u0), len(u1)), "交集比集合本身还大"
    assert len(u0 | u1) >= max(len(u0), len(u1)), "并集比集合本身还小"
    assert not (only0 & u1) and not (only1 & u0), "差集算错"
    assert len(u0) == len(u0 & u1) + len(only0), "A 不等于 交+差"
    print(f"| 口径 | 边数 |")
    print("|---|---|")
    print(f"| {g0} ∪ {g1} | {len(u0 | u1)} |")
    print(f"| {g0} ∩ {g1} | {len(u0 & u1)} |")
    print(f"| **只有 {g0} 摸得到**（{g0} − {g1}） | **{len(only0)}** |")
    print(f"| 只有 {g1} 摸得到（{g1} − {g0}） | {len(only1)} |")
    print()
    print(f"论点直接证据：{g0} 比 {g1} 多摸到 {len(only0)} 条边、"
          f"少摸到 {len(only1)} 条边，并集差 {len(u0) - len(u1):+d}。")

    if args.json:
        out = {
            "own": {k: sorted(v) for k, v in own.items()},
            "union": {k: sorted(v) for k, v in unions.items()},
            "sizes": {"own": {k: len(v) for k, v in own.items()},
                      "union": {k: len(v) for k, v in unions.items()}},
            "diff": {f"{g0}_only": sorted(only0), f"{g1}_only": sorted(only1)},
            "groups": {g: cs for g, cs in groups},
        }
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print(f"已写 {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
