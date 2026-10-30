#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ablation_report.py —— 汇总「单状态池 vs 混状态池」的 fuzz 指标
=============================================================

读 run_state_partition_ablation.sh 落下的 results/<label>/i*/fuzzer_*/fuzzer_stats
（AFL++ 原生指标，不自己造数），打成一张对比表。

只报 fuzzer_stats 里有的字段，不折算、不归一化 —— 两组的实例数/时长/配置
本来就相同，直接比即可。

多轮消融（审查 F5 残留）用 --rounds 模式：
    python3 ablation_report.py --rounds ablation_runs/<runid>
读 round<r>/<label>/ 的逐轮快照，报轮间 mean±std 与同轮配对差 Δ。
"""
from __future__ import annotations

import glob
import hashlib
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# (字段名, fuzzer_stats 里的键, 汇总方式)
FIELDS = [
    ("execs",     "execs_done",     "sum"),
    ("exec/s",    "execs_per_sec",  "sum"),
    ("corpus",    "corpus_count",   "sum"),
    ("crashes",   "saved_crashes",  "sum"),
    ("edges",     "edges_found",    "max"),
    ("bitmap",    "bitmap_cvg",     "max"),
]


def read_stats(path: str) -> dict:
    out = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if ":" not in line:
                    continue
                k, _, v = line.partition(":")
                out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def collect(label: str, root: str) -> dict:
    """一个配置的所有实例的 fuzzer_stats 聚合成一行。"""
    insts = sorted(glob.glob(os.path.join(root, "results", label, "i*", "*",
                                          "fuzzer_stats")))
    return _agg_insts(insts)


def _agg_insts(insts: list) -> dict:
    agg = {}
    for name, key, how in FIELDS:
        vals = []
        for p in insts:
            s = read_stats(p)
            if key in s:
                try:
                    # bitmap_cvg 写成 "28.87%"，float() 认不得百分号
                    vals.append(float(s[key].rstrip("%")))
                except ValueError:
                    pass
        if not vals:
            agg[name] = None
        elif how == "sum":
            agg[name] = sum(vals)
        else:
            agg[name] = max(vals)
    agg["_n_inst"] = len(insts)
    return agg


def dedup_corpus(label: str, root: str) -> tuple[int, int]:
    """(sha256 唯一种子数, 实例求和条数)。

    fuzzer_stats 的 corpus_count 逐实例求和是【上界】：实例间靠 -F 同步的
    副本在每个实例的 queue 里各留一份，求和把同一条种子数好几次。按内容
    sha256 去重后才是「这组配置总共发现了多少条不同种子」（审查 item 4）。
    """
    seen: set = set()
    total = 0
    for p in sorted(glob.glob(os.path.join(root, "results", label, "i*", "*",
                                           "queue", "id:*"))):
        total += 1
        try:
            with open(p, "rb") as f:
                seen.add(hashlib.sha256(f.read()).digest())
        except OSError:
            pass
    return len(seen), total


def fmt(v, name: str) -> str:
    if v is None:
        return "—"
    if name in ("exec/s", "bitmap"):
        return f"{v:.2f}"
    return f"{int(v):,}"


def _mean_std(vals: list):
    """(mean, sample std)。n=1 时 std 为 None —— 单轮报不出方差。"""
    n = len(vals)
    m = sum(vals) / n
    if n < 2:
        return m, None
    var = sum((v - m) ** 2 for v in vals) / (n - 1)
    return m, math.sqrt(var)


def _fmt_ms(vals: list, name: str, signed: bool = False) -> str:
    if not vals:
        return "—"
    m, sd = _mean_std(vals)
    s = fmt(m, name)
    if signed and m > 0:
        s = "+" + s
    return s if sd is None else f"{s} ± {fmt(sd, name)}"


def report_rounds(run_dir: str) -> int:
    """多轮汇总（审查 F5 残留）：报 mean±std，单轮数字不进论文。

    每轮快照在 ablation_runs/<id>/round<r>/<label>/（run_state_partition_ablation.sh
    落的），奇数轮 A→B、偶数轮 B→A 换序消顺序效应。Δ 按【同轮配对差】算 ——
    轮间的共同漂移（机器负载）在配对里消掉，比两组独立均值相减稳。
    """
    rounds = sorted(glob.glob(os.path.join(run_dir, "round*")),
                    key=lambda p: int(os.path.basename(p).replace("round", "")))
    if not rounds:
        print(f"[!] {run_dir} 里没有 round* 快照")
        return 2

    labels = ["A_single_state", "B_mixed_pool"]
    data = {lb: {n: [] for n, _, _ in FIELDS} for lb in labels}
    reach = {lb: [] for lb in labels}
    used = []
    for rp in rounds:
        got_any = False
        for lb in labels:
            insts = sorted(glob.glob(os.path.join(rp, lb, "i*", "*",
                                                  "fuzzer_stats")))
            agg = _agg_insts(insts)
            if agg["_n_inst"] == 0:
                continue
            got_any = True
            for n, _, _ in FIELDS:
                data[lb][n].append(agg[n])
            rj = os.path.join(rp, f"{lb}.reach.json")
            if os.path.isfile(rj):
                with open(rj, encoding="utf-8") as f:
                    d = json.load(f)
                reach[lb].append((d.get("reachable"), d.get("total")))
        if got_any:
            used.append(os.path.basename(rp))
    if not used:
        print(f"[!] {run_dir} 的 round* 快照里没有 fuzzer_stats")
        return 2

    print()
    print(f"### 多轮汇总（{len(used)} 轮：{', '.join(used)}，"
          f"奇数轮 A→B / 偶数轮 B→A）")
    print()
    print("每格 = 轮间 mean ± sample std；Δ = 同轮配对差 A−B 的 mean ± std。")
    print()
    print("| 指标 | A_single_state | B_mixed_pool | Δ(A−B，配对) |")
    print("|---|---|---|---|")
    for name, _, _ in FIELDS:
        cells = [_fmt_ms([v for v in data[lb][name] if v is not None], name)
                 for lb in labels]
        diffs = [a - b for a, b in zip(data[labels[0]][name],
                                       data[labels[1]][name])
                 if a is not None and b is not None]
        cells.append(_fmt_ms(diffs, name, signed=True))
        print(f"| {name} | " + " | ".join(cells) + " |")
    print()
    for lb in labels:
        if reach[lb]:
            vals = "  ".join(f"{a}/{b}" for a, b in reach[lb])
            print(f"level-1 可达 [{lb}]：逐轮 {vals}")
    print()
    print("corpus 一列是实例求和（含 -F 同步副本），为上界；"
          "crashes/execs/exec/s 求和是实数；edges/bitmap 取实例最大。")
    print("level-1 可达是机制证据，上表是结果证据 —— 两层必须同向才成立。")
    return 0


def main() -> int:
    if len(sys.argv) > 2 and sys.argv[1] == "--rounds":
        return report_rounds(sys.argv[2])
    root = sys.argv[1] if len(sys.argv) > 1 else HERE
    want = sys.argv[2:]
    report = os.path.join(root, "ablation", "report.json")
    meta = {}
    if os.path.isfile(report):
        with open(report, encoding="utf-8") as f:
            meta = json.load(f)

    if want:
        labels = want
    elif meta:
        labels = list(meta)
    else:
        # 通用：扫 results/ 下所有跑过的配置
        rd = os.path.join(root, "results")
        labels = sorted(os.listdir(rd)) if os.path.isdir(rd) else []
    labels = [lb for lb in labels if os.path.isdir(os.path.join(root, "results", lb))]
    if not labels:
        print("[!] results/ 里没有可汇总的配置")
        return 2

    rows = [(lb, collect(lb, root)) for lb in labels]

    print()
    print("### fuzz 指标汇总（AFL++ fuzzer_stats，多实例求和/取最大）")
    print()
    for lb in labels:
        m = meta.get(lb, {})
        extra = (f"   状态前缀 `{m.get('prefix')}`，池 {m.get('pool')}，"
                 f"可达 {m.get('reachable')}") if m else ""
        print(f"- **{lb}**{extra}")
    print()
    print("| 配置 | 实例 | " + " | ".join(n for n, _, _ in FIELDS) + " |")
    print("|---" * (len(FIELDS) + 2) + "|")
    for lb, r in rows:
        cells = " | ".join(fmt(r[n], n) for n, _, _ in FIELDS)
        print(f"| {lb} | {r['_n_inst']} | {cells} |")
    print()
    print("corpus 一列是**实例求和，含 -F 同步副本，为上界**；去重口径见下。")
    for lb, r in rows:
        uniq, total = dedup_corpus(lb, root)
        if total:
            print(f"  corpus 去重 [{lb}]：sha256 唯一 {uniq} 条"
                  f"（实例求和 {total} 条，上界）")

    # 只在恰好两组时算差值（ablation 的 A vs B），否则不写结论
    if len(rows) == 2 and all(r["edges"] for _, r in rows):
        a, b = rows[0][1], rows[1][1]
        print()
        print(f"差值（{rows[0][0]} − {rows[1][0]}）：")
        for name, _, how in FIELDS:
            if a[name] is None or b[name] is None:
                continue
            d = a[name] - b[name]
            pct = (d / b[name] * 100) if b[name] else float("inf")
            print(f"  {name:8s} {fmt(a[name], name):>10s} vs "
                  f"{fmt(b[name], name):>10s}   Δ={d:+.2f} ({pct:+.1f}%)")

    # 主实验（run_state_sweep.sh）：ISO 若干配置 + MIX 一个配置，机器时间对齐。
    # ISO 侧按【配置】求和；edges/corpus 是重复计数的【上界】——跨状态共用的
    # 样板边在每个配置里各算一次，所以只能摆出"ΣISO vs MIX"，不能声称并集。
    iso = [(lb, r) for lb, r in rows if lb.startswith("ISO_")]
    mix = [(lb, r) for lb, r in rows if lb.startswith("MIX_")]
    if iso and mix and len(mix) == 1:
        m = mix[0][1]
        print()
        print(f"### 主实验：按状态隔离（Σ {len(iso)} 个配置）vs 不隔离（{mix[0][0]}）")
        print()
        print("| 口径 | 实例 | " + " | ".join(n for n, _, _ in FIELDS) + " |")
        print("|---" * (len(FIELDS) + 2) + "|")
        agg = {}
        for name, _, how in FIELDS:
            vals = [r[name] for _, r in iso if r[name] is not None]
            agg[name] = (sum(vals) if vals else None) if how == "sum" else \
                        (max(vals) if vals else None)
        # edges/corpus 对 ISO 一律求和（Σ = 上界）；crashes/execs 求和本来就是实数
        for name in ("edges", "corpus", "crashes", "execs", "exec/s"):
            vals = [r[name] for _, r in iso if r[name] is not None]
            agg[name] = sum(vals) if vals else None
        agg["_n_inst"] = sum(r["_n_inst"] for _, r in iso)
        cells = " | ".join(fmt(agg[n], n) for n, _, _ in FIELDS)
        print(f"| ISO（Σ{len(iso)} 配置） | {agg['_n_inst']} | {cells} |")
        cells = " | ".join(fmt(m[n], n) for n, _, _ in FIELDS)
        print(f"| MIX（{mix[0][0]}） | {m['_n_inst']} | {cells} |")
        print()
        print("Σedges / Σcorpus 是**上界**：跨状态共用的样板边每个配置各算一次，")
        print("两配置的边集合有交集。MIX 那一行是单配置实测，没有重复计数问题。")
        print("两边的机器时间必须先对齐再比（ISO 是 K×DUR，MIX 是 K×DUR）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
