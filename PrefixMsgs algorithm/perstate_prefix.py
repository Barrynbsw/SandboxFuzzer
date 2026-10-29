#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
perstate_prefix.py —— 会话前缀重建 (Session Prefix Reconstruction)
================================================================

为 SandboxFuzzer 的「一台机器测一个状态」隔离模糊测试适配的前置消息识别算法。
不是重写 HSPFuzzer Algorithm 2 的伪代码，而是替换它的【两个错误假设】：

  假设 A（连续性）  PrefixMsgs = Msgs.SUBLIST(0, x) —— 前缀是【前段连续子表】。
  假设 B（全局唯一）一个会话只有【一个】前缀，供连接复用阶段重放。

实测（counterexample_test.py，RFC 959 语义）Algorithm 2 在 5 个场景里只对 1 个
场景正确：只要会话里无条件噪声消息数 > τ，`num > τ` 立刻在 x=0 触发 break，
输出空前缀。τ 不是常数，它随抓包长度增长，调参救不了。

本算法改成三段：

  A. 依赖矩阵  Deps[i][j] —— 消息 i 是否为消息 j 的前置
     逐条移除，看哪些后续消息覆盖率掉；不做连续性假设，输出是【集合】不是【切点】。
     覆盖成本 N 次实验，与 Algorithm 2 第一阶段同阶。

  B. 按状态最小可达序列  reach(state) -> 保序最短前置序列
     SandboxFuzzer 一个节点只测一个状态，要的不是"全局前缀"，是"到这个状态的
     最短路"。用反向贪心删除（保序 1-最小），每步只依赖一个状态判别器
     T(S)：发完 S 后打一条探针命令，看是否回该状态的响应码 —— 与
     sandbox_harness 的 PROBE_CMD / PREFIX_FILE 接口一一对应。

  C. 拆包判定  NeedSplit / AllSplit
     保留 Algorithm 2 第 18-29 行：这一段是对的，它回答"SUT 能不能在单包里
     解析多条消息"，与前缀假设无关。

用法（无真实 SUT 时跑算法自检）:
    python3 perstate_prefix.py --self-test

接真实 SUT: 实现 CoverageOracle 的 run_sequence/run_single（afl-showmap 即可），
           再给一个状态判别器 probe_fn(序列) -> bool。
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from typing import Callable, Sequence

Coverage = frozenset


# --------------------------------------------------------------------------
# 覆盖率工具
# --------------------------------------------------------------------------

def cov_diff(a: Coverage, b: Coverage) -> float:
    """归一化对称差 |a Δ b| / |a ∪ b|，0 = 完全一致。"""
    if not a and not b:
        return 0.0
    union = len(a | b)
    return (len(a ^ b) / union) if union else 0.0


def cov_union(covs) -> Coverage:
    out = set()
    for c in covs:
        out |= c
    return frozenset(out)


def consensus(covs, min_frac: float = 0.5) -> Coverage:
    """多次重复实验的【稳定核】覆盖：只保留在多数 run 里都出现的边。

    为什么必须做这一步：多线程靶机的线程退出路径会往同一个 SHM 里落笔，
    凭空多出 1~2 条边。LightFTP 每条连接一个线程，`close()` 之后退出路径的
    覆盖照样写进目标 SHM —— 下一条会话清零后它才落笔。这类杂散边在单次 run
    里看着像真实的覆盖差异（DIFF = 1/16 = 0.0625），能直接顶过阈值造出一条
    假依赖。实测曾把会话级前置集从 [USER, PASS] 撑成 5 条假阳性。

    取多数票而不是全交集：真依赖引起的路径变化是确定性的（分支翻转，每次
    都在），杂散边是偶发的（1/5 上下）。全交集会连偶发但真实的边一起丢掉，
    多数票只丢偶发的那些。
    """
    covs = list(covs)
    if not covs:
        return frozenset()
    if len(covs) == 1:
        return frozenset(covs[0])
    import math
    need = max(1, math.ceil(len(covs) * min_frac))     # 5 次 → 至少 3 次
    cnt: dict = {}
    for c in covs:
        for e in c:
            cnt[e] = cnt.get(e, 0) + 1
    return frozenset(e for e, k in cnt.items() if k >= need)


def edge_threshold(delta: float, union_size: int, tolerate_edges: int = 1) -> float:
    """按【边数】定的下限，与按比例的 δ 取大者。

    DIFF 是比值，它的最小非零值 = 1/|并集|，随覆盖率规模浮动：一条 16 边的
    消息 1 条杂散边就是 0.0625，一条 70 边的消息只有 0.014。固定 δ=0.02 对
    后者够用，对前者直接漏判不了、反而把杂散边当依赖。

    所以下限要按边数算：容忍 tolerate_edges 条杂散边，就要求差异超过
    (tolerate_edges + 0.5) 条边换算成的比值 —— 半条边的余量保证
    「正好 k 条杂散」判不进依赖，「真依赖掉 k+1 条边」不会被压掉。
    """
    if union_size <= 0:
        return delta
    return max(delta, (tolerate_edges + 0.5) / union_size)


# --------------------------------------------------------------------------
# 结果容器
# --------------------------------------------------------------------------

@dataclass
class RebuildResult:
    # A 段：依赖矩阵。deps[i] = {j : i 是 j 的前置}
    deps: dict[int, set]
    # A 段导出：被依赖的消息 = 会话级前置集（非连续）
    prerequisite_set: list[int]
    # B 段：每个目标状态的最短保序前置序列
    reaching: dict[str, list[int]] = field(default_factory=dict)
    # C 段
    need_split: bool = False
    all_split: bool = False
    # δ 校准结果（delta=None 时才非零）
    delta_used: float = 0.0
    noise_floor: float = 0.0
    # signals[x][y] = 移除 Mx 后 My 的【共识核】覆盖率差异。
    # 真机诊断用：漏检时看这条边的信号离 δ 有多远，区分「阈值压过信号」
    # 和「信号本来就弱」，两者结论完全不同。
    signals: dict[tuple[int, int], float] = field(default_factory=dict)
    trace: list = field(default_factory=list)


# --------------------------------------------------------------------------
# δ 校准：让算法自己测噪声地板，而不是让使用者手拍
# --------------------------------------------------------------------------

def calibrate_delta(
    sim,
    n: int,
    repeats: int = 5,
    factor: float = 2.5,
    floor: float = 0.02,
    verbose: bool = False,
) -> tuple[float, float]:
    """量出覆盖率抖动幅度，据此定 δ。

    为什么必须校准：
      依赖判定是 cov_diff(base[j], cov_t[j]) > δ，而 base 与 cov_t 是两次
      【独立实验】，各自带噪声。δ 小于噪声地板时，几乎每一对 (i,j) 的 DIFF
      都会过阈 → 前置集膨胀到全序列，precision 崩掉而 recall 恒为 1.0
      （eval_rebuild.py 的噪声扫描就是这个形状）。

      噪声幅度因目标而异：单线程 CLI 约 1%，多线程服务器 5~10%。
      所以 δ 不能写死 0.05，得由测量给出。

    测法与【依赖判定用的是同一个统计量】，这点是关键：
      把全序列跑两批各 repeats 次，各自做共识核，再算两条共识核的 DIFF ——
      正是 build_dependency_matrix 判 (x,j) 时算的那个数。零假设下它就该是
      「同一条消息两次独立实验的差异」，所以噪声地板直接就是判定统计量的零分布。
      早先这里算的是【单批内两两 DIFF 的中位数】，与判定统计量不同，而且中位数
      恒为 0 时会掉到 floor，δ 就成了魔法常数 —— 实测 floor=0.02 压不住
      「1 条杂散边 = 1/16 = 0.0625」，出过 5 条假依赖。

    取 max 而不是中位数（跨消息）：δ 要罩住【最坏的那条消息】，
    宁可保守也不能让任何一条被杂散边冤枉。单条消息内部仍靠共识核压噪声，
    所以这里的 max 不会像早先「噪声取 max → δ=0.18 压过 0.143 真信号」那样顶高。

    返回 (delta, noise_floor)。成本 = 2×repeats 次完整序列实验。
    """
    all_idx = list(range(n))
    batch_a = [sim.run_sequence_idx(all_idx) for _ in range(repeats)]
    batch_b = [sim.run_sequence_idx(all_idx) for _ in range(repeats)]
    per_msg_null = []
    for j in range(n):
        ca = consensus([batch_a[a][j] for a in range(repeats)])
        cb = consensus([batch_b[b][j] for b in range(repeats)])
        per_msg_null.append(cov_diff(ca, cb))
    noise_floor = max(per_msg_null) if per_msg_null else 0.0
    delta = max(noise_floor * factor, floor)
    if verbose:
        print(f"[Calibrate] 噪声地板(判定统计量的零分布, max over 消息)="
              f"{noise_floor:.4f} → δ={delta:.4f} "
              f"(factor={factor}, floor={floor})")
    return delta, noise_floor


# --------------------------------------------------------------------------
# A. 依赖矩阵（非连续前置集识别）
# --------------------------------------------------------------------------

def build_dependency_matrix(
    sim,
    n: int,
    delta: float = 0.05,
    repeats: int = 5,
    tolerate_edges: int = 1,
    verbose: bool = False,
) -> tuple[dict[int, set], dict[tuple[int, int], float]]:
    """Deps[i] = {j > i : 移除 Mi 会让 Mj 的自身覆盖率掉超过阈值}。

    与 Algorithm 2 第一阶段同阶实验，但产出是完整依赖图而不是切点，
    因此不依赖"前缀连续"这一假设 —— 这正是它能处理
    `USER, NOOP, PASS` 这类被打散的会话的原因。

    repeats 次重复取【共识核】（consensus，多数票），不是取单次：单次测量
    会被杂散边淹没真信号，而中位数对【成簇】的杂散边无效 —— 杂散边一旦在
    某一批里多数 run 出现，两两配对的中位数就是 0.0625，直接顶过阈值。
    多数票只丢偶发的边，真依赖的确定性路径变化每次都留着。

    阈值用 edge_threshold：δ 是比值，最小非零值 = 1/|并集|，随覆盖率规模浮动。
    默认容忍 1 条杂散边，等于给判定加了「一条边造不出依赖」这条硬约束。

    返回 (deps, signals)。signals[(x,y)] 是实测差异，供诊断漏检原因。
    """
    all_idx = list(range(n))
    base_runs = [sim.run_sequence_idx(all_idx) for _ in range(repeats)]
    base_core = {y: consensus([base_runs[a][y] for a in range(repeats)])
                 for y in all_idx}
    deps: dict[int, set] = {i: set() for i in all_idx}
    signals: dict[tuple[int, int], float] = {}

    for x in all_idx:
        left = [i for i in all_idx if i != x]
        drop_runs = [sim.run_sequence_idx(left) for _ in range(repeats)]
        # cov_t_maps[rep][idx] = 第 rep 次移除实验里 Mi 的自身覆盖
        cov_t_maps = [
            {idx: drop_runs[rep][k] for k, idx in enumerate(left)}
            for rep in range(repeats)
        ]
        for y in left:
            if y <= x:
                continue                          # 后面的消息才可能依赖 Mx
            drop_core = consensus([cov_t_maps[b][y] for b in range(repeats)])
            d = cov_diff(base_core[y], drop_core)
            thr = edge_threshold(delta, len(base_core[y] | drop_core),
                                 tolerate_edges)
            signals[(x, y)] = d
            if d > thr:
                deps[x].add(y)
            if verbose:
                print(f"    remove M{x}: M{y} DIFF={d:.4f} 阈值={thr:.4f}"
                      f"{'  ← 依赖' if d > thr else ''}")
    return deps, signals


# --------------------------------------------------------------------------
# B. 按状态最小可达序列
# --------------------------------------------------------------------------

def minimize_reaching_sequence(
    probe_fn: Callable[[Sequence[int]], bool],
    all_idx: Sequence[int],
    verbose: bool = False,
) -> list[int]:
    """反向贪心删除，求到达目标状态的 1-最小保序子序列。

    probe_fn(S) == True 表示按序发 S 后靶机处于目标状态。
    每次只删一条并立即验证，故保序且 1-最小：再删任何一条就不成立。
    不是全局最短（那是组合优化），但在"每步一次网络往返"的代价下是实用解。

    为什么从后往前删：前置消息通常排在前面，从尾部删能最快削掉噪声，
    且不会先把前拆除掉导致中间态探测失败。
    """
    s = list(all_idx)
    if not probe_fn(s):
        raise ValueError("完整序列本身到不了目标状态 —— 目标或序列给错了")

    changed = True
    while changed:
        changed = False
        for i in range(len(s) - 1, -1, -1):
            cand = s[:i] + s[i + 1:]
            # 空序列是合法候选：初始态的最短前置序列就是 []。
            # 但只有 probe_fn([]) 为真才会被采纳，不会误删到空。
            if probe_fn(cand):
                if verbose:
                    print(f"    删 M{s[i]} → 仍可达，序列缩到 {cand}")
                s = cand
                changed = True
                break          # s 变短了，下标全失效，回到外层重扫
    return s


# --------------------------------------------------------------------------
# C. 拆包判定（沿用 Algorithm 2 第 18-29 行，这一段是对的）
# --------------------------------------------------------------------------

def detect_split(
    sim,
    n: int,
    base: Sequence[Coverage],
    prefix: Sequence[int],
    delta: float = 0.05,
) -> tuple[bool, bool]:
    """拆包判定，与 Algorithm 2 第 18-29 行同语义。

    AllSplit 问的是「拆完之后，前缀逐条发 + 剩下的拼包发，还丢不丢覆盖」——
    所以 cov_ol 必须【包含前缀逐条重放的覆盖】，且拼包那一步要在前缀建立的
    状态里发（run_blob_in_state_idx）。

    早先这里写的是 cov_ol = run_single_idx(left)：前缀覆盖整个丢了，于是把
    "前缀没重放"和"剩余拼包丢覆盖"混成一件事，AllSplit 几乎恒真。
    """
    all_idx = list(range(n))
    cov_o = sim.run_single_idx(tuple(all_idx))
    cov_a = cov_union(base)
    need = cov_diff(cov_a, cov_o) > n * delta

    all_split = False
    if need:
        left = [i for i in all_idx if i not in set(prefix)]
        acc = set()
        for c in sim.run_sequence_idx(list(prefix)):   # 前缀逐条重放
            acc |= c
        if left:
            acc |= sim.run_blob_in_state_idx(tuple(left), tuple(prefix))
        all_split = cov_diff(cov_a, frozenset(acc)) > n * delta
    return need, all_split


# --------------------------------------------------------------------------
# 按状态的种子归属（种子池必须单状态的判据）
# --------------------------------------------------------------------------

def prerequisites_of(res: "RebuildResult", j: int) -> set:
    """消息 j 的前置集合 = 依赖矩阵里指向 j 的那些消息。

    deps[x] = {y : x 是 y 的前置}，所以反查就是
    {x : j ∈ deps[x]}。这是算法自己的产物，不含任何协议先验。
    """
    return {x for x, ys in res.deps.items() if j in ys}


def playable_in_state(res: "RebuildResult", j: int,
                      reaching: Sequence[int]) -> bool:
    """消息 j 在 reaching 序列建立的那个状态里能不能正常打。

    判据：j 的前置全部被 reaching 满足。

    这是「种子池必须单状态」的判据式 —— 一个状态池只收【本状态可达】的
    种子，混进别状态的种子就会污染该池的可达性（混状态池会污染可达性，
    这是状态分池必须配 ablation 的原因）。

    只用依赖矩阵，不查协议真值表：真实目标上没有那张表，拿它当判据等于
    把答案抄进产物。真值表只该出现在【校验】里，不该出现在【生成】里。
    """
    return prerequisites_of(res, j) <= set(reaching)


# --------------------------------------------------------------------------
# 主入口
# --------------------------------------------------------------------------

def rebuild_session_prefix(
    sim,
    n: int,
    probes: dict[str, Callable[[Sequence[int]], bool]] | None = None,
    delta: float | None = None,
    repeats: int = 5,
    tolerate_edges: int = 1,
    verbose: bool = False,
) -> RebuildResult:
    """会话前缀重建主过程。

    probes: 状态名 -> 判别函数。SandboxFuzzer 里就是
            {state: (lambda S: 发完 S 后 PROBE_CMD 回该状态的响应码)}。
            传空则只输出会话级前置集，不做按状态最小化。
    delta : 覆盖率「相近」阈值。传 None 则自动测噪声地板校准（推荐）。
    tolerate_edges: 判定上额外容忍的杂散边数，见 edge_threshold。
    """
    if n < 1:
        raise ValueError("N >= 1")

    if delta is None:
        delta, noise_floor = calibrate_delta(sim, n, repeats=repeats,
                                             verbose=verbose)
    else:
        noise_floor = 0.0

    deps, signals = build_dependency_matrix(sim, n, delta=delta,
                                            repeats=repeats,
                                            tolerate_edges=tolerate_edges,
                                            verbose=verbose)
    # 会话级前置集 = 被任何消息依赖的消息
    prereq_set = sorted({i for i, ds in deps.items() if ds})
    if verbose:
        print(f"[Rebuild] 依赖矩阵: "
              f"{ {i: sorted(d) for i, d in deps.items() if d} }")
        print(f"[Rebuild] 会话级前置集 = {prereq_set}")

    res = RebuildResult(deps=deps, prerequisite_set=prereq_set,
                        delta_used=delta, noise_floor=noise_floor,
                        signals=signals)

    if probes:
        for state, probe in probes.items():
            seq = minimize_reaching_sequence(probe, list(range(n)), verbose=verbose)
            res.reaching[state] = seq
            if verbose:
                print(f"[Rebuild] 状态 {state!r} 最短前置序列 = {seq}")

    base = sim.run_sequence_idx(list(range(n)))
    res.need_split, res.all_split = detect_split(sim, n, base, prereq_set, delta)
    return res


# --------------------------------------------------------------------------
# 自检：跑 counterexample_test 的场景，验证 A 段能还原真值
# --------------------------------------------------------------------------

def _self_test() -> int:
    from counterexample_test import SCENARIOS, score  # 复用同一套真值

    print("=" * 78)
    print("会话前缀重建 —— ground truth 校验（A 段：依赖矩阵）")
    print("=" * 78)

    rows = []
    for name, desc, msgs, truth, uncond, sim, n in SCENARIOS:
        res = rebuild_session_prefix(sim, n, delta=0.05, verbose=False)
        got = res.prerequisite_set
        prec, rec = score(got, truth)
        verdict = "OK" if set(got) == set(truth) else "MISMATCH"
        print(f"  {name}")
        print(f"    真值 {truth}   重建 {got}   P={prec:.2f} R={rec:.2f}  → {verdict}")
        rows.append((name, got, truth, prec, rec, verdict))

    print(f"\n{'=' * 78}")
    print(f"{'场景':46s} {'重建输出':12s} {'真值':10s} {'P':>5s} {'R':>5s}  判定")
    print("-" * 78)
    for name, got, truth, prec, rec, verdict in rows:
        print(f"{name:46s} {str(got):12s} {str(truth):10s} {prec:5.2f} {rec:5.2f}  {verdict}")
    print("-" * 78)
    ok = sum(1 for r in rows if r[5] == "OK")
    print(f"通过 {ok}/{len(rows)}")

    # ── B 段：按状态最小可达序列 ──────────────────────────────────
    print(f"\n{'=' * 78}\nB 段：按状态最小可达序列（S4 两组前置）")
    name, desc, msgs, truth, uncond, sim, n = SCENARIOS[3]
    print(f"  会话 = {msgs}")
    print(f"  真值依赖: USER/PASS 是登录态前置，PASV 只是 LIST 的前置")

    def reach_logged_in(s):
        """探针 PWD 只有登录态才回 257；S4 里 PWD 的前置 = {0,1}。"""
        return {0, 1}.issubset(set(s))

    def reach_data_ready(s):
        """探针 LIST 需要登录 + 数据连接，前置 = {0,1,2}。"""
        return {0, 1, 2}.issubset(set(s))

    res = rebuild_session_prefix(
        sim, n, delta=0.05, verbose=False,
        probes={"logged_in": reach_logged_in, "data_ready": reach_data_ready},
    )
    for state, seq in res.reaching.items():
        print(f"    状态 {state:12s} → 最短前置序列 {seq}  对应消息 "
              f"{[msgs[i] for i in seq]}")
    print(f"    会话级前置集（B 段之前的输出）= {res.prerequisite_set}")

    # 对比：Algorithm 2 的单一全局切点表达不了"两个状态要两套前缀"
    print(f"\n  → Algorithm 2 只能给一个 PrefixMsgs（S4 上给的是 [0,1]），")
    print(f"    表达不了 data_ready 还要带上 PASV。这正是按状态重建的必要性。")
    return 0 if ok == len(rows) else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    raise SystemExit(_self_test() if args.self_test else 0)
