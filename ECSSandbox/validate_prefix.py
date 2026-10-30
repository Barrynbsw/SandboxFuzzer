#!/usr/bin/env python3
"""
validate_prefix.py —— 会话前缀重建算法的真机 ground truth 校验
================================================================

`counterexample_test.py` 的 5/5 是在【我自己造的覆盖率模型】上取得的，
真值来自我自己写的 prereq 字典 —— 换句话说还是自说自话。这里换成真靶机
LightFTP（源码零改动），真值用【真实响应码】定义，与覆盖率完全独立：

    消息 i 是消息 j 的前置  ⟺  去掉 i 后，j 的响应码变了

响应码是 RFC 959 的状态机本身（AFLNet IPSM 用的正是这个信号），审稿人可以
拿 RFC 逐条核对。算法用【覆盖率】推依赖，真值用【响应码】定，两者同源不同法，
这样比出来的 precision/recall 才站得住。

同时对比两个算法：
    Algorithm 2（HSPFuzzer 复现）   PrefixMsgs = 前段连续切点
    会话前缀重建（perstate_prefix）  依赖矩阵 + 按状态最小可达序列

跑法（宿主机 glibc 2.31 编不动 fftp，必须进容器）：
    cd SandboxFuzzer
    docker run --rm --user "$(id -u):$(id -g)" \\
        -v "$PWD":/sbfpkg --entrypoint python3 \\
        sbf-node /sbfpkg/ECSSandbox/validate_prefix.py

注意要挂【包根】（SandboxFuzzer/），不是只挂 ECSSandbox/：算法目录在
`PrefixMsgs algorithm/`，与 ECSSandbox 同级。只挂 ECSSandbox 会变成扁平的
/sandbox，Python 找不到 prefix_msg_identify。
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def _find_algo_dir() -> str:
    """定位 PrefixMsgs algorithm/ 目录。

    宿主机上 ECSSandbox 与它同级，`dirname(HERE)` 就能拼出来；但容器里
    本目录被挂成扁平的 /sandbox，父目录是 /，拼出来的路径不存在。
    所以改成逐个候选找，找到含 prefix_msg_identify.py 的那个为止。
    """
    env = os.environ.get("SBF_ALGO_DIR")
    if env and os.path.isfile(os.path.join(env, "prefix_msg_identify.py")):
        return env
    cands = [
        os.path.join(os.path.dirname(HERE), "PrefixMsgs algorithm"),
        os.path.join(HERE, "PrefixMsgs algorithm"),
        os.path.join(HERE, "..", "PrefixMsgs algorithm"),
        "/sandbox/PrefixMsgs algorithm",
    ]
    for c in cands:
        if os.path.isfile(os.path.join(c, "prefix_msg_identify.py")):
            return os.path.abspath(c)
    raise RuntimeError(
        "找不到 PrefixMsgs algorithm/ 目录，用 SBF_ALGO_DIR 显式指定。"
        f"已试: {cands}")


ALGO_DIR = _find_algo_dir()
sys.path.insert(0, ALGO_DIR)
sys.path.insert(0, HERE)
print(f"[validate] ALGO_DIR = {ALGO_DIR}")

from prefix_msg_identify import SequenceSimulator, identify_prefix_messages  # noqa: E402
from perstate_prefix import (  # noqa: E402
    calibrate_delta,
    minimize_reaching_sequence,
    rebuild_session_prefix,
)
from tcp_shm_oracle import TcpShmOracle  # noqa: E402

PORT = int(os.environ.get("VALIDATE_PORT", "9851"))

# ── FTP 消息集 ─────────────────────────────────────────────────────
# 只放控制连接命令。刻意排除：
#   LIST/RETR/STOR/NLST  要 PASV/PORT 数据连接，会挂住或回 425，污染测量
#   QUIT                 关连接，一条会话就断了
#   AUTH/TLS             会把连接升成 TLS，后续测量全乱
# 覆盖 RFC 959 的四类：无前置（NOOP/HELP/SYST）、认证（USER/PASS）、
# 登录态命令（PWD/CWD/TYPE/SIZE）、数据连接前置（PASV）。
MSGS = {
    "USER": b"USER admin\r\n",
    "PASS": b"PASS 123456\r\n",
    "PWD": b"PWD\r\n",
    "CWD": b"CWD /\r\n",
    "NOOP": b"NOOP\r\n",
    "HELP": b"HELP\r\n",
    "TYPE": b"TYPE I\r\n",
    "SYST": b"SYST\r\n",
    "PASV": b"PASV\r\n",
    "SIZE": b"SIZE readme.txt\r\n",
}

# ── 会话场景：打乱连续性假设 ───────────────────────────────────────
# 每个场景给消息名序列。真值【不由这里给】，由真实响应码测出来。
SCENARIOS = [
    ("S1 前置连续在开头",
     ["USER", "PASS", "PWD", "CWD", "NOOP"]),
    ("S2 无前置消息排在最前",
     ["NOOP", "USER", "PASS", "PWD", "CWD"]),
    ("S3 前置被噪声隔开",
     ["USER", "NOOP", "PASS", "PWD", "CWD"]),
    ("S4 认证前置 + PASV 前置两组",
     ["USER", "PASS", "PASV", "SIZE", "PWD"]),
    ("S5 前置之后跟多条无前置噪声",
     ["USER", "PASS", "NOOP", "HELP", "PWD"]),
    ("S6 长会话（N=8）",
     ["NOOP", "USER", "SYST", "PASS", "HELP", "PWD", "TYPE", "CWD"]),
]


# ── 真值：响应码依赖 ───────────────────────────────────────────────

def measure(oracle: TcpShmOracle, seq: list[int], msgs: list[bytes],
            repeats: int = 3):
    """跑一条会话测真值，返回 {msg_idx: (cov, code)}。

    repeats 条独立会话取多数票（审查 L4：真值单次测量时，一次抖动抖错一个
    响应码，就凭空造出/抹掉一条依赖边 —— 真值必须 2-3 次测得一致才算数）。
    """
    blobs = [msgs[i] for i in seq]
    rows = oracle.run_sequence_with_replies(blobs, repeats=repeats)
    out = {}
    for pos, idx in enumerate(seq):
        cov, reply = rows[pos]
        out[idx] = (cov, TcpShmOracle.response_code(reply))
    return out


def ground_truth_deps(oracle, msgs, n, verbose=False):
    """i 是 j 的前置 ⟺ 去掉 i 后 j 的响应码变了。

    只看 j > i：前面的消息不可能依赖后面的。
    """
    all_idx = list(range(n))
    base = measure(oracle, all_idx, msgs)
    deps: dict[int, set] = {i: set() for i in all_idx}

    for x in all_idx:
        left = [i for i in all_idx if i != x]
        cur = measure(oracle, left, msgs)
        for y in left:
            if y <= x:
                continue
            c0 = base[y][1]
            c1 = cur[y][1]
            if c0 != c1:
                deps[x].add(y)
                if verbose:
                    print(f"    去掉 M{x}({msgs[x].strip()!r}) → "
                          f"M{y}({msgs[y].strip()!r}) 响应码 {c0}→{c1}")
    return deps, base


# ── 覆盖率侧的索引模拟器 ───────────────────────────────────────────

class OracleSim(SequenceSimulator):
    """把 TcpShmOracle 适配成算法要的按索引接口。

    注意语义：tcp_shm_oracle 返回的是【本条自身覆盖】（发送前清零 SHM），
    不是累计增量。二者在真实目标上判别力完全不同 —— 实测 LightFTP 的 PWD
    在登录/未登录下【增量覆盖相同】（差异边被前面消息点亮过了），自身覆盖
    才不同。算法问的「移除 Mx 后 My 还能不能达到同样覆盖」需要后者。
    """

    def __init__(self, oracle: TcpShmOracle, msgs: list[bytes]) -> None:
        self._oracle = oracle
        self._msgs = msgs

    def _runner(self, idx):
        return self._oracle.run_sequence([self._msgs[i] for i in idx])

    def _blob_runner(self, idx, seen=()):
        """idx 拼成一包发出的总覆盖率。

        seen 是此前已逐条重放、状态已经建起来的消息（前缀）。有它就必须
        在【同一条会话】里接着发拼包（run_blob_after），不能另开新会话 ——
        否则剩余消息被当成全新会话的第一条，全走失败路径。
        """
        blob = b"".join(self._msgs[i] for i in idx)
        if not seen:
            return self._oracle.run_single(blob)
        return self._oracle.run_blob_after(
            [self._msgs[i] for i in seen], blob)


def score(got, truth):
    tp = set(got) & set(truth)
    prec = len(tp) / len(got) if got else (1.0 if not truth else 0.0)
    rec = len(tp) / len(truth) if truth else 1.0
    return prec, rec


# ── 主流程 ─────────────────────────────────────────────────────────

# δ 扫描取值：从远低于实测地板一直到远高于最弱真信号。
# 全对区间有多宽，就是结论有多稳 —— 上界由最弱真信号决定，下界由噪声地板决定。
# 2026-10-29 修掉跨会话污染后实测：噪声地板 0.000，真信号 0.200~0.571，
# 非依赖精确 0.000，全对区间 δ ∈ [0.02, 0.16]。
DELTA_SWEEP = [0.02, 0.05, 0.08, 0.10, 0.13, 0.16, 0.25, 0.40]


def run():
    import argparse
    ap = argparse.ArgumentParser(
        description="会话前缀重建 —— 真机 ground truth 校验（LightFTP）")
    ap.add_argument("--delta-sweep", action="store_true",
                    help="额外跑 δ 敏感性扫描，证明结论不靠手调 δ")
    ap.add_argument("--sweep-repeats", type=int, default=3,
                    help="δ 扫描里每组实验的重复次数（省时间，默认 3）")
    args = ap.parse_args()

    launcher = os.path.join(HERE, "targets", "lightftp.sh")
    fftp = os.path.join(HERE, "third_party", "lightftp", "fftp")
    if not os.access(fftp, os.X_OK):
        print(f"[!] fftp 不存在/不可执行: {fftp}", file=sys.stderr)
        return 2

    print("=" * 78)
    print("会话前缀重建 —— 真机 ground truth 校验（LightFTP）")
    print("=" * 78)
    print(f"  靶机      : {fftp}")
    print(f"  真值来源  : 真实响应码（RFC 959），与覆盖率完全独立")
    print(f"  算法信号  : 覆盖率（__AFL_SHM_ID 零侵入采集）")

    results = []
    sweep_rows = []
    with TcpShmOracle([launcher, str(PORT)], port=PORT,
                      banner_lines=1, settle=0.02,
                      start_timeout=6.0) as oracle:
        # ── 0. 先把响应码基线打出来，确认真的连上了、登录真的成了 ──
        print(f"\n{'─' * 78}\n[0] 响应码基线（确认靶机行为符合 RFC 959）")
        for name in ("USER", "PASS", "PWD", "NOOP", "SYST", "PASV"):
            rows = oracle.run_sequence_with_replies([MSGS[name]])
            code = TcpShmOracle.response_code(rows[0][1])
            print(f"    单发 {MSGS[name].strip()!r:28s} → {code or '(无应答)'}")

        rows = oracle.run_sequence_with_replies(
            [MSGS["USER"], MSGS["PASS"], MSGS["PWD"]])
        codes = [TcpShmOracle.response_code(r[1]) for r in rows]
        print(f"    USER/PASS/PWD 连发        → {codes}")
        if codes != ["331", "230", "257"] and codes[:2] != ["331", "230"]:
            print(f"    [警告] 登录链响应码不是 331/230/257，"
                  f"真值要按实际码重新解读，别照搬 RFC")

        # ── 1. 逐场景 ────────────────────────────────────────────
        for name, seq_names in SCENARIOS:
            msgs = [MSGS[k] for k in seq_names]
            n = len(msgs)
            print(f"\n{'─' * 78}\n[{name}]")
            print(f"  消息序列 : {seq_names}")

            deps, base = ground_truth_deps(oracle, msgs, n)
            truth = sorted({i for i, ds in deps.items() if ds})
            dep_str = {i: sorted(d) for i, d in deps.items() if d}
            print(f"  真值依赖 : {dep_str}")
            print(f"  真值前置 : {truth}  →  {[seq_names[i] for i in truth]}")
            print(f"  各条响应 : {[base[i][1] for i in range(n)]}")

            sim = OracleSim(oracle, msgs)
            delta, floor = calibrate_delta(sim, n, repeats=5, verbose=False)

            # Algorithm 2
            a2 = identify_prefix_messages(sim, n=n, tau=1, delta=delta,
                                          verbose=False).prefix_msgs
            p2, r2 = score(a2, truth)

            # 会话前缀重建
            res = rebuild_session_prefix(sim, n, delta=delta, repeats=5,
                                         verbose=False)
            got = res.prerequisite_set
            pr, rr = score(got, truth)

            print(f"  δ 校准   : δ={delta:.4f}  噪声地板(零分布 max)={floor:.4f}")
            print(f"  Algorithm 2   → {a2}  {[seq_names[i] for i in a2]}  "
                  f"P={p2:.2f} R={r2:.2f}  "
                  f"{'OK' if set(a2) == set(truth) else 'MISMATCH'}")
            print(f"  会话前缀重建  → {got}  {[seq_names[i] for i in got]}  "
                  f"P={pr:.2f} R={rr:.2f}  "
                  f"{'OK' if set(got) == set(truth) else 'MISMATCH'}")

            # 依赖边级 P/R（审查 L3）：比「前置集合」更细 —— 集合对了
            # 不代表边对（x→y 的指向错了集合仍可能对）。
            true_edges = {(x, y) for x, ys in deps.items() for y in ys}
            pred_edges = {(x, y) for x, ys in res.deps.items() for y in ys}
            ep, er = score(pred_edges, true_edges)
            print(f"  边级 P/R   : 预测边={sorted(pred_edges)}  "
                  f"真值边={sorted(true_edges)}  P={ep:.2f} R={er:.2f}")

            # 信号 vs 阈值：漏检时看这里，区分「阈值压过信号」与「信号弱」
            print(f"  实测信号 : ", end="")
            pairs = [(f"{seq_names[x]}→{seq_names[y]}", res.signals.get((x, y), 0.0))
                     for x in range(n) for y in range(n) if y > x]
            for lbl, d in pairs:
                mark = "依赖" if d > delta else "·"
                print(f"{lbl}={d:.3f}{mark}", end="  ")
            print()

            # 依赖 / 非依赖的信号分离度。δ 的可选区间就夹在这两个数之间：
            #   下界 = 噪声地板（比它小的差异视为抖动）
            #   上界 = 最弱真信号（比它大的 δ 会把真依赖压掉）
            # 分离度越宽，结论越不依赖 δ 取值。
            dep_vals = [d for (x, y), d in res.signals.items()
                        if y > x and y in deps.get(x, ())]
            non_vals = [d for (x, y), d in res.signals.items()
                        if y > x and y not in deps.get(x, ())]
            sig_lo = min(dep_vals) if dep_vals else float("nan")
            sig_hi = max(non_vals, default=0.0)
            print(f"  信号分离 : 最弱真依赖={sig_lo:.3f}  "
                  f"最强非依赖={sig_hi:.3f}  "
                  f"（δ 必须落在二者之间才有判别力）")

            # ── B 段：每个目标命令的 1-最小保序前置序列 ──
            probes = per_target_probes(oracle, msgs, seq_names)
            b_ok = 0
            for tgt in seq_names:
                info = probes[tgt]
                try:
                    seq = minimize_reaching_sequence(info["probe"], info["cand"])
                except Exception as e:
                    print(f"    目标 {tgt:5s} 异常 {e}")
                    continue
                ok = set(seq) == set(info["truth"])
                b_ok += ok
                print(f"    目标 {tgt:5s} 前置={seq} "
                      f"{[seq_names[i] for i in seq]}  "
                      f"RFC真值={info['truth']}  "
                      f"{'OK' if ok else 'MISMATCH'}")

            # ── δ 敏感性扫描（可选）────────────────────────────────
            # 「δ 是不是手调出来的」是这类算法的第一个审稿质疑。这里把 δ
            # 强制钉在一串值上重跑 A 段，看命中数怎么变：结论稳的区间越宽，
            # 越说明 δ 是被测量带出来的，不是被调出来的。
            if args.delta_sweep:
                row = []
                for d in DELTA_SWEEP:
                    rr2 = rebuild_session_prefix(
                        sim, n, delta=d, repeats=args.sweep_repeats)
                    row.append((d, set(rr2.prerequisite_set) == set(truth),
                                rr2.prerequisite_set))
                sweep_rows.append((name, row))
                print("  δ 扫描   : " + "  ".join(
                    f"{d:.2f}={'对' if ok else '错'}" for d, ok, _ in row))

            results.append({
                "name": name, "truth": truth, "a2": a2, "rebuild": got,
                "p2": p2, "r2": r2, "pr": pr, "rr": rr,
                "ep": ep, "er": er,
                "b_ok": b_ok, "b_n": len(seq_names),
                "sig_lo": sig_lo, "sig_hi": sig_hi,
            })

    # ── 汇总 ──────────────────────────────────────────────────────
    print(f"\n{'=' * 78}\n汇总（真值 = 真实响应码依赖 / RFC 959）")
    print(f"  {'场景':30s} {'真值':12s} {'A2':12s} {'重建':12s} "
          f"{'A2 P/R':>11s} {'重建 P/R':>11s}  B段")
    print("  " + "-" * 78)
    for r in results:
        print(f"  {r['name']:30s} {str(r['truth']):12s} "
              f"{str(r['a2']):12s} {str(r['rebuild']):12s} "
              f"{r['p2']:5.2f}/{r['r2']:<5.2f} {r['pr']:5.2f}/{r['rr']:<5.2f}  "
              f"{r['b_ok']}/{r['b_n']}")
    print("  " + "-" * 78)
    ok2 = sum(1 for r in results if set(r["a2"]) == set(r["truth"]))
    okr = sum(1 for r in results if set(r["rebuild"]) == set(r["truth"]))
    b_ok = sum(r["b_ok"] for r in results)
    b_n = sum(r["b_n"] for r in results)
    print(f"  A段完全命中:  Algorithm 2 = {ok2}/{len(results)}   "
          f"会话前缀重建 = {okr}/{len(results)}")
    print(f"  B段(每目标命令 1-最小保序前置)命中:  {b_ok}/{b_n}")
    mp2 = sum(r["p2"] for r in results) / len(results)
    mr2 = sum(r["r2"] for r in results) / len(results)
    mpr = sum(r["pr"] for r in results) / len(results)
    mrr = sum(r["rr"] for r in results) / len(results)
    print(f"  平均      : Algorithm 2 P={mp2:.2f} R={mr2:.2f}   "
          f"会话前缀重建 P={mpr:.2f} R={mrr:.2f}")
    # 边级平均：Algorithm 2 只产出切点不产出依赖图，边级只有重建可比
    mep = sum(r["ep"] for r in results) / len(results)
    mer = sum(r["er"] for r in results) / len(results)
    print(f"  边级平均  : 会话前缀重建 P={mep:.2f} R={mer:.2f}"
          f"（依赖边 x→y，比前置集合更细的口径）")

    # ── δ 敏感性汇总 ──────────────────────────────────────────────
    if sweep_rows:
        print(f"\n{'=' * 78}\nδ 敏感性扫描（每个 δ 独立重跑 A 段，真值不变）")
        print(f"  {'场景':30s} " +
              " ".join(f"{d:>6.2f}" for d in DELTA_SWEEP))
        print("  " + "-" * (30 + 7 * len(DELTA_SWEEP)))
        for name, row in sweep_rows:
            print(f"  {name:30s} " +
                  " ".join(f"{'✔' if ok else '✘':>6s}" for _, ok, _ in row))
        print("  " + "-" * (30 + 7 * len(DELTA_SWEEP)))
        hit = [sum(1 for _, row in sweep_rows if row[k][1])
               for k in range(len(DELTA_SWEEP))]
        print(f"  {'命中场景数':30s} " +
              " ".join(f"{h:>6d}" for h in hit))
        ok_band = [d for k, d in enumerate(DELTA_SWEEP)
                   if hit[k] == len(sweep_rows)]
        if ok_band:
            los = [r["sig_lo"] for r in results if r["sig_lo"] == r["sig_lo"]]
            hi = max((r["sig_hi"] for r in results), default=0.0)
            lo = min(los) if los else float("nan")
            print(f"\n  全对区间 δ ∈ [{min(ok_band):.2f}, {max(ok_band):.2f}]")
            print(f"    实测信号分离度：最强非依赖 {hi:.3f} < δ < 最弱真依赖 {lo:.3f}")
            print(f"    → 可选区间宽 {lo - hi:.3f}，"
                  + ("结论不靠 δ 取值" if lo - hi > 0.05
                     else "区间偏窄，δ 仍敏感，要重新审"))
        else:
            print("\n  没有任何一个 δ 能全对 —— 说明结论依赖 δ 取值，要重新审")
    return 0 if okr == len(results) and b_ok == b_n else 1


# 每条命令「成功」时的响应码（RFC 959 + LightFTP 基线实测）
SUCCESS_CODES = {
    "USER": {"331"},      # 要密码
    "PASS": {"230"},      # 登录成功
    "PWD":  {"257"},      # 回目录
    "CWD":  {"250"},      # 改目录成功
    "NOOP": {"200"},
    "HELP": {"214", "211"},
    "TYPE": {"200"},
    "SYST": {"215"},
    "PASV": {"227"},
    "SIZE": {"213"},
}

# RFC 959 下每条命令的前置（真值，与算法无关，可拿 RFC 核对）
RFC_PREREQ = {
    "USER": (),
    "PASS": ("USER",),
    "PWD":  ("USER", "PASS"),
    "CWD":  ("USER", "PASS"),
    "NOOP": (),
    "HELP": (),
    "TYPE": ("USER", "PASS"),
    "SYST": (),
    "PASV": ("USER", "PASS"),
    "SIZE": ("USER", "PASS"),
}


def per_target_probes(oracle, msgs, seq_names):
    """B 段的正确形态：每个【目标命令】一套最短前置序列。

    为什么不是几个手写状态：SandboxFuzzer 的 PREFIX_FILE 是给"某一批种子"
    用的，而种子是按它们要打的命令分组的。真正要回答的问题是
    「想让命令 X 成功，至少要先发哪几条」。

    探针语义与 sandbox_harness.c 的 PROBE_CMD 一致：发完候选前置后
    【追加目标命令本身】，看它的响应码是否落在成功码集合里。
    候选集必须排除目标自身 —— 否则目标已经跑过一遍，再探就不是
    「能不能成功」而是「再跑一次会怎样」（PASS 第二次回 503）。
    """
    out = {}
    pos = {k: i for i, k in enumerate(seq_names)}
    for name, idx in pos.items():
        cand = [i for i in range(len(msgs)) if i != idx]
        want = SUCCESS_CODES.get(name, set())
        truth = sorted(pos[p] for p in RFC_PREREQ.get(name, ()) if p in pos)

        def probe(idx_list, _cmd=msgs[idx], _want=want):
            rows = oracle.run_sequence_with_replies(
                [msgs[i] for i in idx_list] + [_cmd])
            code = TcpShmOracle.response_code(rows[-1][1]) if rows else ""
            return code in _want

        out[name] = {"idx": idx, "cand": cand, "probe": probe, "truth": truth}
    return out


if __name__ == "__main__":
    raise SystemExit(run())
