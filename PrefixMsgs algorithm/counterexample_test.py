#!/usr/bin/env python3
"""
counterexample_test.py —— 对 Algorithm 2 的前缀识别做 ground truth 校验

self_test() 是循环论证：它把"M0 是前缀"硬编码进模拟器，再去验证算法找到 M0。
这只能证明"实现与伪代码一致"，不能证明"算法在真实协议上是对的"。

本脚本构造若干**已知真值**的协议会话场景，逐个跑算法，比对它返回的
前缀集合与人工标注的前置消息集合，报 precision / recall。

真值依据 RFC 959 (FTP) 语义：
  USER        无前置（未登录态可发）
  PASS        前置 = {USER}          否则 503 Login with USER first
  PWD/CWD/... 前置 = {USER, PASS}    否则 530 not logged in
  PASV/PORT   前置 = {USER, PASS}
  LIST/RETR   前置 = {USER, PASS, PASV}  （还要数据连接）
  NOOP/HELP   无前置，任何状态都应答 200   ← 论文 τ 的来源
  QUIT        无前置，但终止会话

覆盖率模型（比"全新边集合"更贴近真实插桩）：
  每条命令处理都必过公共边 COMMON（命令分派 / 应答写出），
  成功路径再走 own[i]，失败路径再走 err[i]。
  → 成功 vs 失败 的 DIFF = 80/110 ≈ 0.73，不是 1.0，δ 的取值会影响判定。
  → 单次覆盖率约 110 条边，1 条噪声边 ≈ 0.9%，与真实 afl-showmap 的噪声占比同阶。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from prefix_msg_identify import SequenceSimulator, identify_prefix_messages  # noqa: E402

Coverage = frozenset

# ── 覆盖率规模 ─────────────────────────────────────────────────────
# 真实 afl-showmap 一次执行踩到的是【上千条】边，噪声边只占千分之几。
# 早先每条消息只造 7 条边时，1 条噪声边就是 14%，δ 的阈值行为完全不可迁移。
# 这里按真实量级放大：公共边 + 每条路径各 40 条，单次覆盖约 110 条边，
# 1 条噪声边 ≈ 0.9%，与真实 SUT 的噪声占比同阶。
EDGE_COMMON = 30          # 公共边数（命令分派 / 应答写出）
EDGE_PER_PATH = 40        # 每条消息成功/失败路径各自的边数
BASE_ERR = 10000          # 失败路径边 ID 起点（与成功路径不相交）
BASE_OWN = 20000          # 成功路径边 ID 起点

COMMON = frozenset(range(1, EDGE_COMMON + 1))


def make_scenario(name, msgs, prereq, desc, pipeline=False):
    """prereq: dict(msg_idx -> 必须先出现的 msg_idx 集合)；不在里面的 = 无前置。

    pipeline 决定 SUT 怎么处理「拼成一包」的多条消息（GETCOVERAGE(MsgsInOne)）：
      False（默认）  只解析第一条 —— LightFTP 的真实行为，2026-10-28 探针实测
                     send("USER a\\r\\nPASS b\\r\\n") 整包被当成一条命令，
                     第二条根本没执行。
      True           包内每条都解析，状态在包内逐条推进 —— 粘包友好的 SUT。
    两种语义都要能建模，拆包判定（NeedSplit/AllSplit）的结论正是由它决定的。
    """
    n = len(msgs)
    own = {i: frozenset(range(BASE_OWN + i * 100,
                              BASE_OWN + i * 100 + EDGE_PER_PATH))
           for i in range(n)}
    err = {i: frozenset(range(BASE_ERR + i * 100,
                              BASE_ERR + i * 100 + EDGE_PER_PATH))
           for i in range(n)}

    def satisfied(keep, i):
        return prereq.get(i, set()).issubset(set(keep))

    def build(keep):
        """按 keep 顺序喂，返回每条的【增量】覆盖率。"""
        out, seen = [], set()
        for i in keep:
            base = COMMON | (own[i] if satisfied(seen, i) else err[i])
            seen.add(i)
            out.append(base)
        return out

    def blob(idx, seen=()):
        """把 idx 拼成一包发出的总覆盖率。

        seen = 此前已逐条重放、状态已经建立起来的消息（比如前缀）。
        拼包是【接着那段会话】发的，所以包内第一条的前置要用 seen 来判 ——
        早先这里写死 satisfied(set(), i)，等于把拼包当成发给全新会话，
        GETCOVERAGE(PrefixMsgs, LeftMsgsInOne) 的语义就错了。
        """
        if not idx:
            return frozenset()
        if not pipeline:
            i = idx[0]
            return COMMON | (own[i] if satisfied(set(seen), i) else err[i])
        out, st = set(), set(seen)
        for i in idx:                       # 粘包友好：包内每条都解析
            out |= COMMON | (own[i] if satisfied(st, i) else err[i])
            st.add(i)
        return frozenset(out)

    # ground truth：被任何消息依赖的消息 = 前置消息
    truth = sorted({p for needs in prereq.values() for p in needs})
    # 无前置消息 = 在任何状态下都能被处理（论文 τ 容忍的那类）
    unconditional = sorted(i for i in range(n) if i not in prereq)
    sim = SequenceSimulator(build, blob)
    # 拆包判定的解析真值要知道 SUT 的拼包语义，挂在模拟器上带出去
    sim.pipeline_flag = pipeline
    return name, desc, msgs, truth, unconditional, sim, n


SCENARIOS = [
    make_scenario(
        "S1 前置连续在开头（算法的舒适区）",
        msgs=["USER a", "PASS b", "PWD", "CWD /tmp", "NOOP"],
        prereq={1: {0}, 2: {0, 1}, 3: {0, 1}},
        desc="USER/PASS 紧挨着排最前，后面是登录态命令 + 一条 NOOP",
    ),
    make_scenario(
        "S2 无前置消息 NOOP 排在最前",
        msgs=["NOOP", "USER a", "PASS b", "PWD", "CWD /tmp"],
        prereq={2: {1}, 3: {1, 2}, 4: {1, 2}},
        desc="NOOP 无前置，却排在 USER/PASS 之前",
    ),
    make_scenario(
        "S3 前置消息被噪声隔开（非连续）",
        msgs=["USER a", "NOOP", "PASS b", "PWD", "CWD /tmp"],
        prereq={2: {0}, 3: {0, 2}, 4: {0, 2}},
        desc="USER 和 PASS 中间夹了一条 NOOP",
    ),
    make_scenario(
        "S4 两组互不相干的前置",
        msgs=["USER a", "PASS b", "PASV", "LIST", "PWD"],
        prereq={1: {0}, 2: {0, 1}, 3: {0, 1, 2}, 4: {0, 1}},
        desc="PASV 只是 LIST 的前置，不是 PWD 的前置",
    ),
    make_scenario(
        "S5 会话中段有重复命令（无前置噪声）",
        msgs=["USER a", "PASS b", "NOOP", "HELP", "PWD"],
        prereq={1: {0}, 4: {0, 1}},
        desc="NOOP/HELP 是无条件噪声，夹在前置之后",
    ),
]


# ── 拆包判定的判别性场景 ─────────────────────────────────────────
# S1~S5 的「剩余」（真值前缀之外的消息）都 ≥2 条。在只解析第一条的 SUT 上，
# 拼包必然丢后面的覆盖，NeedSplit/AllSplit 两个算法都回 True，比不出东西。
# 真正的判别面是【剩余只有 1 条】：那时「前缀逐条 + 剩余拼一包」里的拼包是
# 单条消息，等于没拆 —— AllSplit 必须是 False。
#
# 之所以能拿来区分两个算法：Algorithm 2 的前缀是 Msgs[0:x]【连续切点】，
# 切错时 left = Msgs[x:] 里会混进真正的前置消息（或把噪声当噪声多留几条），
# 那些消息在包内跑不到自己的前置，走失败路径，覆盖照样丢 → 误判 AllSplit=True。
# 会话前缀重建的前缀是依赖集合，left 是真值前缀的补集，不会多留前置消息。
#
# 这几张不进 SCENARIOS：那边比的是【前缀识别】（A2 1/5、重建 5/5），
# 这里比的是【拆包判定】，分子分母不该混在一起。
SCENARIOS_SPLIT = [
    make_scenario(
        "T1 剩余只有 1 条（真值前缀连续）",
        msgs=["USER a", "PASS b", "PWD"],
        prereq={1: {0}, 2: {0, 1}},
        desc="USER→PASS→PWD 链。真值前缀 = {USER,PASS}，剩余只有 PWD 一条，"
             "拆包是空操作 → AllSplit 必须 False",
        pipeline=False,
    ),
    make_scenario(
        "T2 同一条会话，粘包友好的 SUT",
        msgs=["USER a", "PASS b", "PWD"],
        prereq={1: {0}, 2: {0, 1}},
        desc="包内每条都解析（pipeline=True）→ 整包发不丢覆盖，"
             "NeedSplit 本身就该 False",
        pipeline=True,
    ),
    make_scenario(
        "T3 剩余 ≥2 条（S1~S5 那一类，两边恒真）",
        msgs=["USER a", "PASS b", "PWD", "CWD /tmp"],
        prereq={1: {0}, 2: {0, 1}, 3: {0, 1}},
        desc="真值前缀 = {USER,PASS}，剩 PWD/CWD 两条。只解析第一条的 SUT 上"
             "拼包必丢覆盖 → 两个算法都回 True，属于对照组",
        pipeline=False,
    ),
    make_scenario(
        "T4 剩余 ≥2 条，但 SUT 支持粘包",
        msgs=["USER a", "PASS b", "PWD", "CWD /tmp"],
        prereq={1: {0}, 2: {0, 1}, 3: {0, 1}},
        desc="pipeline=True → 整包发不丢覆盖，NeedSplit=False",
        pipeline=True,
    ),
    make_scenario(
        "T5 真值前缀非连续，剩余 ≥2 条",
        msgs=["USER a", "NOOP", "PASS b", "PWD", "CWD /tmp"],
        prereq={2: {0}, 3: {0, 2}, 4: {0, 2}},
        desc="真值前缀 = {USER,PASS}（位置 0,2），被 NOOP 隔开。剩余 3 条，"
             "两边都会回 True —— 拆包判定在这个类里【抓不到】A2 的切点错误，"
             "那要靠 A 段的 precision/recall",
        pipeline=False,
    ),
]


def split_ground_truth(truth_prefix, n, pipeline):
    """拆包判定的解析真值 —— 只看 SUT 的拼包语义和剩余条数，不跑覆盖率。

    真值是 SUT 的性质，不是算法的性质，所以不该由任何算法的输出来定：
        NeedSplit  整包发丢不丢覆盖
                   pipeline=True  包内每条都解析 → 不丢 → False
                   pipeline=False 只解析第一条 → 后面 n-1 条的边全丢
                                  → n>=2 时 True
        AllSplit   拆完之后「前缀逐条 + 剩余拼一包」还丢不丢
                   pipeline=True  → False
                   pipeline=False 剩余 m 条只跑第一条，m>=2 才丢覆盖
                                  （m=1 时拼包就是单条，是空操作）
    """
    m = n - len(set(truth_prefix))
    if pipeline:
        return False, False
    return n >= 2, m >= 2


def score(got, truth):
    tp = set(got) & set(truth)
    prec = len(tp) / len(got) if got else (1.0 if not truth else 0.0)
    rec = len(tp) / len(truth) if truth else 1.0
    return prec, rec


def run():
    print("=" * 78)
    print("Algorithm 2 前缀识别 —— ground truth 校验（RFC 959 语义）")
    print("=" * 78)

    rows = []
    for name, desc, msgs, truth, unconditional, sim, n in SCENARIOS:
        print(f"\n{'─' * 78}\n【{name}】\n  {desc}")
        print(f"  消息序列 : {msgs}")
        print(f"  真值前置 : {truth}   无前置消息: {unconditional}")
        try:
            res = identify_prefix_messages(sim, n=n, tau=1, delta=0.05, verbose=False)
            got = res.prefix_msgs
            extra = f"cut_at={res.cut_at}"
        except Exception as e:
            got, extra = [], f"异常 {type(e).__name__}: {e}"
        prec, rec = score(got, truth)
        verdict = "OK" if set(got) == set(truth) else "MISMATCH"
        print(f"  算法输出 : PrefixMsgs = {got}   {extra}")
        print(f"  precision = {prec:.2f}   recall = {rec:.2f}   → {verdict}")
        rows.append((name, got, truth, prec, rec, verdict))

    print(f"\n{'=' * 78}")
    print(f"{'场景':46s} {'算法输出':12s} {'真值':10s} {'P':>5s} {'R':>5s}  判定")
    print("-" * 78)
    for name, got, truth, prec, rec, verdict in rows:
        print(f"{name:46s} {str(got):12s} {str(truth):10s} {prec:5.2f} {rec:5.2f}  {verdict}")
    print("-" * 78)
    print(f"通过 {sum(1 for r in rows if r[5] == 'OK')}/{len(rows)}")

    # ── 参数敏感性（只看 S1，算法的舒适区）─────────────────────────
    name, desc, msgs, truth, unconditional, sim, n = SCENARIOS[0]
    print(f"\n{'=' * 78}\n参数敏感性（S1，真值 {truth}）")
    print("  tau  delta   PrefixMsgs          判定")
    for tau in (0, 1, 2, 3):
        for delta in (0.0, 0.05, 0.3, 0.8):
            try:
                res = identify_prefix_messages(sim, n=n, tau=tau, delta=delta, verbose=False)
                got = res.prefix_msgs
                mark = "OK" if set(got) == set(truth) else "MISMATCH"
            except Exception as e:
                got, mark = [], f"异常 {e}"
            print(f"  {tau:<4} {delta:<6} {str(got):20s} {mark}")


def run_split_comparison():
    """拆包判定对比段。

    真值**不复用算法自己的前缀**，分两步独立定：
      1. 解析真值 —— 按 SUT 的拼包语义 + 剩余条数直接算（split_ground_truth）；
      2. 交叉核对 —— 把【真值前缀】喂给 detect_split，看它是否也这么说。
    两步对上了，才说明覆盖率法的拆包判定可以拿解析真值当标尺，然后才比
    Algorithm 2 与会话前缀重建各自的判定。任何一步对不上，那条记 NO-TRUTH，
    不算进通过率 —— 否则等于拿算法自己的答案给自己打分。
    """
    from perstate_prefix import detect_split, rebuild_session_prefix

    print(f"\n{'=' * 78}")
    print("拆包判定（NeedSplit / AllSplit）—— ground truth 校验")
    print("  真值 = 拼包语义 + 剩余条数（解析），再用真值前缀跑 detect_split 交叉核对")
    print(f"{'=' * 78}")

    rows = []
    for name, desc, msgs, truth, uncond, sim, n in SCENARIOS_SPLIT:
        pipeline = getattr(sim, "pipeline_flag", None)
        print(f"\n{'─' * 78}\n【{name}】\n  {desc}")
        print(f"  消息序列 : {msgs}")
        print(f"  真值前置 : {truth}   剩余 {n - len(truth)} 条")

        # 1) 解析真值
        t_need, t_all = split_ground_truth(truth, n, pipeline)

        # 2) 交叉核对：真值前缀喂给 detect_split（不是算法自己的前缀）
        base = sim.run_sequence_idx(list(range(n)))
        c_need, c_all = detect_split(sim, n, base, list(truth), delta=0.05)
        cross_ok = (c_need, c_all) == (t_need, t_all)

        # Algorithm 2（前缀 = Msgs[0:x] 连续切点）
        try:
            a2 = identify_prefix_messages(sim, n=n, tau=1, delta=0.05,
                                          verbose=False)
            a2_pref, a2_v = a2.prefix_msgs, (a2.need_split, a2.all_split)
        except Exception as e:
            a2_pref, a2_v = [], f"异常 {type(e).__name__}: {e}"

        # 会话前缀重建（前缀 = 依赖集合）
        try:
            rs = rebuild_session_prefix(sim, n, delta=0.05, verbose=False)
            rs_pref, rs_v = rs.prerequisite_set, (rs.need_split, rs.all_split)
        except Exception as e:
            rs_pref, rs_v = [], f"异常 {type(e).__name__}: {e}"

        print(f"  解析真值 : NeedSplit={t_need}  AllSplit={t_all}"
              f"   （剩余 {n - len(truth)} 条, "
              f"pipeline={'是' if pipeline else '否'}）")
        print(f"  交叉核对 : 真值前缀→detect_split = "
              f"({c_need}, {c_all})  → {'一致' if cross_ok else '不一致'}")
        print(f"  Algo 2   : 前缀={a2_pref}  判定={a2_v}")
        print(f"  会话重建 : 前缀={rs_pref}  判定={rs_v}")

        def mark(v):
            return "?" if not cross_ok else ("OK" if v == (t_need, t_all) else "MISMATCH")

        a2_m, rs_m = mark(a2_v), mark(rs_v)
        print(f"  → Algo2 {a2_m}   会话重建 {rs_m}")
        rows.append((name, pipeline, n - len(truth),
                     (t_need, t_all), a2_pref, a2_v, a2_m,
                     rs_pref, rs_v, rs_m))

    print(f"\n{'=' * 78}")
    print(f"{'场景':40s} {'剩余':4s} {'真值':12s} {'Algo2判定':12s} {'':9s} "
          f"{'重建判定':12s} {'':9s}")
    print("-" * 78)
    for (name, pipeline, m, t, ap, av, am, rp, rv, rm) in rows:
        print(f"{name:40s} {m:<4} {str(t):12s} {str(av):12s} {am:9s} "
              f"{str(rv):12s} {rm:9s}")
    print("-" * 78)

    scored = [r for r in rows if r[6] != "?" and r[9] != "?"]
    a2_ok = sum(1 for r in scored if r[6] == "OK")
    rs_ok = sum(1 for r in scored if r[9] == "OK")
    print(f"  解析真值与交叉核对一致的场景: {len(scored)}/{len(rows)}")
    print(f"  Algo 2     判定对 {a2_ok}/{len(scored)}")
    print(f"  会话前缀重建 判定对 {rs_ok}/{len(scored)}")
    if scored and rs_ok == len(scored) and a2_ok < len(scored):
        bad = [r[0] for r in scored if r[6] != "OK"]
        print(f"\n  → 拆包判定上 Algorithm 2 判错的是: {bad}")
        print("    （前缀是连续切点，left 里多留了真正的前置消息）")
    return 0 if scored and rs_ok == len(scored) else 1


if __name__ == "__main__":
    run()
    raise SystemExit(run_split_comparison())
