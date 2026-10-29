#!/usr/bin/env python3
"""
derive_prefix.py — 给真靶机推导前缀消息与状态种子（会话前缀重建 + 沙箱侧对接）

把 `PrefixMsgs algorithm/perstate_prefix.py` 的**会话前缀重建**接到真靶机上：
  1. 用 __AFL_SHM_ID 零侵入注入，采【同一条 TCP 会话里逐条消息】的自身覆盖率
     （每条发送前清零 SHM —— 增量覆盖会把状态差异边去重掉，见 tcp_shm_oracle）
  2. A 段建依赖矩阵：逐条移除，看谁的覆盖率掉。产出是【集合】不是切点，
     所以前缀不必是会话的前段连续子表（HSPFuzzer 算法 2 的假设，实测证伪）
  3. B 段按【目标命令】求最短保序前置序列，导出成沙箱侧认的格式：
         prefix_analyzer_output/<state>/prefix.raw   到达该状态的前缀串
         prefix_analyzer_output/<state>/seeds/*.raw  该状态下的变异起点
     一个状态 = 一个目标命令。对 [NOOP, USER, SYST, PASS, HELP, PWD]，
     PWD 状态的 prefix.raw 是 USER+PASS（位置 1,3），不是任何 msgs[:k]。

δ 自动测噪声地板校准（中位数），不要手拍 —— 手拍 0.05 在真机上会把
PASS→PWD 这类弱信号压掉。可用 --delta 强制覆盖（不推荐）。

用法:
  # LightFTP（真第三方 FTP 服务器，源码零改动）
  python3 derive_prefix.py --profile ftp \
      --target-cmd "third_party/lightftp/fftp third_party/lightftp/Source/fftp.conf" \
      --launcher targets/lightftp.sh --port 9851 --banner-lines 1 \
      --prefix-name admin_ftp

  # 或自定义消息序列（每行一条，\\r\\n 之类的转义会被解码）
  python3 derive_prefix.py --msgs my_session.txt --target-cmd ...
"""

from __future__ import annotations

import argparse
import os
import shlex
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALGO_DIR = os.environ.get("SBF_ALGO_DIR") or os.path.join(
    os.path.dirname(HERE), "PrefixMsgs algorithm")
sys.path.insert(0, ALGO_DIR)

from prefix_msg_identify import SequenceSimulator  # noqa: E402
from perstate_prefix import (  # noqa: E402
    calibrate_delta,
    minimize_reaching_sequence,
    rebuild_session_prefix,
)
from tcp_shm_oracle import TcpShmOracle  # noqa: E402

# ─────────────────────────────────────────────────────────────────────────
# 内置消息序列（协议模板）
#
# FTP 会话模板：USER / PASS 是状态推演的关键，后面是各状态下都能打的普通命令。
# 算法 2 会自己判断哪些是前缀，这里只是把"典型会话"摆出来。
#
# 两条刻意的约束：
#   ① 不放 LIST/RETR/STOR —— 它们要 PASV 数据连接，会拖着不回或回 425，
#      污染增量覆盖率测量。要用请自己给 --msgs 并把 PASV/EPSV 一起放进去。
#   ② 不放 QUIT —— 它会关连接，且按 HSPFuzzer 的约定种子阶段要剔除 quit 类
#      消息，否则连接复用被打断。
# ─────────────────────────────────────────────────────────────────────────
PROFILES: dict[str, list[str]] = {
    "ftp": [
        "USER admin\r\n",
        "PASS 123456\r\n",
        "PWD\r\n",
        "CWD /\r\n",
        "NOOP\r\n",
        "TYPE I\r\n",
    ],
}


def load_msgs(args) -> list[bytes]:
    if args.msgs:
        out = []
        with open(args.msgs, "r", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                out.append(line.encode().decode("unicode_escape").encode("latin-1"))
        return out
    if args.profile:
        return [m.encode() for m in PROFILES[args.profile]]
    raise SystemExit("需要 --profile 或 --msgs")


class IndexSim(SequenceSimulator):
    """把 TcpShmOracle 的字节接口适配成算法要的索引接口。

    SequenceSimulator 本来就是收两个闭包的（`runner` / `blob_runner`），
    这里把「索引 → 字节」的映射绑在闭包里，算法主体一行不用改。
    """

    def __init__(self, oracle: TcpShmOracle, msgs: list[bytes]) -> None:
        def blob_runner(idx, seen=()):
            """idx 拼成一包的总覆盖率；seen 非空时接着它的状态发。

            seen 是已逐条重放过的前缀。有它就必须同会话接着发拼包
            （run_blob_after），另开新会话等于把剩余消息当成新会话第一条。
            """
            blob = b"".join(msgs[i] for i in idx)
            if not seen:
                return oracle.run_single(blob)
            return oracle.run_blob_after([msgs[i] for i in seen], blob)

        super().__init__(
            runner=lambda idx: oracle.run_sequence([msgs[i] for i in idx]),
            blob_runner=blob_runner,
        )


def main() -> int:
    ap = argparse.ArgumentParser(description="算法 2 推导真靶机的前缀消息与状态种子")
    ap.add_argument("--profile", choices=sorted(PROFILES), help="内置消息序列模板")
    ap.add_argument("--msgs", help="自定义消息序列文件（每行一条）")
    ap.add_argument("--target-cmd", default=None,
                    help="目标启动命令行；给了 --launcher 时可省（端口从配置文件来的目标）")
    ap.add_argument("--launcher", help="启动器脚本（端口从配置文件来的目标用）")
    ap.add_argument("--port", type=int, default=9851)
    ap.add_argument("--banner-lines", type=int, default=0)
    ap.add_argument("--delta", type=float, default=None,
                    help="覆盖率差异阈值；缺省自动测噪声地板校准（推荐）")
    ap.add_argument("--repeats", type=int, default=5,
                    help="每组实验重复次数，取中位数压噪声（缺省 5）")
    ap.add_argument("--prefix-name", default="derived",
                    help="导出目录前缀，如 admin_ftp → admin_ftp_state_2_pwd")
    ap.add_argument("-o", "--out-root", default="prefix_analyzer_output")
    ap.add_argument("--dry-run", action="store_true", help="只跑算法，不导出")
    args = ap.parse_args()

    msgs = load_msgs(args)
    print(f"[*] 消息序列 N={len(msgs)}")
    for i, m in enumerate(msgs):
        print(f"    M{i}: {m!r}")

    # 目标命令：需要启动器（端口从配置文件来）就用它
    if args.launcher:
        cmd = [os.path.join(HERE, args.launcher), str(args.port)]
    elif args.target_cmd:
        cmd = shlex.split(args.target_cmd)
    else:
        raise SystemExit("需要 --target-cmd 或 --launcher 之一")

    oracle = TcpShmOracle(
        cmd, port=args.port,
        banner_lines=args.banner_lines,
        shm_size=65536,
    )

    print(f"\n[*] 启动目标采集覆盖率: {' '.join(cmd)}")
    oracle.start()
    rfc = rfc_prereq_names()
    n = len(msgs)
    reached: list[tuple[int, str, list[int]]] = []   # (j, label, reaching)
    try:
        # 先打一遍全序列，看每条到底触发多少边
        base = oracle.run_sequence(msgs)
        print("[*] 基准自身覆盖（每条消息处理时点亮的边数）:")
        for i, c in enumerate(base):
            print(f"    M{i} {msgs[i]!r:28} → {len(c):4d} 边")

        sim = IndexSim(oracle, msgs)
        delta, floor = (calibrate_delta(sim, n, repeats=args.repeats)
                        if args.delta is None else (args.delta, 0.0))
        res = rebuild_session_prefix(sim, n, delta=delta, repeats=args.repeats,
                                     verbose=True)

        # ── 按【目标命令】求最短前置（必须在 oracle 存活时做完）───
        # 探针闭包引用 oracle，靶机一停就连不上了。
        print(f"\n[*] 逐目标命令求最短保序前置序列")
        for j in range(n):
            label = msg_label(msgs[j])
            cand = [i for i in range(n) if i != j]
            probe = _make_probe(oracle, msgs, j)
            try:
                reach = minimize_reaching_sequence(probe, cand)
            except ValueError:
                print(f"    [跳过] M{j} {label}: 在本序列里到不了成功态")
                continue
            reached.append((j, label, reach))
            want = sorted(rfc.get(label, ()))
            got = sorted(msg_label(msgs[i]) for i in reach)
            print(f"    目标 {label:5s} 前置={[msg_label(msgs[i]) for i in reach]}"
                  f"  RFC真值={want}  {'OK' if got == want else 'MISMATCH'}")
    finally:
        oracle.stop()

    print()
    print("[*] 会话前缀重建结果:")
    print(f"    δ 校准    : δ={res.delta_used:.4f}  噪声地板(中位)={res.noise_floor:.4f}")
    print(f"    依赖矩阵  : "
          f"{ {i: sorted(d) for i, d in res.deps.items() if d} }")
    print(f"    会话级前置: {res.prerequisite_set}  "
          f"→ {[msg_label(msgs[i]) for i in res.prerequisite_set]}")
    print(f"    NeedSplit : {res.need_split}   AllSplit: {res.all_split}")
    if res.signals:
        weak = sorted(res.signals.items(), key=lambda kv: kv[1])
        print(f"    最弱依赖信号: "
              f"{[(f'M{x}→M{y}', round(d, 3)) for (x, y), d in weak if d > res.delta_used][:4]}")

    if args.dry_run:
        return 0

    # ── 导出沙箱侧格式 ───────────────────────────────────────────
    # 旧导出用 prefix = b"".join(msgs[:k])，那是 HSPFuzzer 的"前段连续切点"
    # 思路：前缀必须是 msgs 的前缀子表。实测证伪 —— 对
    #     [NOOP, USER, SYST, PASS, HELP, PWD]
    # PWD 的正确前置是 USER+PASS（位置 1,3），任何 msgs[:k] 都给不对。
    #
    # SandboxFuzzer 的 PREFIX_FILE 语义是「发完它，靶机就在目标状态」，
    # 对应的正是【每个目标命令的最短保序前置序列】：
    #     prefix.raw = 到达该命令可成功的最短前置（不参与变异）
    #     seeds/     = 该状态下能打的消息（变异起点）
    # 一个状态 = 一个目标命令。命令名直接进目录名，不再需要 --state-names。
    print(f"\n[*] 按目标命令导出状态到 {args.out_root}/")

    exported = []
    for j, label, reach in reached:
        state = f"{args.prefix_name}_state_{j}_{label}"
        d = os.path.join(args.out_root, state)
        sd = os.path.join(d, "seeds")
        os.makedirs(sd, exist_ok=True)

        # 前缀 = 最短保序前置序列，按原会话顺序拼接
        prefix = b"".join(msgs[i] for i in reach)
        with open(os.path.join(d, "prefix.raw"), "wb") as f:
            f.write(prefix)
        # 目标命令的原始字节（带参数）。目录名只存了命令名，参数丢了 ——
        # 验收/回放必须发原始字节，发 "PWD\r\n" 这种重建命令会回 501。
        with open(os.path.join(d, "target.raw"), "wb") as f:
            f.write(msgs[j])

        # 种子 = 前置被满足后能打的消息（含目标自己，它正是最该 fuzz 的那条）
        have = {msg_label(msgs[k]) for k in reach}
        n_seed = 0
        for i in range(n):
            need = set(rfc.get(msg_label(msgs[i]), ()))
            if need <= have or i == j:
                with open(os.path.join(
                        sd, f"{args.prefix_name}_{j}_{n_seed + 1}.raw"), "wb") as f:
                    f.write(msgs[i])
                n_seed += 1

        ok = (sorted(msg_label(msgs[i]) for i in reach) ==
              sorted(rfc.get(label, ())))
        exported.append((state, label, reach, prefix, n_seed, ok))
        print(f"    {state}")
        print(f"        prefix.raw = {prefix!r}  ({len(prefix)}B, "
              f"{len(reach)} 条)  RFC真值={sorted(rfc.get(label, ()))} "
              f"{'OK' if ok else 'MISMATCH'}")
        print(f"        seeds/     = {n_seed} 个")

    meta = os.path.join(args.out_root, f"{args.prefix_name}_prefix_meta.txt")
    with open(meta, "w") as f:
        f.write(f"algorithm=session_prefix_rebuild\n")
        f.write(f"delta={res.delta_used}\n")
        f.write(f"noise_floor={res.noise_floor}\n")
        f.write(f"repeats={args.repeats}\n")
        f.write(f"prerequisite_set={res.prerequisite_set}\n")
        f.write(f"NeedSplit={res.need_split}\n")
        f.write(f"AllSplit={res.all_split}\n")
        f.write(f"N={n}\n")
        for i, m in enumerate(msgs):
            f.write(f"M{i}={m!r}\n")
        for state, label, reach, prefix, n_seed, ok in exported:
            f.write(f"state={state}\n")
            f.write(f"    target={label}\n")
            f.write(f"    reaching={reach}\n")
            f.write(f"    prefix={prefix!r}\n")
            f.write(f"    seeds={n_seed}\n")
    n_ok = sum(1 for e in exported if e[5])
    print(f"\n[*] 元信息写到 {meta}")
    print(f"[*] 导出 {len(exported)} 个状态，与 RFC 真值一致 {n_ok}/{len(exported)}")
    if exported:
        print(f"[*] 跑法:  ./run_state_node.sh {exported[0][0]} 2 300")
    return 0 if n_ok == len(exported) else 1


def msg_label(m: bytes) -> str:
    """命令名（首词），用于目录名与 RFC 真值查表。"""
    return m.strip().split(b" ", 1)[0].decode("latin-1", "replace").upper()


def rfc_prereq_names() -> dict:
    """RFC 959 下各命令的前置命令名（真值参考，算法不用它）。"""
    AUTH = ("USER", "PASS")
    return {
        "USER": (),
        "PASS": ("USER",),
        "PWD": AUTH,
        "CWD": AUTH,
        "TYPE": AUTH,
        "PASV": AUTH,
        "SIZE": AUTH,
        "NOOP": (),
        "HELP": (),
        "SYST": (),
    }


# 每条命令「成功」的响应码（LightFTP 基线实测 + RFC 959）
SUCCESS_CODES = {
    "USER": {"331"}, "PASS": {"230"}, "PWD": {"257"}, "CWD": {"250"},
    "NOOP": {"200"}, "HELP": {"214", "211"}, "TYPE": {"200"},
    "SYST": {"215"}, "PASV": {"227"}, "SIZE": {"213"},
}


def _make_probe(oracle: TcpShmOracle, msgs: list[bytes], j: int):
    """目标命令 j 的状态判别器：发完候选前置后追加 msgs[j]，看是否成功。

    与 sandbox_harness.c 的 PROBE_CMD 同语义。候选集排除 j 自身 ——
    否则目标已经跑过一遍，探的是「再跑一次」而不是「能不能成功」
    （PASS 第二次回 503）。
    """
    want = SUCCESS_CODES.get(msg_label(msgs[j]), set())

    def probe(idx: list[int]) -> bool:
        rows = oracle.run_sequence_with_replies([msgs[i] for i in idx] + [msgs[j]])
        code = TcpShmOracle.response_code(rows[-1][1]) if rows else ""
        return code in want

    return probe


if __name__ == "__main__":
    raise SystemExit(main())
