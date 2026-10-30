#!/usr/bin/env python3
"""
verify_prefix.py — 会话前缀重建产物的验收测试
==============================================

`validate_prefix.py` 证明的是【算法】对（precision/recall 对照 RFC 真值）。
这里证明的是【产物】能用：把 derive_prefix.py 导出的 prefix.raw 加载回来，
按 sandbox_harness.c 的方式打给真靶机（前缀 → 目标命令），看真实响应码
是否落在成功码集合里。

闭环链条：
    算法  →  prefix.raw  →  [验收] 真靶机回成功码  →  沙箱 harness 能用
少最后一环，就只是"算法输出自洽"，不等于"可用"。

交付语义：前缀是【报文序列】不是一块字节，必须逐条发（见 sandbox_harness.c
的 send_prefix_msgs）。整块发在 LightFTP 上只执行第一条命令，目标命令回 530 ——
2026-10-28 首跑就是栽在这里（试验组 3/6，全是 2 行以上前缀的状态）。

跑法（宿主机编不动 fftp，进容器）：
    cd SandboxFuzzer
    docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/sbfpkg \\
        --workdir /sbfpkg/ECSSandbox --entrypoint python3 sbf-node \\
        /sbfpkg/ECSSandbox/verify_prefix.py --root prefix_analyzer_output_rebuild
"""
from __future__ import annotations

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALGO_DIR = os.environ.get("SBF_ALGO_DIR") or os.path.join(
    os.path.dirname(HERE), "PrefixMsgs algorithm")
sys.path.insert(0, ALGO_DIR)
sys.path.insert(0, HERE)

from tcp_shm_oracle import TcpShmOracle  # noqa: E402

PORT = int(os.environ.get("VERIFY_PORT", "9853"))

# 每条命令「成功」的响应码（LightFTP 基线实测 + RFC 959）
SUCCESS_CODES = {
    "USER": {"331"}, "PASS": {"230"}, "PWD": {"257"}, "CWD": {"250"},
    "NOOP": {"200"}, "HELP": {"214", "211"}, "TYPE": {"200"},
    "SYST": {"215"}, "PASV": {"227"}, "SIZE": {"213"},
}


def discover(root: str):
    """扫导出目录，找出每个状态的 prefix.raw / target.raw。

    target.raw 是【目标命令的原始字节】（带参数）。不能从目录名重建 ——
    目录名只留命令名（admin_ftp_state_2_PWD），参数（CWD 的 "/"、TYPE 的 "I"、
    USER 的 "admin"）已经丢了，重建出 "CWD\\r\\n" 会回 501。
    """
    out = []
    if not os.path.isdir(root):
        return out
    for name in sorted(os.listdir(root)):
        d = os.path.join(root, name)
        p = os.path.join(d, "prefix.raw")
        if not os.path.isfile(p):
            continue
        # 目录名形如 admin_ftp_state_2_PWD → 末段是命令名（仅用于查成功码）
        m = re.search(r"_state_\d+_(.+)$", name)
        if not m:
            continue
        cmd = m.group(1).upper()
        with open(p, "rb") as f:
            prefix = f.read()
        tp = os.path.join(d, "target.raw")
        if os.path.isfile(tp):
            with open(tp, "rb") as f:
                target = f.read()
        else:
            # 兼容旧导出：没有 target.raw 就只能重建命令名（会丢参数）
            target = f"{cmd}\r\n".encode()
        seeds = os.path.join(d, "seeds")
        n_seed = len(os.listdir(seeds)) if os.path.isdir(seeds) else 0
        out.append((name, cmd, target, prefix, n_seed))
    return out


def split_lines(blob: bytes) -> list[bytes]:
    """把前缀串按行拆成逐条命令，用于失败时逐步诊断。

    前缀是一整块字节（USER admin\\r\\nPASS 123456\\r\\n）。一步发完时若登录
    没成，看不出卡在哪一条；拆开逐步打就能看到每条各自的响应码。
    """
    out, cur = [], b""
    for b in blob:
        cur += bytes([b])
        if b == 0x0A:          # \n
            out.append(cur)
            cur = b""
    if cur:
        out.append(cur)
    return out


def cmd_of(blob: bytes) -> str:
    """从种子的原始字节里取命令名（FTP 的首 token，到空格或 \\r\\n 为止）。

    种子文件名里只有下标（admin_ftp_2_1.raw），命令名要从载荷本身取。
    """
    tok = b""
    for b in blob:
        if b in (0x20, 0x0D, 0x0A):
            break
        tok += bytes([b])
    return tok.decode("latin-1", "replace").upper()


def main() -> int:
    ap = argparse.ArgumentParser(description="验收导出的 prefix.raw 能否真用")
    ap.add_argument("--root", default="prefix_analyzer_output_rebuild")
    ap.add_argument("--launcher", default="targets/lightftp.sh")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--banner-lines", type=int, default=1)
    ap.add_argument("--repeats", type=int, default=5,
                    help="每条打几次，防偶发抖动")
    ap.add_argument("--check-seeds", action="store_true",
                    help="额外验收「种子池单状态」：池里每条种子在本状态下都得能打")
    args = ap.parse_args()

    states = discover(args.root)
    if not states:
        print(f"[!] {args.root} 里没有 prefix.raw，先跑 derive_prefix.py")
        return 2

    launcher = os.path.join(HERE, args.launcher)
    print("=" * 78)
    print("会话前缀重建 —— 产物验收（prefix.raw → 真靶机 → 成功码）")
    print("=" * 78)
    print(f"  导出目录 : {args.root}")
    print(f"  状态数   : {len(states)}")

    n_pass = n_ctrl = n_tested = 0
    with TcpShmOracle([launcher, str(args.port)], port=args.port,
                      banner_lines=args.banner_lines, settle=0.02,
                      start_timeout=6.0) as oracle:
        # ── 试验组：prefix.raw + 目标命令 ─────────────────────────
        for name, cmd, target, prefix, n_seed in states:
            want = SUCCESS_CODES.get(cmd, set())
            if not want:
                print(f"  {name:36s} [跳过] 无 {cmd} 的成功码定义")
                continue
            n_tested += 1

            # 验收判据与 sandbox_harness.c 一致：发 prefix.raw，
            # 再发目标命令，看它的响应码。
            #
            # 前缀要【逐条报文】发（split_lines），不能整块发。LightFTP 把一次
            # recv 的整个缓冲当成一条命令，整块发只执行第一条，后面的载荷打在
            # 未登录会话上回 530 —— 这不是前缀内容错，是交付方式错。
            codes, last_reply = [], ""
            for _ in range(args.repeats):
                rows = oracle.run_sequence_with_replies(
                    split_lines(prefix) + [target])
                last_reply = rows[-1][1] if rows else ""
                codes.append(TcpShmOracle.response_code(last_reply))
            ok = all(c in want for c in codes)
            n_pass += ok
            shown = codes[0] if len(set(codes)) == 1 else codes
            print(f"  {name:36s} 前缀={prefix!r:34s} "
                  f"{target!r}→{shown} 期望{sorted(want)}  "
                  f"{'PASS' if ok else 'FAIL'}")
            if not ok:
                print(f"      原始应答: {last_reply!r}")
                if prefix:
                    rows = oracle.run_sequence_with_replies(
                        [b for b in split_lines(prefix)] + [target])
                    for k, (c, r) in enumerate(rows):
                        print(f"      步{k}: {r!r}")

        print("  " + "-" * 78)
        print(f"  试验组通过 {n_pass}/{n_tested}")

        # ── 对照组：不带前缀直接打目标命令 ─────────────────────────
        # 没有对照，"通过"可能只是因为该命令本来就不需要前缀（假阳性）。
        # 有 prefix.raw 的状态，无前缀时必须失败；没有的，必须照样成功。
        print(f"\n  对照组（不发前缀，直接打目标命令）:")
        for name, cmd, target, prefix, n_seed in states:
            want = SUCCESS_CODES.get(cmd, set())
            if not want:
                continue
            rows = oracle.run_sequence_with_replies([target])
            code = TcpShmOracle.response_code(rows[-1][1]) if rows else ""
            should_fail = bool(prefix)      # 有前缀 = 算法认定它需要前置
            ok = (code not in want) if should_fail else (code in want)
            n_ctrl += ok
            print(f"    {cmd:5s} 无前缀 → {(code or '(无应答)'):5s}  "
                  f"{'期望失败' if should_fail else '期望成功'}  "
                  f"{'符合' if ok else '不符合'}")

        # ── 种子池单状态验收（可选）──────────────────────────────
        n_seed_ok = n_seed_tested = 0
        if args.check_seeds:
            print(f"\n  种子池单状态验收（池内每条种子在本状态下必须能正常打）:")
            for name, cmd, target, prefix, n_seed in states:
                sd = os.path.join(args.root, name, "seeds")
                if not os.path.isdir(sd):
                    continue
                bad, good = [], 0
                for fn in sorted(os.listdir(sd)):
                    with open(os.path.join(sd, fn), "rb") as f:
                        seed = f.read()
                    scmd = cmd_of(seed)
                    want = SUCCESS_CODES.get(scmd, set())
                    if not want:
                        continue
                    n_seed_tested += 1
                    rows = oracle.run_sequence_with_replies(
                        split_lines(prefix) + [seed])
                    code = TcpShmOracle.response_code(rows[-1][1]) if rows else ""
                    if code in want:
                        n_seed_ok += 1
                        good += 1
                    else:
                        bad.append((fn, scmd, code or '(无应答)'))
                print(f"    {name:36s} 可达 {good}/{good + len(bad)}"
                      + (f"   打不响: {bad[:3]}" if bad else "  OK"))

    print(f"  对照组符合预期 {n_ctrl}/{n_tested}")
    if args.check_seeds:
        print(f"  种子池单状态: {n_seed_ok}/{n_seed_tested} 条种子在本状态可达")
    # 两组都必须全对：试验组证明前缀够用，对照组证明前缀是【必要的】。
    verdict = (n_pass == n_tested) and (n_ctrl == n_tested) and n_tested > 0
    if args.check_seeds:
        verdict = verdict and n_seed_ok == n_seed_tested and n_seed_tested > 0
    print(f"\n  {'=' * 70}")
    print(f"  验收结论: {'通过 —— 产物可用' if verdict else '未通过'}")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
