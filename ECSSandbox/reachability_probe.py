#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reachability_probe.py —— 种子池在某状态下的可达比例
===================================================

「种子池必须单状态」的 level-1 证据（机制）：把一个池逐条种子打给真靶机，
看有多少条回到【成功码】。level-2（结果）是 fuzz 的 edges/corpus/crashes，
由 run_state_node.sh 跑出来。两层要对得上，论点才成立。

判据与 sandbox_harness.c / local_seedhub.probe_crash 完全同口径：
    连上 → 读 banner → 【逐条报文】发前缀（每条等一条应答）→ 发种子 → 读应答
逐条发是硬要求：LightFTP 把一次 recv 的整个缓冲当一条命令，整块发只执行
第一条，后面的种子全打在未登录会话上回 530 —— 那不是池的问题，是交付的问题。

用法:
    python3 reachability_probe.py --prefix prefix.raw --seeds seeds_dir
    python3 reachability_probe.py --prefix prefix.raw --seeds dir --json out.json

空前缀（未登录状态）就传一个 0 字节的 --prefix，或干脆省掉。
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALGO_DIR = os.environ.get("SBF_ALGO_DIR") or os.path.join(
    os.path.dirname(HERE), "PrefixMsgs algorithm")
sys.path.insert(0, ALGO_DIR)
sys.path.insert(0, HERE)

from tcp_shm_oracle import TcpShmOracle            # noqa: E402
from verify_prefix import SUCCESS_CODES, cmd_of, split_lines  # noqa: E402

PORT = int(os.environ.get("VERIFY_PORT", "9854"))


def measure(oracle, prefix: bytes, seed: bytes, repeats: int):
    """发 prefix + seed，返回 (响应码列表, 最后一条原始应答)。"""
    codes = []
    last = ""
    for _ in range(repeats):
        rows = oracle.run_sequence_with_replies(split_lines(prefix) + [seed])
        last = rows[-1][1] if rows else ""
        codes.append(TcpShmOracle.response_code(last))
    return codes, last


def main() -> int:
    ap = argparse.ArgumentParser(description="测一个种子池在某状态下的可达比例")
    ap.add_argument("--prefix", default="", help="状态前缀文件；空/缺省 = 无前缀")
    ap.add_argument("--seeds", required=True, help="种子目录")
    ap.add_argument("--launcher", default="targets/lightftp.sh")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--banner-lines", type=int, default=1)
    ap.add_argument("--repeats", type=int, default=3, help="每条打几次，防抖动")
    ap.add_argument("--label", default="", help="报告里显示的名字")
    ap.add_argument("--json", default="", help="顺手把结果写成 JSON")
    args = ap.parse_args()

    prefix = b""
    if args.prefix:
        with open(args.prefix, "rb") as f:
            prefix = f.read()
    if not os.path.isdir(args.seeds):
        print(f"[!] 种子目录不存在: {args.seeds}")
        return 2
    seeds = []
    for fn in sorted(os.listdir(args.seeds)):
        p = os.path.join(args.seeds, fn)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                seeds.append((fn, f.read()))
    if not seeds:
        print(f"[!] {args.seeds} 里没有种子")
        return 2

    label = args.label or f"prefix={prefix!r}"
    print(f"池可达性  [{label}]")
    print(f"  前缀   : {prefix!r}" + ("（无前缀）" if not prefix else ""))
    print(f"  种子数 : {len(seeds)}")

    launcher = os.path.join(HERE, args.launcher)
    rows = []
    with TcpShmOracle([launcher, str(args.port)], port=args.port,
                      banner_lines=args.banner_lines, settle=0.02,
                      start_timeout=6.0) as oracle:
        for fn, blob in seeds:
            scmd = cmd_of(blob)
            want = SUCCESS_CODES.get(scmd)
            codes, last = measure(oracle, prefix, blob, args.repeats)
            code = codes[0] if len(set(codes)) == 1 else "/".join(codes)
            if want is None:
                verdict = "无成功码定义"
                ok = None
            else:
                ok = all(c in want for c in codes)
                verdict = "可达" if ok else "打不响"
            rows.append({"seed": fn, "cmd": scmd, "code": code,
                         "want": sorted(want) if want else None,
                         "playable": ok, "reply": last})
            print(f"    {fn:24s} {blob!r:22s} → {str(code):8s} "
                  f"{verdict:10s}" + ("" if ok else f"  应答={last!r}"))

    known = [r for r in rows if r["playable"] is not None]
    good = sum(1 for r in known if r["playable"])
    print(f"  可达 {good}/{len(known)}"
          + (f"（另有 {len(rows) - len(known)} 条无成功码定义）"
             if len(known) != len(rows) else ""))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"label": label,
                       "prefix": prefix.decode("latin-1", "replace"),
                       "reachable": good, "total": len(known),
                       "seeds": rows}, f, ensure_ascii=False, indent=2)
        print(f"  已写 {args.json}")
    return 0 if good == len(known) else 1


if __name__ == "__main__":
    raise SystemExit(main())
