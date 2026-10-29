#!/usr/bin/env python3
"""
metrics_sampler.py — 周期性抓取一次 AFL++ 状态，落成 CSV 时间序列

第三批 ⑩「结构化指标」的最小形态。run_state_node.sh 结束时只打一张终点汇总表，
看不出覆盖率什么时候饱和、吞吐什么时候掉、崩溃是不是集中爆发 —— 做对比实验
（B0..B4）时要算 coverage–时间曲线的 AUC，就必须有按时间的原始点。

用法（与 run_state_node.sh 并行跑，互不干扰，只读 results/ 与进程表）：
    python3 metrics_sampler.py --state lightftp_state_2_auth --interval 30

输出：results/metrics/<state>.csv，每行一个实例的一次采样。
注意【不能】写进 results/<state>/ —— run_state_node.sh 启动时会对该目录 rm -rf，
采样器若把 csv 放里面，会被删掉而 fd 仍指向已删除的 inode，后续写入全部丢失。
所以观测数据放在 results/metrics/，跟节点自己的输出树分开。
列：
    ts, elapsed_s, inst,
    execs_done, execs_per_sec, corpus_count, saved_crashes,
    bitmap_cvg, edges_found, cycles_done, pending_total,
    shm_orphans, n_target, n_server_loop,   # 进程/SHM 卫生，用于查泄漏
    pool_size, n_crash_files                # 共享池与崩溃归档

设计取舍：
  * 对 results/<state>/ 只读不写，也不碰 /tmp/sbf_node.lock —— 它是旁路观测器，
    崩了不影响 fuzz 本身。
  * 瞬时 execs_per_sec 由 AFL++ 自己算（滑动平均），我们不重复造轮子；
    需要区间吞吐时用相邻两个 execs_done 差分即可。
  * shm_orphans 数「TARGET_SHM_SIZE 字节 / 0 连接数」的段 —— 这是 SBF 的创建签名
    （run_state_node.sh 里 shmget(IPC_PRIVATE, TARGET_SHM_SIZE, 0666)）。
    别的程序的段要么尺寸不同、要么常有连接数，不会误算。
"""

import argparse
import csv
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

FIELDS = ["execs_done", "execs_per_sec", "corpus_count", "saved_crashes",
          "bitmap_cvg", "edges_found", "cycles_done", "pending_total"]

COLUMNS = ["ts", "elapsed_s", "inst"] + FIELDS + [
    "shm_orphans", "n_target", "n_server_loop", "pool_size", "n_crash_files"]


def read_fuzzer_stats(path):
    """AFL++ 的 fuzzer_stats 是 `key : value` 行。缺字段就留空，不猜。"""
    out = {k: "" for k in FIELDS}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if ":" not in line:
                    continue
                key, _, val = line.partition(":")
                key = key.strip()
                if key in out:
                    out[key] = val.strip()
    except OSError:
        pass
    return out


def find_instances(out_base):
    """results/<state>/i<N>/fuzzer_<N>/fuzzer_stats —— 目录名跟 run_state_node.sh 对齐。"""
    insts = {}
    if not os.path.isdir(out_base):
        return insts
    for name in sorted(os.listdir(out_base)):
        if not name.startswith("i") or not name[1:].isdigit():
            continue
        i = int(name[1:])
        stats = os.path.join(out_base, name, f"fuzzer_{i}", "fuzzer_stats")
        if os.path.isfile(stats):
            insts[i] = stats
    return insts


def count_shm_orphans(size=65536):
    """数 SBF 签名的孤儿段：给定字节数、0 连接数。SBF 用
    shmget(IPC_PRIVATE, TARGET_SHM_SIZE, 0666) 创建，段一崩就成孤儿 ——
    这是 soak 要盯的泄漏指标。别的程序（浏览器等）的段常有连接数，不会误算。"""
    try:
        out = subprocess.run(["ipcs", "-m"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    n = 0
    for line in out.splitlines():
        parts = line.split()
        # ipcs -m: key shmid owner perms bytes nattch status
        if len(parts) < 6 or not parts[0].startswith("0x"):
            continue
        try:
            seg_size, nattch = int(parts[4]), int(parts[5])
        except ValueError:
            continue
        if seg_size == size and nattch == 0:
            n += 1
    return n


def count_procs(pattern, exact=False):
    """只数不杀。exact=True 用 pgrep -x 按进程名精确匹配 —— 靶机二进制名（fftp）
    会被 pgrep -f 误匹配到 sbf-server-loop 的命令行和 targets/lightftp.sh，
    数出来虚高。"""
    cmd = ["pgrep", "-c"] + (["-x"] if exact else ["-f"]) + [pattern]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return int(r.stdout.strip() or 0)
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""


def count_files(path):
    try:
        return len([f for f in os.listdir(path)
                    if os.path.isfile(os.path.join(path, f))])
    except OSError:
        return 0


def main():
    ap = argparse.ArgumentParser(description="SandboxFuzzer 结构化指标采样器")
    ap.add_argument("--state", required=True, help="状态名，如 lightftp_state_2_auth")
    ap.add_argument("--root", default=os.path.dirname(os.path.abspath(__file__)),
                    help="ECSSandbox 根目录（默认本脚本所在目录）")
    ap.add_argument("--interval", type=float, default=30.0, help="采样间隔秒（默认 30）")
    ap.add_argument("--duration", type=float, default=0.0,
                    help="采样总时长秒，0 = 一直采到被杀（默认 0）")
    ap.add_argument("--target-name", default=os.environ.get("TARGET_NAME", ""),
                    help="靶机进程名（targets/*.conf 的 TARGET_NAME），如 fftp；"
                         "留空则 n_target 列为空")
    ap.add_argument("--shm-size", type=int,
                    default=int(os.environ.get("TARGET_SHM_SIZE", "65536")),
                    help="覆盖率位图字节数（targets/*.conf 的 TARGET_SHM_SIZE），"
                         "用于识别本系统的 SHM 段")
    args = ap.parse_args()

    out_base = os.path.join(args.root, "results", args.state)   # 节点的输出树（会被 rm -rf）
    metrics_dir = os.path.join(args.root, "results", "metrics")  # 观测数据，节点碰不到
    pool_dir = os.path.join(args.root, "corpus", args.state)
    crash_dir = os.path.join(pool_dir, "crashes")
    csv_path = os.path.join(metrics_dir, f"{args.state}.csv")

    os.makedirs(metrics_dir, exist_ok=True)
    new_file = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0

    t0 = time.time()
    deadline = t0 + args.duration if args.duration > 0 else None

    with open(csv_path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        if new_file:
            writer.writeheader()
            fh.flush()

        n_rows = 0
        while True:
            now = time.time()
            if deadline and now >= deadline:
                break

            insts = find_instances(out_base)
            if insts:
                shm = count_shm_orphans(args.shm_size)
                n_tgt = count_procs(args.target_name, exact=True) if args.target_name else ""
                n_loop = count_procs("[s]bf-server-loop")
                # 共享池规模 = pool 目录下的种子文件数（不含 init_shards/ crashes/ 子目录）
                pool = count_files(pool_dir)
                crashes = count_files(crash_dir)

                ts = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
                for i, stats_path in sorted(insts.items()):
                    row = {"ts": ts, "elapsed_s": int(now - t0), "inst": f"i{i}"}
                    row.update(read_fuzzer_stats(stats_path))
                    row.update({"shm_orphans": shm, "n_target": n_tgt,
                                "n_server_loop": n_loop, "pool_size": pool,
                                "n_crash_files": crashes})
                    writer.writerow(row)
                    n_rows += 1
                fh.flush()
                print(f"[metrics] t+{int(now - t0):>5}s  实例={len(insts)}  "
                      f"池={pool}  崩溃文件={crashes}  孤儿SHM={shm}", flush=True)
            else:
                print(f"[metrics] t+{int(now - t0):>5}s  尚无实例输出（节点还在启动？）", flush=True)

            # 按固定节拍睡，避免采样漂移累积
            next_tick = t0 + (int((now - t0) / args.interval) + 1) * args.interval
            time.sleep(max(0.5, next_tick - time.time()))

    print(f"[metrics] 结束，共 {n_rows} 行 → {csv_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
