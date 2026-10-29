#!/usr/bin/env python3
"""
switch_state.py — 全节点协议状态切换

架构原则：状态同质化 ≠ 状态锁死。一台 ECS 上的所有 AFL++ 实例/沙箱在同一
时刻只测一个状态，但整机可以作为一个整体在状态之间切换。

切换是【原子的】——整机同时停、同时换、同时起，绝不出现一半实例在 S1、
另一半在 S2 的异质局面（那会让 -M/-S 本地种子共享被跨状态语料污染）。

用法:
  ./switch_state.py state_2_auth [--secondaries 3] [--duration 0]
  ./switch_state.py state_0_init --keep-results
"""

import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sbf_redis import Redis, RedisError  # noqa: E402

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(SCRIPT_DIR, "node_state.current")
ARCHIVE_DIR = os.path.join(SCRIPT_DIR, "results_archive")


def read_current_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def write_current_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        f.write(state + "\n")


def _pkill(pattern, sig=signal.SIGTERM):
    subprocess.run(["pkill", "-" + str(sig), "-f", pattern],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop_node(state):
    """停掉本节点上所有属于 state 的进程 —— 各实例 / 靶机 / 种子枢纽 / 回传守护。"""
    outdir = os.path.join(SCRIPT_DIR, "results", state or "")
    print("[STOP] 停止状态 %s 的全部实例..." % state)

    for pat in ("[l]ocal_seedhub.py.*--state %s" % state,
                "[f]inding_sync.py.*--state %s" % state):
        _pkill(pat)
    if state:
        _pkill("[a]fl-fuzz.*%s" % outdir)
    # 先杀保活循环，再杀靶机 —— 否则循环会立刻把靶机拉起来
    _pkill("[s]bf-server-loop")
    _pkill("[s]tateful_server")
    time.sleep(1.5)

    # 二次强杀，确保端口释放
    for pat in ("[l]ocal_seedhub.py.*--state %s" % state,
                "[f]inding_sync.py.*--state %s" % state):
        _pkill(pat, signal.SIGKILL)
    if state:
        _pkill("[a]fl-fuzz.*%s" % outdir, signal.SIGKILL)
    _pkill("[s]bf-server-loop", signal.SIGKILL)
    _pkill("[s]tateful_server", signal.SIGKILL)
    time.sleep(0.5)


def archive_results(state, keep=False):
    """归档旧状态的全部产物：AFL++ 输出、共享种子池、分片投喂目录。"""
    if not state:
        return None
    if keep:
        return os.path.join(SCRIPT_DIR, "results", state)

    stamp = time.strftime("%Y%m%d-%H%M%S")
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    moved = []
    for rel in ("results", "corpus", "work", "sync_outbox"):
        src = os.path.join(SCRIPT_DIR, rel, state)
        if not os.path.isdir(src):
            continue
        dest = os.path.join(ARCHIVE_DIR, "%s_%s_%s" % (state, rel, stamp))
        shutil.move(src, dest)
        moved.append(src)
    for src in moved:
        print("[ARCHIVE] %s → 已归档" % src)
    return os.path.join(ARCHIVE_DIR, "%s_results_%s" % (state, stamp))


def publish_state(node_id, old_state, new_state, redis_url):
    if not redis_url:
        return
    try:
        r = Redis(redis_url).connect()
        r.hset("sbf:node:%s:status" % node_id, {
            "state": new_state,
            "prev_state": old_state or "",
            "switched_at": str(time.time()),
            "hostname": socket.gethostname(),
            "pid": str(os.getpid()),
        })
        r.publish("sbf:events", json_dumps({
            "op": "state_switched",
            "node_id": node_id,
            "from": old_state,
            "to": new_state,
            "ts": time.time(),
        }))
        r.close()
        print("[REDIS] 已上报状态切换 %s → %s" % (old_state, new_state))
    except (RedisError, OSError) as e:
        print("[REDIS] 上报失败（不影响切换）：%s" % e, file=sys.stderr)


def json_dumps(o):
    import json
    return json.dumps(o, ensure_ascii=False)


def main():
    ap = argparse.ArgumentParser(description="全节点协议状态切换")
    ap.add_argument("new_state", help="目标状态名")
    ap.add_argument("--secondaries", type=int, default=None,
                    help="secondary 实例数（默认沿用上次）")
    ap.add_argument("--duration", type=int, default=0,
                    help="切换后运行时长，0=一直跑")
    ap.add_argument("--keep-results", action="store_true",
                    help="不归档旧状态结果，直接覆盖")
    ap.add_argument("--node-id", default=os.environ.get("NODE_ID", socket.gethostname()))
    ap.add_argument("--redis", default=os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0"))
    ap.add_argument("--no-start", action="store_true",
                    help="只停止并切换标记，不拉起新状态")
    args = ap.parse_args()

    prefix_dir = os.path.join(SCRIPT_DIR, "prefix_analyzer_output")
    if not os.path.isdir(os.path.join(prefix_dir, args.new_state)):
        print("[!] 目标状态不存在: %s" % args.new_state)
        for d in sorted(os.listdir(prefix_dir)):
            if os.path.isdir(os.path.join(prefix_dir, d)):
                print("    - %s" % d)
        return 1

    old_state = read_current_state()
    print("=" * 52)
    print("  状态切换（全节点原子切换）")
    print("  %s  →  %s" % (old_state or "(无)", args.new_state))
    print("=" * 52)

    # 1) 停机（整机一起停，不留异质残留）
    stop_node(old_state)
    stop_node(args.new_state)  # 防止目标状态有僵尸

    # 2) 归档旧状态语料
    archive_results(old_state, keep=args.keep_results)

    # 3) 更新状态标记
    write_current_state(args.new_state)
    print("[STATE] node_state.current = %s" % args.new_state)

    # 4) 上报
    publish_state(args.node_id, old_state, args.new_state, args.redis)

    if args.no_start:
        print("[DONE] 已切换标记，未拉起新状态 (--no-start)")
        return 0

    # 5) 整机拉起新状态
    secondaries = args.secondaries
    if secondaries is None:
        try:
            secondaries = max(0, int(os.environ.get("N_SECONDARIES",
                                                   os.cpu_count() or 2) - 1))
        except ValueError:
            secondaries = 1

    cmd = ["bash", os.path.join(SCRIPT_DIR, "run_state_node.sh"),
           args.new_state, str(secondaries), str(args.duration)]
    print("[START] %s" % " ".join(cmd))
    # 脱离当前终端，保证 switch_state 退出后新状态继续跑
    log = open(os.path.join(SCRIPT_DIR, "node_%s.log" % args.new_state), "ab")
    subprocess.Popen(cmd, stdout=log, stderr=log,
                     start_new_session=True, cwd=SCRIPT_DIR)
    print("[DONE] 新状态 %s 已在后台拉起 (日志: node_%s.log)" %
          (args.new_state, args.new_state))
    return 0


if __name__ == "__main__":
    sys.exit(main())
