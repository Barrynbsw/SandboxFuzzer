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
# 与 run_state_node.sh 的 LOCK_PID_FILE 同一约定（可被 SBF_LOCK_FILE 覆盖）
LOCK_PID_FILE = os.environ.get("SBF_LOCK_FILE", "/tmp/sbf_node.lock")


def read_lock_pid():
    try:
        with open(LOCK_PID_FILE, "r", encoding="utf-8") as f:
            return int(f.read().strip() or 0) or None
    except (OSError, ValueError):
        return None


def pid_alive(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def kill_lock_holder(wait_term=5.0, wait_kill=2.0):
    """杀掉持锁的父进程 run_state_node.sh 并等它真正退出。

    只 pkill 子进程（afl-fuzz/靶机/seedhub）杀不到父进程自身：它握着节点锁，
    不等它退就拉起新节点会撞锁 exits 1，调用方却以为切换成功 —— fuzz 静默跑在
    错误状态上（审查 F2）。SIGKILL 后锁文件可能残留（trap 来不及跑），由
    run_state_node.sh 的"持有者已死按残留清扫"兜底。
    """
    holder = read_lock_pid()
    if not holder or holder == os.getpid() or not pid_alive(holder):
        return holder
    for sig, budget in ((signal.SIGTERM, wait_term), (signal.SIGKILL, wait_kill)):
        try:
            os.kill(holder, sig)
        except OSError:
            break
        deadline = time.time() + budget
        while time.time() < deadline and pid_alive(holder):
            time.sleep(0.1)
        if not pid_alive(holder):
            break
    if pid_alive(holder):
        print("[!] 节点父进程 pid=%d 拒不退出，切换不安全" % holder, file=sys.stderr)
    return holder


def wait_new_lock(old_holder, timeout=30.0):
    """等新节点拿到锁并回读确认；返回新持锁 PID，拿不到返回 None。

    run_state_node.sh 早期就 echo $$ > 锁文件，所以锁归属是"新节点是否真的
    起来了"最便宜的探针。[DONE] 只能在确认之后打 —— 否则切换静默失败（F2）。
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        pid = read_lock_pid()
        if pid and pid != old_holder and pid_alive(pid):
            return pid
        time.sleep(0.2)
    return None


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
    # 子进程之外还有持锁的父进程 run_state_node.sh —— 必须等它退出再拉新的
    old_holder = kill_lock_holder()

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

    # 回读节点锁确认新节点真的拿到了锁 —— 拿不到就是切换静默失败（审查 F2），
    # [DONE] 只能在确认之后打。
    new_holder = wait_new_lock(old_holder)
    if not new_holder:
        print("[!] 新状态 %s 没有拿到节点锁，切换失败" % args.new_state,
              file=sys.stderr)
        print("    排查: cat %s ; tail -50 node_%s.log"
              % (LOCK_PID_FILE, args.new_state), file=sys.stderr)
        return 1
    print("[DONE] 新状态 %s 已拉起，持锁 pid=%d (日志: node_%s.log)" %
          (args.new_state, new_holder, args.new_state))
    return 0


if __name__ == "__main__":
    sys.exit(main())
