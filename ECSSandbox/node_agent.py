#!/usr/bin/env python3
"""
node_agent.py — ECS 节点控制面代理

和 finding_sync.py（数据面）分工：
  finding_sync.py  高价值种子/崩溃 → 异步上报 Dispatcher   （出）
  node_agent.py    Dispatcher 指令 → 状态切换 / 种子下发    （入）

它保证"状态同质化但不锁死"：
  整机监听 Dispatcher 的状态指派，一旦变更就调用 switch_state.py 做【整机】
  原子切换 —— 所有 AFL++ 实例与沙箱同时换到新状态，绝不混跑。

用法:
  ./node_agent.py --node-id ecs-01 --redis redis://127.0.0.1:6379/0
"""

import argparse
import base64
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sbf_redis import Redis, PubSub, RedisError  # noqa: E402

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(SCRIPT_DIR, "node_state.current")


def read_current_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


class NodeAgent:
    def __init__(self, node_id, redis_url, poll_interval=5, import_interval=3):
        self.node_id = node_id
        self.redis_url = redis_url
        self.poll_interval = max(1, poll_interval)
        self.import_interval = max(1, import_interval)
        self.running = True
        self.switching = False

    # ── 控制指令 ──────────────────────────────────────────────
    def handle_command(self, msg):
        try:
            cmd = json.loads(msg)
        except ValueError:
            print("[agent] 忽略非法指令: %r" % msg[:120], file=sys.stderr)
            return

        op = cmd.get("op")
        target = cmd.get("node_id", "*")
        if target not in ("*", self.node_id):
            return

        if op == "switch_state":
            new_state = cmd.get("state")
            if not new_state:
                return
            cur = read_current_state()
            if cur == new_state:
                print("[agent] 已处于 %s，忽略重复切换" % new_state)
                return
            print("[agent] 收到状态切换指令: %s → %s" % (cur, new_state))
            self.do_switch(new_state, cmd.get("secondaries"), cmd.get("duration", 0))

        elif op == "import":
            # 只触发一次拉取；常规周期拉取本来就在跑
            n = self.import_seeds()
            print("[agent] 按指令拉取下发种子 %d 个" % n)

        elif op == "stop":
            print("[agent] 收到 stop 指令")
            self.running = False

        else:
            print("[agent] 未知指令 op=%s" % op, file=sys.stderr)

    def do_switch(self, new_state, secondaries=None, duration=0):
        if self.switching:
            return
        self.switching = True
        try:
            cmd = [sys.executable, os.path.join(SCRIPT_DIR, "switch_state.py"),
                   new_state, "--node-id", self.node_id, "--redis", self.redis_url,
                   "--duration", str(int(duration or 0))]
            if secondaries is not None:
                cmd += ["--secondaries", str(int(secondaries))]
            print("[agent] exec: %s" % " ".join(cmd))
            subprocess.run(cmd, cwd=SCRIPT_DIR)
        finally:
            self.switching = False

    # ── 种子下发（Dispatcher → 本机 foreign_sync）────────────
    def import_seeds(self):
        state = read_current_state()
        if not state:
            return 0

        r = None
        try:
            r = Redis(self.redis_url).connect()
        except (RedisError, OSError):
            return 0

        foreign = os.path.join(SCRIPT_DIR, "foreign_sync", state)
        os.makedirs(foreign, exist_ok=True)

        count = 0
        for kind, sub in (("seed", "seed"), ("crash", "crash")):
            key = "sbf:dist:%s:%s" % (sub, state)
            # 每轮最多取 64 条，避免长时间占用连接
            for _ in range(64):
                try:
                    raw = r.lpop(key)
                except (RedisError, OSError):
                    break
                if not raw:
                    break
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue

                blob = base64.b64decode(rec.get("payload_b64", ""))
                if not blob:
                    continue
                h = rec.get("hash") or hashlib.sha256(blob).hexdigest()

                if kind == "seed":
                    # 落进 foreign_sync，master 的 -F 会在下一轮同步周期导入
                    dest = os.path.join(foreign, "dst_%s_%s" % (h[:16], rec.get("name", "seed")))
                    if not os.path.exists(dest):
                        with open(dest, "wb") as f:
                            f.write(blob)
                    count += 1
                else:
                    # 崩溃样本不进语料库，单独归档供人工复现
                    crash_dir = os.path.join(SCRIPT_DIR, "remote_crashes", state)
                    os.makedirs(crash_dir, exist_ok=True)
                    dest = os.path.join(crash_dir, "%s_%s" % (h[:16], rec.get("name", "crash")))
                    if not os.path.exists(dest):
                        with open(dest, "wb") as f:
                            f.write(blob)
                        with open(dest + ".meta.json", "w", encoding="utf-8") as f:
                            json.dump(rec, f, ensure_ascii=False)

        if r:
            try:
                r.close()
            except (RedisError, OSError):
                pass
        return count

    # ── 状态心跳 ──────────────────────────────────────────────
    def heartbeat(self):
        state = read_current_state()
        try:
            r = Redis(self.redis_url).connect()
            r.hset("sbf:node:%s:status" % self.node_id, {
                "state": state or "",
                "agent_pid": str(os.getpid()),
                "hb_ts": str(time.time()),
            })
            # 有指派且与本机不一致 → 触发切换
            assigned = r.get("sbf:assignment:%s" % self.node_id)
            if assigned:
                assigned = assigned.decode() if isinstance(assigned, bytes) else assigned
                if state and assigned != state and not self.switching:
                    print("[agent] Dispatcher 指派状态 %s ≠ 本机 %s，触发切换" %
                          (assigned, state))
                    self.do_switch(assigned, None, 0)
            r.close()
        except (RedisError, OSError):
            pass

    # ── 主循环 ────────────────────────────────────────────────
    def run_pubsub(self):
        """独立线程：订阅 sbf:ctrl 接收即时指令。"""
        while self.running:
            try:
                r = Redis(self.redis_url, timeout=0).connect()
                for _ch, msg in PubSub(r, ["sbf:ctrl"]).listen():
                    if not self.running:
                        break
                    self.handle_command(msg)
            except (RedisError, OSError) as e:
                if self.running:
                    print("[agent] pubsub 断开：%s，%ds 后重连" % (e, self.poll_interval),
                          file=sys.stderr)
                    time.sleep(self.poll_interval)

    def run(self):
        print("[agent] 启动  node=%s  redis=%s" % (self.node_id, self.redis_url))
        print("[agent] 当前状态: %s" % (read_current_state() or "(未指派)"))

        t = threading.Thread(target=self.run_pubsub, daemon=True)
        t.start()

        last_import = 0.0
        while self.running:
            self.heartbeat()
            now = time.time()
            if now - last_import >= self.import_interval:
                n = self.import_seeds()
                if n:
                    print("[agent] 导入下发种子 %d 个 → foreign_sync" % n)
                last_import = now
            time.sleep(self.poll_interval)

        print("[agent] 已停止")

    def stop(self, *_):
        self.running = False


def main():
    ap = argparse.ArgumentParser(description="SandboxFuzzer ECS 节点控制面代理")
    ap.add_argument("--node-id", default=os.environ.get("NODE_ID",
                                                       __import__("socket").gethostname()))
    ap.add_argument("--redis", default=os.environ.get("REDIS_URL",
                                                      "redis://127.0.0.1:6379/0"))
    ap.add_argument("--poll-interval", type=int, default=5)
    ap.add_argument("--import-interval", type=int, default=3)
    args = ap.parse_args()

    agent = NodeAgent(args.node_id, args.redis, args.poll_interval, args.import_interval)
    signal.signal(signal.SIGTERM, agent.stop)
    signal.signal(signal.SIGINT, agent.stop)
    agent.run()


if __name__ == "__main__":
    main()
