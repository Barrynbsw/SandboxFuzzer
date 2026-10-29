#!/usr/bin/env python3
"""
seed_dispatcher.py — 中央 Dispatcher

汇总全集群的高价值发现，并把种子横向分发给【同状态】的其它节点。

核心不变量：只在同状态的节点之间分发种子。跨状态分发会让种子的前缀语义失效
（S2 的 STOR 种子喂给 S0 的沙箱毫无意义），这也是"状态同质化"的必然推论。

Redis 键约定
  上报（节点 → Dispatcher）
    sbf:seed:<state>        LIST  高价值种子记录 (JSON)
    sbf:crash:<state>       LIST  崩溃记录 (JSON)
    sbf:node:<id>:status    HASH  节点心跳 / 当前状态
  指派（Dispatcher → 节点）
    sbf:assignment:<id>     STRING  该节点应当处于的状态
    sbf:ctrl                PUB/SUB 控制指令
  下发（Dispatcher → 节点）
    sbf:dist:seed:<state>   LIST  待导入本机 foreign_sync 的种子
    sbf:dist:crash:<state>  LIST  待归档的崩溃样本

用法:
  ./seed_dispatcher.py run                 # 常驻：收割 + 去重 + 分发
  ./seed_dispatcher.py --stats             # 查看集群状态
  ./seed_dispatcher.py --assign ecs-01 state_2_auth
  ./seed_dispatcher.py --assign-all state_1_user
  ./seed_dispatcher.py --switch state_2_auth   # 让全体节点切到某状态
"""

import argparse
import base64
import hashlib
import json
import os
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sbf_redis import Redis, RedisError  # noqa: E402

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STORE_DIR = os.path.join(SCRIPT_DIR, "store")


class Dispatcher:
    def __init__(self, redis_url, interval=2, redistribute=True):
        self.redis_url = redis_url
        self.interval = max(1, interval)
        self.redistribute = redistribute
        self.running = True
        self.r = None

    def connect(self):
        if self.r is None or self.r.sock is None:
            try:
                self.r = Redis(self.redis_url).connect()
            except (RedisError, OSError) as e:
                print("[dispatcher] Redis 连接失败：%s" % e, file=sys.stderr)
                self.r = None
        return self.r

    # ── 收割上报 ──────────────────────────────────────────────
    def harvest(self):
        r = self.connect()
        if r is None:
            return 0, 0

        seeds_new, crashes_new = 0, 0
        # 从已知节点状态里推断活跃状态集合；再补上 store 目录里的历史状态
        states = self.known_states()

        for state in states:
            for kind, out_key in (("seed", "sbf:dist:seed:%s" % state),
                                  ("crash", "sbf:dist:crash:%s" % state)):
                src = "sbf:%s:%s" % (kind, state)
                seen = "sbf:seen:%s:%s" % (kind, state)

                for _ in range(256):
                    try:
                        raw = r.lpop(src)
                    except (RedisError, OSError):
                        break
                    if not raw:
                        break
                    try:
                        rec = json.loads(raw)
                    except ValueError:
                        continue

                    h = rec.get("hash") or hashlib.sha256(
                        base64.b64decode(rec.get("payload_b64", "") or b"")).hexdigest()
                    rec["hash"] = h

                    # 全局去重：同一个样本只收一次，也只分发一次
                    try:
                        if r.sismember(seen, h):
                            continue
                        r.sadd(seen, h)
                    except (RedisError, OSError):
                        continue

                    self.store(state, kind, rec)

                    if kind == "seed":
                        seeds_new += 1
                        if self.redistribute:
                            try:
                                r.rpush(out_key, json.dumps(rec, ensure_ascii=False))
                            except (RedisError, OSError):
                                pass
                    else:
                        crashes_new += 1
                        # 崩溃样本全集群广播，供各节点离线复现
                        try:
                            r.rpush(out_key, json.dumps(rec, ensure_ascii=False))
                        except (RedisError, OSError):
                            pass

        return seeds_new, crashes_new

    def known_states(self):
        states = set()
        if os.path.isdir(STORE_DIR):
            for d in os.listdir(STORE_DIR):
                if os.path.isdir(os.path.join(STORE_DIR, d)):
                    states.add(d)
        # 从 node 状态 hash 里补齐
        try:
            for key in (self.r.execute("KEYS", "sbf:node:*:status") or []):
                key = key.decode() if isinstance(key, bytes) else key
                st = self.r.hgetall(key).get("state", "")
                if st:
                    states.add(st)
        except (RedisError, OSError):
            pass
        if not states:
            # 兜底：常见状态名
            states = {"state_0_init", "state_1_user", "state_2_auth"}
        return states

    def store(self, state, kind, rec):
        d = os.path.join(STORE_DIR, state, kind + "s")
        os.makedirs(d, exist_ok=True)
        name = rec.get("name", "x")
        # 兼容旧版 finding_sync 的 outbox 命名（hash16_ 前缀），避免重复叠加
        if not name.startswith(rec["hash"][:16] + "_"):
            name = "%s_%s" % (rec["hash"][:16], name)
        path = os.path.join(d, name)
        if not os.path.exists(path):
            try:
                with open(path, "wb") as f:
                    f.write(base64.b64decode(rec.get("payload_b64", "") or b""))
                meta = {k: v for k, v in rec.items() if k != "payload_b64"}
                with open(path + ".meta.json", "w", encoding="utf-8") as f:
                    json.dump(meta, f, ensure_ascii=False, indent=2)
            except OSError as e:
                print("[dispatcher] 落盘失败 %s: %s" % (path, e), file=sys.stderr)

    # ── 集群状态 ──────────────────────────────────────────────
    def stats(self):
        r = self.connect()
        if r is None:
            print("[!] Redis 不可用")
            return
        print("=" * 66)
        print("  SandboxFuzzer 集群状态")
        print("=" * 66)
        print("  Dispatcher 存档: %s" % STORE_DIR)
        print("")

        nodes = []
        try:
            keys = r.execute("KEYS", "sbf:node:*:status") or []
            for key in keys:
                key = key.decode() if isinstance(key, bytes) else key
                node = key.split(":")[2]
                info = r.hgetall(key)
                assigned = r.get("sbf:assignment:%s" % node) or b""
                assigned = assigned.decode() if isinstance(assigned, bytes) else assigned
                nodes.append((node, info.get("state", ""), assigned, info))
        except (RedisError, OSError) as e:
            print("  [!] 读取节点失败: %s" % e)

        print("  %-16s %-16s %-16s %-12s" % ("Node", "Current", "Assigned", "Last HB"))
        print("  " + "-" * 62)
        for node, cur, assigned, info in sorted(nodes):
            hb = info.get("hb_ts") or info.get("last_sync_ts") or ""
            try:
                ago = "%.0fs ago" % (time.time() - float(hb)) if hb else "-"
            except ValueError:
                ago = "-"
            print("  %-16s %-16s %-16s %-12s" % (node, cur or "-", assigned or "-", ago))

        if not nodes:
            print("  (暂无节点上报)")

        print("")
        print("  各状态发现量:")
        if os.path.isdir(STORE_DIR):
            for state in sorted(os.listdir(STORE_DIR)):
                sd = os.path.join(STORE_DIR, state)
                ns = len(os.listdir(os.path.join(sd, "seeds"))) // 2 if os.path.isdir(
                    os.path.join(sd, "seeds")) else 0
                nc = len(os.listdir(os.path.join(sd, "crashes"))) // 2 if os.path.isdir(
                    os.path.join(sd, "crashes")) else 0
                print("    %-16s seeds=%-6d crashes=%d" % (state, ns, nc))
        else:
            print("    (暂无)")
        print("=" * 66)

    # ── 状态指派 ──────────────────────────────────────────────
    def assign(self, node, state):
        r = self.connect()
        if r is None:
            raise RedisError("Redis 不可用")
        r.set("sbf:assignment:%s" % node, state)
        r.publish("sbf:ctrl", json.dumps({
            "op": "switch_state", "node_id": node, "state": state,
        }, ensure_ascii=False))
        print("[dispatcher] 已指派 %s → %s" % (node, state))

    def assign_all(self, state):
        r = self.connect()
        if r is None:
            raise RedisError("Redis 不可用")
        nodes = []
        for key in (r.execute("KEYS", "sbf:node:*:status") or []):
            key = key.decode() if isinstance(key, bytes) else key
            nodes.append(key.split(":")[2])
        if not nodes:
            print("[dispatcher] 未发现在线节点")
            return
        for n in nodes:
            self.assign(n, state)

    # ── 主循环 ────────────────────────────────────────────────
    def run(self):
        print("[dispatcher] 启动  redis=%s  interval=%ds  redistribute=%s" %
              (self.redis_url, self.interval, self.redistribute))
        while self.running:
            try:
                s, c = self.harvest()
                if s or c:
                    print("[dispatcher] 新入库 seeds=%d crashes=%d" % (s, c))
            except (RedisError, OSError) as e:
                print("[dispatcher] 收割异常：%s" % e, file=sys.stderr)
            time.sleep(self.interval)
        if self.r:
            self.r.close()
        print("[dispatcher] 已停止")

    def stop(self, *_):
        self.running = False


def main():
    ap = argparse.ArgumentParser(description="SandboxFuzzer 中央 Dispatcher")
    ap.add_argument("cmd", nargs="?", default="run",
                    choices=["run", "stats", "harvest"])
    ap.add_argument("--redis", default=os.environ.get("REDIS_URL",
                                                      "redis://127.0.0.1:6379/0"))
    ap.add_argument("--interval", type=int, default=2)
    ap.add_argument("--no-redistribute", action="store_true",
                    help="只收不发（观察模式）")
    ap.add_argument("--stats", action="store_true", help="显示集群状态（同 stats 子命令）")
    ap.add_argument("--assign", nargs=2, metavar=("NODE", "STATE"),
                    help="把某节点指派到某状态")
    ap.add_argument("--assign-all", metavar="STATE", help="把全部节点指派到某状态")
    ap.add_argument("--switch", metavar="STATE", help="全体节点原子切换到某状态")
    args = ap.parse_args()

    d = Dispatcher(args.redis, args.interval,
                   redistribute=not args.no_redistribute)

    if args.assign:
        return d.assign(*args.assign)
    if args.assign_all:
        return d.assign_all(args.assign_all)
    if args.switch:
        return d.assign_all(args.switch)
    if args.cmd == "stats" or args.stats:
        return d.stats()
    if args.cmd == "harvest":
        s, c = d.harvest()
        print("harvested seeds=%d crashes=%d" % (s, c))
        return

    signal.signal(signal.SIGTERM, d.stop)
    signal.signal(signal.SIGINT, d.stop)
    d.run()


if __name__ == "__main__":
    main()
