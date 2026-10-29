#!/usr/bin/env python3
"""
finding_sync.py — ECS 节点异步种子回传守护进程（数据面）

职责边界（对应架构原则）：
  1. 微观本地过滤由 AFL++ 自己完成 —— 没触发 New Edge 的变异根本不进 queue/，
     本进程看不见它们，也就【零网络通信】。
  2. 只有 queue/ 里的高价值种子和 crashes/ 里的崩溃会被搬运。
  3. 两级流水线：
       一级（本地，立即）：把新发现拷进本地 sync_outbox/，纯本地 IO；
       二级（网络，异步）：每隔 interval 秒批量打包，RPUSH 给中央 Dispatcher。
  4. 去重靠 sha256 水位线，绝不重复上报。

用法:
  ./finding_sync.py --state state_2_auth --outdir results/state_2_auth \
                    --outbox sync_outbox/state_2_auth \
                    --redis redis://127.0.0.1:6379/0 --interval 5
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import signal
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sbf_redis import Redis, RedisError  # noqa: E402

MAX_PAYLOAD = 512 * 1024      # 超过此大小的样本不内联上传
WATERMARK = ".finding_sync_state.json"


class FindingSync:
    def __init__(self, state, node_id, outdir, outbox, redis_url, interval):
        self.state = state
        self.node_id = node_id
        self.outdir = outdir
        self.outbox = outbox
        self.redis_url = redis_url
        self.interval = max(1, int(interval))
        self.running = True

        os.makedirs(os.path.join(outbox, "seeds"), exist_ok=True)
        os.makedirs(os.path.join(outbox, "crashes"), exist_ok=True)

        self.state_path = os.path.join(outbox, WATERMARK)
        self.watermark = self._load_watermark()
        self.r = None

    # ── 水位线 ────────────────────────────────────────────────
    def _load_watermark(self):
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                d = json.load(f)
                return {
                    "seen": set(d.get("seen", [])),   # 已入库（本地 outbox）
                    "sent": set(d.get("sent", [])),   # 已上报（Redis）
                }
        except (OSError, ValueError):
            return {"seen": set(), "sent": set()}

    def _save_watermark(self):
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({
                "seen": sorted(self.watermark["seen"]),
                "sent": sorted(self.watermark["sent"]),
                "updated": time.time(),
            }, f)
        os.replace(tmp, self.state_path)

    # ── 扫描 AFL++ 输出目录 ──────────────────────────────────
    def scan(self):
        """返回本轮新发现的 (kind, instance, abspath, sha256)。"""
        found = []
        if not os.path.isdir(self.outdir):
            return found

        for instance in sorted(os.listdir(self.outdir)):
            inst_dir = os.path.join(self.outdir, instance)
            if not os.path.isdir(inst_dir):
                continue
            for kind, sub in (("seed", "queue"), ("crash", "crashes")):
                src_dir = os.path.join(inst_dir, sub)
                if not os.path.isdir(src_dir):
                    continue
                for name in sorted(os.listdir(src_dir)):
                    # AFL++ 自述文件与非 id: 样本跳过
                    if not name.startswith("id:"):
                        continue
                    path = os.path.join(src_dir, name)
                    if not os.path.isfile(path):
                        continue
                    try:
                        with open(path, "rb") as f:
                            blob = f.read()
                    except OSError:
                        continue
                    h = hashlib.sha256(blob).hexdigest()
                    if h in self.watermark["seen"]:
                        continue
                    self.watermark["seen"].add(h)
                    found.append((kind, instance, path, h, blob))
        return found

    # ── 一级：本地立即落盘（零网络）──────────────────────────
    def stash_locally(self, kind, instance, name, blob, h):
        dest_dir = os.path.join(self.outbox, "seeds" if kind == "seed" else "crashes")
        orig = os.path.basename(name)
        dest = os.path.join(dest_dir, "%s_%s" % (h[:16], orig))
        if not os.path.exists(dest):
            with open(dest, "wb") as f:
                f.write(blob)
            # 附带一份元数据，便于离线排查
            with open(dest + ".meta.json", "w", encoding="utf-8") as f:
                json.dump({
                    "kind": kind, "instance": instance,
                    "original_name": orig,
                    "sha256": h, "size": len(blob),
                    "state": self.state, "node_id": self.node_id,
                    "ts": time.time(),
                }, f, ensure_ascii=False)
        return dest, orig

    # ── 二级：异步批量上报 ───────────────────────────────────
    def _connect(self):
        if not self.redis_url:
            return None
        if self.r is None or self.r.sock is None:
            try:
                self.r = Redis(self.redis_url).connect()
            except (RedisError, OSError) as e:
                print("[finding_sync] Redis 暂不可用：%s（本地 outbox 继续累积）" % e,
                      file=sys.stderr)
                self.r = None
        return self.r

    def _read_stats(self):
        """从 fuzzer_stats 抽取摘要，随种子一起上报，供 Dispatcher 评估价值。"""
        out = {}
        stats = os.path.join(self.outdir, "fuzzer_master", "fuzzer_stats")
        try:
            with open(stats, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if ":" not in line:
                        continue
                    k, v = line.split(":", 1)
                    k, v = k.strip(), v.strip()
                    if k in ("execs_done", "execs_per_sec", "corpus_count",
                             "saved_crashes", "bitmap_cvg", "edges_found"):
                        out[k] = v
        except OSError:
            pass
        return out

    def flush(self):
        """把 outbox 里尚未上报的样本打包推给 Dispatcher。"""
        if not self.redis_url:
            return 0
        r = self._connect()
        if r is None:
            return 0

        pending = []
        for kind, sub in (("seed", "seeds"), ("crash", "crashes")):
            d = os.path.join(self.outbox, sub)
            if not os.path.isdir(d):
                continue
            for name in sorted(os.listdir(d)):
                if name.endswith(".meta.json"):
                    continue
                path = os.path.join(d, name)
                if not os.path.isfile(path):
                    continue
                try:
                    with open(path, "rb") as f:
                        blob = f.read()
                except OSError:
                    continue
                h = hashlib.sha256(blob).hexdigest()
                if h in self.watermark["sent"]:
                    continue
                # 上报用 AFL++ 原始文件名，而不是 outbox 里的 hash 前缀名
                orig = name
                try:
                    with open(path + ".meta.json", "r", encoding="utf-8") as mf:
                        orig = json.load(mf).get("original_name", name)
                except (OSError, ValueError):
                    pass
                pending.append((kind, orig, path, h, blob))

        if not pending:
            return 0

        stats = self._read_stats()
        ok = 0
        for kind, name, path, h, blob in pending:
            if len(blob) > MAX_PAYLOAD:
                print("[finding_sync] 跳过超大样本 %s (%d bytes)" % (name, len(blob)),
                      file=sys.stderr)
                self.watermark["sent"].add(h)
                continue

            record = {
                "v": 1,
                "kind": kind,
                "node_id": self.node_id,
                "state": self.state,
                "hash": h,
                "name": name,
                "size": len(blob),
                "ts": time.time(),
                "host": socket.gethostname(),
                "stats": stats,
                "payload_b64": base64.b64encode(blob).decode("ascii"),
            }
            key = "sbf:%s:%s" % ("seed" if kind == "seed" else "crash", self.state)
            try:
                r.rpush(key, json.dumps(record, ensure_ascii=False))
            except (RedisError, OSError) as e:
                print("[finding_sync] 上报失败：%s（保留待发）" % e, file=sys.stderr)
                self._save_watermark()
                return ok

            self.watermark["sent"].add(h)
            ok += 1

        self._save_watermark()
        return ok

    def publish_status(self):
        if not self.redis_url:
            return
        r = self._connect()
        if r is None:
            return
        try:
            r.hset("sbf:node:%s:status" % self.node_id, {
                "state": self.state,
                "pid": str(os.getpid()),
                "hostname": socket.gethostname(),
                "last_sync_ts": str(time.time()),
                "queued": str(len(self.watermark["seen"])),
                "reported": str(len(self.watermark["sent"])),
            })
        except (RedisError, OSError):
            pass

    # ── 主循环 ────────────────────────────────────────────────
    def run(self):
        print("[finding_sync] 启动  state=%s node=%s outdir=%s" %
              (self.state, self.node_id, self.outdir))
        print("[finding_sync] outbox=%s  interval=%ds  redis=%s" %
              (self.outbox, self.interval, self.redis_url or "(disabled)"))

        last_flush = 0.0
        while self.running:
            # 一级：本地扫描 + 立即入 outbox，无任何网络
            try:
                found = self.scan()
            except OSError as e:
                print("[finding_sync] 扫描失败：%s" % e, file=sys.stderr)
                found = []

            if found:
                for kind, instance, path, h, blob in found:
                    self.stash_locally(kind, instance, path, blob, h)
                self._save_watermark()
                kinds = {}
                for k, *_ in found:
                    kinds[k] = kinds.get(k, 0) + 1
                print("[finding_sync] 本地暂存 %d 个新发现 %s" % (len(found), kinds))

            # 二级：按间隔异步批量上报
            now = time.time()
            if now - last_flush >= self.interval:
                n = self.flush()
                if n:
                    print("[finding_sync] 异步上报 %d 个样本 → Redis" % n)
                self.publish_status()
                last_flush = now

            time.sleep(0.5)

        # 退出前尽量冲刷
        self.flush()
        self._save_watermark()
        if self.r:
            self.r.close()
        print("[finding_sync] 已停止")

    def stop(self, *_):
        self.running = False


def main():
    ap = argparse.ArgumentParser(description="SandboxFuzzer 异步种子回传守护进程")
    ap.add_argument("--state", required=True, help="当前协议状态名")
    ap.add_argument("--node-id", required=True, help="节点标识")
    ap.add_argument("--outdir", required=True, help="AFL++ 输出目录 (-o 的值)")
    ap.add_argument("--outbox", required=True, help="本地同步暂存目录")
    ap.add_argument("--redis", default="", help="Redis URL，留空则只做本地暂存")
    ap.add_argument("--interval", type=int, default=5, help="网络上报间隔（秒）")
    args = ap.parse_args()

    fs = FindingSync(args.state, args.node_id, args.outdir, args.outbox,
                     args.redis, args.interval)
    signal.signal(signal.SIGTERM, fs.stop)
    signal.signal(signal.SIGINT, fs.stop)
    fs.run()


if __name__ == "__main__":
    main()
