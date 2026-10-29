#!/usr/bin/env python3
"""
local_seedhub.py — 本地优质种子共享枢纽（纯本地，零网络）

解决两件必须同时成立的事：
  1. 【共享】多个 AFL++ 进程共用一个优质种子池，任何进程的发现都进入公共池；
  2. 【不重复】同一个种子在任一时刻只交给【一个】进程去变异。

为什么不能用 AFL++ 的 -M/-S 盲同步：
  盲同步会把每个实例的 queue/ 全量灌给其它实例，结果 N 个进程都在测全量语料，
  同一个种子被重复变异 N 次 —— 这正是要避免的浪费。

做法：
  · 各实例使用【独立的 -o 父目录】，从根上杜绝 AFL++ 互相扫描 queue/
    （AFL++ 的 sync_dir == out_dir，见 afl-fuzz-init.c）
  · 公共池 corpus/<state>/ 是唯一真源，按 sha256 去重
  · 每个种子按 sha256 % N 指派唯一 owner，只投喂到 work/<state>/<owner>/
    该目录是 owner 实例的 -F (foreign sync) 目录，只有它会吸收
  · 初始语料同样分片，开跑即分工，不存在"全员先测一遍全量"

用法:
  ./local_seedhub.py --state state_2_auth --instances 4 --bootstrap   # 开跑前分片
  ./local_seedhub.py --state state_2_auth --instances 4               # 常驻协调
"""

import argparse
import hashlib
import json
import os
import signal
import socket
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

CRASH_DIR_NAME = "crashes"   # AFL++ crashes/ 子目录
QUEUE_DIR_NAME = "queue"     # AFL++ queue/  子目录


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def owner_of(digest, n_instances):
    """确定性分片：同一个种子在同一批实例数下永远归同一人。"""
    if n_instances <= 0:
        return 0
    return int(digest[:8], 16) % n_instances


def index_of_found_by(found_by):
    """
    把 meta 里的 found_by（形如 "i1/fuzzer_1"）映射回实例序号。
    初始语料 / 未知来源返回 None。
    """
    if not found_by:
        return None
    head = found_by.split("/")[0]
    if len(head) > 1 and head[0] == "i" and head[1:].isdigit():
        return int(head[1:])
    return None


class LocalSeedHub:
    def __init__(self, state, out_base, corpus_root, work_root, n_instances,
                 init_seed_dir=None, interval=2.0, owner_mode="hash",
                 probe_host="127.0.0.1", probe_port=None, prefix_file=None):
        self.state = state
        self.out_base = out_base
        self.n_instances = max(1, int(n_instances))
        self.interval = max(0.5, float(interval))
        self.init_seed_dir = init_seed_dir
        # 崩溃探测：与 sandbox_harness.c 的"代理自杀式判定"同口径
        self.probe_host = probe_host
        self.probe_port = int(probe_port) if probe_port else None
        self.prefix_file = prefix_file
        # hash   : owner = sha256 % N，发现者≠owner 时会投喂给 owner
        #          —— 跨进程真正共享优质种子，代价是"发现者残留" 1 份
        # finder : owner = 发现者，运行期零重复；跨进程交换只在重新分片时发生
        self.owner_mode = owner_mode if owner_mode in ("hash", "finder") else "hash"

        self.corpus_dir = os.path.join(corpus_root, state)
        self.crash_dir = os.path.join(corpus_root, state, "crashes")
        self.work_root = os.path.join(work_root, state)
        self.init_root = os.path.join(corpus_root, state, "init_shards")

        for d in (self.corpus_dir, self.crash_dir, self.work_root, self.init_root):
            os.makedirs(d, exist_ok=True)
        for k in range(self.n_instances):
            os.makedirs(self.work_dir(k), exist_ok=True)

        self.running = True

    def owner_for(self, digest, meta):
        """决定一个池内种子归谁。"""
        if self.owner_mode == "finder":
            idx = index_of_found_by((meta or {}).get("found_by"))
            if idx is not None and 0 <= idx < self.n_instances:
                return idx
        return owner_of(digest, self.n_instances)

    def _load_meta(self, digest):
        try:
            with open(os.path.join(self.corpus_dir, digest + ".json"),
                      "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    # ── 路径 ──────────────────────────────────────────────────
    def work_dir(self, k):
        return os.path.join(self.work_root, str(k))

    def init_dir(self, k):
        return os.path.join(self.init_root, str(k))

    # ── 优质种子入库 ──────────────────────────────────────────
    def ingest(self, blob, found_by, orig_name, is_crash):
        """返回 (digest, is_new)。"""
        digest = sha256_bytes(blob)

        if is_crash:
            path = os.path.join(self.crash_dir, digest + ".raw")
            if os.path.exists(path):
                return digest, False
            with open(path, "wb") as f:
                f.write(blob)
            self._write_meta(digest, blob, found_by, orig_name, is_crash,
                             base=self.crash_dir)
            return digest, True

        path = os.path.join(self.corpus_dir, digest + ".raw")
        if os.path.exists(path):
            return digest, False
        with open(path, "wb") as f:
            f.write(blob)
        self._write_meta(digest, blob, found_by, orig_name, is_crash,
                         base=self.corpus_dir)
        return digest, True

    def _write_meta(self, digest, blob, found_by, orig_name, is_crash, base):
        meta = {
            "sha256": digest,
            "size": len(blob),
            "found_by": found_by,
            "original_name": orig_name,
            "is_crash": bool(is_crash),
            "state": self.state,
            "owner": self.owner_for(digest, {"found_by": found_by}),
            "ts": time.time(),
        }
        with open(os.path.join(base, digest + ".json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)

    # ── 扫描各实例的 AFL++ 输出 ───────────────────────────────
    def _instance_dirs(self):
        """
        找出所有含 queue/ 的 AFL++ 实例目录。

        布局是 results/<state>/i<k>/<sync_id>/queue/ —— 每个实例有独立的 -o
        父目录，AFL++ 才不会互相盲同步（sync_dir == out_dir）。
        """
        found = []
        if not os.path.isdir(self.out_base):
            return found
        for a in sorted(os.listdir(self.out_base)):
            pa = os.path.join(self.out_base, a)
            if not os.path.isdir(pa):
                continue
            if os.path.isdir(os.path.join(pa, QUEUE_DIR_NAME)):
                found.append(pa)
                continue
            for b in sorted(os.listdir(pa)):
                pb = os.path.join(pa, b)
                if os.path.isdir(pb) and os.path.isdir(os.path.join(pb, QUEUE_DIR_NAME)):
                    found.append(pb)
        return found

    def scan_instances(self):
        """把各实例 queue/ 里的新边缘种子、crashes/ 里的崩溃收集进公共池。"""
        new_seeds, new_crashes = [], []

        for inst_path in self._instance_dirs():
            entry = os.path.relpath(inst_path, self.out_base)
            for kind, sub, sink in (("seed", QUEUE_DIR_NAME, new_seeds),
                                    ("crash", CRASH_DIR_NAME, new_crashes)):
                d = os.path.join(inst_path, sub)
                if not os.path.isdir(d):
                    continue
                for name in sorted(os.listdir(d)):
                    if not name.startswith("id:"):
                        continue
                    p = os.path.join(d, name)
                    if not os.path.isfile(p):
                        continue
                    try:
                        with open(p, "rb") as f:
                            blob = f.read()
                    except OSError:
                        continue
                    if not blob:
                        continue
                    digest, is_new = self.ingest(blob, entry, name,
                                                 kind == "crash")
                    if is_new:
                        sink.append((digest, blob, entry, name))
        return new_seeds, new_crashes

    # ── 分片投喂（去重分工的核心）─────────────────────────────
    def assign(self):
        """
        让每个种子只出现在它 owner 的 -F 目录里。
        返回 (moved_in, moved_out, residual)：
          residual = 发现者≠owner 的种子数（发现者 queue 里那份无法回收，
                     是 AFL++ 队列只增不减带来的固有残留）。
        """
        moved_in = moved_out = residual = 0
        wanted = {k: set() for k in range(self.n_instances)}

        for name in sorted(os.listdir(self.corpus_dir)):
            if not name.endswith(".raw"):
                continue
            digest = name[:-4]
            meta = self._load_meta(digest)
            k = self.owner_for(digest, meta)
            wanted[k].add(digest)

            # 发现者残留：owner 接到投喂，发现者自己那份还在 queue 里
            fb = index_of_found_by(meta.get("found_by"))
            if fb is not None and fb != k:
                residual += 1

            dest = os.path.join(self.work_dir(k), digest + ".raw")
            if not os.path.exists(dest):
                src = os.path.join(self.corpus_dir, name)
                # 硬链接，池子与投喂目录共享同一份数据，省磁盘
                try:
                    os.link(src, dest)
                except OSError:
                    with open(src, "rb") as f:
                        data = f.read()
                    with open(dest, "wb") as f:
                        f.write(data)
                moved_in += 1

        # 清掉不属于该实例的投喂文件 —— 这就是"避免大家在测同一种子"
        for k in range(self.n_instances):
            wd = self.work_dir(k)
            for name in os.listdir(wd):
                if not name.endswith(".raw"):
                    continue
                digest = name[:-4]
                if digest not in wanted[k]:
                    try:
                        os.remove(os.path.join(wd, name))
                        moved_out += 1
                    except OSError:
                        pass

        return moved_in, moved_out, residual

    # ── 崩溃探测（与 sandbox_harness.c 同口径）───────────────
    def _wait_target(self):
        for _ in range(50):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            try:
                s.connect((self.probe_host, self.probe_port))
                s.close()
                return True
            except OSError:
                s.close()
                time.sleep(0.1)
        return False

    def probe_crash(self, blob, prefix):
        """
        这个载荷会不会打死靶机？

        判定口径【完全复刻 sandbox_harness.c】——否则会出现"这边说安全、
        那边 AFL++ 说 crash"的口径漂移，正是 fuzzer_0 起不来的根因：
            连上 → 发前缀 → 发载荷 → recv
            recv 失败 → 再开一条新连接；连不上 = 靶机已物理死亡 = 崩溃样本
        """
        # 靶机可能刚被上一个崩溃样本打死，保活循环需要 ~0.1s 拉起，这里重试
        s = None
        for _ in range(10):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                s.connect((self.probe_host, self.probe_port))
                break
            except OSError:
                s.close()
                s = None
                time.sleep(0.1)
        if s is None:
            return False   # 靶机没起来，无从判定；宁可放行也不误杀

        got = -1
        try:
            if prefix:
                try:
                    s.sendall(prefix)
                    s.recv(512)
                except OSError:
                    pass
            s.sendall(blob)
            try:
                got = len(s.recv(512))
            except OSError:
                got = -1
        finally:
            s.close()

        if got > 0:
            return False   # 靶机有响应，活得好好的

        p = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        p.settimeout(0.3)
        try:
            p.connect((self.probe_host, self.probe_port))
            p.close()
            return False   # 二次连接成功 → 只是超时，不是崩溃
        except OSError:
            p.close()
            return True    # 二次连接失败 → 靶机已死

    # ── 初始语料分片（开跑即分工）────────────────────────────
    def bootstrap(self):
        """
        把初始种子按同一分片规则切成 N 份，供各实例作为 -i 目录。

        关键：初始语料里【混着崩溃样本】（state_1_user 的 "PASS CRASH"、
        state_2_auth 的 "STOR BUG"）。AFL++ 要求 -i 里至少有一个不崩的种子，
        否则干跑把种子全跳过后直接退出
            "We need at least one valid input seed that does not crash!"
        该实例就永远写不出 fuzzer_stats —— 这正是 fuzzer_0 N/A 的根因。

        所以先探测分类：
          崩溃样本 → corpus/<state>/crashes/   （它本来就是发现物，归档）
          正常样本 → init_shards/<k>/          （按 sha256%N 唯一 owner）
        """
        if not self.init_seed_dir or not os.path.isdir(self.init_seed_dir):
            print("[seedhub] 无初始种子目录，跳过 bootstrap")
            return

        for k in range(self.n_instances):
            os.makedirs(self.init_dir(k), exist_ok=True)

        prefix = b""
        if self.prefix_file and os.path.isfile(self.prefix_file):
            with open(self.prefix_file, "rb") as f:
                prefix = f.read()

        if self.probe_port:
            if not self._wait_target():
                print("[seedhub] 警告：靶机 %s:%s 未就绪，跳过崩溃探测"
                      % (self.probe_host, self.probe_port))

        n_crash = 0
        n_seed = 0
        for name in sorted(os.listdir(self.init_seed_dir)):
            p = os.path.join(self.init_seed_dir, name)
            if not os.path.isfile(p):
                continue
            try:
                with open(p, "rb") as f:
                    blob = f.read()
            except OSError:
                continue
            if not blob:
                continue

            is_crash = bool(self.probe_port) and self.probe_crash(blob, prefix)
            digest, _ = self.ingest(blob, "init", name, is_crash)

            if is_crash:
                n_crash += 1
                print("[seedhub] 初始语料崩溃样本 → crashes/  %-10s %s"
                      % (name, digest[:16]))
                continue

            k = owner_of(digest, self.n_instances)
            dest = os.path.join(self.init_dir(k), "%s_%s" % (digest[:16], name))
            if not os.path.exists(dest):
                with open(dest, "wb") as f:
                    f.write(blob)
                n_seed += 1

        # AFL++ 要求 -i 目录非空。空分片需要一个占位种子，但【绝不能】
        # 复用别的分片里的真实种子 —— 那会造成两个实例在测同一种子，
        # 正是本模块要消灭的现象。占位内容按分片序号生成，天然互不相同。
        n_pad = 0
        for k in range(self.n_instances):
            d = self.init_dir(k)
            if any(os.path.isfile(os.path.join(d, x)) for x in os.listdir(d)):
                continue
            blob = b"SBF-PLACEHOLDER-%d\r\n" % k
            if self.probe_port and self.probe_crash(blob, prefix):
                blob = b"HELP %d\r\n" % k   # 兜底：HELP 不会触发任何 abort()
            with open(os.path.join(d, "placeholder_%d.raw" % k), "wb") as f:
                f.write(blob)
            n_pad += 1
            print("[seedhub] 分片 %d 无正常种子，放入唯一占位种子（不与他人重复）" % k)

        print("[seedhub] bootstrap 完成：%d 个正常种子 → %d 个分片  "
              "崩溃样本=%d  占位=%d" % (n_seed, self.n_instances, n_crash, n_pad))
        self.assign()

    # ── 观测 ──────────────────────────────────────────────────
    def report(self):
        counts = []
        for k in range(self.n_instances):
            wd = self.work_dir(k)
            n = len([x for x in os.listdir(wd) if x.endswith(".raw")])
            counts.append(n)
        total_corpus = len([x for x in os.listdir(self.corpus_dir)
                            if x.endswith(".raw")])
        total_assigned = sum(counts)
        # 期望：分片总量 == 池子总量（每个种子恰好一个 owner）
        overlap = max(0, total_assigned - total_corpus)

        # 发现者残留：owner≠发现者 的种子（发现者 queue 里那份回收不了）
        residual = 0
        for name in os.listdir(self.corpus_dir):
            if not name.endswith(".raw"):
                continue
            digest = name[:-4]
            meta = self._load_meta(digest)
            fb = index_of_found_by(meta.get("found_by"))
            if fb is not None and fb != self.owner_for(digest, meta):
                residual += 1

        print("[seedhub] 池=%d  分片=%s  合计=%d  重复=%d  发现者残留=%d" %
              (total_corpus, counts, total_assigned, overlap, residual))
        return total_corpus, counts, overlap

    # ── 主循环 ────────────────────────────────────────────────
    def run(self):
        print("[seedhub] 启动  state=%s  实例数=%d  owner模式=%s" %
              (self.state, self.n_instances, self.owner_mode))
        print("[seedhub] 公共池: %s" % self.corpus_dir)
        print("[seedhub] 投喂目录: %s/<0..%d>  (-F 指向)" %
              (self.work_root, self.n_instances - 1))
        self.assign()

        last_report = 0.0
        while self.running:
            new_seeds, new_crashes = self.scan_instances()
            if new_seeds or new_crashes:
                print("[seedhub] 新入库 优质种子=%d  崩溃=%d" %
                      (len(new_seeds), len(new_crashes)))
            moved_in, moved_out, residual = self.assign()
            if moved_in or moved_out:
                print("[seedhub] 重新分片  投喂+%d  收回%d  发现者残留=%d" %
                      (moved_in, moved_out, residual))

            now = time.time()
            if now - last_report >= 10.0:
                self.report()
                last_report = now

            time.sleep(self.interval)

        self.report()
        print("[seedhub] 已停止")

    def stop(self, *_):
        self.running = False


def main():
    ap = argparse.ArgumentParser(description="本地优质种子共享枢纽（去重分工）")
    ap.add_argument("--state", required=True, help="当前协议状态名")
    ap.add_argument("--instances", type=int, required=True,
                    help="本机 AFL++ 实例数（分片数）")
    ap.add_argument("--out-base", default=None,
                    help="AFL++ 输出根目录，默认 results/<state>")
    ap.add_argument("--corpus-root", default=os.path.join(SCRIPT_DIR, "corpus"))
    ap.add_argument("--work-root", default=os.path.join(SCRIPT_DIR, "work"))
    ap.add_argument("--init-seed-dir", default=None,
                    help="初始种子目录，配合 --bootstrap 使用")
    ap.add_argument("--bootstrap", action="store_true",
                    help="只做初始语料分片后退出")
    ap.add_argument("--report", action="store_true",
                    help="只做一次分片整理并打印核查结果后退出")
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--owner-mode", choices=["hash", "finder"], default="hash",
                    help="hash=按 sha256%%N 分片(跨进程共享)；"
                         "finder=发现者继续跟进(运行期零重复)")
    ap.add_argument("--probe-port", type=int, default=None,
                    help="靶机端口；提供则 bootstrap 前探测初始语料里的崩溃样本")
    ap.add_argument("--probe-host", default="127.0.0.1")
    ap.add_argument("--prefix-file", default=None,
                    help="状态前缀报文，探测时按 harness 口径先发前缀")
    args = ap.parse_args()

    out_base = args.out_base or os.path.join(SCRIPT_DIR, "results", args.state)

    hub = LocalSeedHub(args.state, out_base, args.corpus_root, args.work_root,
                       args.instances, args.init_seed_dir, args.interval,
                       args.owner_mode, args.probe_host, args.probe_port,
                       args.prefix_file)

    if args.bootstrap:
        hub.bootstrap()
        hub.report()
        return

    if args.report:
        hub.scan_instances()
        hub.assign()
        hub.report()
        return

    signal.signal(signal.SIGTERM, hub.stop)
    signal.signal(signal.SIGINT, hub.stop)
    hub.run()


if __name__ == "__main__":
    main()
