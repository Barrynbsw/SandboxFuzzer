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


def _norm_probe_cmd(cmd):
    """PROBE_CMD 归一成 bytes：str/bytes 都收，缺行尾补 \\r\\n。

    harness（sandbox_harness.c 的 g_probe_cmd）是【原样发送】的，默认
    "NOOP\\r\\n"；适配器给的 TARGET_PROBE_CMD 同值，逐字节对齐。
    """
    if not cmd:
        return b"NOOP\r\n"
    b = cmd.encode("latin-1") if isinstance(cmd, str) else bytes(cmd)
    if not b.endswith(b"\n"):
        b += b"\r\n"
    return b


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
    # 与 sandbox_harness.c 的 g_probe_cmd 同默认值。类属性兜底：
    # 测试里 __new__ 出来的实例也要能判活。
    probe_cmd = b"NOOP\r\n"

    def __init__(self, state, out_base, corpus_root, work_root, n_instances,
                 init_seed_dir=None, interval=2.0, owner_mode="hash",
                 probe_host="127.0.0.1", probe_port=None, prefix_file=None,
                 banner_lines=0, probe_cmd=None):
        self.state = state
        self.out_base = out_base
        self.n_instances = max(1, int(n_instances))
        self.interval = max(0.5, float(interval))
        self.init_seed_dir = init_seed_dir
        # 崩溃探测：与 sandbox_harness.c 的"代理自杀式判定"同口径
        self.probe_host = probe_host
        self.probe_port = int(probe_port) if probe_port else None
        self.prefix_file = prefix_file
        self.probe_cmd = _norm_probe_cmd(probe_cmd)
        # 连上后靶机先送几行 banner（FTP/SSH/SMTP）。不读掉它，banner 就会被
        # 当成"载荷的应答" —— 于是【前缀为空】的状态永远判成"活着"，
        # 崩溃样本全漏掉。与 TARGET_BANNER_LINES / read_banner() 同一约定。
        self.banner_lines = int(banner_lines)
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
    def _wait_target(self, tries=50, interval=0.1):
        """等靶机【恢复应答能力】—— 判活走 target_alive()，不是裸 connect。

        单次判活压到 0.2s：半死靶（连得上但不应答）每次尝试都会吃满超时，
        等待预算不能被单次超时拖穿。
        """
        for _ in range(tries):
            if self.target_alive(timeout=0.2):
                return True
            time.sleep(interval)
        return False

    def target_alive(self, timeout=0.5):
        """与 sandbox_harness.c 的 target_alive() 同口径：连上 + 读 banner +
        发 PROBE_CMD + 收到一条应答行。

        只裸 connect 不够：半死靶（监听在、工作线程亡）连得上但不应答，
        裸 connect 会把它判活。三个阶段全覆盖（对照 harness 注释）：
          落 core 中   → 连得上但无应答  → 不活
          已死未重启   → 连不上          → 不活
          保活拉起后   → 连得上且有应答  → 活

        超时默认 0.5s（harness 在 fuzz 循环里给 60s）：bootstrap 是离线分类，
        真靶机的 NOOP 应答在 ms 级，0.5s 不应答视同不活，不用陪跑慢靶。
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((self.probe_host, self.probe_port))
            if self.banner_lines > 0 and self.recv_lines(s, self.banner_lines) < 0:
                return False
            try:
                s.sendall(self.probe_cmd)
            except OSError:
                return False
            return self.recv_lines(s, 1) >= 0
        except OSError:
            return False
        finally:
            s.close()

    def _attack_once(self, blob, prefix):
        """一轮完整攻击：连上 → 读 banner → 逐条发前缀 → 发载荷 → 收应答。

        返回 (是否连上, 收到的应答字节数)。"连上"必须单独报：
        靶机根本没起来时无从判定，宁可放行也不误杀 —— 这时不能走进复现确认，
        否则 2ms/30ms 判活会对一具"从头就不存在的尸体"连判两次死，整个初始
        语料都会被误归档成崩溃。
        """
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
            return False, -1

        got = -1
        try:
            # banner 属于「连接建立」，不属于任何一条消息，必须先读掉
            if self.banner_lines > 0 and self.recv_lines(s, self.banner_lines) < 0:
                got = -1
            elif not self.send_prefix(s, prefix):
                got = -1      # 前缀都没应答了，多半是上一个样本打死的
            else:
                try:
                    s.sendall(blob)
                    got = self.recv_lines(s, 1)
                except OSError:
                    got = -1
        finally:
            s.close()
        return True, got

    # ── 探测口径（三条都必须与 sandbox_harness.c 对齐）────────────
    @staticmethod
    def split_msgs(blob):
        """把前缀串按 '\\n' 拆成逐条报文。

        消息边界取 '\\n'，与 send_prefix_msgs() / recv_lines() /
        TARGET_BANNER_LINES 同一约定。空行（裸 \\n）不是报文，跳过。
        """
        out, start = [], 0
        while start < len(blob):
            end = blob.find(b"\n", start)
            end = len(blob) if end < 0 else end + 1
            msg = blob[start:end]
            if msg.strip(b"\r\n"):
                out.append(msg)
            start = end
        return out

    @staticmethod
    def recv_lines(s, need, respsz=65536, idle=0.0):
        """读满 need 条应答行（以 \\n 结尾）；返回字节数，-1 = 无应答/断开。

        两件事都得做，少一件就误判：

        · 按【行数】读而不是 recv 一次。前缀是两条命令两条应答，只 recv 一次
          会把第二条留在套接字里，下一次 recv 就把它误当成「载荷的应答」，
          从而掩盖靶机死亡。
        · 读满之后把同一连接上余下的应答捞干净（= sandbox_harness.c 的
          drain_pending）。一条命令可能回多行（FTP 的 HELP；LightFTP 的畸形
          回显会把参数里的 \\r\\n 原样吐出来），留着的那几行同样会被下一次读
          误认。

        drain 用【非阻塞】：残留只在缓冲里已经有数据时才存在，空转不会等超时。
        idle>0 时才改成等一小会儿（给慢应答一个机会），默认不等。
        """
        old = s.gettimeout()
        got = total = 0
        try:
            while got < need and total < respsz:
                try:
                    n = s.recv(min(4096, respsz - total))
                except OSError:
                    return -1
                if not n:
                    return -1
                total += len(n)
                got += n.count(b"\n")
            if got < need:
                return -1
            s.settimeout(idle)
            while True:
                try:
                    if not s.recv(4096):
                        break
                except OSError:
                    break
        finally:
            s.settimeout(old)
        return total

    def send_prefix(self, s, prefix):
        """前缀要【逐条报文】发：一条命令一次 send + 等一条应答。

        实测 LightFTP 把一次 recv 的整个缓冲当成【一条】命令：
            sendall(b"USER admin\\r\\nPASS 123456\\r\\n")
              → '331 User admin\\r\\nPASS 123456 OK. Password required'
        用户名被回显成 "admin\\r\\nPASS 123456"，PASS 根本没执行 —— 整块发
        等于状态推演完全失效，后面的载荷全程打在【未登录会话】上。
        更阴的是这条应答内嵌 \\r\\n，按行计数会数出两行，静默失效不报错。
        """
        for msg in self.split_msgs(prefix):
            try:
                s.sendall(msg)
            except OSError:
                return False
            if self.recv_lines(s, 1) < 0:
                return False
        return True

    def probe_crash(self, blob, prefix):
        """
        这个载荷会不会打死靶机？判定口径与 sandbox_harness.c 对齐：
            连上 → 读 banner → 逐条发前缀（每条等一条应答）→ 发载荷
            → 【事后判活】（不是看本轮拿没拿到应答）
            → 不活则复现确认：等靶机回来重放同一载荷，
              2ms 后 PROBE_CMD 判活 + 30ms 再判一次，两次都判死才算

        曾经对不上的五处（前四处已全部对齐）：
          ① 前缀整块 sendall   → 粘包，状态推演失效（见 send_prefix）
          ② 不读 banner        → banner 被当成「载荷的应答」，前缀为空的
                                 状态（state_0/state_4）永远判成活着，崩溃全漏
          ③ 应答只 recv 一次   → 前缀的第二条应答残留，被误当成载荷的应答
          ④ 无二次复现         → 时机型 flaky 崩溃被误归档。harness 的
                                 confirm_crash 是重放 + 2ms/30ms 两次判活，
                                 这里同构（见 _confirm_crash）
          ⑤ 裸 connect 判活    → 半死靶（监听在、工作线程亡）被判活。
                                 判活一律走 PROBE_CMD 应答（见 target_alive）
        "事后判活"也是 harness 主循环的结构（发完载荷才 target_alive）：
        "回一包再慢慢死"的载荷只有事后判活才抓得到。

        与 confirm_crash 的一处有意差异：靶机彻底起不来（保活没拉起）时，
        harness 选择「宁可漏报」不确认；bootstrap 分类宁可归档 —— 攻击轮已
        证明载荷送进【活的】靶机之后它才死，且归档样本还要过 replay_judge
        双向判卷，误归档会被拦下，漏掉的崩溃样本则再没人找回。
        """
        connected, _ = self._attack_once(blob, prefix)
        if not connected:
            return False   # 靶机没起来，无从判定；宁可放行也不误杀
        if self.target_alive():
            return False   # 发完载荷还能应答，活得好好的
        return self._confirm_crash(blob, prefix)

    def _confirm_crash(self, blob, prefix):
        """复现确认，对齐 sandbox_harness.c 的 confirm_crash：
        同一载荷重放一次 + 2ms/30ms 两次 PROBE_CMD 判活，两次都判死才算。

        真崩溃落 core 的 ~115ms 窗口内两次都不应答；"慢但活着"的靶机在
        2ms 那次就会应答，从而免于误报；flaky 载荷重放杀不死 → 不归档。
        """
        up = self._wait_target(tries=20, interval=0.01)   # 等保活拉起，≈200ms
        if up:
            self._attack_once(blob, prefix)               # 重放，结果忽略
        time.sleep(0.002)                                 # 让 abort() 发作
        if self.target_alive():
            return False
        time.sleep(0.030)                                 # 30ms 远在落 core 窗口(≈115ms)内
        return not self.target_alive()

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
        shard_sets = []
        for k in range(self.n_instances):
            wd = self.work_dir(k)
            digests = {name[:-4] for name in os.listdir(wd)
                       if name.endswith(".raw")}
            shard_sets.append(digests)
            counts.append(len(digests))
        corpus_digests = {name[:-4] for name in os.listdir(self.corpus_dir)
                          if name.endswith(".raw")}
        total_corpus = len(corpus_digests)
        total_assigned = sum(counts)
        # 「重复」按 (state, sha256) 集合算真实交并差（审查 F4）：
        #   multi  = 同一 digest 落进 ≥2 个分片（违背唯一 owner）
        #   orphan = 分片里有、池里没有（池/分片不一致）
        # 旧口径 max(0, 总量差) 是差值指标：分配端与语料端各错一条会互相
        # 抵消仍报 0。反例：corpus={A,B}，分片0={A}，分片1={A} ——
        # 总量差=0 报"重复=0"，实际 A 被投喂了两次。
        union = set().union(*shard_sets) if shard_sets else set()
        multi = sum(len(s) for s in shard_sets) - len(union)
        orphan = len(union - corpus_digests)
        overlap = multi + orphan

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
    ap.add_argument("--banner-lines", type=int, default=0,
                    help="连上后靶机先送几行 banner，必须先读掉"
                         "（与 TARGET_BANNER_LINES 同值）")
    ap.add_argument("--probe-cmd", default=None,
                    help="判活命令（默认 NOOP，与 harness 的 PROBE_CMD 同值）")
    args = ap.parse_args()

    out_base = args.out_base or os.path.join(SCRIPT_DIR, "results", args.state)

    hub = LocalSeedHub(args.state, out_base, args.corpus_root, args.work_root,
                       args.instances, args.init_seed_dir, args.interval,
                       args.owner_mode, args.probe_host, args.probe_port,
                       args.prefix_file, args.banner_lines, args.probe_cmd)

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
