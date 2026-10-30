#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_seedhub_probe.py —— seedhub 崩溃探测的口径回归
===================================================

`local_seedhub.probe_crash()` 的判定口径必须与 `sandbox_harness.c` 完全一致，
否则会出现「seedhub 说安全、AFL++ 说 crash」的口径漂移。这里守五个曾经
对不上的点，每一条都有一个能复现 bug 的用例：

    ① 前缀整块 sendall     → 粘包，状态推演失效（PASS 根本没执行）
    ② 不读 banner          → banner 被当成「载荷的应答」，空前缀的状态
                             永远判成活着，崩溃样本全漏
    ③ 应答只 recv 一次     → 前缀/多行应答的残留被误当成「载荷的应答」
    ④ 无二次复现           → 时机型 flaky 崩溃被误归档（审查 F1③）
    ⑤ 裸 connect 判活      → 半死靶（监听在、工作线程亡）被判活（审查 F1④）
    ⑥ 「重复=0」总量差口径  → 分配/语料各错一条互相抵消（审查 F4）

mock 服务端刻意照抄 LightFTP 的两个行为，否则测不出东西：
    · 连上先送一行 banner
    · **一次 recv 到的整个缓冲当一条命令**（粘包语义）
    · USER 的应答把参数原样回显（整块发时参数里带 \\r\\n，应答内嵌 \\r\\n，
      按行计数一次就数出多行 —— 这是 ① 最阴的地方，静默失效不报错）

跑法:
    python3 tests/test_seedhub_probe.py
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from local_seedhub import LocalSeedHub  # noqa: E402


# ── mock 靶机：照抄 LightFTP 的粘包与畸形回显 ─────────────────────
class MockTarget:
    def __init__(self) -> None:
        self.log: list = []          # 每收到【一条】命令记一条
        self.dead = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._thr = threading.Thread(target=self._accept_loop, daemon=True)
        self._thr.start()

    def _accept_loop(self) -> None:
        while not self.dead:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _send(conn, data: bytes) -> None:
        try:
            conn.sendall(data)
        except OSError:
            pass

    def _serve(self, conn) -> None:
        state = "init"
        try:
            self._send(conn, b"220 mock ready\r\n")          # banner
            while not self.dead:
                try:
                    buf = conn.recv(4096)
                except OSError:
                    return
                if not buf:
                    return
                # ★ 粘包：整个缓冲当【一条】命令。这是 LightFTP 的真实行为。
                cmd = buf.strip(b"\r\n")
                self.log.append(cmd)
                head, _, arg = cmd.partition(b" ")
                head = head.upper()

                if head == b"USER":
                    state = "user"
                    # ★ 畸形回显：参数里有什么就回什么。整块发时参数含 \r\n，
                    #   于是这一条应答里内嵌 \r\n，按行计数一次数出多行。
                    self._send(conn, b"331 User " + arg + b" OK. Password required\r\n")
                elif head == b"PASS":
                    if state == "user":
                        state = "auth"
                        self._send(conn, b"230 Login OK.\r\n")
                    else:
                        self._send(conn, b"530 Not logged in.\r\n")
                elif head == b"WHOAMI":
                    self._send(conn, b"200 state=" + state.encode() + b"\r\n")
                elif head == b"NOOP":
                    self._send(conn, b"200 OK.\r\n")
                elif head == b"DIE":                        # 回一包再死
                    self._send(conn, b"200 bye\r\n")
                    self.kill()
                    return
                elif head == b"DIE_NOW":                    # 不回包直接死
                    self.kill()
                    return
                else:
                    self._send(conn, b"500 unknown\r\n")
        finally:
            # 必须显式关 conn：只把监听套接字关掉，客户端那头收不到 EOF，
            # 只能等满 socket 超时才拿到 OSError，测试会平白慢一截。
            try:
                conn.close()
            except OSError:
                pass

    def kill(self) -> None:
        """靶机物理死亡：之后 connect() 必须失败（probe_crash 的判据）。

        光 close() 不够：accept 线程还阻塞在内核里，它自己握着一份 socket
        引用，监听套接字在内核层面依然 LISTEN，backlog 照样吃新连接 ——
        于是「二次连接」永远成功，probe_crash 永远判不出崩溃。
        真实靶机是【整个进程】退出才没有这个问题。
        shutdown(SHUT_RDWR) 才能把阻塞的 accept() 唤醒并让新连接吃 RST。
        """
        self.dead = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def close(self) -> None:
        self.kill()

    # —— 便捷断言 ——
    def talk(self, *msgs, prefix=b"", banner_lines=1):
        """逐条发（模拟 send_prefix），返回最后一条的应答文本。"""
        s = socket.socket()
        s.settimeout(1.0)
        s.connect(("127.0.0.1", self.port))
        hub = LocalSeedHub.__new__(LocalSeedHub)   # 只用静态/无状态方法
        hub.banner_lines = banner_lines
        try:
            if banner_lines > 0:
                LocalSeedHub.recv_lines(s, banner_lines)
            if prefix:
                assert hub.send_prefix(s, prefix), "send_prefix 失败"
            last = b""
            for m in msgs:
                s.sendall(m)
                buf = b""
                try:
                    while True:
                        c = s.recv(4096)
                        if not c:
                            break
                        buf += c
                        if b"\n" in buf:
                            break
                except OSError:
                    pass
                last = buf
            return last.decode("latin-1", "replace")
        finally:
            s.close()


PASS, FAIL = 0, 0


# ── 时机型 flaky 靶机：只死一次，保活循环拉起后免疫 ──────────────
class FlakyTarget(MockTarget):
    """第一次 DIE_ONCE 打死自己，0.12s 后（模拟 sbf-server-loop）拉起并
    免疫后续同命令 —— 重放杀不死。confirm_crash 的二次复现必须把这类样本
    挡在 crashes/ 外（审查 F1③），否则时机型 flaky 会被误归档。"""

    def __init__(self):
        self.killed_once = False
        super().__init__()

    def _serve(self, conn) -> None:
        try:
            self._send(conn, b"220 mock ready\r\n")
            while not self.dead:
                try:
                    buf = conn.recv(4096)
                except OSError:
                    return
                if not buf:
                    return
                cmd = buf.strip(b"\r\n")
                self.log.append(cmd)
                head = cmd.upper()
                if head.startswith(b"DIE_ONCE"):
                    if not self.killed_once:
                        self._send(conn, b"200 bye\r\n")   # 回一包再死
                        self.kill()
                        return
                    self._send(conn, b"200 still here\r\n")
                elif head.startswith(b"NOOP"):
                    self._send(conn, b"200 OK.\r\n")
                else:
                    self._send(conn, b"500 unknown\r\n")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def kill(self) -> None:
        if self.killed_once:
            return                      # 第二次起：免疫，不再死
        self.killed_once = True
        self.dead = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
        threading.Thread(target=self._restart, daemon=True).start()

    def _restart(self) -> None:
        time.sleep(0.12)                # 保活循环的拉起延迟
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.listen(8)
        self.dead = False
        threading.Thread(target=self._accept_loop, daemon=True).start()


# ── 半死靶：监听还在、工作线程亡 ────────────────────────────────
class HalfDeadTarget:
    """connect 成功但永远不应答（接受连接后晾着）。

    旧口径裸 connect 会把它判活；判活必须走 PROBE_CMD 应答（审查 F1④）。
    对照 sandbox_harness.c 的 target_alive 注释：「连得上但无应答 → 不活」。
    """

    def __init__(self):
        self.conns = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.conns.append(conn)     # 接下就晾着：无人应答，也无人关连接

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
        for c in self.conns:
            try:
                c.close()
            except OSError:
                pass


def check(cond, label, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {label}")
    else:
        FAIL += 1
        print(f"  ✗ {label}" + (f"\n      {detail}" if detail else ""))


# ── 用例 ─────────────────────────────────────────────────────────
def test_split_msgs():
    print("① split_msgs：消息边界按 '\\n'，空行不是报文")
    got = LocalSeedHub.split_msgs(b"USER a\r\nPASS b\r\n")
    check(got == [b"USER a\r\n", b"PASS b\r\n"], "两条报文拆开", repr(got))
    got = LocalSeedHub.split_msgs(b"\r\nUSER a\r\n\r\n")
    check(got == [b"USER a\r\n"], "空行跳过", repr(got))
    got = LocalSeedHub.split_msgs(b"NOOP\r\n")
    check(got == [b"NOOP\r\n"], "单条保持", repr(got))


def test_prefix_delivery():
    print("② 前缀必须逐条发（粘包会让状态推演完全失效）")
    t = MockTarget()
    try:
        reply = t.talk(b"WHOAMI\r\n", prefix=b"USER admin\r\nPASS 123456\r\n")
        check(len(t.log) == 3,
              f"服务端看到 3 条独立命令（实得 {len(t.log)}）", repr(t.log))
        check(t.log == [b"USER admin", b"PASS 123456", b"WHOAMI"],
              "命令边界没被粘在一起", repr(t.log))
        check("state=auth" in reply,
              f"前缀建起了登录态（实得 {reply!r}）")

        # 反证：整块发时服务端只看到 1 条命令，状态停在 user
        t2 = MockTarget()
        try:
            s = socket.socket(); s.settimeout(1.0)
            s.connect(("127.0.0.1", t2.port))
            s.recv(256)                                   # banner
            s.sendall(b"USER admin\r\nPASS 123456\r\n")   # 整块发 ← bug
            s.recv(1024)
            s.sendall(b"WHOAMI\r\n")
            bad = s.recv(1024).decode("latin-1", "replace")
            s.close()
            check(len(t2.log) == 2 and b"PASS" not in t2.log[1],
                  "对照：整块发时 PASS 确实没被执行（bug 可复现）",
                  repr(t2.log))
            check("state=auth" not in bad,
                  f"对照：整块发时状态停在 user（实得 {bad!r}）")
        finally:
            t2.close()
    finally:
        t.close()


def test_banner_not_a_reply():
    print("③ banner 不能当成「载荷的应答」（空前缀状态才测得出来）")
    t = MockTarget()
    try:
        hub = LocalSeedHub.__new__(LocalSeedHub)
        hub.probe_host, hub.probe_port = "127.0.0.1", t.port
        hub.banner_lines = 1
        # 前缀为空（state_0_USER / state_4_NOOP 就是这种）
        is_crash = hub.probe_crash(b"DIE_NOW\r\n", b"")
        check(is_crash, "无应答且二次连接失败 → 判为崩溃样本", f"实得 {is_crash}")
    finally:
        t.close()


def test_residue_not_a_reply():
    print("④ 前缀/多行应答的残留不能当成「载荷的应答」")
    t = MockTarget()
    try:
        hub = LocalSeedHub.__new__(LocalSeedHub)
        hub.probe_host, hub.probe_port = "127.0.0.1", t.port
        hub.banner_lines = 1
        # 一条 600 字节的单行应答：只 recv 一次(512B) 会留下尾巴
        long_arg = b"x" * 600
        is_crash = hub.probe_crash(b"DIE_NOW\r\n", b"USER " + long_arg + b"\r\n")
        check(is_crash, "残留没掩盖靶机死亡 → 判为崩溃样本", f"实得 {is_crash}")

        # 反证：活着的靶机不能被误判成崩溃
        t2 = MockTarget()
        try:
            hub.probe_host, hub.probe_port = "127.0.0.1", t2.port
            is_crash = hub.probe_crash(b"NOOP\r\n", b"USER " + long_arg + b"\r\n")
            check(not is_crash, "活着的靶机不被误杀", f"实得 {is_crash}")
        finally:
            t2.close()
    finally:
        t.close()


def test_flaky_not_archived():
    print("⑤ flaky 载荷经二次复现不归档（审查 F1③）")
    t = FlakyTarget()
    try:
        hub = LocalSeedHub.__new__(LocalSeedHub)
        hub.probe_host, hub.probe_port = "127.0.0.1", t.port
        hub.banner_lines = 1
        is_crash = hub.probe_crash(b"DIE_ONCE\r\n", b"")
        check(t.killed_once, "靶机确实被打死过一次（场景成立）")
        check(not is_crash, "重放杀不死 → 不归档为崩溃样本", f"实得 {is_crash}")
    finally:
        t.close()


def test_half_dead_judged_dead():
    print("⑥ 半死靶必须判死（审查 F1④：裸 connect 会误判成活）")
    t = HalfDeadTarget()
    try:
        s = socket.socket()
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", t.port))
            bare_ok = True
        except OSError:
            bare_ok = False
        finally:
            s.close()
        check(bare_ok, "反证：裸 connect 确实连得上（旧口径会判活）")

        hub = LocalSeedHub.__new__(LocalSeedHub)
        hub.probe_host, hub.probe_port = "127.0.0.1", t.port
        hub.banner_lines = 0
        is_crash = hub.probe_crash(b"NOOP\r\n", b"")
        check(is_crash, "PROBE_CMD 判活下判死 → 归档为崩溃样本", f"实得 {is_crash}")
    finally:
        t.close()


def test_overlap_set_based():
    print("⑦ 「重复」按 (state, sha256) 集合算真实交并差（审查 F4）")
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        hub = LocalSeedHub("st", os.path.join(td, "out"),
                           os.path.join(td, "corpus"), os.path.join(td, "work"), 2)
        a, b, c = "a" * 8, "b" * 8, "c" * 8
        for d in (a, b):
            with open(os.path.join(hub.corpus_dir, d + ".raw"), "wb") as f:
                f.write(b"x")

        def put(k, digest):
            with open(os.path.join(hub.work_dir(k), digest + ".raw"), "wb") as f:
                f.write(b"x")

        def reset():
            for k in range(2):
                for n in os.listdir(hub.work_dir(k)):
                    os.remove(os.path.join(hub.work_dir(k), n))

        # 反例：corpus={A,B}，分片0={A}，分片1={A} —— 总量差=0，
        # 旧口径报「重复=0」，实际 A 被投喂了两次
        put(0, a)
        put(1, a)
        _, _, overlap = hub.report()
        check(overlap == 1,
              f"总量差=0 的抵消场景仍报出重叠（实得 重复={overlap}）")

        # 分片里有、池里没有（池/分片不一致）
        reset()
        put(0, a)
        put(1, c)
        _, _, overlap = hub.report()
        check(overlap == 1, f"池外种子报出孤儿（实得 重复={overlap}）")

        # 干净分片：零重复
        reset()
        put(0, a)
        put(1, b)
        _, _, overlap = hub.report()
        check(overlap == 0, f"干净分片不误报（实得 重复={overlap}）")


def main() -> int:
    print("=" * 70)
    print("seedhub 崩溃探测口径回归（对照 sandbox_harness.c）")
    print("=" * 70)
    test_split_msgs()
    test_prefix_delivery()
    test_banner_not_a_reply()
    test_residue_not_a_reply()
    test_flaky_not_archived()
    test_half_dead_judged_dead()
    test_overlap_set_based()
    print("-" * 70)
    print(f"  通过 {PASS}   失败 {FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
