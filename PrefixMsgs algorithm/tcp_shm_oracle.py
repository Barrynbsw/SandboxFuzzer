#!/usr/bin/env python3
"""
tcp_shm_oracle.py — 给算法 2 补一个能驱动【网络服务】的覆盖率后端

`prefix_msg_identify.py` 自带的 `ShowmapOracle` 把载荷从 stdin 喂给
`afl-showmap -- <target>`，这对文件/标准输入型目标够用，但对 **TCP 服务**
完全无效 —— LightFTP 这类目标不从 stdin 读数据。

这里改用沙箱侧同一套机制：目标用 `afl-clang-fast` 编译，启动时设
`__AFL_SHM_ID=<私有段号>`，AFL++ 运行时把 `__afl_area_ptr` 指到那个段，
插桩自动把边写进去 —— **目标源码零改动**。然后：

    run_sequence([M0, M1, ...])   同一条 TCP 会话里逐条发送，
                                  返回每条的【增量】覆盖率
    run_single(blob)              全新会话里把 blob 当一整条发，返回总覆盖率

这与 `sandbox_harness.c` 的 `merge_target_trace()` 用的是同一个 SHM，
也就是说：**微观本地过滤**和**前缀识别**共用同一套零侵入覆盖率注入。

用法（被 prefix_msg_identify.py / protocol_seed_analyzer.py 作为后端）：

    oracle = TcpShmOracle(["./third_party/lightftp/fftp", "conf"], port=9001)
    ...
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import socket
import subprocess
import time
from typing import Sequence

Coverage = frozenset  # 与 prefix_msg_identify.py 的别名一致

SHM_SIZE = 65536


class Shm:
    """System V 共享内存段（与 sandbox_harness.c 的 target_trace 同一个）。"""

    def __init__(self, size: int = SHM_SIZE) -> None:
        libc = ctypes.CDLL(ctypes.util.find_library("c"))
        libc.shmget.restype = ctypes.c_int
        libc.shmat.restype = ctypes.c_void_p
        self._libc = libc
        self.size = size
        self.id = libc.shmget(0, size, 0o1000 | 0o666)   # IPC_PRIVATE
        if self.id < 0:
            raise RuntimeError("shmget 失败（内核段数可能已达上限）")
        self.addr = libc.shmat(self.id, None, 0)
        if self.addr in (0, ctypes.c_void_p(-1).value):
            raise RuntimeError("shmat 失败")
        self.buf = (ctypes.c_ubyte * size).from_address(self.addr)
        self.zero()

    def zero(self) -> None:
        ctypes.memset(self.addr, 0, self.size)

    def snapshot(self) -> Coverage:
        """当前非零偏移集合 = 这段时间内被点亮的边。"""
        b = self.buf
        return frozenset(i for i in range(self.size) if b[i])

    def destroy(self) -> None:
        self._libc.shmdt(ctypes.c_void_p(self.addr))
        self._libc.shmctl(self.id, 0, None)   # IPC_RMID


class TcpShmOracle:
    """用 __AFL_SHM_ID 注入采集 TCP 会话的逐条边覆盖。

    target_cmd   目标启动命令行，例如 ["./fftp", "fftp.conf"]
    port         目标监听端口（由启动器/适配器决定）
    banner_lines 连上后目标主动送几行 banner（FTP=1）。必须先读掉，
                 否则会把 banner 的覆盖算进第一条消息头上。
    """

    def __init__(
        self,
        target_cmd: Sequence[str],
        port: int,
        host: str = "127.0.0.1",
        shm_size: int = SHM_SIZE,
        banner_lines: int = 0,
        settle: float = 0.08,
        start_timeout: float = 4.0,
    ) -> None:
        self.target_cmd = list(target_cmd)
        self.port = port
        self.host = host
        self.shm_size = shm_size
        self.banner_lines = banner_lines
        self.settle = settle
        self.start_timeout = start_timeout
        self._proc: subprocess.Popen | None = None
        self._shm: Shm | None = None
        self._bg: Coverage = frozenset()   # 会话簿记边集，见 _sample_background

    # ── 进程生命周期 ──────────────────────────────────────────────
    def start(self) -> None:
        self._shm = Shm(self.shm_size)
        env = os.environ.copy()
        env["__AFL_SHM_ID"] = str(self._shm.id)
        env["AFL_NO_FORKSRV"] = "1"      # 常驻服务，不能进 forkserver 握手
        self._proc = subprocess.Popen(
            self.target_cmd, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + self.start_timeout
        while time.time() < deadline:
            try:
                s = socket.socket()
                s.settimeout(0.2)
                s.connect((self.host, self.port))
                s.close()
                self._bg = self._sample_background()
                if self._bg:
                    print(f"[shm] 会话簿记边集 = {sorted(self._bg)}"
                          f"（{len(self._bg)} 条），每次快照自动扣除",
                          flush=True)
                return
            except OSError:
                time.sleep(0.05)
        self.stop()
        raise RuntimeError(f"目标起不来: {self.target_cmd} :{self.port}")

    def _sample_background(self, seconds: float = 1.2) -> Coverage:
        """采「会话簿记」点亮的边 —— 这些边不属于任何一条消息。

        多线程靶机有【常驻的并发线程】往同一个 SHM 落笔：LightFTP 的 ftpmain
        监听线程（main.c:185 pthread_create）和每连接的 ftp_client_thread
        并发跑。实测只有一条边（834）会这样漏进来，但它总在【消息处理中途】
        冒出来 —— `_quiesce` 等不掉，因为那是活线程在跑，不是退出线程的残留。

        后果与退出线程污染同形：DIFF 恰好 = 1/|Cov|，看着像一条稳定的弱依赖，
        实测能把会话级前置集从 [USER, PASS] 撑成 5 条假阳性，而且重跑又变回去。

        关键：这条边只在【有连接进出】时才走得到（accept / 建线程 / 线程退出）。
        所以纯空转采样大概率采不到它 —— 必须自己制造连接抖动才采得全。
        分两段采，取并集：

            阶段 1  空转窗口：抓周期性/纯后台分支
            阶段 2  连接抖动：反复 connect→close（一条消息都不发），
                    抓 accept / 建线程 / 线程退出这条簿记路径

        采出来之后每次快照都把它【减掉】（见 _snap）。减掉是安全的：base 与
        drop 两次测量减的是同一个集合，cov_diff 不受影响；只有 union_size
        会略微变小，影响不到 edge_threshold 的量级。

        这是第一道防线；第二道是算法侧的共识核（consensus，多数票）。
        """
        if self._shm is None:
            return frozenset()
        acc: set = set()
        deadline = time.time() + seconds

        # 阶段 1：空转 —— 什么都不发，只看靶机自己在写什么
        while time.time() < deadline:
            self._shm.zero()
            time.sleep(0.02)
            acc |= self._shm.snapshot()

        # 阶段 2：连接抖动 —— 连上就读掉 banner 再关，一条命令都不发
        deadline = time.time() + seconds
        while time.time() < deadline:
            self._shm.zero()
            try:
                s = socket.socket()
                s.settimeout(0.3)
                s.connect((self.host, self.port))
                if self.banner_lines > 0:
                    got, buf = 0, b""
                    while got < self.banner_lines:
                        chunk = s.recv(256)
                        if not chunk:
                            break
                        buf += chunk
                        got = buf.count(b"\n")
                s.close()
            except OSError:
                pass
            time.sleep(0.03)      # 等客户端线程走完退出路径再采
            acc |= self._shm.snapshot()

        self._shm.zero()
        return frozenset(acc)

    def _snap(self) -> Coverage:
        """快照并减去后台边集 —— 只留本条消息点亮的边。"""
        cur = self._shm.snapshot()
        if not self._bg:
            return cur
        return frozenset(cur - self._bg)

    def stop(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.kill()
            self._proc.wait()
        self._proc = None
        if self._shm is not None:
            self._shm.destroy()
            self._shm = None

    def __enter__(self) -> "TcpShmOracle":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ── 一次会话 ──────────────────────────────────────────────────
    def _connect(self) -> socket.socket:
        s = socket.socket()
        s.settimeout(2.0)
        s.connect((self.host, self.port))
        # banner 先读掉；它属于"连接建立"，不属于任何一条消息
        if self.banner_lines > 0:
            got, buf = 0, b""
            while got < self.banner_lines:
                chunk = s.recv(256)
                if not chunk:
                    break
                buf += chunk
                got = buf.count(b"\n")
        return s

    def _drain(self, s: socket.socket) -> None:
        """把服务端应答读到静默 —— 这就是「命令处理完了」的同步点。

        覆盖率是服务端处理命令时写进 SHM 的，sendall 完立刻快照会系统性
        低估（网络往返 + 处理还没做完）。收到应答说明处理结束，此时采样
        才准。顺带把应答排空，避免 TCP 窗口堵住服务端。
        """
        s.settimeout(self.settle)
        try:
            while s.recv(4096):
                pass
        except socket.timeout:
            pass          # 静默了 = 这一轮处理结束
        except OSError:
            pass          # 对端关连接（如 QUIT），同样算结束
        s.settimeout(2.0)

    def _quiesce(self, window: float = 0.05, timeout: float = 1.5) -> None:
        """等上一条会话的线程真正退干净，再开下一条。

        LightFTP 每条连接起一个线程。`s.close()` 只关 socket，线程还要走
        退出路径，而那条路径的覆盖是【写进同一个 SHM】的 —— 下一次测量清零
        之后它才落笔，于是凭空多出 1~2 条边（实测是 834 这类）。

        这不是噪声，是**跨会话污染**，而且成簇出现（取决于线程退出时机）：
        它让依赖矩阵的 DIFF 恰好等于 1/16 = 0.0625，看起来像一条稳定的弱依赖，
        实测能把会话级前置集从 [USER, PASS] 撑成 5 条假阳性。

        做法：清零 SHM，轮询到连续 window 秒没有新边才认为静默。

        SBF_NO_QUIESCE=1 可以关掉（仅供回归探针验证它有牙齿，别在正式测量里用）。
        """
        if self._shm is None or os.environ.get("SBF_NO_QUIESCE"):
            return
        self._shm.zero()
        deadline = time.time() + timeout
        while time.time() < deadline:
            before = self._shm.snapshot()
            time.sleep(window)
            if self._shm.snapshot() == before:
                self._shm.zero()
                return
        self._shm.zero()

    def _measure(self, blobs: Sequence[bytes]) -> list[Coverage]:
        """在一条新会话里逐条发送 blobs，返回每条【自身处理】点亮的边集。

        关键：**每条发送前清零 SHM**。这样得到的是「处理本条消息点亮了哪些边」，
        而不是「本条新点亮了哪些边」。二者不同，而且差别是致命的：

          cur - acc（增量）会把与前面消息共用的样板边（命令分发、应答发送…）
          全部去重掉。实测 LightFTP 的 PWD 在登录/未登录两种状态下
          【增量覆盖完全相同】(都是 {196,197,737,739,745} 五条边)，
          因为差异部分正好落在已被前面消息点亮的边里；
          但「自身覆盖」不同 —— 未登录走 530 早退，登录后走 strcpy/strcat 拼 257。

          算法 2 的 DIFF(Cov(Mi), CovT(Mi)) 问的是「移除 Mx 后 My 还能不能达到
          同样的覆盖」，需要的是后者。用增量会让 USER/PASS 被误判成非前缀。
        """
        if self._shm is None or self._proc is None:
            raise RuntimeError("先调用 start()")
        if self._proc.poll() is not None:
            raise RuntimeError("目标已退出，无法采集")

        out: list[Coverage] = []
        s = self._connect()
        try:
            self._shm.zero()          # 排除 banner / 上一次会话的残余
            for b in blobs:
                self._shm.zero()      # 只留【本条处理】点亮的边
                s.sendall(b)
                self._drain(s)        # 等服务端处理完再采，见 _drain 注释
                out.append(self._snap())
        finally:
            s.close()
            self._quiesce()           # 等退出线程落完笔，别污染下一条会话
        return out

    # ── CoverageOracle 接口 ───────────────────────────────────────
    def run_sequence(self, msgs: Sequence[bytes]) -> list[Coverage]:
        """同一次会话中按序逐条发送，返回每条自身的覆盖率。"""
        return self._measure(list(msgs))

    def run_single(self, blob: bytes) -> Coverage:
        """把 blob 当【一整条】消息在全新会话里发出，返回它的覆盖率。"""
        res = self._measure([blob])
        return res[0] if res else frozenset()

    def run_blob_after(
        self, prefix: Sequence[bytes], blob: bytes
    ) -> Coverage:
        """在【同一条会话】里先把 prefix 逐条发完（建立状态），再把 blob 当
        一整条发出，只返回 blob 自身点亮的边集。

        对应 GETCOVERAGE(PrefixMsgs, LeftMsgsInOne) 的后半段：拼包那一步
        必须发在前缀建起来的状态里。用 run_single 会另开全新会话，剩余消息
        全走失败路径，AllSplit 就把「前缀没重放」和「剩余拼包丢覆盖」混成
        一件事了。

        前缀逐条发时每条都清零 SHM 但不快照 —— 调用方要的是「拼包在该状态里
        点亮了什么」，不是整段会话的并。
        """
        if self._shm is None or self._proc is None:
            raise RuntimeError("先调用 start()")
        if self._proc.poll() is not None:
            raise RuntimeError("目标已退出，无法采集")

        s = self._connect()
        try:
            self._shm.zero()            # 排除 banner / 上次会话残余
            for b in prefix:
                self._shm.zero()
                s.sendall(b)
                self._drain(s)          # 等处理完，状态才真正建起来
            self._shm.zero()
            s.sendall(blob)
            self._drain(s)
            return self._snap()
        finally:
            s.close()
            self._quiesce()           # 等退出线程落完笔，别污染下一条会话

    def reset(self) -> None:
        if self._shm is not None:
            self._shm.zero()

    # ── 响应码采集（真值 oracle，与覆盖率完全独立）─────────────────
    def run_sequence_with_replies(
        self, blobs: Sequence[bytes], repeats: int = 3
    ) -> list[tuple[Coverage, str]]:
        """同一条会话逐条发，返回 (本条自身覆盖率, 本条响应码)。

        响应码取服务端应答**最后一行**的前三位数字（FTP 单行应答时就是那行；
        多行应答 213-xxx / 213 yyy 取末行，符合 RFC 959 §4.2 的多行规则）。

        为什么要有这个：覆盖率推断出的"依赖"必须有一个【与覆盖率无关】的
        真值来校验。响应码就是那个真值 —— i 是 j 的前置 ⟺ 去掉 i 后 j 的
        响应码变了。审稿人可以拿 RFC 逐条核对。

        repeats 条独立会话取【多数票】（审查 L4：真值单次测量时，一次调度/
        网络抖动抖错一个码，就凭空造出或抹掉一条依赖边）。按响应码投票、
        平票取先出现的 —— 不能按应答原文投：PASV 的 227 里带临时端口号，
        每次都不一样，按原文投会三票分裂。覆盖率取第一条会话的，本接口只供
        响应码真值，要覆盖走 run_sequence（它有自己的共识核）。
        """
        reps = max(1, int(repeats))
        runs = [self._run_sequence_once(blobs) for _ in range(reps)]
        if reps == 1:
            return runs[0]
        out: list[tuple[Coverage, str]] = []
        for pos in range(len(runs[0])):
            codes = [self.response_code(r[pos][1]) for r in runs]
            counts: dict[str, int] = {}
            for c in codes:
                counts[c] = counts.get(c, 0) + 1
            best = max(codes, key=lambda c: counts[c])   # 平票取先出现
            reply = next(r[pos][1] for r, c in zip(runs, codes) if c == best)
            out.append((runs[0][pos][0], reply))
        return out

    def _run_sequence_once(
        self, blobs: Sequence[bytes]
    ) -> list[tuple[Coverage, str]]:
        """一条独立会话逐条发一遍（run_sequence_with_replies 的单次测量）。"""
        if self._shm is None or self._proc is None:
            raise RuntimeError("先调用 start()")
        if self._proc.poll() is not None:
            raise RuntimeError("目标已退出，无法采集")

        out: list[tuple[Coverage, str]] = []
        s = self._connect()
        try:
            self._shm.zero()
            for b in blobs:
                self._shm.zero()
                s.sendall(b)
                reply = self._drain_collect(s)
                out.append((self._snap(), reply))
        finally:
            s.close()
            self._quiesce()           # 等退出线程落完笔，别污染下一条会话
        return out

    def _drain_collect(self, s: socket.socket) -> str:
        """读满一条【完整应答】，返回应答文本（供提取响应码）。

        「收满」按 RFC 959 §4.2 的多行规则判（审查 L4）：单行 '214 xxx' 一行
        即满；多行 '214-...' 要读到 '214 ' 结束行才算完。早先只按 settle 静默
        判行，HELP 这类多行应答行间隔超过 20ms 就被截断 —— response_code 对
        半截文本取末行规则会得 ''/错码，真值直接被污染。

        settle 只作兜底：完全无应答（半死靶机）不干等；多行行间隔用总期限
        （≥1s）桥接。正常路径靠结束行判满，单行应答反而比静默判行快。
        """
        s.settimeout(self.settle)
        buf = b""
        deadline = time.time() + max(1.0, self.settle * 10)
        try:
            while not self._reply_complete(buf):
                if time.time() > deadline:
                    break
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    if not buf:
                        break             # 无应答，别干等
                    continue              # 多行行间隔：继续等结束行
                if not chunk:
                    break                 # 对端关连接
                buf += chunk
        except OSError:
            pass
        # 残留排空：留在缓冲里的尾巴会被下一条的采集误认成本条应答
        s.settimeout(0.005)
        try:
            while s.recv(4096):
                pass
        except (socket.timeout, OSError):
            pass
        s.settimeout(2.0)
        return buf.decode("latin-1", "replace")

    @staticmethod
    def _reply_complete(buf: bytes) -> bool:
        """RFC 959 §4.2：应答收满了吗？

        结束行 = 3 位数字 + 空格（或裸 3 位）；多行应答 '214-...' 的中间行
        带 '-' 不算结束。只认 \\n 收齐的行，半行不算 —— 宁可多等一个往返，
        不能把 '214 xxx' 的半截当成完整应答提前收工。
        """
        lines = buf.split(b"\n")
        if not buf.endswith(b"\n"):
            lines = lines[:-1]            # 最后一段可能只到了半行
        for ln in lines:
            ln = ln.rstrip(b"\r")
            if len(ln) >= 3 and ln[:3].isdigit() and \
                    (len(ln) == 3 or ln[3:4] == b" "):
                return True
        return False

    @staticmethod
    def response_code(reply: str) -> str:
        """从应答文本提取响应码；无应答/无法解析返回 ''。

        规则（RFC 959 §4.2）：多行应答首行形如 '213-...'，末行 '213 ...'，
        整个应答的码以【末行】为准。单行就是它自己。
        """
        lines = [ln for ln in reply.replace("\r\n", "\n").split("\n") if ln.strip()]
        for ln in reversed(lines):
            if len(ln) >= 3 and ln[:3].isdigit() and (len(ln) == 3 or ln[3] == " "):
                return ln[:3]
        return ""
