#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HSPFuzzer 算法 2 —— 前缀消息识别 (Prefix Message Identification)
==============================================================

依据论文重建的参考实现：

    Zhewei Xia, Yingpei Zeng, Xiangpu Song, Shanqing Guo, Ting Wu.
    "HSPFuzzer: High-Speed Network Protocol Fuzzing with Connection Reuse."
    IEEE Internet of Things Journal, 2025.  §III-B, Algorithm 2.

重要说明
--------
官方仓库 github.com/hspfuzzer/hspfuzzer **并未发布** 该算法的代码。
仓库里只有连接复用那一半 (shm_hook.c + pre_queue)。本文件是根据论文
Algorithm 2 的伪代码独立复现的，不是官方实现。

与官方 fuzzer 的接口契约（从源码逆向得出）
------------------------------------------
src/afl-fuzz-queue.c:631

    if (strstr(q->fname, "pre")) {
        q->is_pre_packet = 1;
        q->disabled = 1;              /* 不参与变异 */
        ++afl->queued_pre;
        pre_queue_buf[afl->queued_pre - 1] = q;
    }

src/afl-fuzz-run.c:1086

    if (afl->fsrv.need_new_conn || !pre_had_been_send) {
        for (u32 i = 0; i < afl->queued_pre; i++) {
            write_to_testcase(...);
            fuzz_run_target(...);     /* 每条前缀消息单独一次 exec */
        }
    }

=> 只要把前缀消息导出成文件名含 "pre" 的种子，放进 -i 目录，
   HSPFuzzer 就会自动把它们当作连接建立阶段的必备消息按序发出。

算法摘要
--------
输入 : PcapFile（客户端->服务器的应用层消息序列 M0..MN-1）
输出 : PrefixMsgs, NeedSplit, AllSplit

第一阶段（识别前缀）
    基准：按序发送全部 N 条消息，记录每条消息的增量覆盖率 Cov(Mi)。
    逐个尝试移除 Mx（x 从 0 到 N-2-τ），看 Mx 之后还有多少条消息
    仍能达到与原来相近（差值 ≤ δ）的覆盖率，记为 Num。
    若 Num > τ  说明 Mx 不是前缀（后面消息基本不受影响）→ break。
    否则继续。最终 PrefixMsgs = Msgs[0:x]（最后一个非前缀之前的所有消息）。

    直觉：前缀消息（如 FTP 的 USER/PASS）缺失时，后续消息无法达到相同
    覆盖率；而普通消息缺失影响很小。τ 容忍少数无条件处理的消息（如 quit）。

第二阶段（判断是否需要拆包）
    CovA  = 所有单条消息覆盖率之并
    CovO  = 全部消息拼成一个包一次发出的覆盖率
    若 DIFF(CovA, CovO) > N·δ  → NeedSplit = true（SUT 无法在单包里解析多条消息）
    进一步：前缀单独发 + 非前缀拼成一个包，得 CovOL
    若 DIFF(CovA, CovOL) > N·δ  → AllSplit = true（非前缀消息也需逐条拆开）

用法
----
    python prefix_msg_identify.py -i capture.pcap -o out/ --target ./server

    # 仅测试算法逻辑（无真实 SUT）
    python prefix_msg_identify.py --self-test
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

# --------------------------------------------------------------------------
# 覆盖率表示与 DIFF()
# --------------------------------------------------------------------------

Coverage = frozenset  # 元素为 int（边 ID / 分支 ID）


def cov_diff(a: Coverage, b: Coverage) -> float:
    """Algorithm 2 里的 DIFF()。

    返回归一化后的对称差大小：
        |a Δ b| / |a ∪ b|
    0.0 表示完全一致，1.0 表示完全不重叠。
    论文用 δ 作为容差阈值，以吸收网络抖动 / 多线程带来的噪声。
    """
    if not a and not b:
        return 0.0
    union = len(a | b)
    return (len(a ^ b) / union) if union else 0.0


def cov_union(covs: Iterable[Coverage]) -> Coverage:
    """Algorithm 2 第 21 行 CovA ← Σ Cov(Mi)，即覆盖率之并。"""
    out = set()
    for c in covs:
        out |= c
    return frozenset(out)


# --------------------------------------------------------------------------
# 覆盖率后端抽象
# --------------------------------------------------------------------------

class CoverageOracle(ABC):
    """驱动 SUT 并采集覆盖率。

    论文要求「使用相同启动参数的 SUT 实例」采集 llvm-cov 覆盖率。
    这里抽象成两个操作，正好对应 GETCOVERAGE 的两种重载。
    """

    @abstractmethod
    def run_sequence(self, msgs: Sequence[bytes]) -> list[Coverage]:
        """在**同一次会话**中按序把 msgs 逐条喂给 SUT。

        返回与 msgs 等长的列表，第 i 项是处理 Mi 时的**增量**覆盖率。
        """

    @abstractmethod
    def run_single(self, blob: bytes) -> Coverage:
        """把 blob 作为**单条**消息喂给全新的 SUT，返回总覆盖率。

        用于 MsgsInOne（多条消息拼成一个包）的场景。
        """

    def reset(self) -> None:
        """可选：清理状态。"""


class FakeOracle(CoverageOracle):
    """用于自测的假后端。

    约定：每条消息有自己「专属」的覆盖率边集合；
    前缀消息另有若干「共享前置」边，这些边一旦缺失，后续消息的
    专属边就采不到 —— 用来验证算法能正确识别出前缀。
    """

    def __init__(
        self,
        per_msg: Sequence[set],
        prefix_gate: dict[int, set],
        prefix_ids: Sequence[int],
    ) -> None:
        self.per_msg = [frozenset(s) for s in per_msg]
        self.prefix_gate = {k: frozenset(v) for k, v in prefix_gate.items()}
        self.prefix_ids = set(prefix_ids)

    def run_sequence(self, msgs: Sequence[bytes]) -> list[Coverage]:
        # FakeOracle 用消息**条数**定位，所以 msgs 传的是哨兵 bytes，
        # 真实索引由 _call_sequence 传入的 mock 维护。
        raise NotImplementedError

    def run_single(self, blob: bytes) -> Coverage:
        raise NotImplementedError


class SequenceSimulator(CoverageOracle):
    """把「移除第 x 条」这类实验交给可调用对象执行。

    实际项目里这里换成 afl-showmap / llvm-cov 驱动即可。
    """

    def __init__(
        self,
        runner: Callable[[Sequence[int]], list[Coverage]],
        blob_runner: Callable[[tuple[int, ...], tuple[int, ...]], Coverage],
    ) -> None:
        self._runner = runner
        self._blob_runner = blob_runner

    def run_sequence(self, msgs: Sequence[bytes]) -> list[Coverage]:
        # msgs 是占位；真实索引序列由调用方通过闭包绑定
        raise RuntimeError("use run_sequence_idx / run_single_idx")

    def run_single(self, blob: bytes) -> Coverage:
        raise RuntimeError("use run_sequence_idx / run_single_idx")

    def run_sequence_idx(self, idx: Sequence[int]) -> list[Coverage]:
        return self._runner(list(idx))

    def run_single_idx(self, idx: tuple[int, ...]) -> Coverage:
        """拼包发到【全新会话】（MsgsInOne，Algorithm 2 第 20 行）。"""
        return self._blob_runner(idx, ())

    def run_blob_in_state_idx(
        self, idx: tuple[int, ...], seen: tuple[int, ...]
    ) -> Coverage:
        """把 idx 拼成一包，发到由 seen 已逐条重放建立起来的状态里。

        GETCOVERAGE(PrefixMsgs, LeftMsgsInOne)（第 25 行）的后半段是这个，
        不是 run_single_idx：前缀已经逐条发过、状态建好了，剩余消息才拼包。
        两者混同会让拼包被当成"发给全新会话"，剩余消息全走失败路径 ——
        那样 AllSplit 就把"前缀没重放"和"剩余拼包丢覆盖"两件事混在一起了。
        """
        return self._blob_runner(idx, seen)


# --------------------------------------------------------------------------
# 算法 2 本体
# --------------------------------------------------------------------------

@dataclass
class Algo2Result:
    prefix_msgs: list[int]      # PrefixMsgs 的下标
    need_split: bool            # NeedSplit
    all_split: bool             # AllSplit
    cut_at: int                 # 伪代码里的 x（PrefixMsgs = Msgs[0:x]）
    trace: list = field(default_factory=list)  # 调试用


def identify_prefix_messages(
    sim: SequenceSimulator,
    n: int,
    tau: int = 1,
    delta: float = 0.05,
    verbose: bool = True,
) -> Algo2Result:
    """Algorithm 2 主过程。

    sim 提供两个按索引驱动实验的函数：
        run_sequence_idx([i0, i1, ...]) -> 每条的增量覆盖率
        run_single_idx((i0, i1, ...))   -> 一次发出拼接包的总覆盖率

    n     : 消息条数 N（论文要求 N ≥ 2 + τ）
    tau   : τ，缺少前缀后仍能被无条件处理的消息数上限（通常 1）
    delta : δ，判定「覆盖率相近」的阈值
    """
    if n < 2 + tau:
        raise ValueError(f"论文假设 N >= 2 + tau，但 N={n}, tau={tau}")

    all_idx = list(range(n))

    # ---- 第 3 行：基准覆盖率 -------------------------------------------
    cov = sim.run_sequence_idx(all_idx)  # Cov(Mi)
    if verbose:
        print(f"[Algo2] 基准：{n} 条消息，各条覆盖率规模 "
              f"{[len(c) for c in cov]}")

    # ---- 第 4-16 行：确定 PrefixMsgs ----------------------------------
    x = n - 2 - tau  # 若循环不 break，则 x 落在上界
    trace = []

    for x in range(0, n - 1 - tau):
        left_idx = [i for i in all_idx if i != x]           # 第 5 行 Remove
        cov_t = sim.run_sequence_idx(left_idx)               # 第 6 行
        cov_t_map = {idx: cov_t[k] for k, idx in enumerate(left_idx)}

        num = 0                                              # 第 7 行
        for y in range(x + 1, n):                            # 第 8 行
            d = cov_diff(cov[y], cov_t_map[y])               # 第 9 行
            if d <= delta:
                num += 1                                     # 第 10 行
            if verbose:
                print(f"    x={x} y={y} DIFF={d:.4f} "
                      f"({'≈' if d <= delta else '≠'})")

        trace.append({"x": x, "num": num, "tau": tau})
        if verbose:
            print(f"[Algo2] 移除 M{x} 后仍有 {num} 条覆盖率相近 "
                  f"(tau={tau})")

        if num > tau:                                        # 第 13 行
            if verbose:
                print(f"[Algo2] -> M{x} 不是前缀消息，停止")
            break                                            # 第 14 行
    else:
        # 循环自然结束：x 为最后一次迭代的值
        x = n - 2 - tau

    # 第 17 行：PrefixMsgs ← Msgs.SUBLIST(0, x)
    prefix_msgs = all_idx[:x]
    if verbose:
        print(f"[Algo2] PrefixMsgs = M0..M{x-1} = {prefix_msgs}")

    # ---- 第 18-29 行：NeedSplit / AllSplit ---------------------------
    need_split = False
    all_split = False

    # 第 19 行：全部消息拼成一个包
    msgs_in_one = tuple(all_idx)
    cov_o = sim.run_single_idx(msgs_in_one)                  # 第 20 行

    # 第 21 行：CovA ← Σ Cov(Mi)
    cov_a = cov_union(cov)

    if verbose:
        print(f"[Algo2] CovA={len(cov_a)} CovO={len(cov_o)} "
              f"DIFF={cov_diff(cov_a, cov_o):.4f} 阈值={n * delta:.4f}")

    if cov_diff(cov_a, cov_o) > n * delta:                   # 第 22 行
        need_split = True                                    # 第 23 行
        # 第 24 行：非前缀消息拼成一个包
        left_msgs_in_one = tuple(all_idx[x:])
        # 第 25 行：前缀逐条发 + 非前缀拼包发
        cov_ol = _run_prefix_then_blob(sim, prefix_msgs, left_msgs_in_one)

        if verbose:
            print(f"[Algo2] CovOL={len(cov_ol)} "
                  f"DIFF={cov_diff(cov_a, cov_ol):.4f}")

        if cov_diff(cov_a, cov_ol) > n * delta:              # 第 26 行
            all_split = True                                 # 第 27 行

    return Algo2Result(
        prefix_msgs=prefix_msgs,
        need_split=need_split,
        all_split=all_split,
        cut_at=x,
        trace=trace,
    )


def _run_prefix_then_blob(
    sim: SequenceSimulator,
    prefix: Sequence[int],
    blob: Sequence[int],
) -> Coverage:
    """GETCOVERAGE(PrefixMsgs, LeftMsgsInOne)。

    前缀逐条发送，非前缀拼成一个包发送，返回整段会话的总覆盖率。
    拼包那一步必须【在前缀建立的状态里】发（run_blob_in_state_idx），
    否则剩余消息会被当成全新会话里的第一条，判成 AllSplit 的证据。
    """
    acc = set()
    if prefix:
        for c in sim.run_sequence_idx(list(prefix)):
            acc |= c
    if blob:
        acc |= sim.run_blob_in_state_idx(tuple(blob), tuple(prefix))
    return frozenset(acc)


# --------------------------------------------------------------------------
# pcap 解析：提取 客户端 -> 服务器 的应用层消息
# --------------------------------------------------------------------------

def parse_pcap_messages(
    path: str | Path,
    client_ip: str | None = None,
    server_ip: str | None = None,
) -> list[bytes]:
    """从 pcap/pcapng 提取应用层消息（客户端方向的 payload 序列）。

    简化处理：
      * 同方向、同一 TCP 流上相邻的 payload 视为独立消息
        （真实实现需按协议分界，HSPFuzzer 论文提到可用 [23],[10] 的方法）
      * 自动跳过 TCP 握手/纯 ACK（payload 为空）
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)

    # 优先 scapy（支持 pcapng），否则退回自研的 pcap 解析
    try:
        return _parse_with_scapy(path, client_ip, server_ip)
    except ImportError:
        return _parse_with_builtin(path, client_ip, server_ip)


def _parse_with_scapy(path, client_ip, server_ip) -> list[bytes]:
    from scapy.all import IP, TCP, UDP, rdpcap  # type: ignore

    pkts = rdpcap(str(path))
    msgs = []
    for p in pkts:
        if IP not in p:
            continue
        ip = p[IP]
        if client_ip and ip.src != client_ip:
            continue
        if server_ip and ip.dst != server_ip:
            continue
        payload = b""
        if TCP in p:
            payload = bytes(p[TCP].payload)
        elif UDP in p:
            payload = bytes(p[UDP].payload)
        if payload:
            msgs.append(payload)
    return msgs


def _parse_with_builtin(path, client_ip, server_ip) -> list[bytes]:
    """极简 pcap (非 pcapng) 解析：Ethernet + IPv4 + TCP/UDP payload。"""
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError("文件太短，不是有效 pcap")

    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        raise ValueError("这是 pcapng 或 nanosecond pcap，请安装 scapy")
    else:
        raise ValueError(f"无法识别的 pcap magic: {magic!r}")

    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype != 1:
        raise ValueError(f"仅支持 Ethernet (linktype=1)，当前为 {linktype}")

    msgs: list[bytes] = []
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            endian + "IIII", data[off:off + 16]
        )
        off += 16
        frame = data[off:off + incl_len]
        off += incl_len
        payload = _eth_payload(frame)
        if payload is None:
            continue
        src, dst, proto, body = payload
        if client_ip and src != client_ip:
            continue
        if server_ip and dst != server_ip:
            continue
        if body:
            msgs.append(body)
    return msgs


def _eth_payload(frame: bytes):
    """返回 (src_ip, dst_ip, proto, app_payload) 或 None。"""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    # VLAN tag
    if ethertype == 0x8100:
        if len(frame) < 18:
            return None
        ethertype = struct.unpack("!H", frame[16:18])[0]
        off = 18
    if ethertype != 0x0800:  # IPv4
        return None

    ip = frame[off:]
    if len(ip) < 20:
        return None
    ver_ihl = ip[0]
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return None
    total_len = struct.unpack("!H", ip[2:4])[0]
    proto = ip[9]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])

    seg = ip[ihl:total_len if total_len else len(ip)]

    if proto == 6:  # TCP
        if len(seg) < 20:
            return None
        data_off = ((seg[12] >> 4) & 0xF) * 4
        if data_off < 20 or len(seg) < data_off:
            return None
        return src, dst, proto, seg[data_off:]
    if proto == 17:  # UDP
        if len(seg) < 8:
            return None
        return src, dst, proto, seg[8:]
    return None


# --------------------------------------------------------------------------
# afl-showmap 后端（真实 SUT）
# --------------------------------------------------------------------------

class ShowmapOracle(CoverageOracle):
    """用 afl-showmap 采集边覆盖集合。

    run_sequence 通过「会话重放」近似单次顺序会话：
        第 k 次调用喂前 k 条消息，相邻两次的 bitmap 差即第 k 条的增量覆盖率。
    对确定性 SUT 而言，这与单次顺序会话等价。
    """

    def __init__(
        self,
        target_cmd: Sequence[str],
        showmap: str = "afl-showmap",
        timeout_ms: int = 1000,
    ) -> None:
        self.target_cmd = list(target_cmd)
        self.showmap = showmap
        self.timeout_ms = timeout_ms

    def _showmap(self, blob: bytes) -> Coverage:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(blob)
            in_path = f.name
        out_path = in_path + ".map"
        try:
            subprocess.run(
                [self.showmap, "-q", "-o", out_path, "-m", "none",
                 "-t", str(self.timeout_ms), "--"]
                + self.target_cmd,
                input=blob, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=False,
            )
            if not os.path.exists(out_path):
                return frozenset()
            edges = set()
            for line in open(out_path, "r", errors="ignore"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    edges.add(int(line.split(":")[0], 16))
                except ValueError:
                    continue
            return frozenset(edges)
        finally:
            for p in (in_path, out_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def run_sequence(self, msgs: Sequence[bytes]) -> list[Coverage]:
        out: list[Coverage] = []
        acc = frozenset()
        for i in range(1, len(msgs) + 1):
            cur = self._showmap(b"".join(msgs[:i]))
            out.append(frozenset(cur - acc))
            acc = cur
        return out

    def run_single(self, blob: bytes) -> Coverage:
        return self._showmap(blob)


# --------------------------------------------------------------------------
# 导出：写成 HSPFuzzer 认得的种子文件
# --------------------------------------------------------------------------

def export_for_hspfuzzer(
    msgs: Sequence[bytes],
    prefix_ids: Sequence[int],
    out_dir: str | Path,
    need_split: bool = False,
    all_split: bool = False,
) -> Path:
    """把结果导出成 HSPFuzzer 的种子目录。

    关键：前缀消息文件名必须含 "pre"，见 src/afl-fuzz-queue.c:631。
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    for k, i in enumerate(prefix_ids):
        (out / f"pre_{k:03d}.msg").write_bytes(msgs[i])

    # 普通消息
    prefix_set = set(prefix_ids)
    normals = [i for i in range(len(msgs)) if i not in prefix_set]

    if all_split:
        # 非前缀消息也逐条拆成独立种子
        for k, i in enumerate(normals):
            (out / f"seed_{k:03d}.msg").write_bytes(msgs[i])
    elif need_split:
        # 只需保证前缀单独成包，非前缀可以整段作为一个种子
        blob = b"".join(msgs[i] for i in normals)
        (out / "seed_all.msg").write_bytes(blob)
    else:
        # SUT 能在单包内解析多条消息 → 整段 pcap 直接当一个种子
        blob = b"".join(msgs)
        (out / "seed_all.msg").write_bytes(blob)

    meta = {
        "prefix_msg_indices": list(prefix_ids),
        "need_split": need_split,
        "all_split": all_split,
        "n_messages": len(msgs),
    }
    (out / "prefix_meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return out


# --------------------------------------------------------------------------
# 自测：验证算法 2 的逻辑正确性
# --------------------------------------------------------------------------

def self_test() -> int:
    """构造一个「M0 是前缀，其余是普通消息」的场景。"""
    print("=" * 62)
    print("自测：构造 N=6, M0 为前缀消息，tau=1, delta=0.05")
    print("=" * 62)

    n = 6
    # 每条消息自己的专属边
    own = [{1000 + i * 10 + k for k in range(5)} for i in range(n)]
    # M0 解锁的「门」边：缺失 M0 时，M1..M5 的专属边全部采不到
    gate = {0: {2000, 2001, 2002}}

    def build(keep: Sequence[int]) -> list[Coverage]:
        """按 keep 顺序喂消息，返回每条的增量覆盖率。"""
        out = []
        gate_hit = False
        for i in keep:
            acc = set()
            if i == 0:
                acc |= gate[0]
                gate_hit = True
            if gate_hit or i == 0:
                acc |= own[i]
            out.append(frozenset(acc))
        return out

    def blob(indices: Sequence[int]) -> Coverage:
        """把 indices 对应消息拼成一包：SUT 无法在单包里解析多条 → 只认第一条。"""
        if not indices:
            return frozenset()
        first = indices[0]
        acc = set()
        if first == 0:
            acc |= gate[0]
            acc |= own[0]
        # 拼包时后续消息不被解析（模拟 NeedSplit=true 的场景）
        return frozenset(acc)

    sim = SequenceSimulator(runner=build, blob_runner=blob)

    res = identify_prefix_messages(sim, n=n, tau=1, delta=0.05, verbose=True)

    print()
    print("结果:")
    print(f"  PrefixMsgs = {res.prefix_msgs}   (期望 [0])")
    print(f"  cut_at x   = {res.cut_at}        (期望 1)")
    print(f"  NeedSplit  = {res.need_split}    (期望 True)")
    print(f"  AllSplit   = {res.all_split}")

    ok = res.prefix_msgs == [0] and res.cut_at == 1 and res.need_split is True
    print()
    print("自测" + ("通过 [OK]" if ok else "失败 [FAIL]"))

    # 导出演示
    demo_dir = Path(__file__).parent / "_selftest_out"
    msgs = [f"MSG{i}".encode() for i in range(n)]
    export_for_hspfuzzer(msgs, res.prefix_msgs, demo_dir,
                         need_split=res.need_split, all_split=res.all_split)
    print(f"演示导出目录: {demo_dir}")
    for p in sorted(demo_dir.iterdir()):
        print(f"  {p.name}")
    return 0 if ok else 1


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: Sequence[str] | None = None) -> int:
    # Windows 控制台默认 GBK，强制 UTF-8 以免中文输出抛 UnicodeEncodeError
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(
        description="HSPFuzzer 算法 2：前缀消息识别（论文复现版）")
    ap.add_argument("-i", "--input", help="pcap/pcapng 文件")
    ap.add_argument("-o", "--output", default="prefix_out",
                    help="导出目录（默认 prefix_out）")
    ap.add_argument("--target", nargs=argparse.REMAINDER,
                    help="被测程序命令行，例如 --target ./ftp_server -p 21")
    ap.add_argument("--showmap", default="afl-showmap",
                    help="afl-showmap 路径（默认 afl-showmap）")
    ap.add_argument("--tau", type=int, default=1,
                    help="τ：缺少前缀后仍可无条件处理的消息数上限（默认 1）")
    ap.add_argument("--delta", type=float, default=0.05,
                    help="δ：覆盖率相近阈值（默认 0.05）")
    ap.add_argument("--client-ip", help="只取该源 IP 的方向")
    ap.add_argument("--server-ip", help="只取该目的 IP 的方向")
    ap.add_argument("--self-test", action="store_true",
                    help="仅运行算法自测（无需真实 SUT）")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.input:
        ap.error("需要 -i capture.pcap，或使用 --self-test")
    if not args.target:
        ap.error("需要 --target <被测程序命令行>（用于采集覆盖率）")

    msgs = parse_pcap_messages(args.input, args.client_ip, args.server_ip)
    print(f"[*] 从 {args.input} 解析出 {len(msgs)} 条应用层消息")
    for i, m in enumerate(msgs):
        head = m[:24].hex()
        print(f"    M{i}: len={len(m):5d}  head={head}")

    if len(msgs) < 2 + args.tau:
        print(f"[!] 消息数 N={len(msgs)} < 2+τ={2 + args.tau}，论文假设不满足")
        return 2

    oracle = ShowmapOracle(args.target, showmap=args.showmap)

    class _Sim(SequenceSimulator):
        def __init__(self, o, m):
            super().__init__(runner=None, blob_runner=None)
            self._o, self._m = o, m

        def run_sequence_idx(self, idx):
            return self._o.run_sequence([self._m[i] for i in idx])

        def run_single_idx(self, idx):
            return self._o.run_single(b"".join(self._m[i] for i in idx))

        def run_blob_in_state_idx(self, idx, seen):
            # ShowmapOracle 每次都是新进程，没有"同会话接着发"的原语。
            # 只能近似成 seen 逐条发 + 拼包另发的并，对无状态 stdin 目标等价。
            acc = set()
            for c in self._o.run_sequence([self._m[i] for i in seen]):
                acc |= c
            acc |= self._o.run_single(b"".join(self._m[i] for i in idx))
            return frozenset(acc)

    sim = _Sim(oracle, msgs)
    res = identify_prefix_messages(
        sim, n=len(msgs), tau=args.tau, delta=args.delta, verbose=True)

    print()
    print("[*] 算法 2 结果:")
    print(f"    PrefixMsgs : {res.prefix_msgs}")
    print(f"    NeedSplit  : {res.need_split}")
    print(f"    AllSplit   : {res.all_split}")

    out = export_for_hspfuzzer(
        msgs, res.prefix_msgs, args.output,
        need_split=res.need_split, all_split=res.all_split)
    print(f"[*] 已导出到 {out}")
    print("    （文件名含 'pre' 的会被 HSPFuzzer 自动当作前缀消息）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
