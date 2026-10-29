#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
协议种子分析器 —— 状态集合 / 状态种子 / IPSM 状态机 + 前缀消息识别
=================================================================

把 HSPFuzzer 算法 2（前缀消息识别）和 AFLNet 的状态反馈模型
（响应码 → 状态序列 → IPSM）整合成一个种子准备工具。

术语对照
--------
AFLNet (AFLNet-CN.pdf)                     本工具
-----------------------------------------  --------------------------------
响应码 (response code)                     ResponseCode，如 "331"
状态 (state)                               StateKey（code 模式 / sequence 模式）
状态序列 (state sequence)                  MessageState.seq_state
IPSM（协议状态机）                         Analysis.transitions / to_ipsm()
状态种子                                   Analysis.state_seeds
状态集合                                   Analysis.state_set
序列前缀 / 候选子序列 / 后缀               Algorithm 2 的 PrefixMsgs + 其余

为什么需要它
------------
* HSPFuzzer（github.com/hspfuzzer）**没有**状态机。全树检索
  `state_seq` / `extract_state` / `IPSM` 均 0 命中；`focusing/focused`
  是变异阶段的标记，与协议状态无关。它靠连接复用提速，不靠状态反馈。
* AFLNet 及其变种（AFLNeTrans 等）靠状态反馈引导。做对比实验、
  或做状态感知的调度，必须自己析出状态集合与状态种子。
* 论文的前缀消息识别（算法 2）只产出 PrefixMsgs/NeedSplit/AllSplit，
  不产出状态信息 —— 本工具补齐这一块。

状态的定义（可选两种粒度）
--------------------------
mode="code"      : 状态 = 本条消息响应的**最后一个**响应码
                   例 FTP 登录后 230 → 状态 "230"
                   粒度粗，状态数少，适合快速探索

mode="sequence"  : 状态 = **累积**响应码序列，如 "220>331>230"
                   即 AFLNet IPSM 的键空间
                   粒度细，能区分「同一响应码但路径不同」

用法
----
    # 从 pcap 分析状态
    python protocol_seed_analyzer.py analyze -i capture.pcap -p ftp -o out/

    # 同时跑前缀识别（需要可采集覆盖率的 SUT）
    python protocol_seed_analyzer.py analyze -i capture.pcap -p ftp -o out/ \
        --target ./ftp_server --prefix

    # 导出 AFLNet 风格语料库 + IPSM
    python protocol_seed_analyzer.py analyze -i capture.pcap -p rtsp -o out/ \
        --state-mode sequence

    # 自测
    python protocol_seed_analyzer.py selftest
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
import sys
from abc import ABC, abstractmethod
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Iterable, Sequence

# 算法 2 复用
try:
    from prefix_msg_identify import (
        Algo2Result,
        CoverageOracle,
        SequenceSimulator,
        ShowmapOracle,
        cov_diff,
        cov_union,
        identify_prefix_messages,
        parse_pcap_messages,
    )
    _HAS_ALGO2 = True
except ImportError:  # 允许单独使用状态分析部分
    _HAS_ALGO2 = False


# ==========================================================================
# 1. 会话模型：客户端消息 与 服务器响应 按序对齐
# ==========================================================================

@dataclass
class Session:
    """一次完整的客户端<->服务器交互。

    messages[i] 是客户端发出的第 i 条请求；
    responses[i] 是服务器对该请求的响应（可为空 bytes）。
    二者按下标对齐；若 pcap 里响应缺失，对应项为 b""。
    """
    messages: list[bytes] = field(default_factory=list)
    responses: list[bytes] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.messages)

    def aligned(self) -> list[tuple[bytes, bytes]]:
        out = []
        for i, m in enumerate(self.messages):
            r = self.responses[i] if i < len(self.responses) else b""
            out.append((m, r))
        return out


# ==========================================================================
# 2. pcap 解析：双向会话重建
# ==========================================================================

def parse_pcap_sessions(
    path: str | Path,
    client_ip: str | None = None,
    server_ip: str | None = None,
    client_port: int | None = None,
) -> list[Session]:
    """从 pcap/pcapng 重建会话。

    简化策略（与 HSPFuzzer/prefix_msg_identify 一致）：
      * 单向 payload 即一条应用层消息
      * 客户端方向 -> Session.messages，服务器方向 -> Session.responses
      * 按 (src,dst,port) 五元组分组，每组一个 Session
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    try:
        frames = _read_frames_scapy(path)
    except ImportError:
        frames = _read_frames_builtin(path)

    # 五元组 -> Session
    buckets: dict[tuple, Session] = {}
    for src, dst, sport, dport, payload in frames:
        if client_ip and src != client_ip and dst != client_ip:
            continue
        if server_ip and src != server_ip and dst != server_ip:
            continue
        if not payload:
            continue

        if client_ip:
            c_is_src = (src == client_ip)
        elif server_ip:
            c_is_src = (dst != server_ip)
        else:
            # 未指定时：源端口大者视为客户端（临时端口）
            c_is_src = (sport > dport)

        if client_port and c_is_src and sport != client_port:
            continue

        # 归一化五元组方向
        if c_is_src:
            key = ("C2S", src, dst, sport, dport)
            sess = buckets.setdefault(key, Session())
            sess.messages.append(payload)
        else:
            key = ("S2C", dst, src, dport, sport)
            sess = buckets.setdefault(key, Session())
            sess.responses.append(payload)

    # 把 S2C 的响应合并进同连接的 C2S 会话
    merged: dict[tuple, Session] = {}
    for (dir_, a, b, pa, pb), sess in buckets.items():
        base = (a, b, pa, pb)
        if dir_ == "C2S":
            merged.setdefault(base, Session())
            merged[base].messages.extend(sess.messages)
        else:
            merged.setdefault(base, Session())
            merged[base].responses.extend(sess.responses)

    sessions = [s for s in merged.values() if s.messages]
    for s in sessions:
        # 对齐：响应按序配给消息，多余丢弃，缺失补 b""
        while len(s.responses) < len(s.messages):
            s.responses.append(b"")
        s.responses = s.responses[: len(s.messages)]
    return sessions


def _read_frames_scapy(path) -> list[tuple]:
    from scapy.all import IP, TCP, UDP, rdpcap  # type: ignore
    out = []
    for p in rdpcap(str(path)):
        if IP not in p:
            continue
        ip = p[IP]
        if TCP in p:
            t = p[TCP]
            out.append((ip.src, ip.dst, int(t.sport), int(t.dport),
                        bytes(t.payload)))
        elif UDP in p:
            u = p[UDP]
            out.append((ip.src, ip.dst, int(u.sport), int(u.dport),
                        bytes(u.payload)))
    return out


def _read_frames_builtin(path) -> list[tuple]:
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError("文件太短，不是有效 pcap")
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError(f"无法识别的 pcap magic {magic!r}，请安装 scapy")
    if struct.unpack(endian + "I", data[20:24])[0] != 1:
        raise ValueError("仅支持 Ethernet (linktype=1)")

    out = []
    off = 24
    while off + 16 <= len(data):
        _ts, _tu, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        frame = data[off:off + incl]
        off += incl
        rec = _eth_payload(frame)
        if rec:
            out.append(rec)
    return out


def _eth_payload(frame: bytes):
    if len(frame) < 14:
        return None
    et = struct.unpack("!H", frame[12:14])[0]
    off = 14
    if et == 0x8100:
        if len(frame) < 18:
            return None
        et = struct.unpack("!H", frame[16:18])[0]
        off = 18
    if et != 0x0800:
        return None
    ip = frame[off:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return None
    total = struct.unpack("!H", ip[2:4])[0] or len(ip)
    proto = ip[9]
    src = ".".join(map(str, ip[12:16]))
    dst = ".".join(map(str, ip[16:20]))
    seg = ip[ihl:total]
    if proto == 6 and len(seg) >= 20:
        doff = ((seg[12] >> 4) & 0xF) * 4
        if doff < 20 or len(seg) < doff:
            return None
        sport, dport = struct.unpack("!HH", seg[0:4])
        return src, dst, sport, dport, seg[doff:]
    if proto == 17 and len(seg) >= 8:
        sport, dport = struct.unpack("!HH", seg[0:4])
        return src, dst, sport, dport, seg[8:]
    return None


# ==========================================================================
# 3. 协议状态提取器：响应 -> 响应码序列
# ==========================================================================

class StateExtractor(ABC):
    """把服务器响应解析成响应码列表。

    一条请求可能产生多个响应码（如 FTP 多行 2xx-2xx），
    也可能不产生（如数据通道）。
    """

    name = "abstract"

    @abstractmethod
    def extract(self, response: bytes) -> list[str]:
        """返回本条响应里的响应码列表（有序）。"""

    def describe(self) -> str:
        return self.name


# ---- RFC 风格「三位数字码」：FTP / SMTP / POP3 / NNTP --------------------

class NumericCodeExtractor(StateExtractor):
    """匹配 `^(\d{3})([- ])?`，多行响应全部收集。

    FTP:  220 / 331 / 230 / 250 / 530 ...
    SMTP: 220 / 250 / 354 / 221 ...
    POP3: +OK 不用数字码，另见 Pop3Extractor
    """

    _re = re.compile(rb"(?m)^\s*(\d{3})(?:[-\s]|$)")

    def __init__(self, name: str = "numeric"):
        self.name = name

    def extract(self, response: bytes) -> list[str]:
        return [m.group(1).decode() for m in self._re.finditer(response or b"")]


class FtpExtractor(NumericCodeExtractor):
    def __init__(self):
        super().__init__("ftp")


class SmtpExtractor(NumericCodeExtractor):
    def __init__(self):
        super().__init__("smtp")


# ---- 状态行式：HTTP / RTSP / SIP ----------------------------------------

class StatusLineExtractor(StateExtractor):
    """匹配 `<PROTO>/<ver> <CODE>`。

    HTTP/1.1 200 OK  -> "200"
    RTSP/1.0 200 OK  -> "200"
    SIP/2.0 200 OK   -> "200"
    """

    _re = re.compile(
        rb"(?m)^(?:HTTP|RTSP|SIP)/\d\.\d\s+(\d{3})\b"
    )

    def __init__(self, name: str = "statusline"):
        self.name = name

    def extract(self, response: bytes) -> list[str]:
        return [m.group(1).decode() for m in self._re.finditer(response or b"")]


class HttpExtractor(StatusLineExtractor):
    def __init__(self):
        super().__init__("http")


class RtspExtractor(StatusLineExtractor):
    def __init__(self):
        super().__init__("rtsp")


class SipExtractor(StatusLineExtractor):
    def __init__(self):
        super().__init__("sip")


# ---- POP3：+OK / -ERR ---------------------------------------------------

class Pop3Extractor(StateExtractor):
    name = "pop3"
    _re = re.compile(rb"(?m)^([+\-])(OK|ERR)\b", re.I)

    def extract(self, response: bytes) -> list[str]:
        out = []
        for m in self._re.finditer(response or b""):
            out.append((m.group(1) + m.group(2)).decode().upper())
        return out


# ---- Redis：RESP 首字节 -------------------------------------------------

class RedisExtractor(StateExtractor):
    name = "redis"

    def extract(self, response: bytes) -> list[str]:
        if not response:
            return []
        # +OK / -ERR / :123 / $5\r\n / *2\r\n
        tag = response[:1]
        if tag in (b"+", b"-", b":", b"$", b"*"):
            line = response.split(b"\r\n", 1)[0]
            # 保留首字节 + 首行摘要，便于区分不同回复
            return [line[:32].decode("latin-1", "replace")]
        return ["RESP:" + tag.decode("latin-1", "replace")]


# ---- DNS：header flags + rcode -----------------------------------------

class DnsExtractor(StateExtractor):
    name = "dns"

    def extract(self, response: bytes) -> list[str]:
        if len(response) < 12:
            return []
        flags = struct.unpack("!H", response[2:4])[0]
        rcode = flags & 0xF
        qr = (flags >> 15) & 1
        aa = (flags >> 10) & 1
        tc = (flags >> 9) & 1
        rd = (flags >> 8) & 1
        ra = (flags >> 7) & 1
        qd, an = struct.unpack("!HH", response[4:8])
        return [f"DNS:qr={qr},aa={aa},tc={tc},rd={rd},ra={ra},"
                f"rcode={rcode},qd={qd},an={an}"]


# ---- TLS：record type + handshake type ----------------------------------

class TlsExtractor(StateExtractor):
    name = "tls"

    def extract(self, response: bytes) -> list[str]:
        out = []
        i = 0
        while i + 5 <= len(response):
            typ = response[i]
            ver = struct.unpack("!H", response[i + 1:i + 3])[0]
            ln = struct.unpack("!H", response[i + 3:i + 5])[0]
            body = response[i + 5:i + 5 + ln]
            if typ == 0x16 and len(body) >= 1:        # handshake
                hs = body[0]
                out.append(f"TLS:hs={hs},ver={ver:04x}")
            elif typ == 0x15:                          # alert
                lvl = body[0] if body else -1
                desc = body[1] if len(body) > 1 else -1
                out.append(f"TLS:alert={lvl}/{desc}")
            elif typ == 0x17:                          # app data
                out.append(f"TLS:appdata,ver={ver:04x}")
            else:
                out.append(f"TLS:type={typ},ver={ver:04x}")
            if ln == 0:
                break
            i += 5 + ln
        return out or (["TLS:empty"] if response else [])


# ---- Modbus TCP：function code + exception bit ---------------------------

class ModbusExtractor(StateExtractor):
    name = "modbus"

    def extract(self, response: bytes) -> list[str]:
        if len(response) < 8:
            return []
        # MBAP(7) + PDU
        func = response[7]
        is_exc = bool(func & 0x80)
        code = response[8] if len(response) > 8 else -1
        return [f"MB:func={func & 0x7F},exc={int(is_exc)},code={code}"]


# ---- MySQL：packet header + err/ok --------------------------------------

class MysqlExtractor(StateExtractor):
    name = "mysql"

    def extract(self, response: bytes) -> list[str]:
        if len(response) < 5:
            return []
        pkt_len = response[0] | (response[1] << 8) | (response[2] << 16)
        seq = response[3]
        tag = response[4]
        if tag == 0x00:
            return [f"MySQL:OK,seq={seq}"]
        if tag == 0xFF:
            code = struct.unpack("<H", response[5:7])[0] if len(response) >= 7 else -1
            return [f"MySQL:ERR,code={code},seq={seq}"]
        if tag == 0xFE:
            return [f"MySQL:EOF,seq={seq}"]
        return [f"MySQL:DATA,pkt={pkt_len},seq={seq},tag={tag}"]


# ---- 兜底：响应哈希（未知协议也能分状态） --------------------------------

class GenericExtractor(StateExtractor):
    """把响应的形状特征作为状态码：首字节 + 长度桶 + 哈希前缀。"""

    name = "generic"

    def extract(self, response: bytes) -> list[str]:
        if not response:
            return ["EMPTY"]
        # 长度桶，避免把同一状态的轻微长度差异误判为新状态
        n = len(response)
        bucket = 0 if n < 16 else 1 if n < 64 else 2 if n < 256 else 3
        h = hashlib.sha1(response).hexdigest()[:8]
        head = response[:2].hex()
        return [f"GEN:b{bucket},h={h},hd={head},n={n}"]


# ---- 注册表 -------------------------------------------------------------

EXTRACTORS: dict[str, Callable[[], StateExtractor]] = {
    "ftp": FtpExtractor,
    "smtp": SmtpExtractor,
    "http": HttpExtractor,
    "rtsp": RtspExtractor,
    "sip": SipExtractor,
    "pop3": Pop3Extractor,
    "redis": RedisExtractor,
    "dns": DnsExtractor,
    "tls": TlsExtractor,
    "modbus": ModbusExtractor,
    "mysql": MysqlExtractor,
    "numeric": NumericCodeExtractor,
    "statusline": StatusLineExtractor,
    "generic": GenericExtractor,
}


def get_extractor(name: str) -> StateExtractor:
    if name not in EXTRACTORS:
        raise KeyError(
            f"未知协议 {name!r}，可选：{', '.join(sorted(EXTRACTORS))}")
    return EXTRACTORS[name]()


# ==========================================================================
# 4. 状态分析：状态集合 / 状态种子 / IPSM
# ==========================================================================

@dataclass
class MessageState:
    """单条消息的状态标注。"""
    index: int
    request_len: int
    request_head: str
    codes: list[str]          # 本条消息的响应码
    base_state: str           # 状态键（code 模式下 = 最后一个响应码）
    seq_state: str            # 累积状态键，如 "220>331>230"
    prev_state: str           # 前一条消息结束时的状态


@dataclass
class StateInfo:
    """单个状态的汇总。"""
    key: str
    kind: str                 # "code" | "sequence"
    first_seen_index: int     # 首次到达的消息下标
    hit_count: int            # 到达次数
    seed_ids: list[int]       # 到达该状态的种子下标（去重保序）
    examples: list[str]       # 触发该状态的请求示例（十六进制头）
    order: int = 0            # 注册顺序，用于稳定排序


@dataclass
class Analysis:
    """一次分析的完整结果。"""
    protocol: str
    state_mode: str
    n_messages: int
    state_set: list[str]                       # 状态集合（按首次出现序）
    state_seeds: dict[str, list[int]]          # 状态 -> 种子下标列表
    seeds_states: dict[int, list[str]]         # 种子下标 -> 到达的状态
    transitions: dict[str, int]                # "src -> dst" -> 次数（IPSM 边）
    msg_states: list[MessageState]
    states_detail: list[StateInfo]
    unreachable_hint: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        d = asdict(self)
        return d

    def ipsm(self) -> dict[str, dict[str, int]]:
        """IPSM：src_state -> {dst_state: count}。"""
        g: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for edge, cnt in self.transitions.items():
            src, dst = edge.split(" -> ")
            g[src][dst] = cnt
        return {k: dict(v) for k, v in g.items()}

    def rare_states(self, top: int = 10) -> list[tuple[str, int]]:
        """按到达次数升序：越罕见越值得定向探索（AFLNet 目标状态选择）。"""
        return sorted(((s.key, s.hit_count) for s in self.states_detail),
                      key=lambda x: x[1])[:top]

    def state_seeds_report(self) -> list[tuple[str, int, int]]:
        """(状态键, 种子数, 到达次数) —— 状态种子一览。"""
        return [(s.key, len(s.seed_ids), s.hit_count) for s in self.states_detail]


class StateAnalyzer:
    """把 Session 变成 Analysis。

    state_mode:
      "code"      —— 状态 = 本条消息响应的最后一个响应码
      "sequence"  —— 状态 = 累积响应码序列（AFLNet IPSM 键空间）
    """

    def __init__(self, extractor: StateExtractor, state_mode: str = "code"):
        if state_mode not in ("code", "sequence"):
            raise ValueError("state_mode 必须是 'code' 或 'sequence'")
        self.extractor = extractor
        self.state_mode = state_mode

    def analyze(self, sessions: Sequence[Session]) -> Analysis:
        msg_states: list[MessageState] = []
        # 状态详情累积
        detail: dict[str, StateInfo] = {}
        transitions: Counter = Counter()
        # 状态 -> 种子下标
        state_seeds: dict[str, list[int]] = defaultdict(list)
        seeds_states: dict[int, list[str]] = defaultdict(list)

        for sess in sessions:
            self._analyze_session(sess, msg_states, detail,
                                  transitions, state_seeds, seeds_states)

        # 首次出现序；同一消息内触达多个状态时按注册顺序稳定输出
        state_set = sorted(detail,
                           key=lambda k: (detail[k].first_seen_index,
                                          detail[k].order))

        return Analysis(
            protocol=self.extractor.name,
            state_mode=self.state_mode,
            n_messages=len(msg_states),
            state_set=state_set,
            state_seeds={k: state_seeds[k] for k in state_set},
            seeds_states={k: seeds_states[k] for k in sorted(seeds_states)},
            transitions={f"{a} -> {b}": c for (a, b), c in transitions.items()},
            msg_states=msg_states,
            states_detail=[detail[k] for k in state_set],
        )

    # ---- 单会话 -------------------------------------------------------

    def _analyze_session(
        self,
        sess: Session,
        msg_states: list[MessageState],
        detail: dict[str, StateInfo],
        transitions: Counter,
        state_seeds: dict[str, list[int]],
        seeds_states: dict[int, list[str]],
    ) -> None:
        # 每个会话的累积序列从 "<INIT>"（初始状态）开始
        seq_parts: list[str] = []
        prev_key = "<INIT>"
        # 状态注册顺序（保证 state_set 按首次出现稳定输出）
        reg_order: dict[str, int] = {}

        def register(key: str, idx: int) -> None:
            if key not in detail:
                reg_order[key] = len(reg_order)
                detail[key] = StateInfo(
                    key=key, kind=self.state_mode,
                    first_seen_index=idx, hit_count=0,
                    seed_ids=[], examples=[],
                    order=reg_order[key],
                )
            info = detail[key]
            info.hit_count += 1
            if idx not in info.seed_ids:
                info.seed_ids.append(idx)
            if idx not in state_seeds[key]:
                state_seeds[key].append(idx)
            if key not in seeds_states[idx]:
                seeds_states[idx].append(key)

        for i, (req, resp) in enumerate(sess.aligned()):
            codes = self.extractor.extract(resp)

            # 累积响应码序列（两种模式都需要，作为元数据）
            seq_parts.extend(codes)
            seq_key = ">".join(seq_parts) if seq_parts else "<INIT>"

            if self.state_mode == "sequence":
                # 状态 = 累积响应码序列（AFLNet IPSM 键空间）
                key = seq_key
                reached = [key]
            else:
                # code 模式：本条消息触达的**每个**响应码都是状态
                # （FTP 的 LIST 会同时经过 150 和 226），
                # IPSM 上的「落点」取最后一个
                key = codes[-1] if codes else prev_key
                reached = list(codes) if codes else [key]

            ms = MessageState(
                index=len(msg_states),
                request_len=len(req),
                request_head=req[:24].hex(),
                codes=codes,
                base_state=codes[-1] if codes else "",
                seq_state=seq_key,
                prev_state=prev_key,
            )
            msg_states.append(ms)

            for rk in reached:
                register(rk, ms.index)
                if req and len(detail[rk].examples) < 3:
                    detail[rk].examples.append(req[:32].hex())

            # IPSM 边：prev -> 落点
            transitions[(prev_key, key)] += 1
            prev_key = key


# ==========================================================================
# 5. 种子导出：兼容 HSPFuzzer 的 "pre" 命名 + AFLNet 语料库
# ==========================================================================

def export_seeds(
    analysis: Analysis,
    sessions: Sequence[Session],
    out_dir: str | Path,
    prefix_ids: Sequence[int] | None = None,
    need_split: bool | None = None,
    all_split: bool | None = None,
    split_by: str = "message",
) -> Path:
    """导出种子 + 状态元数据。

    split_by = "message" : 每条消息一个种子（HSPFuzzer 的 all_split 情形）
    split_by = "session" : 每个会话一个种子（AFLNet 的「消息序列」语料库）

    前缀消息文件名含 "pre"，HSPFuzzer 会自动放进 pre_queue
    （src/afl-fuzz-queue.c:631 strstr(q->fname, "pre")）。
    """
    out = Path(out_dir)
    seed_dir = out / "seeds"
    seed_dir.mkdir(parents=True, exist_ok=True)

    prefix_set = set(prefix_ids or [])
    files: list[dict] = []

    if split_by == "session":
        k = 0
        for si, sess in enumerate(sessions):
            blob = b"".join(sess.messages)
            # 会话级种子：若含前缀，文件名带 pre
            has_pre = any(j in prefix_set for j in
                          range(k, k + len(sess.messages)))
            fname = f"pre_{si:03d}.msg" if has_pre else f"seed_{si:03d}.msg"
            (seed_dir / fname).write_bytes(blob)
            files.append({"file": fname, "kind": "session", "session": si,
                          "n_messages": len(sess.messages)})
            k += len(sess.messages)
    else:
        # 消息级
        idx = 0
        pre_k = 0
        seed_k = 0
        for sess in sessions:
            for req in sess.messages:
                if idx in prefix_set:
                    fname = f"pre_{pre_k:03d}.msg"
                    pre_k += 1
                else:
                    fname = f"seed_{seed_k:03d}.msg"
                    seed_k += 1
                (seed_dir / fname).write_bytes(req)
                files.append({"file": fname, "kind": "message",
                              "msg_index": idx, "len": len(req)})
                idx += 1

    # ---- 状态元数据 ----
    meta = {
        "protocol": analysis.protocol,
        "state_mode": analysis.state_mode,
        "n_messages": analysis.n_messages,
        "state_set": analysis.state_set,
        "n_states": len(analysis.state_set),
        "state_seeds": analysis.state_seeds,
        "seeds_states": {str(k): v for k, v in analysis.seeds_states.items()},
        "ipsm": analysis.ipsm(),
        "transitions": analysis.transitions,
        "prefix_msg_indices": list(prefix_ids or []),
        "need_split": need_split,
        "all_split": all_split,
        "split_by": split_by,
        "files": files,
        "states_detail": [
            {"key": s.key, "first_seen": s.first_seen_index,
             "hit_count": s.hit_count, "seed_ids": s.seed_ids}
            for s in analysis.states_detail
        ],
        "rare_states": [{"state": k, "hit": v}
                        for k, v in analysis.rare_states()],
    }
    (out / "state_meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    # ---- IPSM（AFLNet 风格邻接表）----
    ipsm = analysis.ipsm()
    with open(out / "ipsm.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["src_state", "dst_state", "count"])
        for src, dsts in ipsm.items():
            for dst, cnt in sorted(dsts.items(),
                                   key=lambda x: -x[1]):
                w.writerow([src, dst, cnt])

    # ---- 种子索引 CSV ----
    with open(out / "seeds_index.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["msg_index", "file", "is_prefix", "codes",
                    "base_state", "seq_state", "req_len"])
        fname_by_idx = {e["msg_index"]: e["file"]
                        for e in files if "msg_index" in e}
        for ms in analysis.msg_states:
            w.writerow([
                ms.index,
                fname_by_idx.get(ms.index, ""),
                "1" if ms.index in prefix_set else "0",
                "|".join(ms.codes),
                ms.base_state,
                ms.seq_state,
                ms.request_len,
            ])

    return out


# ==========================================================================
# 6. 前缀消息识别（算法 2）接线
# ==========================================================================

def run_prefix_identification(
    sessions: Sequence[Session],
    target_cmd: Sequence[str],
    tau: int = 1,
    delta: float = 0.05,
    showmap: str = "afl-showmap",
    verbose: bool = True,
):
    """对全部会话的消息序列跑算法 2。返回 (Algo2Result, n_messages)。"""
    if not _HAS_ALGO2:
        raise RuntimeError("缺少 prefix_msg_identify.py，无法跑算法 2")

    msgs = [m for s in sessions for m in s.messages]
    n = len(msgs)
    if n < 2 + tau:
        raise ValueError(f"N={n} < 2+τ={2 + tau}，论文假设不满足")

    oracle = ShowmapOracle(target_cmd, showmap=showmap)

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
    res = identify_prefix_messages(sim, n=n, tau=tau, delta=delta,
                                   verbose=verbose)
    return res, n


# ==========================================================================
# 7. 自测
# ==========================================================================

def selftest() -> int:
    print("=" * 68)
    print("自测 1：FTP 响应码状态提取 / 状态集合 / 状态种子 / IPSM")
    print("=" * 68)

    # 模拟一段 FTP 登录 + 两条命令的交互
    sess = Session()
    sess.messages = [
        b"USER foo\r\n",
        b"PASS bar\r\n",
        b"PWD\r\n",
        b"LIST\r\n",
        b"QUIT\r\n",
    ]
    sess.responses = [
        b"331 User name okay, need password.\r\n",
        b"230 User logged in, proceed.\r\n",
        b'257 "/" is current directory.\r\n',
        b"150 Here comes the directory listing.\r\n226 Transfer complete.\r\n",
        b"221 Goodbye.\r\n",
    ]

    an = StateAnalyzer(get_extractor("ftp"), state_mode="code")
    a = an.analyze([sess])

    print(f"协议={a.protocol}  模式={a.state_mode}  消息数={a.n_messages}")
    print(f"\n状态集合 ({len(a.state_set)}): {a.state_set}")

    print("\n状态种子 (state -> 到达它的种子下标):")
    for st, seeds in a.state_seeds.items():
        print(f"  {st:6s}  seeds={seeds}")

    print("\n状态机 IPSM (src -> dst : count):")
    for src, dsts in a.ipsm().items():
        for dst, cnt in dsts.items():
            print(f"  {src:8s} -> {dst:8s} : {cnt}")

    print("\n罕见状态（越靠前越该定向探索）:")
    for k, v in a.rare_states():
        print(f"  {k}  hit={v}")

    # 断言
    # LIST 的响应是两行 150 + 226，二者都是状态；IPSM 落点取最后一个 226
    expect_states = ["331", "230", "257", "150", "226", "221"]
    ok1 = a.state_set == expect_states
    ok2 = "150" in a.state_set and "226" in a.state_set
    ok3 = set(a.state_seeds.keys()) == set(a.state_set)
    ok4 = len(a.ipsm()) > 0
    # 中间码 150 与 落点 226 都应关联到同一条种子（下标 3）
    ok4b = (a.state_seeds.get("150") == [3]
            and a.state_seeds.get("226") == [3])

    print(f"\n断言: state_set 正确={ok1}  多行码全采集={ok2}  "
          f"状态种子齐全={ok3}  IPSM 非空={ok4}  中间码入种子={ok4b}")

    print()
    print("=" * 68)
    print("自测 2：sequence 模式（AFLNet IPSM 键空间）")
    print("=" * 68)
    an2 = StateAnalyzer(get_extractor("ftp"), state_mode="sequence")
    a2 = an2.analyze([sess])
    print(f"状态集合 ({len(a2.state_set)}):")
    for s in a2.state_set:
        print(f"  {s}")
    ok5 = a2.state_set[-1].endswith("221")

    print()
    print("=" * 68)
    print("自测 3：导出种子 + 状态元数据")
    print("=" * 68)
    out = Path(__file__).parent / "_selftest_state_out"
    export_seeds(a, [sess], out, prefix_ids=[0, 1],
                 need_split=True, all_split=False, split_by="message")
    print(f"导出目录: {out}")
    for p in sorted(out.rglob("*")):
        if p.is_file():
            print(f"  {p.relative_to(out)}  ({p.stat().st_size} B)")

    ok6 = (out / "state_meta.json").exists()
    ok6 = ok6 and (out / "ipsm.csv").exists()
    ok6 = ok6 and (out / "seeds_index.csv").exists()
    ok6 = ok6 and (out / "seeds" / "pre_000.msg").exists()

    all_ok = all([ok1, ok2, ok3, ok4, ok4b, ok5, ok6])
    print()
    print(f"断言: sequence 模式尾状态={ok5}  导出完整={ok6}")
    print("自测" + ("全部通过 [OK]" if all_ok else "存在失败 [FAIL]"))
    return 0 if all_ok else 1


# ==========================================================================
# 8. CLI
# ==========================================================================

def _reconfigure_stdio() -> None:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def cmd_analyze(args) -> int:
    sessions = parse_pcap_sessions(
        args.input, args.client_ip, args.server_ip, args.client_port)
    total = sum(len(s) for s in sessions)
    print(f"[*] {args.input}: {len(sessions)} 个会话, {total} 条客户端消息")

    if not sessions:
        print("[!] 未解析出任何客户端消息，检查 --client-ip / 过滤条件")
        return 2

    ext = get_extractor(args.protocol)
    an = StateAnalyzer(ext, state_mode=args.state_mode)
    analysis = an.analyze(sessions)

    print(f"[*] 协议={analysis.protocol}  状态模式={analysis.state_mode}")
    print(f"[*] 状态集合 ({len(analysis.state_set)}):")
    for s in analysis.state_set:
        print(f"      {s}")

    print(f"\n[*] 状态种子:")
    for s in analysis.states_detail:
        print(f"      {s.key:20s}  种子={s.seed_ids}  到达={s.hit_count}次")

    print(f"\n[*] IPSM 转移 ({len(analysis.transitions)}):")
    for edge, cnt in sorted(analysis.transitions.items(),
                            key=lambda x: -x[1])[:20]:
        print(f"      {edge}  x{cnt}")

    prefix_ids: list[int] = []
    need_split = all_split = None

    if args.prefix:
        if not args.target:
            print("[!] --prefix 需要 --target <被测程序命令行>")
            return 2
        print("\n[*] 运行算法 2（前缀消息识别）...")
        res, n = run_prefix_identification(
            sessions, args.target, tau=args.tau, delta=args.delta,
            showmap=args.showmap, verbose=args.verbose)
        prefix_ids = res.prefix_msgs
        need_split = res.need_split
        all_split = res.all_split
        print(f"\n[*] 算法 2 结果:")
        print(f"      PrefixMsgs = {prefix_ids}")
        print(f"      NeedSplit  = {need_split}")
        print(f"      AllSplit   = {all_split}")
    elif not args.no_prefix_guess:
        # 无 SUT 时的启发式前缀估计：连续的、不可跳过的初始化消息
        # （粗略：会话开头直到第一个「非 2xx/3xx 成功」之后的稳定段）
        prefix_ids = _guess_prefix(analysis, args.tau)
        print(f"\n[*] 启发式前缀估计（未跑算法 2，仅供参考）: {prefix_ids}")
        print("    要精确识别请加 --prefix --target <SUT>")

    out = export_seeds(analysis, sessions, args.output,
                       prefix_ids=prefix_ids,
                       need_split=need_split, all_split=all_split,
                       split_by=args.split_by)
    print(f"\n[*] 已导出到 {out}")
    for p in sorted(out.rglob("*")):
        if p.is_file():
            print(f"      {p.relative_to(out)}")
    return 0


def _guess_prefix(analysis, tau: int) -> list[int]:
    """无覆盖率时的前缀启发式（粗略，仅供预览）。

    规则：会话开头连续的、到达**新状态**的消息视为前缀，
    一旦出现重复状态（消息可跳过）即停止。
    """
    seen = set()
    out = []
    for ms in analysis.msg_states:
        key = ms.base_state or ms.seq_state
        if key in seen:
            break
        seen.add(key)
        out.append(ms.index)
        if len(out) > 32:
            break
    return out


def main(argv: Sequence[str] | None = None) -> int:
    _reconfigure_stdio()
    ap = argparse.ArgumentParser(
        description="协议种子分析器：状态集合/状态种子/IPSM + 前缀消息识别")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_a = sub.add_parser("analyze", help="分析 pcap，产出状态与种子")
    ap_a.add_argument("-i", "--input", required=True, help="pcap/pcapng 文件")
    ap_a.add_argument("-o", "--output", default="seed_out", help="导出目录")
    ap_a.add_argument("-p", "--protocol", default="ftp",
                      help="协议：" + "|".join(sorted(EXTRACTORS)))
    ap_a.add_argument("--state-mode", choices=["code", "sequence"],
                      default="code",
                      help="状态粒度：code=最后响应码, sequence=累积序列(IPSM)")
    ap_a.add_argument("--split-by", choices=["message", "session"],
                      default="message", help="种子粒度")
    ap_a.add_argument("--client-ip", help="客户端 IP")
    ap_a.add_argument("--server-ip", help="服务器 IP")
    ap_a.add_argument("--client-port", type=int, help="客户端端口")
    ap_a.add_argument("--prefix", action="store_true",
                      help="运行算法 2 精确识别前缀（需 --target）")
    ap_a.add_argument("--no-prefix-guess", action="store_true",
                      help="不输出启发式前缀估计")
    ap_a.add_argument("--target", nargs=argparse.REMAINDER,
                      help="被测程序命令行，如 --target ./ftp_server -p 21")
    ap_a.add_argument("--showmap", default="afl-showmap")
    ap_a.add_argument("--tau", type=int, default=1, help="算法 2 的 τ")
    ap_a.add_argument("--delta", type=float, default=0.05, help="算法 2 的 δ")
    ap_a.add_argument("-v", "--verbose", action="store_true")

    sub.add_parser("selftest", help="运行自测")

    args = ap.parse_args(argv)
    if args.cmd == "selftest":
        return selftest()
    return cmd_analyze(args)


if __name__ == "__main__":
    sys.exit(main())
