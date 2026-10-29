#!/usr/bin/env python3
"""
sbf_redis.py — 极简 RESP2 Redis 客户端（零第三方依赖）

SandboxFuzzer 的各组件（finding_sync.py / node_agent.py / seed_dispatcher.py）
共用本模块与中央 Dispatcher 通信。刻意不依赖 redis-py，保证 ECS 镜像开箱即用。
"""

import socket
import urllib.parse


class RedisError(Exception):
    pass


class ConnectionError(RedisError):
    pass


def _encode_command(*args):
    parts = [b"*%d\r\n" % len(args)]
    for a in args:
        if isinstance(a, str):
            a = a.encode("utf-8")
        elif not isinstance(a, (bytes, bytearray)):
            a = str(a).encode("utf-8")
        parts.append(b"$%d\r\n" % len(a))
        parts.append(bytes(a))
        parts.append(b"\r\n")
    return b"".join(parts)


class Redis:
    """单连接、同步阻塞的 RESP2 客户端。线程不安全（每个线程各建连接）。"""

    def __init__(self, url="redis://127.0.0.1:6379/0", timeout=30.0):
        u = urllib.parse.urlparse(url)
        if u.scheme not in ("redis", ""):
            raise RedisError("不支持的 Redis URL scheme: %s" % u.scheme)
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or 6379
        self.db = int((u.path or "/0").strip("/") or 0)
        self.password = u.password
        self.timeout = timeout
        self.sock = None
        self.rf = None

    # ── 连接管理 ──────────────────────────────────────────────
    def connect(self):
        try:
            self.sock = socket.create_connection((self.host, self.port), self.timeout)
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.rf = self.sock.makefile("rb")
        except OSError as e:
            raise ConnectionError("无法连接 Redis %s:%d — %s" % (self.host, self.port, e))
        if self.password:
            self.execute("AUTH", self.password)
        if self.db:
            self.execute("SELECT", self.db)
        return self

    def close(self):
        for x in (self.rf, self.sock):
            try:
                if x:
                    x.close()
            except OSError:
                pass
        self.sock = self.rf = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    def _reconnect(self):
        self.close()
        self.connect()

    # ── 协议编解码 ────────────────────────────────────────────
    def _read_line(self):
        line = self.rf.readline()
        if not line:
            raise ConnectionError("Redis 连接被关闭")
        return line[:-2]

    def _read_reply(self):
        line = self._read_line()
        t, rest = line[:1], line[1:]
        if t == b"+":
            return rest.decode("utf-8", "replace")
        if t == b"-":
            raise RedisError(rest.decode("utf-8", "replace"))
        if t == b":":
            return int(rest)
        if t == b"$":
            n = int(rest)
            if n == -1:
                return None
            data = self.rf.read(n)
            self.rf.read(2)  # 丢弃尾部 CRLF
            return data
        if t == b"*":
            n = int(rest)
            if n == -1:
                return None
            return [self._read_reply() for _ in range(n)]
        raise RedisError("无法解析 RESP 回复: %r" % line)

    def execute(self, *args):
        if self.sock is None:
            self.connect()
        try:
            self.sock.sendall(_encode_command(*args))
            return self._read_reply()
        except (OSError, ConnectionError):
            # 一次自动重连重试，应对 Dispatcher 重启
            try:
                self._reconnect()
                self.sock.sendall(_encode_command(*args))
                return self._read_reply()
            except (OSError, ConnectionError, RedisError):
                self.close()
                raise

    # ── 常用命令 ──────────────────────────────────────────────
    def ping(self):
        return self.execute("PING")

    def rpush(self, key, *values):
        return self.execute("RPUSH", key, *values)

    def lpop(self, key):
        return self.execute("LPOP", key)

    def llen(self, key):
        return self.execute("LLEN", key)

    def lrange(self, key, start, stop):
        return self.execute("LRANGE", key, start, stop)

    def set(self, key, value):
        return self.execute("SET", key, value)

    def get(self, key):
        return self.execute("GET", key)

    def hset(self, key, mapping):
        args = ["HSET", key]
        for k, v in mapping.items():
            args.extend([k, v])
        return self.execute(*args)

    def hgetall(self, key):
        flat = self.execute("HGETALL", key) or []
        return {flat[i].decode() if isinstance(flat[i], bytes) else flat[i]:
                flat[i + 1].decode() if isinstance(flat[i + 1], bytes) else flat[i + 1]
                for i in range(0, len(flat), 2)}

    def sadd(self, key, *members):
        return self.execute("SADD", key, *members)

    def sismember(self, key, member):
        return bool(self.execute("SISMEMBER", key, member))

    def smembers(self, key):
        return self.execute("SMEMBERS", key) or []

    def publish(self, channel, message):
        return self.execute("PUBLISH", channel, message)


class PubSub:
    """最小 Pub/Sub 订阅器：SUBSCRIBE 之后消息会主动推送过来。"""

    def __init__(self, redis_conn, channels):
        self.r = redis_conn
        self.channels = list(channels)

    def listen(self):
        if self.r.sock is None:
            self.r.connect()
        self.r.sock.sendall(_encode_command("SUBSCRIBE", *self.channels))
        # 订阅确认帧
        for _ in self.channels:
            self.r._read_reply()
        while True:
            frame = self.r._read_reply()
            if not isinstance(frame, list) or len(frame) < 3:
                continue
            kind = frame[0]
            if isinstance(kind, bytes):
                kind = kind.decode()
            if kind == "message":
                ch = frame[1].decode() if isinstance(frame[1], bytes) else frame[1]
                msg = frame[2].decode() if isinstance(frame[2], bytes) else frame[2]
                yield ch, msg
