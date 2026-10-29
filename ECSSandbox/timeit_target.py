#!/usr/bin/env python3
"""
timeit_target.py — 测靶机单次会话各阶段耗时，定位 harness 吞吐衰减的来源

用法: python3 timeit_target.py <port> [n_iter]

每轮模拟 sandbox_harness 主循环的网络交互：
  connect → recv banner → 发前缀(USER/PASS) → 收 2 行 → 发载荷 → 收应答 → close
分别计时，看哪一段随迭代次数变慢。
"""
import socket
import sys
import time

PREFIX = b"USER admin\r\nPASS 123456\r\n"


def one_iter(port, payload, probe=True):
    t = {}
    t0 = time.perf_counter()
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    t["connect"] = time.perf_counter() - t0

    s.settimeout(0.05)  # 与 harness 一致：50ms
    t0 = time.perf_counter()
    try:
        s.recv(256)          # banner
    except socket.timeout:
        pass
    t["banner"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    try:
        s.sendall(PREFIX)
        s.recv(256)
    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        pass
    t["prefix"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    try:
        s.sendall(payload)
    except Exception:
        pass
    t["send"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    got = False
    try:
        if s.recv(4096):
            got = True
    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        pass
    t["payload_recv"] = time.perf_counter() - t0
    try:
        s.close()
    except OSError:
        pass

    if probe:
        # target_alive() 的等价开销：新开连接 + banner + NOOP + 收 1 行
        t0 = time.perf_counter()
        s2 = socket.create_connection(("127.0.0.1", port), timeout=5)
        s2.settimeout(0.06)
        try:
            s2.recv(256)
        except socket.timeout:
            pass
        s2.sendall(b"NOOP\r\n")
        try:
            s2.recv(256)
        except socket.timeout:
            pass
        s2.close()
        t["alive_probe"] = time.perf_counter() - t0

    t["total"] = sum(t.values())
    return t, got


def main():
    port = int(sys.argv[1])
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    scenarios = [
        ("小载荷/有应答", b"NOOP\r\n"),
        ("小载荷/无应答", b"XXXXYYYYZZZZ\r\n"),
        ("大载荷 64KB", b"A" * 65536),
        ("大载荷 256KB", b"B" * 262144),
    ]
    for name, payload in scenarios:
        samples = []
        bucket = []
        print(f"\n=== {name}  (n={n}) ===")
        for i in range(n):
            try:
                t, _ = one_iter(port, payload)
            except Exception as e:
                t = {k: 0.0 for k in ("connect", "banner", "prefix", "send", "payload_recv", "alive_probe", "total")}
                t["total"] = 0.0
                if i < 3:
                    print(f"  [warn] iter {i}: {type(e).__name__}: {e}")
            samples.append(t)
            bucket.append(t)
            if len(bucket) >= 500:
                tot = sum(x["total"] for x in bucket) / len(bucket) * 1000
                pr = sum(x["payload_recv"] for x in bucket) / len(bucket) * 1000
                ap = sum(x["alive_probe"] for x in bucket) / len(bucket) * 1000
                print(f"  iter {i+1:6d}  total={tot:7.2f}ms  payload_recv={pr:6.2f}  alive={ap:6.2f}  → {1000/tot:7.1f}/s", flush=True)
                bucket = []
        def avg(sl, key):
            return sum(x[key] for x in sl) / len(sl) * 1000
        head, tail = samples[:20], samples[-20:]
        for k in ("connect", "banner", "prefix", "send", "payload_recv", "alive_probe", "total"):
            print(f"  {k:12s} 前20={avg(head,k):7.2f}ms  后20={avg(tail,k):7.2f}ms")
        print(f"  → 隐含吞吐: 前期 {1000/avg(head,'total'):6.1f}/s   后期 {1000/avg(tail,'total'):6.1f}/s")


if __name__ == "__main__":
    main()
