#!/usr/bin/env python3
"""
test_coverage_injection.py — 覆盖率注入回归测试

证明「真靶机覆盖率可以零侵入注入」：
  · 靶机源码里没有 record_cov()、没有 SHM 代码、不碰任何 __afl_* 符号
  · 只靠 __AFL_SHM_ID 环境变量，AFL++ 运行时把 __afl_area_ptr 指到私有段
  · 覆盖率随输入增长；不给 __AFL_SHM_ID 则私有段保持全零（对照）

顺带守住两个坑：
  1. 靶机源码里 extern __afl_area_ptr 会链接失败（LLVM pass 改名成 .N）
  2. 靶机是常驻服务，必须 AFL_NO_FORKSRV=1，否则 __afl_start_forkserver() 会握手

用法: test_coverage_injection.py [--bin ./tests/bin/real_target] [--port 9701]
"""
import argparse
import ctypes
import ctypes.util
import os
import socket
import subprocess
import sys
import time

SHM_SIZE = 65536
fail = 0
ok_n = 0


def check(cond, msg):
    global fail, ok_n
    if cond:
        print(f"  ✓ {msg}")
        ok_n += 1
    else:
        print(f"  ✗ {msg}")
        fail += 1


class Shm:
    def __init__(self, size=SHM_SIZE):
        libc = ctypes.CDLL(ctypes.util.find_library("c"))
        libc.shmget.restype = ctypes.c_int
        libc.shmat.restype = ctypes.c_void_p
        self.libc = libc
        self.id = libc.shmget(0, size, 0o1000 | 0o666)
        if self.id < 0:
            raise RuntimeError("shmget 失败")
        self.addr = libc.shmat(self.id, None, 0)
        self.buf = (ctypes.c_ubyte * size).from_address(self.addr)
        self.size = size
        self.zero()

    def zero(self):
        for i in range(self.size):
            self.buf[i] = 0

    def nonzero(self):
        return sum(1 for i in range(self.size) if self.buf[i])

    def offsets(self):
        return [i for i in range(self.size) if self.buf[i]]

    def destroy(self):
        self.libc.shmdt(ctypes.c_void_p(self.addr))
        self.libc.shmctl(self.id, 0, None)  # IPC_RMID


def hit(port, cmds, timeout=1.0):
    """发一组命令。靶机 recv 空闲超时只有 10ms —— 必须一次发完，中途不能 sleep。"""
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall("".join(cmds).encode())
        try:
            while True:
                if not s.recv(512):
                    break
        except Exception:
            pass
    except Exception:
        pass
    finally:
        s.close()


def start_target(bin_path, port, env_extra):
    env = os.environ.copy()
    env.update(env_extra)
    p = subprocess.Popen([os.path.abspath(bin_path), str(port)], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # 等它真开始 accept
    for _ in range(50):
        try:
            s = socket.socket(); s.settimeout(0.2)
            s.connect(("127.0.0.1", port)); s.close()
            return p
        except Exception:
            time.sleep(0.02)
    p.kill()
    raise RuntimeError(f"靶机起不来: {bin_path}:{port}")


def stop(p):
    if p.poll() is None:
        p.kill()
    p.wait()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="./tests/bin/real_target")
    ap.add_argument("--port", type=int, default=9701)
    args = ap.parse_args()

    if not os.path.isfile(args.bin):
        print(f"[!] 靶机不存在: {args.bin}")
        return 1

    print("════ 覆盖率注入回归测试 ════")
    print(f"靶机: {args.bin}（无 record_cov / 无 SHM 代码 / 不碰 __afl_*）\n")

    shm = Shm()

    # ── T1 对照组：不给 __AFL_SHM_ID，私有段必须保持全零 ──
    print("[T1] 对照组：不给 __AFL_SHM_ID")
    p = start_target(args.bin, args.port, {"AFL_NO_FORKSRV": "1"})
    hit(args.port, ["HELP\r\n", "USER a\r\n", "PASS b\r\n", "STOR x\r\n", "NOOP\r\n"])
    n0 = shm.nonzero()
    stop(p)
    check(n0 == 0, f"私有段非零 = {n0}（期望 0）")

    # ── T2 实验组：只靠 __AFL_SHM_ID ──
    print("\n[T2] 实验组：只设 __AFL_SHM_ID")
    shm.zero()
    p = start_target(args.bin, args.port + 1, {
        "__AFL_SHM_ID": str(shm.id), "AFL_NO_FORKSRV": "1"})

    steps = [("HELP", ["HELP\r\n"]),
             ("USER", ["USER a\r\n"]),
             ("PASS", ["PASS b\r\n"]),
             ("STOR", ["STOR x\r\n"]),
             ("NOOP", ["NOOP\r\n"]),
             ("未知", ["ZZZZ\r\n"])]
    seq = []
    for label, cmds in steps:
        hit(args.port + 1, cmds)
        n = shm.nonzero()
        seq.append(n)
        print(f"        {label:<6} 非零字节 = {n}")

    check(seq[0] > 0, f"第一条命令就写进了私有段（{seq[0]} 字节）")
    check(max(seq) > seq[0], f"不同命令触发不同边（{seq[0]} → {max(seq)}）")
    offsets = shm.offsets()
    check(len(offsets) >= 5, f"至少 5 个不同的边被点亮（实际 {len(offsets)}）")
    stop(p)

    # ── T3 幂等：同一命令重复打，不应无限长出新边 ──
    print("\n[T3] 幂等：重复同一命令")
    before = shm.nonzero()
    p = start_target(args.bin, args.port + 2, {
        "__AFL_SHM_ID": str(shm.id), "AFL_NO_FORKSRV": "1"})
    for _ in range(5):
        hit(args.port + 2, ["HELP\r\n"])
    stop(p)
    after = shm.nonzero()
    check(after <= before + 2, f"重复命令基本不增边（{before} → {after}）")

    shm.destroy()

    print(f"\n════ 通过 {ok_n}  失败 {fail} ════")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
