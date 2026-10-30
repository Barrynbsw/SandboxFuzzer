#!/usr/bin/env python3
"""
replay_judge.py — 崩溃样本归属判卷器

对 AFL++ 归档的每个 crash 样本，起一台干净靶机、发前缀 + 载荷，
看靶机是不是【真的】死了。

判据有两条，缺一不可：
  1. ground truth = 进程退出码（不看 recv 返回值——recv()==b'' 不抛异常）
  2. 判活口径与 sandbox_harness.c 一致：连上 + 发 PROBE_CMD + 收到应答行

  只用 connect() 判活不够：abort() 落 core 要约 115ms，这段时间 listen 套接字
  还在、connect() 照样成功，但进程马上就要消失。等它真正 wait() 收尸才作数。

用法: replay_judge.py <样本目录> <prefix.raw> [--bin ./stateful_server] [--port 9200]
                        [--expect crash|benign]
"""
import os, socket, subprocess, sys, time, glob

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from local_seedhub import LocalSeedHub  # noqa: E402  复用逐条发/按行收口径

PROBE_CMD = b"NOOP\r\n"


def server_responds(port, tmo=0.3):
    """判活：连上 + 发一条无害命令 + 收到应答行。与 harness 的 target_alive() 同口径。"""
    s = socket.socket()
    s.settimeout(tmo)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(PROBE_CMD)
        buf = b""
        while b"\n" not in buf:
            d = s.recv(256)
            if not d:
                return False
            buf += d
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def wait_up(port, tries=40):
    for _ in range(tries):
        if server_responds(port):
            return True
        time.sleep(0.02)
    return False


def judge_one(srv, port, prefix, payload, banner_lines=0):
    """返回 (是否真崩溃, 观测描述)。真崩溃=True / 良性=False / 无法判定=None"""
    if not wait_up(port):
        return None, "靶机起不来"

    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect(("127.0.0.1", port))
    except Exception as e:
        return None, f"connect 失败 {e}"

    try:
        # banner 属于连接建立，不属于任何一条消息，先读掉（FTP/SSH/SMTP）
        if banner_lines > 0 and LocalSeedHub.recv_lines(s, banner_lines) < 0:
            return None, "banner 无应答"
        # 前缀要【逐条报文】发、逐条等应答（审查 F7）：LightFTP 一次 recv
        # 当一条命令，整块 sendall 会被合并吞噬，"种子是否可达"判定系统性出错。
        # 不能 sleep：靶机 recv 超时只有 10ms，睡 20ms 等于让靶机先把连接关了。
        for msg in LocalSeedHub.split_msgs(prefix):
            s.sendall(msg)
            if LocalSeedHub.recv_lines(s, 1) < 0:
                break
        s.sendall(payload)
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass

    # ground truth：等进程真正收尸。
    # 不能只 sleep 一小段再 poll() —— abort() 落 core 约 115ms，正卡在中间的话
    # poll() 会说"还活着"，实际它已经注定要死。给足余量，谁先到谁说了算。
    deadline = time.time() + 1.0
    while time.time() < deadline:
        rc = srv.poll()
        if rc is not None:
            return True, f"靶机死亡 rc={rc}"
        time.sleep(0.01)

    # 1s 还没死 = 不是这个载荷干的。再确认它真能应答（而非僵死）。
    if server_responds(port):
        return False, "靶机存活"
    return False, "进程在但不应答（未崩溃，计为良性）"


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("crash_dir")
    ap.add_argument("prefix")
    ap.add_argument("--bin", default="./stateful_server")
    ap.add_argument("--port", type=int, default=9200)
    ap.add_argument("--expect", choices=["crash","benign"], default="crash")
    ap.add_argument("--banner-lines", type=int, default=0,
                    help="连上后靶机先送几行 banner（与 TARGET_BANNER_LINES 同值）")
    args = ap.parse_args()

    prefix = b""
    if args.prefix and os.path.exists(args.prefix):
        prefix = open(args.prefix, "rb").read()

    allf = sorted(glob.glob(os.path.join(args.crash_dir, "*")))
    idf = [f for f in allf if os.path.basename(f).startswith("id:")]
    files = idf if idf else [f for f in allf if os.path.isfile(f)]
    if not files:
        print(f"[!] {args.crash_dir} 里没有崩溃样本")
        return 1

    expect_crash = (args.expect == "crash")
    real = false_pos = lost = 0
    print(f"{'样本':<52} {'判定':<8} 观测")
    print("-" * 100)
    for f in files:
        payload = open(f, "rb").read()
        env = os.environ.copy()
        srv = subprocess.Popen([os.path.abspath(args.bin), str(args.port)],
                               env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ok, obs = judge_one(srv, args.port, prefix, payload, args.banner_lines)
        if srv.poll() is None:
            srv.kill(); srv.wait()

        name = os.path.basename(f)
        shown = payload[:28].replace(b"\r", b"\\r").replace(b"\n", b"\\n").decode("latin1")
        if ok is True:
            verdict = "靶机死亡"
            if expect_crash: real += 1
            else: false_pos += 1; verdict = "★误崩★"
        elif ok is False:
            verdict = "靶机存活"
            if expect_crash: false_pos += 1; verdict = "★漏报★"
            else: real += 1
        else:
            lost += 1; verdict = "跳过"
        print(f"{name:<52} {verdict:<8} {obs}   payload={shown!r}")

    print("-" * 100)
    print(f"合计 {len(files)}  符合预期={real}  违背预期={false_pos}  跳过={lost}")
    return 0 if false_pos == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
