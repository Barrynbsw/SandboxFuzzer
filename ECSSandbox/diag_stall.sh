#!/bin/bash
#
# diag_stall.sh —— 吞吐为什么跑 ~60s 后从 250 exec/s 崩到 4.6 exec/s
# =====================================================================
#
# 现象（results/*/plot_data）：AFL++ 在 t≈61s 前干完 16,088 execs（250/s），
# 之后掉到 4.6 exec/s，corpus/edges 全程冻结。这让"机器时间对齐"的实验前提
# 失效：ISO 跑 K 个配置各拿到一份"前 60s 有效预算"，MIX 跑 K×DUR 却只拿到
# 一份 —— 偏置纯粹来自卡顿，不是来自状态隔离。
#
# 源码层的怀疑对象（third_party/lightftp，上游未改动）：
#   main.c:114    maxusers 默认 10，lightftp.sh 没覆盖 → 只有 10 个会话槽
#   ftpserv.c:2026  pthread_create(&th, ..., &ftp_client_thread, &scb[i])
#                 【默认 joinable】，全文件没有对它 pthread_join / pthread_detach
#                 （386 行那个 join 是 LIST/RETR/STOR 的数据线程，不是控制线程）
#   → 每个 FTP 会话结束后线程留在 ZOMBIE，task_struct + TID 永久泄漏
#   → 会话槽被占满时 ftpmain 走 NOSLOTS 分支：收下连接立刻回一句就 close
#   → harness 的 read_banner / target_alive() 拿不到应答 → 进 confirm_crash
#     （usleep(2000)+usleep(30000) + 二次探测）→ 单轮 ~200-300ms
#
# 这里只测不改：逐 2s 采 fftp 的线程数（含僵尸）、系统僵尸数、AFL++ execs、
# 以及【靶机还发不发 banner】—— 最后一项直接对上 NOSLOTS 的后果。
#
# 用法（宿主机编不动 fftp，必须进容器，挂【包根】）：
#   cd SandboxFuzzer
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/sbfpkg \
#       --workdir /sbfpkg/ECSSandbox --entrypoint bash sbf-node \
#       -lc './diag_stall.sh 150 2'
#
# 用法: ./diag_stall.sh [duration_sec] [n_secondaries]
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR"

DUR=${1:-150}
N=${2:-2}
STATE=diag_stall
SRC=ablation/A_single_state

[ -d "$SRC" ] || { echo "[!] 找不到 fixture 源 $SRC"; exit 1; }

rm -rf "ablation/$STATE" "results/$STATE" run/diag_sampler.log run/diag_run.log run/diag_timing.txt
cp -a "$SRC" "ablation/$STATE"

export SBF_TIMING_FILE="$SCRIPT_DIR/run/diag_timing.txt"

echo "============================================"
echo "  吞吐卡顿诊断   ${DUR}s   从实例=${N}"
echo "  pid_max=$(cat /proc/sys/kernel/pid_max)  threads-max=$(cat /proc/sys/kernel/threads-max)"
echo "============================================"

# ─── 采样器（后台）──────────────────────────────────────────────
(
    echo "pid_max=$(cat /proc/sys/kernel/pid_max) threads-max=$(cat /proc/sys/kernel/threads-max)"
    for _ in $(seq 1 $((DUR / 2 + 15))); do
        thr=""
        for p in $(pgrep -x fftp 2>/dev/null); do
            t=$(wc -l <"/proc/$p/task" 2>/dev/null || echo 0)
            thr="$thr,$t"
        done
        z=$(ps -eo stat= --no-headers | grep -c '^Z')
        tot=$(ps -e --no-headers | wc -l)

        ex=0
        for f in results/$STATE/i*/fuzzer_*/fuzzer_stats; do
            [ -f "$f" ] && ex=$((ex + $(awk '/^execs_done/{print $3}' "$f")))
        done

        # 靶机可用性：每端口试连并读 banner。Y=有 banner  N=连不上  E=连上没 banner(=NOSLOTS)
        av=""
        for port in $(seq 9001 $((9001 + N))); do
            ok=$(python3 -c "
import socket
s = socket.socket(); s.settimeout(0.5)
try:
    s.connect(('127.0.0.1', $port))
    print('Y' if s.recv(64) else 'E')
except OSError:
    print('N')
finally:
    s.close()
" 2>/dev/null)
            av="$av${ok:-?}"
        done

        echo "t=$(( $(date +%s) % 100000 )) execs=$ex fftp_threads=$thr zombies=$z procs=$tot banner=$av"
        sleep 2
    done
) >run/diag_sampler.log 2>&1 &
SAMP=$!

T0=$(date +%s)
TARGET_CONF="$SCRIPT_DIR/targets/lightftp.conf" \
    PREFIX_ROOT="$SCRIPT_DIR/ablation" \
    ./run_state_node.sh "$STATE" "$N" "$DUR" >run/diag_run.log 2>&1
T1=$(date +%s)

kill "$SAMP" 2>/dev/null || true
wait "$SAMP" 2>/dev/null || true

echo ""
echo "===== harness 分段计时（累计均值，来自 SBF_TIMING_FILE）====="
cat run/diag_timing.txt 2>/dev/null || echo "（没写出来）"

echo ""
echo "===== 采样器 ====="
cat run/diag_sampler.log

echo ""
echo "===== AFL++ plot_data（每次 plot 的累计 execs）====="
for f in results/$STATE/i*/fuzzer_*/plot_data; do
    echo "--- $f"
    awk 'NR==1 || NR%8==2' "$f"
done

echo ""
echo "墙钟 $((T1 - T0))s。产物留在 ablation/$STATE、results/$STATE、run/diag_*"
