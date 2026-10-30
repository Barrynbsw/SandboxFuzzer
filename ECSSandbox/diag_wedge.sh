#!/bin/bash
#
# diag_wedge.sh —— 验证「PASV accept() 无超时楔死会话槽」假设
# ==============================================================
#
# 假设（源码层已坐实，这里只做实证）：
#   ftpserv.c:284  create_datasocket() 的 MODE_PASSIVE 分支是
#                  accept(context->DataSocket, ...)  【无超时】
#   ftpserv.c:381  WorkerThreadCleanup() 先 sleep(2) 再 pthread_join 那个 worker
#
#   AFL++ 变异出 PASV+数据传输命令（LIST/NLST/RETR/STOR/APPE/MLSD）时，
#   worker 永久卡在 accept()，client 线程随之永久卡在 pthread_join ——
#   该会话占着 maxusers=10 的一个槽【直到进程死】。
#   攒满 10 个 → ftpmain 走 NOSLOTS 分支，之后每个连接收下就 close。
#
#   注意 NOSLOTS = "MAXIMUM ALLOWED USERS CONNECTED\r\n"，【不带状态码】
#   （ftpserv.h:196），所以"连上读到东西"不等于"靶机正常"——
#   上一版采样器正是栽在这里。这版直接打 banner 原文。
#
# 三个判据（任一坐实即说明楔死发生）：
#   ① fftp 的线程数爬到 >= maxusers 并【不回落】
#   ② 有线程的 wchan 停在 accept 相关内核函数
#   ③ banner 原文变成 "MAXIMUM ALLOWED USERS CONNECTED"
#
# 用法（宿主机编不动 fftp，必须进容器，挂【包根】）：
#   cd SandboxFuzzer
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/sbfpkg \
#       --workdir /sbfpkg/ECSSandbox --entrypoint bash sbf-node \
#       -lc './diag_wedge.sh 120 2'
#
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR"

DUR=${1:-120}
N=${2:-2}
STATE=diag_wedge
SRC=ablation/A_single_state

[ -d "$SRC" ] || { echo "[!] 找不到 fixture 源 $SRC"; exit 1; }

rm -rf "ablation/$STATE" "results/$STATE" run/wedge_sampler.log run/wedge_run.log run/timing_diag.txt
cp -a "$SRC" "ablation/$STATE"

# 顺手拿 harness 分段计时（3 个实例写同一个文件，会互相覆盖，只看量级）
export SBF_TIMING_EVERY=200
export SBF_TIMING_FILE="$SCRIPT_DIR/run/timing_diag.txt"

echo "============================================"
echo "  会话槽楔死验证   ${DUR}s   从实例=${N}"
echo "============================================"

# 采样器：线程数 / wchan / banner 原文
(
    for _ in $(seq 1 $((DUR / 2 + 10))); do
        ex=0
        for f in results/$STATE/i*/fuzzer_*/fuzzer_stats; do
            [ -f "$f" ] && ex=$((ex + $(awk '/^execs_done/{print $3}' "$f")))
        done

        line="execs=$ex"
        for port in $(seq 9001 $((9001 + N))); do
            pid=$(pgrep -f "fftp.*fftp_$port.conf" | head -1)
            nth=0
            [ -n "$pid" ] && nth=$(find "/proc/$pid/task" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
            # 卡在 accept 的线程数
            nacc=0
            if [ -n "$pid" ]; then
                for w in /proc/$pid/task/*/wchan; do
                    v=$(cat "$w" 2>/dev/null)
                    case "$v" in *accept*|*inet_csk*) nacc=$((nacc + 1)) ;; esac
                done
            fi
            # banner 原文（前 44 字节）
            bn=$(python3 -c "
import socket
s = socket.socket(); s.settimeout(1.0)
try:
    s.connect(('127.0.0.1', $port))
    print(repr(s.recv(64)[:44]))
except OSError as e:
    print('CONN_FAIL')
finally:
    s.close()
" 2>/dev/null)
            line="$line | p$port thr=$nth accept=$nacc ban=$bn"
        done
        echo "$line"
        sleep 2
    done
) >run/wedge_sampler.log 2>&1 &
SAMP=$!

TARGET_CONF="$SCRIPT_DIR/targets/lightftp.conf" \
    PREFIX_ROOT="$SCRIPT_DIR/ablation" \
    ./run_state_node.sh "$STATE" "$N" "$DUR" >run/wedge_run.log 2>&1

kill "$SAMP" 2>/dev/null || true
wait "$SAMP" 2>/dev/null || true

echo ""
echo "===== 采样器 ====="
cat run/wedge_sampler.log

echo ""
echo "===== 末态 fftp 线程 wchan 分布 ====="
for port in $(seq 9001 $((9001 + N))); do
    pid=$(pgrep -f "fftp.*fftp_$port.conf" | head -1)
    [ -z "$pid" ] && { echo "port=$port  fftp 已不在"; continue; }
    echo "port=$port pid=$pid threads=$(find /proc/$pid/task -mindepth 1 -maxdepth 1 | wc -l)"
    for w in /proc/$pid/task/*/wchan; do
        cat "$w" 2>/dev/null
        echo
    done | sort | uniq -c | sort -rn
done

echo ""
echo "===== harness 分段计时 ====="
cat run/timing_diag.txt 2>/dev/null || echo "（未启用 SBF_TIMING_FILE）"
