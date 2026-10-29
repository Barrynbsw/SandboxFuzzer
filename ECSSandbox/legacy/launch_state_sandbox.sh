#!/bin/bash
#
# launch_state_sandbox.sh — 启动单个状态沙箱
# 用法: ./launch_state_sandbox.sh <STATE_NAME> <PORT> <PREFIX_FILE> <SEED_DIR> [DURATION]
#

set -e

STATE_NAME=$1
PORT=$2
PREFIX_FILE=$3
SEED_DIR=$4
DURATION=${5:-60}

if [ -z "$STATE_NAME" ] || [ -z "$PORT" ] || [ -z "$SEED_DIR" ]; then
    echo "Usage: $0 <STATE_NAME> <PORT> <PREFIX_FILE> <SEED_DIR> [DURATION]"
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
export PATH="/home/barry/AFLplusplus:$PATH"

# 创建该状态的 64KB 共享内存
SHM_ID=$(python3 -c "
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library('c'))
IPC_CREAT = 0o1000
shmget = libc.shmget
shmget.restype = ctypes.c_int
shmid = shmget(0, 65536, IPC_CREAT | 0o666)
print(shmid)
")
echo "[$STATE_NAME] SHM_ID=$SHM_ID"

# 清理旧进程
fuser -k $PORT/tcp 2>/dev/null || true
sleep 0.3

# 后台死循环启动靶机（崩溃自动重启）
(
    while true; do
        TARGET_SHM_ID=$SHM_ID $SCRIPT_DIR/stateful_server $PORT 2>/dev/null
        sleep 0.1
    done
) &
SERVER_LOOP_PID=$!
echo "[$STATE_NAME] Server loop PID=$SERVER_LOOP_PID (port $PORT)"

# 等待靶机就绪
sleep 1

# 设置环境变量
export PREFIX_FILE="$PREFIX_FILE"
export TARGET_PORT=$PORT
export TARGET_SHM_ID=$SHM_ID
export AFL_SKIP_CPUFREQ=1
export AFL_NO_UI=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

# 清理旧输出
rm -rf "$SCRIPT_DIR/results/$STATE_NAME"

# 启动 AFL++ 实例
echo "[$STATE_NAME] Starting AFL++ (port=$PORT, prefix=$PREFIX_FILE, seeds=$SEED_DIR)..."
afl-fuzz -i "$SEED_DIR" -o "$SCRIPT_DIR/results/$STATE_NAME" \
    -M "fuzzer_$STATE_NAME" -t 1000 \
    -- "$SCRIPT_DIR/sandbox_harness" 2>&1 &

AFL_PID=$!
echo "[$STATE_NAME] AFL++ PID=$AFL_PID"

# 超时退出
(sleep $DURATION && kill $AFL_PID 2>/dev/null && kill $SERVER_LOOP_PID 2>/dev/null) &
WATCHDOG_PID=$!

# 等待 AFL++ 结束
wait $AFL_PID 2>/dev/null || true

# 清理
kill $SERVER_LOOP_PID 2>/dev/null || true
kill $WATCHDOG_PID 2>/dev/null || true
# 杀掉该端口上的所有靶机进程
fuser -k $PORT/tcp 2>/dev/null || true

echo "[$STATE_NAME] Done."