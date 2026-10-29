#!/bin/bash
#
# SandboxFuzzer - 本地构建 & 运行受控状态模糊测试（无 Docker）
# 用法: ./build_and_run.sh [duration_in_seconds]
#

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR"

# AFL++ 工具路径（本机编译安装）
export PATH="/home/barry/AFLplusplus:$PATH"

DURATION=${1:-180}
OUTPUT_DIR="$SCRIPT_DIR/output"
SEED_DIR="$SCRIPT_DIR/seeds_state2"
PREFIX_FILE="$SCRIPT_DIR/prefix_state2.raw"
PORT=9001

echo "============================================"
echo "  SandboxFuzzer - Controlled State Fuzzing"
echo "  (Local AFL++, No Docker)"
echo "============================================"
echo "  Duration: ${DURATION}s"
echo "  Output:   ${OUTPUT_DIR}"
echo ""

# 清理旧的编译产物和残留进程
rm -f stateful_server sandbox_harness
pkill -f stateful_server 2>/dev/null || true
pkill -f afl-fuzz 2>/dev/null || true
pkill -f sandbox_harness 2>/dev/null || true
sleep 1
fuser -k $PORT/tcp 2>/dev/null || true
sleep 0.5

# Step 1: 编译靶机（注入覆盖率探针）
echo "[1/3] 编译靶机 stateful_server.c ..."
afl-clang-fast stateful_server.c -o stateful_server -lrt
echo "  ✓ stateful_server 编译完成"

# Step 2: 编译通用 Harness 测试桩
echo "[2/3] 编译 Harness sandbox_harness.c ..."
# 桥接 TU 必须用普通 cc —— 参见 afl_map_bridge.c 头部说明
cc -O2 -c afl_map_bridge.c -o afl_map_bridge.o
afl-clang-fast sandbox_harness.c afl_map_bridge.o -o sandbox_harness -lrt
echo "  ✓ sandbox_harness 编译完成"

# Step 3: 启动模糊测试
echo "[3/3] 启动 AFL++ 模糊测试 (AFLNet 持久模式)..."

# 清理旧输出
rm -rf "$OUTPUT_DIR"

# 后台启动靶机
./stateful_server $PORT &
TARGET_PID=$!
sleep 1

# 确认靶机已启动
if ! kill -0 $TARGET_PID 2>/dev/null; then
    echo "[!] 靶机启动失败"
    exit 1
fi
echo "  ✓ 靶机已启动 (PID: $TARGET_PID, Port: $PORT)"

# 设置环境变量
export PREFIX_FILE="$PREFIX_FILE"
export AFL_SKIP_CPUFREQ=1
export AFL_NO_UI=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

# 启动 AFL++ 模糊测试
echo "  开始模糊测试，持续 ${DURATION}s ..."
echo ""

# 设置超时退出
(sleep $DURATION && kill $TARGET_PID 2>/dev/null) &
WATCHDOG_PID=$!

# 运行 AFL++
afl-fuzz -i "$SEED_DIR" -o "$OUTPUT_DIR" -M fuzzer_main \
    -t 1000 \
    -- ./sandbox_harness &
AFL_PID=$!

# 等待 AFL++ 结束或超时
wait $AFL_PID 2>/dev/null || true

# 清理
kill $TARGET_PID 2>/dev/null || true
kill $WATCHDOG_PID 2>/dev/null || true
wait $TARGET_PID 2>/dev/null || true

echo ""
echo "[*] 模糊测试完成"

# 输出结果摘要
if [ -d "$OUTPUT_DIR/fuzzer_main" ]; then
    echo ""
    echo "=========================================="
    echo "  结果摘要"
    echo "=========================================="
    if [ -f "$OUTPUT_DIR/fuzzer_main/fuzzer_stats" ]; then
        echo "  统计文件: $OUTPUT_DIR/fuzzer_main/fuzzer_stats"
        grep -E "execs_done|execs_per_sec|corpus_count|saved_crashes|edges_found" \
            "$OUTPUT_DIR/fuzzer_main/fuzzer_stats" 2>/dev/null | \
        while IFS=: read -r key val; do
            printf "  %-20s %s\n" "$(echo $key | xargs)" "$(echo $val | xargs)"
        done
    fi
    echo ""
    echo "  崩溃样本: $OUTPUT_DIR/fuzzer_main/crashes/"
    echo "  路径目录: $OUTPUT_DIR/fuzzer_main/queue/"
    echo "=========================================="
fi