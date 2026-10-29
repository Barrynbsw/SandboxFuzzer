#!/bin/bash

echo "[*] SandboxFuzzer: 正在启动容器内受控模糊测试..."

# 1. 后台启动靶机服务
./stateful_server 9001 &
TARGET_PID=$!
sleep 1  # 等待端口监听就绪

# 2. 注入平台下发的前缀文件路径
export PREFIX_FILE=/sandbox/prefix_state2.raw

# 3. AFL++ 驱动通用 Harness，使用平台下发的专属种子集
afl-fuzz -i seeds_state2/ -o results/ -M fuzzer_main -- ./sandbox_harness

# 4. 捕获退出信号，清理靶机
kill $TARGET_PID 2>/dev/null