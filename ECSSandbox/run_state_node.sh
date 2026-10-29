#!/bin/bash
#
# run_state_node.sh — 状态同质化（State-Homogeneous）ECS 节点启动器
#
# 原则一：单台 ECS 上【所有】AFL++ 实例与沙箱只测试【同一个】协议状态。
#
# 原则二（本地去重分工）：多个 AFL++ 进程共享一个优质种子池，但【同一个种子
#       只交给一个实例】去变异 —— 不做 -M/-S 盲同步（那会让 N 个进程都在测
#       全量语料）。做法：
#         · 每个实例独立 -o 父目录 → AFL++ 的 sync_dir 互不重叠，不互相扫描
#         · local_seedhub.py 维护公共池 corpus/<state>/，按 sha256 % N 分片
#         · 每片经 -F (foreign sync) 只投喂给 owner 实例
#         · 初始语料同样分片，开跑即分工
#
# 用法:
#   ./run_state_node.sh <state_name> [n_secondaries] [duration_sec]
#
#   state_name     : prefix_analyzer_output/ 下的状态目录名
#   n_secondaries  : 从实例数量（默认 nproc-1，即 1 + N 个实例）
#   duration_sec   : 运行时长，0 = 一直跑（默认 0）
#
# 环境变量:
#   BASE_PORT      靶机起始端口（默认 9001，每个实例 +1）
#   BIND_CPUS=1    把实例绑定到 CPU 核（默认不绑定）
#   REDIS_URL      若设置，则额外启动 finding_sync.py 异步回传
#                  （中央 Dispatcher 尚未定稿，默认关闭）
#

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# AFL++ 工具链位置：优先 AFLPP_PATH，其次 PATH 里已有的 afl-clang-fast，最后试常见路径
if [ -n "${AFLPP_PATH:-}" ]; then
    export PATH="$AFLPP_PATH:$PATH"
elif ! command -v afl-clang-fast >/dev/null 2>&1; then
    for d in "$HOME/AFLplusplus" /usr/local/bin /opt/AFLplusplus; do
        [ -x "$d/afl-clang-fast" ] && export PATH="$d:$PATH" && break
    done
fi
if ! command -v afl-clang-fast >/dev/null 2>&1 || ! command -v afl-fuzz >/dev/null 2>&1; then
    echo "[!] 找不到 AFL++ 工具链（afl-clang-fast / afl-fuzz）"
    echo "    请设置 AFLPP_PATH 指向 AFL++ 安装目录，例如："
    echo "        AFLPP_PATH=\$HOME/AFLplusplus $0 $*"
    exit 1
fi

# ─── 依赖预检 ───
# 少一个命令都可能在很后面才炸（比如 fuser 缺失表现为端口残留、靶机起不来），
# 在这儿一次说清楚。见 README 的依赖小节 / Dockerfile。
MISSING=()
for _cmd in cc python3 ipcrm ipcs fuser pkill nproc awk; do
    command -v "$_cmd" >/dev/null 2>&1 || MISSING+=("$_cmd")
done
if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "[!] 缺少依赖命令: ${MISSING[*]}"
    echo "    Debian/Ubuntu: apt-get install -y build-essential python3 util-linux psmisc"
    echo "    （fuser 来自 psmisc；ipcrm/ipcs 来自 util-linux）"
    exit 1
fi

STATE_NAME=$1
N_SECONDARIES=${2:-}
DURATION=${3:-0}

if [ -z "$STATE_NAME" ]; then
    echo "Usage: $0 <state_name> [n_secondaries] [duration_sec]"
    echo "  e.g. $0 state_2_auth 3 60"
    exit 1
fi

# ─── 全局互斥：同一台机器只允许一个节点在跑 ───
# 不加锁时两个并发 run 会互相 pkill 对方的编译进程、抢同一个端口段，
# 表现为莫名其妙的编译失败和"靶机起不来"。
#
# 这里【不能用 flock】：`exec 9>lock` 的 fd 会被 afl-fuzz / 靶机 / 保活循环
# 一并继承，父进程被 kill -9 时锁还留在子进程手上，留下"幽灵锁"——
# 下一次启动被自己上一轮的孤儿挡住。PID 存活检查没有这个问题：
# 持有者死了就是死了，直接放行并按残留清扫。
LOCK_PID_FILE=${SBF_LOCK_FILE:-/tmp/sbf_node.lock}
if [ -f "$LOCK_PID_FILE" ]; then
    _old=$(cat "$LOCK_PID_FILE" 2>/dev/null || true)
    if [ -n "${_old:-}" ] && [ "$_old" != "$$" ] && kill -0 "$_old" 2>/dev/null; then
        echo "[!] 已有 SandboxFuzzer 节点在运行（pid=$_old）"
        echo "    同机只能跑一个节点：状态同质化要求整机统一状态。"
        echo "    要停掉它:  kill $_old"
        exit 1
    fi
    echo "[LOCK] 上一轮持有者 pid=${_old:-?} 已不存在，按残留处理"
    rm -f "$LOCK_PID_FILE"
fi
echo $$ > "$LOCK_PID_FILE"

# 锁一拿到就装 trap：后面任何一步失败（状态不存在、编译失败、shmget 失败）
# 都不能把锁留在半路。完整 cleanup() 还没定义，这里先只兜住锁；
# 定义好之后会用 trap cleanup 覆盖掉。
trap 'rm -f "$LOCK_PID_FILE" 2>/dev/null || true' EXIT INT TERM

# ─── 靶机适配器 ───
# 一份 targets/*.conf 描述"怎么把一个程序当成 fuzz 靶机"：二进制、启动参数、
# 判活命令、覆盖率来源。接新目标只加一个 conf，不改任何 C 代码。
# 详见 targets/README.md
TARGET_CONF=${TARGET_CONF:-$SCRIPT_DIR/targets/stateful_server.conf}
if [ ! -f "$TARGET_CONF" ]; then
    echo "[!] 靶机适配器不存在: $TARGET_CONF"
    echo "    可用适配器:"
    for c in "$SCRIPT_DIR"/targets/*.conf; do
        [ -f "$c" ] && echo "      - ${c#$SCRIPT_DIR/}"
    done
    exit 1
fi
# shellcheck source=/dev/null
. "$TARGET_CONF"
: "${TARGET_NAME:?TARGET_NAME 必填（targets/*.conf）}"
: "${TARGET_BIN:?TARGET_BIN 必填（targets/*.conf）}"
: "${TARGET_PROBE_CMD:=$'NOOP\r\n'}"
: "${TARGET_SHM_SIZE:=65536}"
: "${TARGET_RECV_IDLE_US:=10000}"
: "${TARGET_COV_MODE:=instrument}"
: "${TARGET_NEEDS_RESTART:=1}"
# 连上后靶机先送几行 banner（FTP/SSH/SMTP 都是）。harness 必须先读掉，
# 否则判活的 recv_lines(1) 会把 banner 当成 PROBE_CMD 的应答 —— 靶机死了都判成活。
: "${TARGET_BANNER_LINES:=0}"
echo "[TARGET] 适配器: ${TARGET_CONF#$SCRIPT_DIR/}"
echo "         名称=$TARGET_NAME  覆盖率=$TARGET_COV_MODE  位图=${TARGET_SHM_SIZE}B"

BASE_PORT=${BASE_PORT:-9001}
# 用 ${VAR-default}（仅未设置时取默认）：REDIS_URL="" 表示明确关闭
REDIS_URL=${REDIS_URL-}
SYNC_INTERVAL=${SYNC_INTERVAL:-5}
# hash   = 按 sha256%N 分片，跨进程共享优质种子（发现者会有 1 份残留）
# finder = 发现者继续跟进，运行期零重复
OWNER_MODE=${OWNER_MODE:-hash}

# 靶机崩溃是预期的（代理自杀式崩溃检测），别把 core dump 写满磁盘
ulimit -c 0 2>/dev/null || true

PREFIX_DIR="$SCRIPT_DIR/prefix_analyzer_output"
PREFIX_FILE="$PREFIX_DIR/$STATE_NAME/prefix.raw"
SEED_DIR="$PREFIX_DIR/$STATE_NAME/seeds"

if [ ! -d "$PREFIX_DIR/$STATE_NAME" ]; then
    echo "[!] 状态不存在: $STATE_NAME"
    echo "    可用状态:"
    for d in "$PREFIX_DIR"/*/; do
        [ -d "$d" ] && echo "      - $(basename "$d")"
    done
    exit 1
fi

# ─── 实例数：默认吃满核心 ───
if [ -z "$N_SECONDARIES" ]; then
    NCORES=$(nproc 2>/dev/null || echo 2)
    N_SECONDARIES=$(( NCORES - 1 ))
    [ "$N_SECONDARIES" -lt 0 ] && N_SECONDARIES=0
fi
N_INSTANCES=$(( N_SECONDARIES + 1 ))

OUT_BASE="$SCRIPT_DIR/results/$STATE_NAME"
CORPUS_DIR="$SCRIPT_DIR/corpus/$STATE_NAME"
WORK_DIR="$SCRIPT_DIR/work/$STATE_NAME"
STATE_FILE="$SCRIPT_DIR/node_state.current"
# SHM 号必须落在 OUT_BASE 之外：OUT_BASE 每次启动都会 rm -rf
RUN_DIR="$SCRIPT_DIR/run"
SHM_LIST_FILE="$RUN_DIR/$STATE_NAME.shmids"

# ─── SHM 生命周期 ───
# shmget(IPC_PRIVATE) 造出来的段没有任何路径能反查，进程一崩就永远留在内核里
# （实测攒了 110 个 64KB 段）。所以：启动时把上一轮的号写进 shmids 文件，
# 退出时逐个 shmctl(IPC_RMID)。IPC_RMID 对仍挂载的段是"延迟释放"——
# 最后一个 shmdt 时才真正回收，所以顺序无所谓，但必须记账。
release_shm() {
    local id
    # 本进程创建的
    for id in "${SHM_IDS[@]:-}"; do
        [ -n "$id" ] && [ "$id" != "-1" ] && ipcrm -m "$id" 2>/dev/null || true
    done
    # 上一轮崩溃残留的
    if [ -f "$SHM_LIST_FILE" ]; then
        while read -r id; do
            [ -n "$id" ] && ipcrm -m "$id" 2>/dev/null || true
        done <"$SHM_LIST_FILE"
    fi
    rm -f "$SHM_LIST_FILE"
}

# ─── 停机清理 ───
# 定义在启动段之前（而不是等待段）：启动中途任何一步失败都要走同一条清理路径，
# 尤其是 SHM 记账 —— 崩在半路留下的段会被下一次启动清扫。
cleanup() {
    trap - EXIT INT TERM
    echo ""
    echo "[STOP] 停止本节点所有进程..."
    [ -n "${SEEDHUB_PID:-}" ] && kill "$SEEDHUB_PID" 2>/dev/null || true
    [ -n "${SYNC_PID:-}" ] && kill "$SYNC_PID" 2>/dev/null || true
    for p in "${AFL_PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    for p in "${PIDS_SERVER_LOOP[@]:-}"; do kill "$p" 2>/dev/null || true; done
    sleep 1
    for p in "${AFL_PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
    for p in "${PIDS_SERVER_LOOP[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
    # 兜底：确保保活循环与靶机都真正退出，端口释放干净
    pkill -f "[s]bf-server-loop" 2>/dev/null || true
    pkill -x "$TARGET_NAME" 2>/dev/null || true
    for ((i = 0; i < ${N_INSTANCES:-0}; i++)); do
        fuser -k $((BASE_PORT + i))/tcp 2>/dev/null || true
    done
    # 最后收回 SHM —— 靶机/harness 已退出，此时 ipcrm 才能真正回收
    release_shm
    rm -f "$LOCK_PID_FILE" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

mkdir -p "$RUN_DIR"

echo "============================================"
echo "  SandboxFuzzer — 状态同质化 ECS 节点"
echo "============================================"
echo "  状态:         $STATE_NAME   ← 全机统一，可切换"
echo "  实例数:       $N_INSTANCES（各自独立 outdir，互不盲同步）"
echo "  靶机端口:     $BASE_PORT .. $((BASE_PORT + N_INSTANCES - 1))"
echo "  共享种子池:   $CORPUS_DIR"
echo "  去重分工:     owner模式=$OWNER_MODE（每种子唯一 owner，经 -F 投喂）"
echo "  异步回传:     $([ -n "$REDIS_URL" ] && echo "Redis $REDIS_URL" || echo "关闭（Dispatcher 后续设计）")"
echo "============================================"
echo ""

# ─── 编译 ───
echo "[BUILD] 编译靶机与 Harness..."
# 桥接 TU 必须用普通 cc —— 参见 afl_map_bridge.c 头部说明
cc -O2 -c "$SCRIPT_DIR/afl_map_bridge.c" -o "$SCRIPT_DIR/afl_map_bridge.o"

# 靶机：三种构建来源，优先级从高到低
#   TARGET_BUILD_CMD  自定义构建命令（多文件 / 带库 / make，真目标常用）
#   TARGET_SRC        单文件，afl-clang-fast 一把梭
#   都没给            直接用现成二进制
if [ -n "${TARGET_BUILD_CMD:-}" ]; then
    echo "         靶机  按 TARGET_BUILD_CMD 构建..."
    ( cd "$SCRIPT_DIR" && eval "$TARGET_BUILD_CMD" ) || {
        echo "[!] 靶机构建失败（TARGET_BUILD_CMD）"; exit 1; }
elif [ -n "${TARGET_SRC:-}" ]; then
    SRC_PATH="$SCRIPT_DIR/$TARGET_SRC"
    OUT_BIN="$SCRIPT_DIR/${TARGET_BIN#./}"
    mkdir -p "$(dirname "$OUT_BIN")"
    afl-clang-fast "$SRC_PATH" -o "$OUT_BIN" -lrt || {
        echo "[!] 靶机编译失败: $TARGET_SRC"; exit 1; }
    echo "         靶机  $TARGET_SRC → $TARGET_BIN"
else
    if [ ! -x "$SCRIPT_DIR/${TARGET_BIN#./}" ]; then
        echo "[!] 适配器没给 TARGET_SRC/TARGET_BUILD_CMD，但二进制不存在: $TARGET_BIN"; exit 1
    fi
    echo "         靶机  $TARGET_BIN（现成二进制，不编译）"
fi

afl-clang-fast "$SCRIPT_DIR/sandbox_harness.c" "$SCRIPT_DIR/afl_map_bridge.o" \
    -o "$SCRIPT_DIR/sandbox_harness" -lrt
echo "[BUILD] ✓ 编译完成"
echo ""

# ─── 清理本节点残留 ───
echo "[CLEAN] 清理旧进程与输出..."
# 先清上一轮遗留的 SHM（进程被 kill -9 时来不及 ipcrm）
SHM_IDS=()
release_shm
pkill -f "[l]ocal_seedhub.py.*--state $STATE_NAME" 2>/dev/null || true
pkill -f "[f]inding_sync.py.*--state $STATE_NAME" 2>/dev/null || true
pkill -f "[a]fl-fuzz.*$OUT_BASE" 2>/dev/null || true
pkill -f "[s]bf-server-loop" 2>/dev/null || true
pkill -x "$TARGET_NAME" 2>/dev/null || true
for ((p = 0; p < N_INSTANCES; p++)); do
    fuser -k $((BASE_PORT + p))/tcp 2>/dev/null || true
done
sleep 1

rm -rf "$OUT_BASE" "$WORK_DIR" "$CORPUS_DIR"
mkdir -p "$OUT_BASE" "$WORK_DIR" "$CORPUS_DIR"

echo "$STATE_NAME" > "$STATE_FILE"
echo "[STATE] node_state.current = $STATE_NAME"

# ─── 为每个实例创建私有覆盖率 SHM + 靶机 ───
# 必须先起靶机：bootstrap 要靠它探测初始语料里的崩溃样本。
PIDS_SERVER_LOOP=()
PORTS=()
SHM_IDS=()

echo "[LAUNCH] 启动 $N_INSTANCES 个状态同质沙箱..."
for ((i = 0; i < N_INSTANCES; i++)); do
    PORT=$((BASE_PORT + i))

    SHM_ID=$(python3 -c "
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library('c'))
libc.shmget.restype = ctypes.c_int
print(libc.shmget(0, $TARGET_SHM_SIZE, 0o1000 | 0o666))
")
    if [ -z "$SHM_ID" ] || [ "$SHM_ID" = "-1" ]; then
        echo "[!] shmget 失败（SHM_ID='$SHM_ID'）—— 内核段数可能已达上限"
        echo "    ipcs -m 查看；可 ipcrm -m <id> 清理历史残留"
        cleanup
        exit 1
    fi
    # 立刻记账：中途崩掉也能被下一次启动清扫到
    echo "$SHM_ID" >> "$SHM_LIST_FILE"

    fuser -k $PORT/tcp 2>/dev/null || true

    # 覆盖率注入：按适配器的 COV_MODE 决定给靶机哪套环境变量。
    #   instrument  __AFL_SHM_ID      AFL++ 运行时把 __afl_area_ptr 指到该段，
    #                               插桩自动写 —— 真目标零侵入（见 targets/README.md）
    #   manual      TARGET_SHM_ID     靶机源码自己调 record_cov()
    #   both        两个都给          mock 用：插桩为主，record_cov 补几条固定边
    COV_ENV=()
    if [ "$TARGET_COV_MODE" = "instrument" ] || [ "$TARGET_COV_MODE" = "both" ]; then
        COV_ENV+=("__AFL_SHM_ID=$SHM_ID" "AFL_NO_FORKSRV=1")
    fi
    if [ "$TARGET_COV_MODE" = "manual" ] || [ "$TARGET_COV_MODE" = "both" ]; then
        COV_ENV+=("TARGET_SHM_ID=$SHM_ID")
    fi
    if [ "${#COV_ENV[@]}" -eq 0 ]; then
        echo "[!] TARGET_COV_MODE='$TARGET_COV_MODE' 无法识别（instrument|manual|both）"
        cleanup; exit 1
    fi

    # 靶机崩溃自动重启（代理自杀式崩溃检测的前提）。
    # 注意：必须给这个保活循环一个可识别的进程名（$0 = sbf-server-loop），
    # 否则 pkill -x "$TARGET_NAME" 只杀掉靶机、循环会立刻把它拉起来，
    # 状态切换后残留孤儿循环抢占端口。
    # "$@" = env <覆盖率变量...> <靶机二进制> <参数...>
    BIN_PATH="$SCRIPT_DIR/${TARGET_BIN#./}"
    # TARGET_ARGS 里的 $PORT 占位符替换成该实例端口，再按空白切成参数数组
    read -r -a ARG_ARR <<< "${TARGET_ARGS//\$PORT/$PORT}"
    bash -c 'while true; do env "$@" 2>/dev/null; sleep 0.1; done' \
        sbf-server-loop "${COV_ENV[@]}" "$BIN_PATH" "${ARG_ARR[@]}" 2>/dev/null &
    PIDS_SERVER_LOOP+=($!)
    PORTS+=($PORT)
    SHM_IDS+=($SHM_ID)

    echo "    [$i] port=$PORT  SHM_ID=$SHM_ID  server_loop=${PIDS_SERVER_LOOP[$i]}"
done

sleep 1
echo ""

# ─── 初始语料分片：开跑即分工 ───
# 先探测再分片：初始语料里混着崩溃样本（如 state_1_user 的 "PASS CRASH"），
# 直接塞进 -i 会让 AFL++ 干跑全跳过、"need at least one valid input seed
# that does not crash" 直接退出。崩溃样本归档进 crashes/，只切正常的。
echo "[SEEDHUB] 探测崩溃样本并按 sha256 % $N_INSTANCES 切分初始语料..."
python3 "$SCRIPT_DIR/local_seedhub.py" \
    --state "$STATE_NAME" \
    --instances "$N_INSTANCES" \
    --out-base "$OUT_BASE" \
    --init-seed-dir "$SEED_DIR" \
    --owner-mode "$OWNER_MODE" \
    --probe-port "$BASE_PORT" \
    --prefix-file "$PREFIX_FILE" \
    --bootstrap
echo ""

# ─── 启动 AFL++ 实例：独立 outdir + 按 owner 投喂 ───
export AFL_SKIP_CPUFREQ=1
export AFL_NO_UI=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_NO_AFFINITY=1
# 注意：不能设 AFL_NO_SYNC=1 —— AFL++ 的 -F 投喂实现在 sync_fuzzers() 内部，
# 该开关会连投喂一起关掉。盲同步靠"每实例独立 -o 父目录"来杜绝：
#   sync_dir == out_dir，见 afl-fuzz-init.c，各自目录下只有自己，无从互扫。
export PREFIX_FILE="$PREFIX_FILE"
# 靶机适配器给出的判定口径，harness 必须跟着走，否则判活命令/位图长度对不上
export PROBE_CMD="$TARGET_PROBE_CMD"
export TARGET_SHM_SIZE="$TARGET_SHM_SIZE"
export TARGET_BANNER_LINES="$TARGET_BANNER_LINES"

AFL_PIDS=()
INIT_ROOT="$SCRIPT_DIR/corpus/$STATE_NAME/init_shards"

for ((i = 0; i < N_INSTANCES; i++)); do
    export TARGET_PORT=${PORTS[$i]}
    export TARGET_SHM_ID=${SHM_IDS[$i]}

    # 每实例独立 -o 父目录 → sync_dir 互不重叠
    INST_OUT="$OUT_BASE/i$i"
    mkdir -p "$INST_OUT"

    CPU_ARG=""
    [ "${BIND_CPUS:-0}" = "1" ] && CPU_ARG="-b $i"
    DICT_ARG=""
    [ -n "${DICT:-}" ] && DICT_ARG="-x $DICT"

    echo "[AFL++] fuzzer_$i  port=$TARGET_PORT  -i <分片$i>  -F work/<state>/$i"
    # -M 必需（-F 的前提）；-i 用本实例专属分片；-F 只喂 owner 种子。
    # stderr 落盘而不是丢弃 —— 启动失败（例如干跑全部种子都崩）只有这里有线索。
    # shellcheck disable=SC2086
    afl-fuzz -i "$INIT_ROOT/$i" -o "$INST_OUT" \
        -M "fuzzer_$i" -F "$WORK_DIR/$i" $CPU_ARG $DICT_ARG -t 1000 -- \
        "$SCRIPT_DIR/sandbox_harness" >"$INST_OUT/afl_stdout.log" 2>"$INST_OUT/afl_stderr.log" &
    AFL_PIDS+=($!)
done

echo ""
echo "[RUN] $N_INSTANCES 个 AFL++ 实例运行中（状态同质：$STATE_NAME）"
echo "      共享种子池 + 唯一 owner 分工，无盲同步重复劳动"
echo ""

# ─── 本地种子枢纽：共享 + 去重分工 ───
SEEDHUB_PID=""
echo "[SEEDHUB] 启动 local_seedhub.py ..."
python3 "$SCRIPT_DIR/local_seedhub.py" \
    --state "$STATE_NAME" \
    --instances "$N_INSTANCES" \
    --out-base "$OUT_BASE" \
    --owner-mode "$OWNER_MODE" \
    --interval 2 &
SEEDHUB_PID=$!
echo "[SEEDHUB] PID=$SEEDHUB_PID"
echo ""

# ─── 可选：异步回传（Dispatcher 定稿后再启用）───
SYNC_PID=""
if [ -n "$REDIS_URL" ]; then
    echo "[SYNC] 启动 finding_sync.py (interval=${SYNC_INTERVAL}s)..."
    python3 "$SCRIPT_DIR/finding_sync.py" \
        --state "$STATE_NAME" \
        --node-id "$(hostname)" \
        --outdir "$OUT_BASE" \
        --outbox "$SCRIPT_DIR/sync_outbox/$STATE_NAME" \
        --redis "$REDIS_URL" \
        --interval "$SYNC_INTERVAL" &
    SYNC_PID=$!
    echo ""
fi

# ─── 超时 / 等待 ───
# （cleanup 已定义在上方并 trap EXIT INT TERM）

WATCHDOG_PID=""
if [ "$DURATION" -gt 0 ] 2>/dev/null; then
    echo "[RUN] 将在 ${DURATION}s 后自动停止..."
    ( sleep "$DURATION" && kill "${AFL_PIDS[@]}" 2>/dev/null ) &
    WATCHDOG_PID=$!
fi

for p in "${AFL_PIDS[@]}"; do
    wait "$p" 2>/dev/null || true
done

# ─── 汇总 ───
echo ""
echo "============================================"
echo "  状态 $STATE_NAME — 实例汇总"
echo "============================================"
printf "%-14s %-12s %-10s %-10s %-12s %-10s %-8s\n" \
    "Instance" "Execs" "Exec/s" "Corpus" "Crashes" "Coverage" "Edges"
echo "------------------------------------------------------------------------------------------------------"

TOTAL_CORPUS=0
TOTAL_CRASHES=0
for ((i = 0; i < N_INSTANCES; i++)); do
    STATS_FILE="$OUT_BASE/i$i/fuzzer_$i/fuzzer_stats"
    if [ -f "$STATS_FILE" ]; then
        EXECS=$(awk '/^execs_done/{print $3}' "$STATS_FILE")
        EXECS_SEC=$(awk '/^execs_per_sec/{print $3}' "$STATS_FILE")
        CORPUS=$(awk '/^corpus_count/{print $3}' "$STATS_FILE")
        CRASHES=$(awk '/^saved_crashes/{print $3}' "$STATS_FILE")
        COVG=$(awk '/^bitmap_cvg/{print $3}' "$STATS_FILE")   # 已自带 %
        EDGES=$(awk '/^edges_found/{print $3}' "$STATS_FILE")
        printf "%-14s %-12s %-10s %-10s %-12s %-10s %-8s\n" \
            "fuzzer_$i" "$EXECS" "$EXECS_SEC" "$CORPUS" "$CRASHES" "$COVG" "$EDGES"
        TOTAL_CORPUS=$((TOTAL_CORPUS + ${CORPUS:-0}))
        TOTAL_CRASHES=$((TOTAL_CRASHES + ${CRASHES:-0}))
    else
        printf "%-14s %-12s %-10s %-10s %-12s %-10s %-8s\n" \
            "fuzzer_$i" "N/A" "N/A" "N/A" "N/A" "N/A" "N/A"
    fi
done

echo ""
echo "  ─── 去重分工核查 ───"
python3 "$SCRIPT_DIR/local_seedhub.py" \
    --state "$STATE_NAME" \
    --instances "$N_INSTANCES" \
    --out-base "$OUT_BASE" \
    --owner-mode "$OWNER_MODE" \
    --report 2>/dev/null | grep "池=" || true
echo ""
echo "  共享种子池: $CORPUS_DIR"
echo "  分片投喂:   $WORK_DIR/<0..$((N_INSTANCES - 1))>"
echo "  崩溃归档:   $CORPUS_DIR/crashes/"
echo "============================================"

if [ -n "$WATCHDOG_PID" ]; then kill "$WATCHDOG_PID" 2>/dev/null || true; fi
