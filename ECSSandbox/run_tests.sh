#!/bin/bash
#
# run_tests.sh — SandboxFuzzer 沙箱侧回归测试
#
# 四层，逐层加深：
#   1. 编译            靶机 + harness + 桥接 TU 能编过
#   2. 判定链单元测试   tests/test_crash_detection.c（复用 harness 真代码）
#   3. 归属判卷        replay_judge.py 双向：崩溃 fixture 必崩、良性 fixture 必不崩
#   4. 集成            种子去重分工（重复=0）+ SHM 不泄漏
#
# 用法:
#   ./run_tests.sh              # 全跑
#   ./run_tests.sh unit         # 只跑 1+2
#   ./run_tests.sh judge        # 只跑 1+3
#   ./run_tests.sh smoke        # 只跑 1+2+3（不做耗时的集成项）
#
# 退出码 0 = 全绿；非 0 = 有失败，末尾会汇总。

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR"

export PATH="${AFLPP_PATH:-$HOME/AFLplusplus}:$PATH"

# 测试用独立端口段，避开生产用的 9001 起
T_PORT_BASE=${T_PORT_BASE:-9410}
SEEDHUB_PORT=${SEEDHUB_PORT:-9460}

PASS=0
FAIL=0
declare -a FAILURES=()

note()  { printf "\n\033[1m▸ %s\033[0m\n" "$*"; }
ok()    { printf "  \033[32m✓\033[0m %s\n" "$*"; PASS=$((PASS+1)); }
bad()   { printf "  \033[31m✗\033[0m %s\n" "$*"; FAIL=$((FAIL+1)); FAILURES+=("$*"); }
skip()  { printf "  \033[33m–\033[0m %s\n" "$*"; }

MODE=${1:-all}

# ════════════════════════════════════════════════════════════
# 1. 编译
# ════════════════════════════════════════════════════════════
note "1) 编译"

if ! command -v afl-clang-fast >/dev/null 2>&1; then
    bad "找不到 afl-clang-fast（AFL++ 未安装或 AFLPP_PATH 未设置）"
    echo; echo "无法继续。"; exit 1
fi

mkdir -p tests/bin
if cc -O2 -c afl_map_bridge.c -o tests/bin/afl_map_bridge.o 2>tests/bin/build_bridge.log; then
    ok "afl_map_bridge.o（必须用普通 cc，避开 AFL++ LLVM pass 符号冲突）"
else
    bad "afl_map_bridge.o 编译失败"; cat tests/bin/build_bridge.log
fi

if afl-clang-fast stateful_server.c -o tests/bin/stateful_server -lrt 2>tests/bin/build_srv.log; then
    ok "stateful_server"
else
    bad "stateful_server 编译失败"; cat tests/bin/build_srv.log
fi

if afl-clang-fast sandbox_harness.c tests/bin/afl_map_bridge.o \
        -o tests/bin/sandbox_harness -lrt 2>tests/bin/build_harness.log; then
    ok "sandbox_harness"
else
    bad "sandbox_harness 编译失败"; cat tests/bin/build_harness.log
fi

if afl-clang-fast tests/test_crash_detection.c tests/bin/afl_map_bridge.o \
        -I. -o tests/bin/test_crash_detection -lrt 2>tests/bin/build_test.log; then
    ok "test_crash_detection"
else
    bad "test_crash_detection 编译失败"; cat tests/bin/build_test.log
fi

# 真目标 PoC：零 SBF 代码，用来测覆盖率注入
if afl-clang-fast tests/poc/real_target.c -o tests/bin/real_target -lrt 2>tests/bin/build_poc.log; then
    ok "real_target（真目标 PoC，零 SBF 代码）"
else
    bad "real_target 编译失败"; cat tests/bin/build_poc.log
fi

if [ "$FAIL" -gt 0 ]; then
    echo; echo "编译都没过，后面的测试没意义。"; exit 1
fi

# ════════════════════════════════════════════════════════════
# 2. 崩溃判定链单元测试
# ════════════════════════════════════════════════════════════
if [ "$MODE" = "all" ] || [ "$MODE" = "unit" ] || [ "$MODE" = "smoke" ]; then
    note "2) 崩溃判定链（SIGPIPE / 落core窗口 / 应答残留 / 多行归属）"
    P=$((T_PORT_BASE + 1))
    if ./tests/bin/test_crash_detection ./tests/bin/stateful_server "$P" \
            >tests/bin/t_unit.log 2>&1; then
        ok "单元测试全过（$(grep -c '✓' tests/bin/t_unit.log) 项）"
    else
        bad "崩溃判定链有回归"
        sed 's/^/      /' tests/bin/t_unit.log
    fi
fi

# ════════════════════════════════════════════════════════════
# 2b. seedhub 探测口径（Python 侧必须与 sandbox_harness.c 同口径）
#     三处曾经对不上：前缀整块发（粘包）/ 不读 banner / 应答只 recv 一次。
#     任何一处漂移都会变成"seedhub 说安全、AFL++ 说 crash"。
#     mock 纯本地起，不需要真靶机，也不需要进容器。
# ════════════════════════════════════════════════════════════
if [ "$MODE" = "all" ] || [ "$MODE" = "unit" ] || [ "$MODE" = "smoke" ]; then
    note "2b) seedhub 探测口径（前缀逐条发 / banner / 应答残留）"
    if python3 tests/test_seedhub_probe.py >tests/bin/t_seedhub.log 2>&1; then
        ok "探测口径全过（$(grep -c '✓' tests/bin/t_seedhub.log) 项）"
    else
        bad "seedhub 探测口径与 sandbox_harness.c 漂移"
        sed 's/^/      /' tests/bin/t_seedhub.log
    fi
fi

# ════════════════════════════════════════════════════════════
# 2c. bootstrap 崩溃分类（真靶机 stateful_server）
#     审查 F1 残留③④ 的验收：PASS CRASH / STOR BUG 等崩溃样本必须
#     全部判死归档，正常种子必须零误判 —— 逐样本独立靶机，互不干扰。
# ════════════════════════════════════════════════════════════
if [ "$MODE" = "all" ] || [ "$MODE" = "unit" ] || [ "$MODE" = "smoke" ]; then
    note "2c) bootstrap 崩溃分类（真靶机：崩溃全判死 / 正常零误判）"
    if python3 tests/test_seedhub_bootstrap.py >tests/bin/t_seedhub_bs.log 2>&1; then
        ok "崩溃分类全对（$(grep -c '✓' tests/bin/t_seedhub_bs.log) 项）"
    else
        bad "bootstrap 崩溃分类有误"
        sed 's/^/      /' tests/bin/t_seedhub_bs.log
    fi
fi

# ════════════════════════════════════════════════════════════
# 3. 归属判卷：双向
#    崩溃 fixture 必须复现（否则归档不可信）
#    良性 fixture 必须不崩（否则假 crash 淹掉真发现）
# ════════════════════════════════════════════════════════════
if [ "$MODE" = "all" ] || [ "$MODE" = "judge" ] || [ "$MODE" = "smoke" ]; then
    note "3) 崩溃归属判卷（replay_judge.py 双向）"
    P=$((T_PORT_BASE + 2))
    for state in state_1_user state_2_auth; do
        FIX="tests/fixtures/$state"
        [ -d "$FIX" ] || { skip "$state: 无 fixture"; continue; }

        if [ -d "$FIX/crashes" ] && [ -n "$(ls -A "$FIX/crashes" 2>/dev/null)" ]; then
            if python3 replay_judge.py "$FIX/crashes" "$FIX/prefix.raw" \
                    --bin ./tests/bin/stateful_server --port "$P" --expect crash \
                    >"tests/bin/t_judge_${state}_crash.log" 2>&1; then
                n=$(grep -c '靶机死亡' "tests/bin/t_judge_${state}_crash.log" 2>/dev/null || echo 0)
                ok "$state 崩溃样本 $n/$n 可复现"
            else
                bad "$state 崩溃样本归属/复现有问题"
                sed 's/^/      /' "tests/bin/t_judge_${state}_crash.log"
            fi
        fi

        if [ -d "$FIX/benign" ] && [ -n "$(ls -A "$FIX/benign" 2>/dev/null)" ]; then
            if python3 replay_judge.py "$FIX/benign" "$FIX/prefix.raw" \
                    --bin ./tests/bin/stateful_server --port "$P" --expect benign \
                    >"tests/bin/t_judge_${state}_benign.log" 2>&1; then
                n=$(grep -c '靶机存活' "tests/bin/t_judge_${state}_benign.log" 2>/dev/null || echo 0)
                ok "$state 良性样本 $n/$n 零误报"
            else
                bad "$state 良性样本有误崩"
                sed 's/^/      /' "tests/bin/t_judge_${state}_benign.log"
            fi
        fi
    done
fi

# ════════════════════════════════════════════════════════════
# 3b. 覆盖率注入：真靶机零侵入（只靠 __AFL_SHM_ID）
# ════════════════════════════════════════════════════════════
if [ "$MODE" = "all" ] || [ "$MODE" = "judge" ] || [ "$MODE" = "smoke" ]; then
    note "3b) 覆盖率注入（真靶机零侵入）"
    if python3 tests/test_coverage_injection.py \
            --bin ./tests/bin/real_target --port $((T_PORT_BASE + 3)) \
            >tests/bin/t_cov.log 2>&1; then
        n=$(grep -c '✓' tests/bin/t_cov.log 2>/dev/null || echo 0)
        ok "覆盖率注入全过（$n 项）"
    else
        bad "覆盖率注入有回归"
        sed 's/^/      /' tests/bin/t_cov.log
    fi
fi

if [ "$MODE" = "unit" ] || [ "$MODE" = "judge" ] || [ "$MODE" = "smoke" ]; then
    echo
    echo "════════════════════════════════════════"
    printf "  通过 %d   失败 %d\n" "$PASS" "$FAIL"
    [ "$FAIL" -gt 0 ] && printf "  失败项：%s\n" "${FAILURES[*]}"
    echo "════════════════════════════════════════"
    [ "$FAIL" -eq 0 ] && echo "✓ 全绿" || echo "✗ 有失败"
    exit $(( FAIL > 0 ? 1 : 0 ))
fi

# ════════════════════════════════════════════════════════════
# 4a. 种子去重分工：同一个种子绝不交给两个实例
# ════════════════════════════════════════════════════════════
note "4a) 种子去重分工（重复必须为 0）"

SH=$(mktemp -d)
trap 'rm -rf "$SH"' EXIT

python3 local_seedhub.py \
    --state _test_dedup --instances 4 \
    --corpus-root "$SH/corpus" --work-root "$SH/work" \
    --init-seed-dir tests/fixtures/state_1_user/benign \
    --owner-mode hash --bootstrap \
    >tests/bin/t_seedhub.log 2>&1

REPORT=$(python3 local_seedhub.py \
    --state _test_dedup --instances 4 \
    --corpus-root "$SH/corpus" --work-root "$SH/work" \
    --owner-mode hash --report 2>/dev/null | grep "池=" || true)
echo "      $REPORT"

if echo "$REPORT" | grep -q "重复=0"; then
    ok "重复=0 —— 没有任何种子被两个实例同时持有"
else
    bad "去重分工失效：$REPORT"
fi

# 每个种子只出现在一个 work 分片里
DUPED=$(find "$SH/work/_test_dedup" -type f -printf "%f\n" 2>/dev/null | sort | uniq -d | wc -l)
if [ "$DUPED" -eq 0 ]; then
    ok "work/ 分片之间无同名种子"
else
    bad "work/ 里有 $DUPED 个种子出现在多个分片"
fi

# ════════════════════════════════════════════════════════════
# 4b. SHM 不泄漏
#     跑一小段节点，结束后内核里不该多出我们的 64KB 段。
#     这条防的是"每次跑一轮攒 4 个段"那种慢性资源泄漏。
# ════════════════════════════════════════════════════════════
note "4b) SHM 生命周期（跑完不得残留）"

count_shm() {
    ipcs -m | awk -v u="$(id -un)" \
        '$3==u && $4=="666" && $5==65536 && $6==0 {n++} END{print n+0}'
}

BEFORE=$(count_shm)

# 独立端口段 + 独立锁文件，别跟生产/其它测试打架
SBF_LOCK_FILE=/tmp/sbf_test_node.lock \
BASE_PORT=$((T_PORT_BASE + 10)) \
timeout 40 ./run_state_node.sh state_1_user 1 12 \
    >tests/bin/t_node.log 2>&1 || true

sleep 2
AFTER=$(count_shm)

echo "      64KB/666/0连接 段数:  跑前 $BEFORE → 跑后 $AFTER"
if [ "$AFTER" -le "$BEFORE" ]; then
    ok "无 SHM 残留（+0）"
else
    bad "SHM 泄漏：多了 $((AFTER - BEFORE)) 个段"
    echo "      run_state_node.sh 的 cleanup() 是否调用了 release_shm？"
    tail -20 tests/bin/t_node.log | sed 's/^/      /'
fi

# 4b-2: 被 kill -9 打断后留下的孤儿段 + 幽灵锁，下一次启动要能自愈
note "4b-2) 崩溃残留清扫（kill -9 后自愈）"

rm -f /tmp/sbf_test_node.lock run/state_1_user.shmids
SBF_LOCK_FILE=/tmp/sbf_test_node.lock \
BASE_PORT=$((T_PORT_BASE + 10)) \
./run_state_node.sh state_1_user 2 60 >tests/bin/t_node_orphan.log 2>&1 &
NODE_PID=$!
disown "$NODE_PID" 2>/dev/null || true   # 免得 kill -9 时 bash 打印作业通知

# 等 SHM 账本建好
for _ in $(seq 1 40); do [ -f run/state_1_user.shmids ] && break; sleep 0.5; done
sleep 2

if [ ! -f run/state_1_user.shmids ]; then
    skip "节点没能跑到创建 SHM，跳过孤儿测试"
else
    N_ORPHAN=$(wc -l < run/state_1_user.shmids)
    # 制造崩溃：kill -9 父进程，子进程与 SHM 全部留下
    kill -9 "$NODE_PID" 2>/dev/null || true
    pkill -f "[s]bf-server-loop" 2>/dev/null || true
    pkill -x stateful_server 2>/dev/null || true
    pkill -f "[a]fl-fuzz" 2>/dev/null || true
    pkill -f "[l]ocal_seedhub" 2>/dev/null || true
    sleep 1

    ORPHANED=$(count_shm)
    echo "      制造孤儿 $N_ORPHAN 个段，实测遗留 $ORPHANED 个"

    # 下一次启动：应识别幽灵锁并清扫孤儿段
    SBF_LOCK_FILE=/tmp/sbf_test_node.lock \
    BASE_PORT=$((T_PORT_BASE + 10)) \
    timeout 35 ./run_state_node.sh state_1_user 1 8 \
        >tests/bin/t_node_sweep.log 2>&1 || true
    sleep 2

    STILL=$(count_shm)
    if [ "$STILL" -le "$BEFORE" ]; then
        ok "孤儿段被启动清扫（$ORPHANED → $((STILL - BEFORE))）"
    else
        bad "孤儿段清扫失效：仍有 $((STILL - BEFORE)) 个"
    fi

    if grep -q "已不存在，按残留处理" tests/bin/t_node_sweep.log; then
        ok "幽灵锁被识别并自愈（不会被上一轮的孤儿挡住）"
    else
        bad "幽灵锁未自愈"
        tail -15 tests/bin/t_node_sweep.log | sed 's/^/      /'
    fi
fi

# ════════════════════════════════════════════════════════════
# 汇总
# ════════════════════════════════════════════════════════════
echo
echo "════════════════════════════════════════"
printf "  通过 %d   失败 %d\n" "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf "  失败项：\n"
    for f in "${FAILURES[@]}"; do printf "    · %s\n" "$f"; done
fi
echo "════════════════════════════════════════"
[ "$FAIL" -eq 0 ] && echo "✓ 全绿" || echo "✗ 有失败"
exit $(( FAIL > 0 ? 1 : 0 ))
