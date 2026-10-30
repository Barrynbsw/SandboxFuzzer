#!/bin/bash
#
# run_state_partition_ablation.sh —— 状态分池种子管理 的 ablation
# =================================================================
#
# 论点（创新点 2）：**种子池必须单状态，机器可以多状态。**
#
# 证伪形式：同一批种子、同样大小、同样的 AFL++ 配置、同样时长、同样实例数，
# 只改一件事 —— 这批种子待在【它所属状态】的池里，还是被丢进【别状态】的池里。
#
#   A  单状态池（设计如此）  前缀 = 种子所属状态的前缀   预期可达 6/6
#   B  状态错配池（对照）    前缀 = 别状态的（空前缀）   预期可达 2/6
#      （目录名 B_mixed_pool 是历史标识；语义是【状态错配】，不是把种子混进一个池）
#
# 只换前缀 = 只换「种子被放在哪个状态池」，其余变量全部锁死。若 A 与 B 的
# fuzz 指标没有差别，「必须单状态」就是空话；有差别，机制（可达比例）与
# 结果（edges/corpus/crashes）两层才算都对上。
#
# 跑法（宿主机编不动 fftp，必须进容器，挂【包根】）：
#   cd SandboxFuzzer
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/sbfpkg \
#       --workdir /sbfpkg/ECSSandbox --entrypoint bash sbf-node \
#       -lc './run_state_partition_ablation.sh 300 2 3'
#
# 用法: ./run_state_partition_ablation.sh [duration_sec] [n_secondaries] [n_rounds]
#
# 统计强度（审查 F5 残留）：默认跑 3 轮，奇数轮 A→B、偶数轮 B→A（换序消除
# 顺序效应），每轮结果快照进 ablation_runs/<runid>/round<r>/，最后报均值±标准差。
# 单轮数字不能进论文 —— 无方差无重复。
#
set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR"

DUR=${1:-300}
N=${2:-2}
ROUNDS=${3:-3}
ROOT=${PREFIX_SRC:-prefix_analyzer_output_rebuild}
AB="$SCRIPT_DIR/ablation"
# 同一批种子：state_2_PWD 的池（6 条，覆盖 USER/PASS/PWD/CWD/NOOP/TYPE）
SEED_SRC="$SCRIPT_DIR/$ROOT/admin_ftp_state_2_PWD/seeds"
PFX_SRC="$SCRIPT_DIR/$ROOT/admin_ftp_state_2_PWD/prefix.raw"

[ -d "$SEED_SRC" ] || { echo "[!] 找不到种子源 $SEED_SRC"; exit 1; }
[ -f "$PFX_SRC" ]  || { echo "[!] 找不到前缀源 $PFX_SRC"; exit 1; }

# ─── 造 fixture ─────────────────────────────────────────────────
# 两个目录结构完全一致（prefix.raw + seeds/），run_state_node.sh 一视同仁，
# 不给任何一方特殊的接线待遇。
# 旧 ablation/ 里有 level-1 证据（*.reach.json / report.json），不能 rm -rf
# —— 一并归档（审查 F3 同源问题），fixture 本身下面无条件重建。
if [ -d "$AB" ] && [ -n "$(ls -A "$AB" 2>/dev/null)" ]; then
    AB_ARCHIVE="$SCRIPT_DIR/archive/ablation_pre_$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$AB_ARCHIVE"
    mv "$AB" "$AB_ARCHIVE/"
    echo "[ARCHIVE] 旧 ablation/ 已归档: ${AB_ARCHIVE#"$SCRIPT_DIR"/}"
fi
for spec in "A_single_state:$PFX_SRC" "B_mixed_pool:"; do
    name=${spec%%:*}
    psrc=${spec#*:}
    mkdir -p "$AB/$name/seeds"
    : > "$AB/$name/prefix.raw"
    [ -n "$psrc" ] && cp "$psrc" "$AB/$name/prefix.raw"
    cp "$SEED_SRC"/* "$AB/$name/seeds/"
    echo "[FIXTURE] $name  prefix=$(wc -c <"$AB/$name/prefix.raw")B  "
    echo "          seeds=$(ls "$AB/$name/seeds" | wc -l) 条（与 A/B 同源）"
done

echo "============================================"
echo "  状态分池 ablation   时长=${DUR}s  从实例=${N}  轮数=${ROUNDS}"
echo "  控制变量：池内容/池大小/实例数/时长/AFL++ 配置 全部相同"
echo "  唯一自变量：种子待在哪个状态池（= 用哪条前缀）"
echo "  换序：奇数轮 A→B，偶数轮 B→A"
echo "============================================"

RUN_ID=$(date +%Y%m%d-%H%M%S)
RUN_DIR="$SCRIPT_DIR/ablation_runs/$RUN_ID"
mkdir -p "$RUN_DIR"
echo "[RUNS] 逐轮快照目录: ${RUN_DIR#"$SCRIPT_DIR"/}"

for ((r = 1; r <= ROUNDS; r++)); do
    if [ $((r % 2)) -eq 1 ]; then
        ORDER=(A_single_state B_mixed_pool)
    else
        ORDER=(B_mixed_pool A_single_state)
    fi
    echo ""
    echo "══════════ 第 $r/$ROUNDS 轮（顺序: ${ORDER[*]}）══════════"
    mkdir -p "$RUN_DIR/round$r"

    for name in "${ORDER[@]}"; do
        # ─── level-1：可达比例（机制证据）──────────────────────
        echo ""
        echo "──── level-1 可达比例  $name ────"
        python3 reachability_probe.py \
            --prefix "$AB/$name/prefix.raw" \
            --seeds  "$AB/$name/seeds" \
            --label  "$name" \
            --json   "$AB/$name.reach.json" || true
        cp -f "$AB/$name.reach.json" "$RUN_DIR/round$r/" 2>/dev/null || true

        # ─── level-2：真 fuzz（结果证据）───────────────────────
        echo ""
        echo "============================================"
        echo "  level-2 真 fuzz   $name   ${DUR}s × $((N + 1)) 实例"
        echo "============================================"
        TARGET_CONF="$SCRIPT_DIR/targets/lightftp.conf" \
            PREFIX_ROOT="$AB" \
            ./run_state_node.sh "$name" "$N" "$DUR" || true

        # 立刻快照：下一轮同名启动会把 results/<name> 归档走
        if [ -d "$SCRIPT_DIR/results/$name" ]; then
            cp -r "$SCRIPT_DIR/results/$name" "$RUN_DIR/round$r/$name"
        fi
    done

    python3 - "$AB" <<'PY'
import json, os, sys
ab = sys.argv[1]
out = {}
for name in ("A_single_state", "B_mixed_pool"):
    p = os.path.join(ab, f"{name}.reach.json")
    if not os.path.isfile(p):
        continue
    with open(p, encoding="utf-8") as f:
        d = json.load(f)
    out[name] = {"prefix": d["prefix"], "pool": f"{d['total']} 条",
                 "reachable": f"{d['reachable']}/{d['total']}"}
with open(os.path.join(ab, "report.json"), "w", encoding="utf-8") as f:
    json.dump(out, f, ensure_ascii=False, indent=2)
PY
done

echo ""
python3 ablation_report.py --rounds "$RUN_DIR"
