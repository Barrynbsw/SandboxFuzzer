#!/bin/bash
#
# run_state_sweep.sh —— 按状态隔离 vs 不隔离（论文主实验）
# =========================================================
#
# 论点（创新点 1 + 2 合起来）：**机器按状态隔离跑，比整机钉死在一个状态下
# 摸到的代码多。**
#
#   ISO  按状态隔离（设计如此）  每个【去重后的】状态配置各跑一次
#   MIX  不隔离（对照）          整机钉死在最深那态跑满全程（实测 ≡ ISO_1）
#
# 机器时间对齐：ISO 是 K×DUR，MIX 就跑 K×DUR（同一个全局状态跑到底）。
# 实例数、AFL++ 配置、编译产物全部相同，只换「分几个状态跑」。
#
# ── 为什么按 (前缀, 池内容) 去重 ────────────────────────────────
# 会话前缀重建产出 6 个状态，但它们作为【协议状态】不同（目标命令不同、
# 最小到达序列不同），作为【fuzz 配置】只有 3 种 —— state_2/3/5 的 prefix.raw
# 与种子内容逐字节相同（只是种子文件名带了不同的状态下标），state_0/4 同理。
# 拿同一个配置跑 6 遍只是估方差，不是 6 个独立实验；去重后每条数据都是新信息。
# level-1 可达性【不去重】—— 每个状态的目标命令确实不同，逐个测才有意义。
#
# ── MIX 对照其实是 ISO_1 本身（实测，要如实交代）────────────────
# 6 个状态的种子按【内容】去重后总共只有 6 条，且 state_0/4 的 2 条、
# state_1 的 3 条都是 state_2/3/5 那 6 条的子集 —— 于是「跨状态全池」的并集
# 恰好等于 ISO_1 的池，最长前缀也恰好是 ISO_1 的前缀，MIX_global ≡ ISO_1。
# 所以这条对照真正比的是：**三态各跑一遍** vs **整机钉死在最深那态跑满全程**。
# 那正是「机器按状态隔离 vs 不隔离」的字面意思，而且是最强对照（MIX 拿最深的
# 状态、又不缺任何一条种子），偏向 MIX —— ISO 还能赢才算数。
# MIX 的池构造本身也是"全池按内容并集"，不是 bash 顺手 cp 出来的子集；
# 少一条种子对照就变弱、主实验偏向 ISO，见下面 python 块的注释。
#
# 汇总时诚实交代：ISO 的 edges 求和会把跨状态共用的样板边重复计数，
# 所以 Σedges 是【上界】；单状态的 MIX 没有这个问题。两边都摆出来。
#
# 跑法（宿主机编不动 fftp，必须进容器，挂【包根】）：
#   cd SandboxFuzzer
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/sbfpkg \
#       --workdir /sbfpkg/ECSSandbox --entrypoint bash sbf-node \
#       -lc './run_state_sweep.sh 300 2'
#
# 用法: ./run_state_sweep.sh [dur_per_config_sec] [n_secondaries]
#
set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR"

DUR=${1:-300}
N=${2:-2}
ROOT=${PREFIX_SRC:-prefix_analyzer_output_rebuild}
SW="$SCRIPT_DIR/sweep"
REBUILD="$SCRIPT_DIR/$ROOT"
TARGET_CONF="$SCRIPT_DIR/targets/lightftp.conf"

[ -d "$REBUILD" ] || { echo "[!] 找不到状态产物根 $REBUILD"; exit 1; }

# ─── 造 fixture：每个去重后的配置一份 ───────────────────────────
# dedupe 由 python 做（比 bash 里拼 md5 可靠），产出 sweep/<cfg>/ 目录，
# 结构与 prefix_analyzer_output_rebuild/<state>/ 完全一致，run_state_node.sh
# 一视同仁，不给任何一方特殊接线。
rm -rf "$SW"
python3 - "$REBUILD" "$SW" <<'PY'
import hashlib, os, sys
rebuild, sw = sys.argv[1], sys.argv[2]
groups = {}
all_blobs = set()
longest = b""
for name in sorted(os.listdir(rebuild)):
    d = os.path.join(rebuild, name)
    p = os.path.join(d, "prefix.raw")
    if not os.path.isfile(p):
        continue
    with open(p, "rb") as f:
        pre = f.read()
    if len(pre) > len(longest):
        longest = pre
    sd = os.path.join(d, "seeds")
    blobs = []
    if os.path.isdir(sd):
        for fn in sorted(os.listdir(sd)):
            with open(os.path.join(sd, fn), "rb") as f:
                blobs.append(f.read())
    all_blobs.update(blobs)
    key = hashlib.md5(pre + b"\x00" + b"\x00".join(sorted(blobs))).hexdigest()[:8]
    groups.setdefault(key, {"prefix": pre, "seeds": blobs, "states": []})
    groups[key]["states"].append(name)

os.makedirs(sw, exist_ok=True)
for i, (key, g) in enumerate(sorted(groups.items())):
    cfg = f"ISO_{i}_{key}"
    os.makedirs(os.path.join(sw, cfg, "seeds"), exist_ok=True)
    with open(os.path.join(sw, cfg, "prefix.raw"), "wb") as f:
        f.write(g["prefix"])
    for j, b in enumerate(sorted(set(g["seeds"]))):
        with open(os.path.join(sw, cfg, "seeds", f"s{j}.raw"), "wb") as f:
            f.write(b)
    print(f"  [CFG] {cfg}: prefix={len(g['prefix'])}B "
          f"seeds={len(set(g['seeds']))}种  ← {', '.join(g['states'])}")
print(f"  K={len(groups)} 个去重配置")

# MIX 对照：跨状态【全】池 + 最长前缀。池按内容去重，与 ISO 侧同口径
# （ISO 那边也是 sorted(set(blobs))），否则 MIX 多一堆重复种子白烧预算。
#
# 这里必须真·全池。早先用 bash「前缀变长才 cp」顺手带种子，会漏掉排在最长前缀
# 【之后】那些状态的种子 —— 眼下 state_2/3/5 与 state_0/4 的种子内容恰好逐字节
# 相同，漏了看不出来；但只要哪天出现一条独有种子，对照臂就少一份语料，
# 主实验直接偏向 ISO。宁可把并集明确算出来。
mix = os.path.join(sw, "MIX_global", "seeds")
os.makedirs(mix, exist_ok=True)
with open(os.path.join(sw, "MIX_global", "prefix.raw"), "wb") as f:
    f.write(longest)
for j, b in enumerate(sorted(all_blobs)):
    with open(os.path.join(mix, f"s{j}.raw"), "wb") as f:
        f.write(b)
print(f"  [CFG] MIX_global: prefix={len(longest)}B seeds={len(all_blobs)}种"
      f"  ← {len(groups)} 个配置的种子按内容并集")
PY

# ─── MIX 对照 fixture ─────────────────────────────────────────
# （和 ISO 一起在上面那个 python 块里造完了：前缀取所有状态里最长的 ——
#   不隔离 = 整机钉死在最深的状态；池取跨状态全池 —— 不隔离 = 一个池装下
#   所有种子。放在一处算并集，省得 bash 漏种子，理由见 python 块内注释。）

K=$(ls -d "$SW"/ISO_* 2>/dev/null | wc -l)
echo "============================================"
echo "  按状态隔离 vs 不隔离   每配置 ${DUR}s   从实例=${N}"
echo "  ISO  $K 个配置 × ${DUR}s = $(( K * DUR ))s"
echo "  MIX  1 个全局状态 × $(( K * DUR ))s（机器时间对齐）"
echo "============================================"
echo "  MIX_global  prefix=$(wc -c <"$SW/MIX_global/prefix.raw")B  "
echo "        seeds=$(ls "$SW/MIX_global/seeds" | wc -l) 条（全池按内容并集）"
echo "============================================"

# ─── level-1：每状态可达比例（机制证据，不去重）────────────────
echo ""
echo "──── level-1 可达比例（每个协议状态都测，目标命令各不相同）────"
for s in "$REBUILD"/*/; do
    [ -f "$s/prefix.raw" ] || continue
    echo ""
    python3 reachability_probe.py \
        --prefix "$s/prefix.raw" --seeds "$s/seeds" \
        --label "$(basename "$s")" --repeats 3 || true
done
echo ""
python3 reachability_probe.py \
    --prefix "$SW/MIX_global/prefix.raw" --seeds "$SW/MIX_global/seeds" \
    --label "MIX_global（钉死最深态 @ 最长前缀）" --repeats 3 || true

run_one() {
    echo ""
    echo "──────── $1   ${3}s × $((N + 1)) 实例 ────────"
    TARGET_CONF="$TARGET_CONF" PREFIX_ROOT="$2" \
        ./run_state_node.sh "$1" "$N" "$3" || true
}

# ─── ISO：每个去重配置一次 ─────────────────────────────────────
for cfg in "$SW"/ISO_*/; do
    run_one "$(basename "$cfg")" "$SW" "$DUR"
done

# ─── MIX：机器时间对齐，跑 K×DUR ──────────────────────────────
run_one "MIX_global" "$SW" "$(( K * DUR ))"

# label 显式传：ablation/report.json 是上一轮 ablation 留下的，不显式指定的
# 话报告脚本会优先读它，把旧数据当成 sweep 的结果打出来。
echo ""
python3 ablation_report.py "$SCRIPT_DIR" \
    $(for d in "$SW"/ISO_*/; do basename "$d"; done) MIX_global
