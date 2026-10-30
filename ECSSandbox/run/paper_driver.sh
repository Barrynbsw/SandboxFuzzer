#!/bin/bash
# 主实验串行跑：sweep（隔离 vs 不隔离）→ ablation（单状态池 vs 混状态池）。
# 两个都要整机，run_state_node.sh 有全局互斥锁，必须串行。
set +e
cd /home/barry/桌面/SandboxFuzzer
RUN=ECSSandbox/run
: > "$RUN/paper_status.txt"
echo "start $(date -Is)" >> "$RUN/paper_status.txt"

docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/sbfpkg \
    --workdir /sbfpkg/ECSSandbox --entrypoint bash sbf-node \
    -lc './run_state_sweep.sh 300 2' > "$RUN/paper_sweep.log" 2>&1
echo "sweep_exit=$? $(date -Is)" >> "$RUN/paper_status.txt"

docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/sbfpkg \
    --workdir /sbfpkg/ECSSandbox --entrypoint bash sbf-node \
    -lc './run_state_partition_ablation.sh 300 2' > "$RUN/paper_ablation.log" 2>&1
echo "ablation_exit=$? $(date -Is)" >> "$RUN/paper_status.txt"

echo "DONE $(date -Is)" >> "$RUN/paper_status.txt"
