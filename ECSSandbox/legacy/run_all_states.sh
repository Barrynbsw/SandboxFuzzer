#!/bin/bash
#
# run_all_states.sh — 【已废弃】多状态并行启动器
#
# 为什么废弃：
#   旧实现在同一台 ECS 上并行拉起 S0/S1/S2 三个状态的沙箱与 AFL++ 实例，
#   违反了「状态同质化（State-Homogeneous）」原则 —— 一台宿主机上的所有
#   AFL++ 实例与沙箱必须测试同一个协议状态。
#
#   后果很具体：
#     1. -M/-S 的本地种子共享会把 S0 的种子灌进 S2 的语料库，前缀语义全废；
#     2. 每个状态各自持有一套 SHM/端口/输出目录，资源与调度都被打散；
#     3. 种子回传无法按状态聚类，中央 Dispatcher 无法做同状态横向分发。
#
# 新入口：
#   ./run_state_node.sh <state_name> [n_secondaries] [duration_sec]
#   例：./run_state_node.sh state_2_auth 3 300
#
#   想换状态（整机原子切换，不锁死）：
#   ./switch_state.py state_0_init
#   或由 Dispatcher 远程指派：
#   ./dispatcher/seed_dispatcher.py --switch state_1_user
#

echo "=================================================================="
echo "  run_all_states.sh 已废弃 —— 违反「状态同质化」原则"
echo "=================================================================="
echo ""
echo "  单台 ECS 宿主机上的所有 AFL++ 实例与沙箱，只测试同一个协议状态。"
echo "  这样 -M/-S 才能原生共享本地种子，不被跨状态语料污染。"
echo ""
echo "  请改用："
echo "    ./run_state_node.sh state_2_auth 3 300"
echo "    ./run_state_node.sh state_0_init          # 1 master + (nproc-1) secondary"
echo ""
echo "  状态切换（整机原子切换，非锁死）："
echo "    ./switch_state.py state_1_user"
echo ""
echo "  查看架构说明：DESIGN.md"
echo "=================================================================="
exit 1
