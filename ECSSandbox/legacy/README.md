# legacy/ — 已废弃的旧入口

这些是 `run_state_node.sh` 之前那一版（单状态单实例 / 多状态并行）的产物。
**不要用它们启动模糊测试**，功能上已被取代，有的已经跑不起来了。

| 文件 | 原用途 | 为什么废弃 | 取代者 |
|---|---|---|---|
| `run.sh` | 容器内单实例启动 | 单实例单状态，没有去重分工、没有崩溃归属 | `run_state_node.sh` |
| `run_all_states.sh` | 同机并行拉起 S0/S1/S2 | **违反状态同质化**：本地种子共享被污染，SHM/端口被打散 | `run_state_node.sh` + `switch_state.py` |
| `build_and_run.sh` | 无 Docker 的本地构建+运行 | 硬编码 `seeds_state2`/`prefix_state2`，不支持多状态 | `run_state_node.sh`（自带编译） |
| `launch_state_sandbox.sh` | 单状态单沙箱启动 | 被 `run_state_node.sh` 的 N 实例循环取代 | `run_state_node.sh` |
| `prefix_state2.raw` / `seeds_state2/` | 旧的 S2 前缀与种子 | 状态固化在一个文件里 | `prefix_analyzer_output/<state>/` |
| `in-ftp/` / `output/` | 旧的一次性输入输出目录 | 一次性产物，无入口引用 | `corpus/` `results/` `work/` |
| `Dockerfile` | 打包上面那套 `run.sh` 流程 | **已损坏**：只 COPY 三个文件、漏了 `afl_map_bridge.o`，`afl-clang-fast sandbox_harness.c` 会链接失败；`ENTRYPOINT` 指向废弃的 `run.sh` | 待重写（第二批） |
| `old_logs/` | 历史运行日志 | 仅作留档 | — |

## 当前正确的入口

```bash
./run_state_node.sh state_2_auth 3 300   # 起一个状态同质化节点
./switch_state.py state_1_user           # 整机原子切换状态
./run_tests.sh                           # 回归测试
```

详见 `../DESIGN.md`。
