# SandboxFuzzer — 有状态模糊测试架构

## 0. 一句话

**一台机器测一个状态；一个种子只交给一个进程。**
状态同质化是分工边界，不是状态锁死。

---

## 1. 被否决的旧设计

旧实现在同一台宿主机上并行拉起 S0 / S1 / S2 三套沙箱 + 三套 AFL++ 实例
（`run_all_states.sh`，现已废弃）：

```
ECS-A
 ├─ S0_init  port 9000  SHM#0  afl-fuzz -M fuzzer_state_0_init
 ├─ S1_user  port 9001  SHM#1  afl-fuzz -M fuzzer_state_1_user   ← 异质
 └─ S2_auth  port 9002  SHM#2  afl-fuzz -M fuzzer_state_2_auth   ← 异质
```

问题：

1. **本地种子共享被污染。** 状态不同 → 前缀不同 → S0 的种子进 S2 的队列毫无意义。
2. **SHM / 端口 / 输出目录被打散**，每个状态都拿不到完整的核。
3. **回传无法按状态聚类**，中央侧无法做"同状态横向分发"。

---

## 2. 本地侧的三条硬性原则

### 原则一：状态同质化（State-Homogeneous）

> 单台 ECS 上的**所有** AFL++ 实例与沙箱，必须测试**同一个**协议状态。

```
ECS-A  (state = state_2_auth)
 ├─ afl-fuzz -M fuzzer_0  -o results/<state>/i0  -F work/<state>/0
 ├─ afl-fuzz -M fuzzer_1  -o results/<state>/i1  -F work/<state>/1
 └─ ...
```

入口：`run_state_node.sh <state_name> [n_instances_minus_1] [duration]`

### 原则二：微观本地过滤（Micro Local Filtering）

变异时通过**私有 SHM** 实时判断有没有触发**新边缘（New Edge）**：

```
变异 → sandbox_harness → 靶机（插桩版）
                          └─ 插桩自动写私有 SHM（__AFL_SHM_ID）
       ← merge_target_trace() 把私有 SHM 合并进 AFL++ 的 trace_bits
       ← AFL++ 判定：本次执行是否扩展了位图？
              ├─ 否 → 本地丢弃，【不产生任何网络通信】
              └─ 是 → 写入 queue/，成为"优质种子"
```

**实现要点**（`sandbox_harness.c` + `afl_map_bridge.c`）：靶机覆盖率记在私有
SHM 里，但必须 `merge_target_trace()` 合并进 AFL++ 的覆盖率位图，否则
AFL++ 的 New Edge 判定对靶机是瞎的。

#### 覆盖率怎么进私有 SHM：零侵入注入

接**真靶机**时不可能往第三方源码里插 `record_cov()`。可行的做法只有一个 —— **靠插桩**：

```
靶机用 afl-clang-fast 编译
      ↓
启动时设 __AFL_SHM_ID=<私有段号>
      ↓
AFL++ compiler-rt 在初始化时 shmat() 该段并赋给 __afl_area_ptr
      ↓
插桩代码自动把边缘写进【我们的】私有段        ← 靶机源码一个字没改
      ↓
harness 的 merge_target_trace() 合并进 AFL++ 位图
```

实测（`tests/poc/real_target.c`，一个不含任何 SBF 代码、不碰任何 `__afl_*` 符号的
TCP 服务）：

| 输入 | 私有段非零字节 |
|---|---|
| （对照）不给 `__AFL_SHM_ID` | **0** |
| `HELP` | 9 |
| `+USER` / `+PASS` / `+STOR` / `+NOOP` / `+未知` | 10 → 11 → 12 → 13 → 14 |

同一个 mock 靶机的两种覆盖率来源：

| 来源 | 单个 `NOOP` 触发的边数 | 侵入性 |
|---|---|---|
| `__AFL_SHM_ID` 插桩 | **13** | 零侵入 |
| 手写 `record_cov()` | 1 | 要改靶机源码 |

**两个坑：**

1. **靶机源码里不能 `extern __afl_area_ptr`。** AFL++ 的 LLVM pass 会把插桩模块里
   的同名引用改名（实测 `__afl_area_ptr.16`），链接直接失败。需要读写这个符号的
   场合（比如 harness 合并位图）必须放在**不参与插桩**的 TU 里单独编译 ——
   `afl_map_bridge.c` 就是干这个的，用普通 `cc` 编译。
2. **`AFL_NO_FORKSRV=1` 必须设。** 靶机是常驻服务，不能进 AFL++ 的 forkserver 握手；
   不设的话 `__afl_start_forkserver()` 会往 fd 199 写握手包。

覆盖率来源由**靶机适配器**声明（`targets/*.conf` 的 `TARGET_COV_MODE`）：
`instrument`（真目标）/ `manual`（老 mock）/ `both`（本仓库的 mock）。见 `targets/README.md`。

实测（A/B，25s，同状态）：

| | 有合并 | 无合并 |
|---|---|---|
| `edges_found` | **23** | 9 |
| `bitmap_cvg` | **38.98%** | 23.08% |

> 绝大多数变异在这里就被挡掉了。往下走的永远只是**新边缘**和**崩溃**。

### 原则三：共享种子池 + 唯一 owner（本地去重分工）

> 多个 AFL++ 进程**共享一个优质种子池**，但**同一个种子只交给一个实例**去变异。

为什么不能用 AFL++ `-M`/`-S` 盲同步：

盲同步会把每个实例的 `queue/` 全量灌给其它实例，结果 **N 个进程都在测全量
语料** —— 同一个种子被重复变异 N 次，这正是要避免的浪费。

做法：

| 手段 | 作用 |
|---|---|
| 每实例**独立 `-o` 父目录** | AFL++ 的 `sync_dir == out_dir`，各自目录下只有自己，**无从互扫**，盲同步从根上消失 |
| `corpus/<state>/` 公共池 | 唯一真源，按 sha256 去重；任何实例的发现都进池 |
| `owner = sha256 % N` | 每个种子确定性指派**唯一 owner** |
| `work/<state>/<k>/` + `-F` | 只把种子投喂给 owner 实例（`-F` = foreign sync） |
| 初始语料同样分片 | **开跑即分工**，不存在"全员先测一遍全量" |

```
                 ┌──────────────── corpus/<state>/ ────────────────┐
                 │   <sha256>.raw  （唯一真源，去重）               │
                 └───┬────────────────┬────────────────┬───────────┘
                     │ owner=0        │ owner=1        │ owner=2
                     ▼                ▼                ▼
              work/<state>/0    work/<state>/1    work/<state>/2
                     │                │                │
                     ▼                ▼                ▼
                  fuzzer_0          fuzzer_1         fuzzer_2
                   (i0)              (i1)             (i2)
                     │                │                │
                     └──────── 新边缘/崩溃 回到公共池 ───┘
```

> 注意：`AFL_NO_SYNC` 不能开 —— AFL++ 的 `-F` 投喂实现在 `sync_fuzzers()`
> 内部，那个开关会连投喂一起关掉。隔离靠独立 `-o` 父目录就够了。

#### 初始语料里混着崩溃样本

`prefix_analyzer_output/<state>/seeds/` 里**故意埋了崩溃触发器**：

| 状态 | 崩溃种子 | 靶机行为 |
|---|---|---|
| `state_1_user` | `PASS CRASH` | `abort()` |
| `state_2_auth` | `STOR BUG` | `abort()` |

这类样本**绝不能进 `-i`**。AFL++ 干跑会把它们跳过，一旦某个分片里全是崩溃样本：

```
[!] Test case '...orig:s1_3.raw' results in a crash, skipping
[-] PROGRAM ABORT : We need at least one valid input seed that does not crash!
```

该实例直接退出、**永远写不出 `fuzzer_stats`**（表现为汇总表 `N/A`）。

所以 bootstrap **先探测再分片**（`local_seedhub.py --probe-port`）：

```
初始语料 ──probe──┬─ 不崩 → init_shards/<k>/     （按 sha256%N 唯一 owner）
                  └─ 打死靶机 → corpus/<state>/crashes/   （它本来就是发现物）
```

探测口径**与 `sandbox_harness.c` 的崩溃判定完全一致**（连上 → 发前缀 → 发载荷 →
**靶机不再应答** → 同载荷复现确认），否则会出现"seedhub 说安全、AFL++ 说 crash"
的口径漂移。空分片则放入**按分片序号生成的唯一占位种子**（绝不复用别人的种子）。

入口：`local_seedhub.py`

---

## 2.5 崩溃判定：可复现 + 归属准确

> 崩溃归档里的样本，必须是**它自己**打死靶机的，而且能复现。

这是整套系统里最容易做错的一环，实测踩过三个坑，现在口径是这样：

```
每轮收尾 ── 靶机还能应答？ ── 否 ── 同载荷复现确认 ── 再次不应答 ── abort() 归档
                     │                        │
                     是                       否 ── 静默丢弃本轮（不是它干的）
                     ↓
                  正常结束
```

**为什么不能"连接层异常就当崩溃"：**
靶机 `recv` 超时只有 10ms，harness 因 CPU 争用被调度延迟就会撞上空闲关连接 ——
这是常态，不是崩溃。实测约 20 万次执行里连接层异常远多于真崩溃。

**为什么不能只看"能不能 connect"：**
`abort()` 落 core 要约 **115ms**（strace 实测：`tgkill(SIGABRT)` 到进程真正被杀
相隔 115ms）。这段时间进程还活着、listen 套接字还在，`connect()` 照样成功。
只用 connect 判活会把"正在死"误判成"活着"，崩溃就被算到下一轮头上。

**为什么必须按行读干净应答：**
前缀是两条命令两条应答，只 `recv` 一次会把第二条应答留在套接字里，下一次 `recv`
就把它误当成"载荷的应答"，从而掩盖靶机死亡。

**为什么必须复现确认：**
多行载荷会先回包、后 `abort()`（如 `HELP\r\nSTOR BUG\r\n`）—— 单次 `recv` 看到
响应就以为本轮没事。不复现的话，崩溃会被记到**下一个无辜样本**头上，crash 文件
里的载荷根本打不死靶机。

| 判据 | 覆盖"落 core 中" | 覆盖"已死未重启" | 多行归属正确 | 良性零误报 |
|---|---|---|---|---|
| `recv` 失败 → 二次 connect 失败 | ✗ | ✓ | ✗ | ✗ |
| 能否 `connect()` | ✗ | ✓ | ✗ | ✓ |
| **能否应答 + 复现确认** | ✓ | ✓ | ✓ | ✓ |

存活探测用一条无害命令（`PROBE_CMD`，默认 `NOOP`，须是靶机在任何协议状态都会
应答的命令）。确认时要**两次**都判死才算：真崩溃落 core 的 115ms 内两次都不应答，
而"慢但活着"的靶机第二次会应答，从而免于误报。

判卷器：`replay_judge.py`（对归档的 crash 样本逐个起干净靶机重放）。它必须和
harness 用**同一套判据**，否则会出现"判卷说漏报、harness 说对了"的口径漂移：

| 判卷器里的判定 | 口径 |
|---|---|
| 是否真崩溃 | **进程退出码**（`wait()` 收尸），不看 `recv` 返回值 —— `recv() == b''` 不抛异常，靠它判会翻车 |
| 是否还活着 | **能否应答**（连上 + 发 `PROBE_CMD` + 收到应答行），与 harness 的 `target_alive()` 一致 |
| 等多久才下结论 | 轮询到 1s 上限，而不是固定 `sleep(0.15)` 再 `poll()` —— 后者正撞上 115ms 落 core 窗口，会把"正在死"记成"活着" |

回归测试入口：`./run_tests.sh`（见 §6.1）。

## 3. 状态可切换（不锁死）

> 所有靶机处于统一状态，但**可以切换**，不是锁死在某一状态。

切换是**整机原子**的 —— 一起停、一起换、一起起，绝不出现一半实例在 S1、
另一半在 S2 的异质局面：

```
switch_state.py state_2_auth
  1. stop_node()       整机停掉 afl-fuzz / stateful_server / local_seedhub
  2. archive_results() results|corpus|work|sync_outbox/<旧状态> → results_archive/
  3. node_state.current = state_2_auth
  4. run_state_node.sh  整机拉起新状态
```

---

## 4. 组件地图

| 文件 | 本地/远程 | 职责 |
|---|---|---|
| `run_state_node.sh` | 本地 | **状态同质化节点启动器**：N 个独立实例 + 各自 SHM/靶机；负责 SHM 生命周期与单机互斥 |
| `run_tests.sh` | 本地 | **回归测试**：判定链单测 + 双向判卷 + 去重核查 + SHM 泄漏核查 |
| `local_seedhub.py` | 本地 | **共享种子池 + 唯一 owner 分工**（去重分工的核心） |
| `switch_state.py` | 本地 | **整机原子状态切换**：停机 / 归档 / 换标 / 重拉 |
| `sandbox_harness.c` | 本地 | AFL++ 持久化 harness；**把靶机私有 SHM 合并进覆盖率位图** |
| `afl_map_bridge.c` | 本地 | 不参与插桩的位图访问桥（避开 LLVM pass 同名符号冲突） |
| `stateful_server.c` | 本地 | 有状态协议靶机（S0/S1/S2），`record_cov()` 写私有 SHM |
| `finding_sync.py` | 待定 | 异步种子回传（**Dispatcher 定稿后再启用**，默认关闭） |
| `node_agent.py` | 待定 | 节点控制面（同上，暂不接入） |
| `dispatcher/seed_dispatcher.py` | 待定 | 中央 Dispatcher（**后续设计**） |
| `sbf_redis.py` | 待定 | RESP2 客户端，供上述远程组件使用 |
| `targets/` | 本地 | **靶机适配器**：一份 conf 描述怎么把一个程序当 fuzz 靶机（接新目标不改 C 代码） |
| `tests/` | 本地 | 回归测试与 fixture（含"看着像崩溃但不崩"的反向用例、真目标覆盖率注入 PoC） |
| `Dockerfile` | 本地 | **可移植性**：一条命令起一个状态同质化节点；`third_party/AFLplusplus.tar.gz` 随仓库走 |
| `legacy/` | — | **已废弃的旧入口**（`run.sh` / `run_all_states.sh` / 旧 Dockerfile 等），见 `legacy/README.md` |

## 5. 目录布局

```
results/<state>/i<k>/fuzzer_<k>/   AFL++ 输出（独立 -o，互不盲同步）
  ├─ queue/                        新边缘种子
  └─ crashes/                      崩溃样本

corpus/<state>/                    共享优质种子池（唯一真源）
  ├─ <sha256>.raw                  种子本体
  ├─ <sha256>.json                 meta: found_by / owner / ts
  ├─ crashes/                      崩溃归档
  └─ init_shards/<k>/              初始语料分片（各实例的 -i）

work/<state>/<k>/                  实例 k 的 -F 投喂目录（只含 owner 种子）

run/<state>.shmids                 本节点的 SHM 记账（崩溃后靠它清扫孤儿段）

targets/<name>.conf                靶机适配器（二进制 / 启动参数 / 判活命令 / 覆盖率来源）
tests/fixtures/<state>/{crashes,benign}/  回归 fixture
tests/poc/real_target.c            真目标 PoC：零 SBF 代码，用来验证覆盖率零侵入注入
```

### SHM 生命周期

`shmget(IPC_PRIVATE)` 造出来的段没有路径可反查，进程被 `kill -9` 就永远留在内核里
（实测攒过 110 个 64KB 段）。所以：

```
启动 ── 清扫 run/<state>.shmids 里记的上一轮段 ── 创建新段 ── 立刻把 shmid 追加进账本
退出 ── cleanup() 逐个 ipcrm -m ── 删掉账本
```

单机互斥用 **PID 存活检查**，不用 `flock`：`exec 9>lock` 的 fd 会被 afl-fuzz / 靶机 /
保活循环一并继承，父进程被 `kill -9` 后锁留在子进程手上，形成"幽灵锁"，
下一次启动会被自己上一轮的孤儿挡住。PID 文件没有这个问题 —— 持有者死了就是死了。

## 6. 快速开始

```bash
# 先跑回归测试（改动判定逻辑 / harness 之后必跑）
./run_tests.sh              # 全量
./run_tests.sh smoke        # 只跑单测 + 判卷（约 20s）

# 起一个状态同质化节点（4 个实例，跑 300 秒）
./run_state_node.sh state_2_auth 3 300

# 换个靶机（只换适配器配置，不改任何 C 代码）
TARGET_CONF=targets/real_target.conf ./run_state_node.sh state_2_auth 3 300

# 整机切换状态（原子，非锁死）
./switch_state.py state_1_user

# 只做初始语料分片 / 只核查分工
./local_seedhub.py --state state_2_auth --instances 4 --init-seed-dir \
    prefix_analyzer_output/state_2_auth/seeds --bootstrap
./local_seedhub.py --state state_2_auth --instances 4 --report

# 装进容器（可移植性：环境与宿主机解耦）
docker build -t sbf-node .
docker run --rm -it sbf-node                    # 默认 state_2_auth，4 实例
docker run --rm -it sbf-node state_1_user 3 300 # 换状态/实例数/时长
docker run --rm -it --entrypoint ./run_tests.sh sbf-node   # 容器内跑回归
```

**镜像为什么不用 `aflplusplus/aflplusplus` 当底座**：那镜像 2.5GB / 12 层，
在受限网络里反复拉不下来（实测多次停在 9/12 层）。改成 `ubuntu:22.04` +
源码编 AFL++（`third_party/AFLplusplus.tar.gz`，3MB，随仓库走），构建期只需
apt 拉 clang/llvm，整条链路小一个数量级，且不依赖 Docker Hub 上某个特定镜像。
实测镜像 1.13GB；容器内 4 实例 30s：5203 次执行、27.8%–30.2% 覆盖率、
`池=57 重复=0`，回归测试 **16/16 全绿**（与宿主机同一套判据）。

### 6.1 回归测试覆盖什么

| 层 | 测什么 | 防哪个回归 |
|---|---|---|
| 编译 | 靶机 / harness / 桥接 TU / 测试体都能编过 | 链接期符号冲突（`__afl_area_ptr`） |
| `tests/test_crash_detection.c` | 19 项断言，复用 harness **真代码**（`#include` 而非复制） | SIGPIPE 假崩溃、落 core 窗口漏报、应答残留、多行归属错误 |
| `replay_judge.py` 双向 | 崩溃 fixture 必须 `rc=-6` 复现；良性 fixture 必须不崩 | 归档不可信、假 crash 淹掉真发现 |
| 覆盖率注入 | 真目标零侵入：不给 `__AFL_SHM_ID` 时私有段全零，给了则随输入增长 | 覆盖率注入失效 / 位图被污染 |
| `local_seedhub.py` | `重复=0` + work 分片无同名种子 | 同一种子被两个实例重复变异 |
| SHM 生命周期 | 跑完 0 残留；`kill -9` 后下一次启动能清扫 | 慢性内核资源泄漏 |

## 7. 去重分工核查

运行结束会打印：

```
[seedhub] 池=137  分片=[35, 34, 34, 34]  合计=137  重复=0
                              ↑ 每片大小均衡        ↑ 必须为 0
```

`重复=0` 表示没有任何种子同时出现在两个实例的投喂目录里 ——
这正是"避免大家在测同一种子"的量化保证。

## 8. 网络流量守则

| 事件 | 网络开销 |
|---|---|
| 变异未触发 New Edge | **0**（本地丢弃） |
| 触发 New Edge | 入公共池，按 owner 本地投喂；**0 网络** |
| Crash | 入公共池 `crashes/`；**0 网络** |
| 种子跨实例分工 | **0**（本机硬链接 + `-F` 目录） |
| 跨状态 | **不分发**（前缀语义不通） |

> 上面全部是本地行为。跨机回传 / 中央 Dispatcher 属于后续设计，
> 相关代码（`finding_sync.py` / `node_agent.py` / `dispatcher/`）已就位但默认不启用。
