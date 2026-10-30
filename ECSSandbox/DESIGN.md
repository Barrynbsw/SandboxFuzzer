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

## 2.6 靶机自毒化与定时回收

> 真目标会**自己把自己搞死**。不回收靶机，任何超过约 60 秒的实验都在一台
> **已经不服务**的靶机上进行 —— 机器时间对齐的前提整个作废。

这不是 fuzzing 的常态损耗，是 SUT 的一个确定性缺陷，实测表现如下：

| 现象 | 实测 |
|---|---|
| 吞吐 | 前 ~60s 约 250 exec/s，之后**永久**塌到 4.5 exec/s（≈217ms/exec） |
| 靶机应答 | banner 从 `220 LightFTP server v2.0a ready` 变成 `MAXIMUM ALLOWED USERS CONNECTED`，**不可恢复** |
| 语料 | corpus / edges 完全冻结，白烧机器时间 |
| 触发点 | 约 16k 次执行/实例（harness 每轮 2 条会话 → 32k 条会话） |

**机理：每个 FTP 会话泄漏一个线程的 VMA。**
`ftpmain()`（`ftpserv.c:2026`）对 `ftp_client_thread` 只 `pthread_create` 就放着，
**既不 `pthread_join` 也不 `pthread_detach`**。攒到 `pthread_create` 直接 `ENOMEM`
—— 独立 C 程序实测**第 32,754 次**创建失败，正好 ≈ `vm.max_map_count`/2
（每个线程 2 个 VMA）。此后 `ftpmain` 走 `if (rv != 0)` 分支，对**所有**新连接
回 `NOSLOTS` 并 close。

**排错路上的两个假象（都别再踩）：**

1. **`maxusers` 不是失能的原因。** 把 conf 的 `maxusers` 从 10 提到 1024 **完全
   无效**，失能点一模一样 —— 那是会话槽，不是线程数。**但这不代表 maxusers
   无害**，见下。
2. **`/proc/<pid>/status` 的 `Threads:` 看不见泄漏线程。** 32k 次创建后它仍显示
   1（退出但未回收的线程不在 `task/` 里）。"线程数正常"推不出"没泄漏"，
   判据只能是把 `pthread_create` 打到失败。

**第二个、独立的毛病：`maxusers=10` 的会话槽饱和（混淆变量）。**
变异出 `PASV` + `LIST/RETR/STOR` 却不建数据连接时，worker 卡在**无超时**的
`accept()`（`ftpserv.c:284`），client 线程随之卡在 `WorkerThreadCleanup` 的
`sleep(2); pthread_join(...)`（`ftpserv.c:381`）—— 这个会话**占一个槽两秒**。
300 exec/s 下只要 2% 的变异体是这类载荷，就有 ~12 个会话同时活着，顶穿
`maxusers=10`，所有新连接收下 NOSLOTS 就关，白丢若干轮。

这件事**必须修**，因为丢轮多少正比于"该臂有多爱生成数据传输载荷" ——
前缀更深的臂更容易摸到 `PASV`/`LIST`，就多吃亏，主实验偏向 ISO。
实测证据（同一批 fixture，180s×3 实例）：`maxusers=10` 时两次 `thr=12` + NOSLOTS；
`maxusers=1024` 时**一次都没有**，而且出现过 `thr=14` / `thr=15` 仍安然无恙 ——
正好坐实"是 10 这个数在卡"。

**修法：两个旋钮，各管一件事。**

| 旋钮 | 位置 | 管什么 | 默认 |
|---|---|---|---|
| `SBF_TARGET_TTL` | `run_state_node.sh` 的 `sbf-server-loop` | 线程 VMA 泄漏 → 自毒化 | 15 s（0 = 不回收） |
| `maxusers=1024` | `targets/lightftp.sh` 生成的 conf | 会话槽饱和 → 丢轮混淆 | 1024 |

TTL 的取值算式：~300 exec/s × 2 会话/exec × 15 s ≈ **9,000** 个泄漏线程，
离 32,754 的墙还有 **3.6×** 余量（TTL=30 只剩 1.8×，跑快一点就撞墙）。
回收本身几乎不要钱：实测 180s×3 实例 TTL=30 共 161,041 次执行、TTL=15 共
150,645 次，差异落在实例间波动内，两档全程平稳、banner 一直是 `220`。

**为什么回收对正确性零影响：**
harness **每一轮**都从 `prefix.raw` 重建协议状态，靶机是无状态可言的执行体，
换一个新靶机不改变任何一轮的判定。正好撞上回收时，判活探测失败 →
`confirm_crash()` 的 `wait_target_up()` 等它起来 → 同载荷复现不出 → 判为
**非崩溃**，只丢掉该轮，绝不误记 crash。**各臂同一个 TTL = 同样的回收节奏**，
不给任何一方加偏置。

**否决掉的两条路：**
- 调 `maxusers` 救自毒化 —— 错的机理，实测无效（但对丢轮混淆有效，见上）。
- `LD_PRELOAD` 强行把 `ftp_client_thread` 变成 detached —— 会连带改掉
  `WorkerThreadCleanup` 对数据线程的 `pthread_join` 语义，动的就不是回收了。

**读数据时的又一个假象：** `AFL_NO_UI=1` 下 AFL++ 每 **40~60 秒**才写一次
`fuzzer_stats` / `plot_data`，读出来是台阶不是曲线。别把刷盘边界当成吞吐断崖。

> **2026-10-29 之前采集的所有 fuzz 数据都测在失能靶机上，一律作废重跑。**

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
| `run_state_sweep.sh` | 本地 | **主实验**：按状态隔离 vs 不隔离，机器时间对齐（ISO K×DUR vs MIX K×DUR） |
| `run_state_partition_ablation.sh` | 本地 | **创新点 2 的 ablation**：同一批种子，只换「待在哪个状态池」 |
| `reachability_probe.py` | 本地 | **level-1 机制证据**：一个种子池在某状态下有多少条打到成功码 |
| `ablation_report.py` | 本地 | 汇总 `fuzzer_stats` 成对比表（含 ΣISO vs MIX，Σ 标为上界） |
| `union_coverage.py` | 本地 | **并集边覆盖**（精确）：确定性回放各配置语料，替代 Σedges 那个上界，见 §9.3 |
| `diag_wedge.sh` / `diag_stall.sh` / `diag_slot_leak.py` | 本地 | **吞吐诊断工具**（banner 原文 / 线程数 / wchan / 泄漏速率），见 §2.6 |
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
sweep/<cfg>/{prefix.raw,seeds/}    主实验 fixture：去重后的配置（ISO_*）+ 对照（MIX_global）
ablation/<arm>/{prefix.raw,seeds/} ablation fixture：A_single_state / B_mixed_pool
run/union_queue/<cfg>/             各臂 AFL++ queue/ 的全量输入（§9.3 稳健性复测用）

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
> 相关代码（`finding_sync.py` / `node_agent.py` / `dispatcher/`）已就位但默认不启用，
> 且同步链路有断点、没做过双节点验证 —— **本文不主张任何跨节点能力**（见 9.4）。

## 9. 主实验

> 两个论点、两层证据：**机制**（可达比例）与**结果**（fuzz 指标）必须对得上。
> ablation 数据 2026-10-30 在 §2.6 的靶机回收机制下以 **3 轮交替序**重采
> （奇 A→B / 偶 B→A，报 mean±std）；ISO/MIX 数据 2026-10-29 重采（单次）。
> 在那之前采的数据全测在一台 60 秒后就不再服务的靶机上，已作废。

| 实验 | 论点 | 自变量 | 预算 |
|---|---|---|---|
| **状态分池 ablation** | 种子池必须单状态 | 只换「种子待在哪个状态池」（= 用哪条前缀），池内容/大小/实例数/时长全锁死 | 300s × 3 实例 × 2 臂 × **3 轮**（换序） |
| **隔离 vs 不隔离** | 机器按状态隔离摸到的代码多 | 只换「分几个状态跑」 | ISO 3 配置 × 300s vs MIX 900s（**机器时间对齐**） |

实例数一律 3（`n_secondaries=2`），`SBF_TARGET_TTL=15`，`maxusers=1024`，
AFL++ 配置、编译产物完全相同。

### 9.1 level-1：机制证据

**ablation —— 同一批 6 条种子，只换它待在哪个池：**

| 臂 | 状态前缀 | 池 | 可达 |
|---|---|---|---|
| A_single_state | `USER admin\r\nPASS 123456\r\n`（25 B，自己的状态） | 6 条 | **6/6** |
| B_mixed_pool（**状态错配**） | 空（0 B，别状态） | 同样 6 条 | **2/6** |

种子一字未动，只换前缀就从 6/6 掉到 2/6 ——「种子池必须单状态」的机制就是这样。
对照组**必须失败**才证明前缀是必要的，否则「通过」可能只是因为该命令本来就不需要前缀。
3 轮交替序重采，逐轮都是 A 6/6、B 2/6，与 fuzz 轮次同一批（见 9.2）。

**隔离实验 —— 每个协议状态各自量一遍（不去重，目标命令各不相同）：**

| 状态 | 前缀 | 自己的池在自己的状态下 |
|---|---|---|
| state_0_USER / state_4_NOOP | 0 B | 2/2 |
| state_1_PASS | 12 B | 3/3 |
| state_2_PWD / state_3_CWD / state_5_TYPE | 25 B | 6/6 |
| MIX_global（最深态） | 25 B | 6/6 |

六个状态的产物各自自洽。MIX 那行 6/6 不是反例 —— 它说的是「最深状态下 6 条都打得响」，
而「必须单状态」说的是**反过来**的方向（浅状态下打不响），见 ablation 那张表。

### 9.2 level-2：结果证据

**ablation（300s × 3 实例 × 3 轮，奇数轮 A→B / 偶数轮 B→A；mean ± sample std）：**

| 臂 | execs | exec/s | corpus | crashes | edges | bitmap |
|---|---|---|---|---|---|---|
| A_single_state | 271,986 ± 5,540 | 906.87 ± 18.50 | **239 ± 19** | 0 | **151 ± 1** | 62.14% ± 0.41 |
| B_mixed_pool（状态错配） | 330,341 ± 26,140 | 1101.33 ± 87.17 | 49 ± 2 | 0 | 102 ± 4 | 42.11% ± 1.90 |
| Δ（同轮配对 A−B） | −58,354 ± 30,511 | −194.46 ± 101.76 | **+190 ± 18** | — | **+48 ± 3** | +20.03pt ± 1.56 |

**注意 A 的 execs 少 17.7%** —— A 每轮要付 2 条前缀报文的重放开销，B 的前缀是空的。
即便在执行次数吃亏的情况下，corpus 还是约 4.9 倍、edges 还是多 47%。预算按
**机器时间**对齐（两臂都是 300s），这正是要的口径：付完前缀重放的代价还赢，才算赢。
corpus 一列是实例求和（含 -F 同步副本），为**上界**；两臂同一口径，臂间比较不受影响。

**隔离 vs 不隔离（机器时间对齐：Σ 695,289 vs 699,702 次执行，差 0.6%）：**

| 配置 | 前缀 | 池 | execs | exec/s | corpus | crashes | edges | bitmap |
|---|---|---|---|---|---|---|---|---|
| ISO_0_3567275f | 0 B | 2 | 230,829 | 769.57 | 46 | 0 | 96 | 39.51% |
| ISO_1_5185be6d | 25 B | 6 | 241,271 | 804.42 | 186 | 0 | 146 | 60.08% |
| ISO_2_5616cc54 | 12 B | 3 | 223,189 | 744.10 | 53 | 0 | 120 | 49.38% |
| **MIX_global** | 25 B | 6 | **699,702** | 777.53 | **263** | 0 | **148** | 60.91% |

MIX 跑满 900s 拿到 148 条边，ISO_1 只跑 300s 就有 146 条 —— **同一个状态跑三倍时间只多 2 条边**。
这就是「不能靠加时间，得换状态」最直接的证据。

### 9.3 并集边覆盖（精确，替代 Σedges）

`fuzzer_stats` 只能给每配置各自的 `edges_found`，隔离臂求和就成 Σ —— 可 **Σ 是上界**：
三个配置跑的是同一个 fftp 核心，命令分发、应答发送这些样板边每个配置各算一次。
这张表里 Σ=362 而 AFL++ 自报 `map_size` 只有 **243**（四次 `edges_found`/`bitmap_cvg`
的比值 96/39.51%、120/49.38%、146/60.08%、148/60.91% 全都等于 243.0）——
**求和求出了超过整个位图的边数**，这本身就是"求和在重复计数"的铁证。

所以另做一趟确定性回放（`union_coverage.py`）：同一个位图，把各配置的语料按
**它自己的前缀**逐条会话回放，读出来的就是并集。去污染走 `TcpShmOracle` 的
会话簿记边集扣除（17 条）+ 静默窗口。

| 臂 | 配置数 | Σ 上界 | **并集（精确）** | 虚高 |
|---|---|---|---|---|
| ISO | 3 | 233 | **137** | **41.2%** |
| MIX | 1 | 130 | **130** | 0% |

| 口径 | 边数 |
|---|---|
| ISO ∪ MIX | 141 |
| ISO ∩ MIX | 126 |
| **只有按状态隔离才摸得到**（ISO − MIX） | **11** |
| 只有不隔离才摸得到（MIX − ISO） | 4 |

重叠结构（自身覆盖的交集）：

| | ISO_0 | ISO_1 | ISO_2 | MIX |
|---|---|---|---|---|
| **ISO_0** (39) | 39 | 30 | 38 | 33 |
| **ISO_1** (128) | 30 | 128 | 58 | 121 |
| **ISO_2** (66) | 38 | 58 | 66 | 61 |
| **MIX** (130) | 33 | 121 | 61 | 130 |

**结论**：并集 137 vs 130（+5.4%），而且是**不对称**的 —— 隔离臂多摸到 11 条
对方摸不到的边，反向只有 4 条。不隔离那臂（MIX，等价于把整机钉死在最深状态跑满全程）
是**最强对照**：它拿最深前缀、又不缺任何一条种子，天平是偏向它的。

**稳健性**：改用各臂 AFL++ `queue/` 的**全量**输入（46/186/53/263 条，与
`corpus_count` 逐个对得上）重测一遍，数字**一个不差**（137 / 130 / 11 vs 4）。
结论不依赖于是取种子池还是取队列。

### 9.4 诚实交代

- **靶机很小。** LightFTP 的插桩位图只有 243 条边（见 9.3 的推算）。137 vs 130
  是在这个尺度上的 5.4%，换个大目标未必是这个比例，也未必更强。
- **两把尺子不能混用。** `fuzzer_stats` 的 `edges_found`（ISO_1 146 / MIX 148）
  是 AFL++ 自己位图的读数，含【插桩过的 harness】和多线程落笔的污染；
  `union_coverage.py` 的 137/130 是**纯靶机**、去污染后的读数。绝对值不可互比，
  同一把尺子量两臂才公平 —— 本文只拿后者做臂间比较。
- **没有崩溃。** 两臂 0 crash，崩溃发现能力这层**没有证据**，不写进结论。
- **对照其实是最强形式。** 6 个状态按 (前缀, 池内容) 去重后只剩 3 个 fuzz 配置
  （state_2/3/5 逐字节相同，state_0/4 同理），且 6 条种子按内容去重后总共只有 6 条、
  各状态的池互为子集 —— 于是 MIX_global 与 ISO_1 的 (前缀, 池) **完全相同**。
  所以这条对照比的是「三态各跑一遍」vs「整机钉死在最深那态跑满全程」，
  正是「按状态隔离 vs 不隔离」的字面意思。
- **ablation 有重复，ISO/MIX 没有。** ablation 跑 3 轮、A→B/B→A 交替序消顺序
  效应，报轮间 mean±std 与同轮配对差；ISO/MIX 仍各只跑一次，那张表的差值
  只有点估计、报不出方差。
- **ISO 求和类指标全是上界。** Σedges 虚高 41.2%，Σcorpus（285 vs 263）同理
  会把两配置都发现的种子数两次。要看真实规模就看 9.3 的并集。
- **只做单机，不主张跨节点能力。** 跨节点同步链路（`finding_sync.py` /
  `node_agent.py` / `sbf_redis.py`）只有骨架、链路有断点，没做过双节点 smoke
  验证（审查 F6）。论文/报告不写跨节点、分布式、多机调度能力；所有结论都在
  单机多核范围内成立，与 §8 的「0 网络」口径一致。
- **单 SUT、单协议。** 主实验全部在 LightFTP（FTP）上；`stateful_server` 只是
  判定链的测试靶，不算第二个 SUT。换协议（SMTP/SSH）没验过，不外推。
- **依赖判定容忍 1 条杂散边（`tolerate_edges=1`）。** 判据是差异超过
  (1+0.5) 条边换算的比值才算依赖 —— 这条硬约束让「1 条边的抖动造不出依赖」，
  但也意味着真实差异恰好 1 条边的弱依赖会被压掉，弱依赖下界是保守的。
- **δ 校准取零分布 max×2.5。** 不是均值/中位数 —— 用最大噪声观测放大 2.5 倍
  当地板，宁可 δ 偏高压掉弱信号，也不让噪声翻成假依赖（假依赖比漏依赖更伤）。
