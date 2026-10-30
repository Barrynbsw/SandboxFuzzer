# LibAFLstar：快速且具备状态感知的协议模糊测试

**原论文题目**：LibAFLstar: Fast and State-Aware Protocol Fuzzing  
**作者**：Cristian Daniele¹, Timme Bethe², Marcello Maugeri³, Andrea Continella², Erik Poll¹  
**机构**：  
¹ 荷兰内梅亨大学（Radboud University, Nijmegen, The Netherlands） `{cristian.daniele, erik.poll}@ru.nl`  
² 荷兰特温特大学（University of Twente, Enschede, The Netherlands） `timme@timmebethe.nl, a.continella@utwente.nl`  
³ 意大利卡塔尼亚大学（University of Catania, Catania, Italy） `marcello.maugeri@phd.unict.it`  

---

## 摘要（Abstract）

模糊测试（Fuzzing）公认是目前最有效的软件漏洞挖掘技术之一。然而，尽管近期取得了不少进展，对有状态软件（Stateful Software）进行模糊测试仍然面临严重的低效性与可扩展性瓶颈。这极大地阻碍了对依赖状态模型的软件（如网络协议实现）开展自动化测试。与无状态方法不同，高效的有状态模糊测试工具必须做到：
1. 探索目标系统的状态模型；
2. 聚焦于最关键、最有趣的状态；
3. 追踪哪些消息对于每个特定状态是有价值的；
4. 妥善处理昂贵的目标系统重启与同步开销。

在本文中，我们提出了 **LibAFLstar**，一款快速且具备状态感知能力的协议模糊测试工具。该工具通过结合以下核心机制解决了上述挑战：
- **部分消息序列（前缀，Prefixes）**；
- **新颖的状态调度器（State Scheduler）**；
- **状态感知型队列与位图（State-aware Queues and Bitmaps）**；
- **持久模式（Persistent Mode）**。

我们首先通过在 6 个协议实现上运行包含 20 余种配置的大规模消融实验（Ablation Study）来微调该方法。随后，我们在相同的协议实现（覆盖 FTP、RTSP 和 HTTP 协议）上对 LibAFLstar 进行了 24 小时的评估，并将其性能与两个最先进的（State-of-the-Art）模糊测试工具——**AFLNet** 和 **ChatAFL** 进行了对比。实验结果表明，LibAFLstar 的执行速度比同类先进工具**快 30 倍以上**，并且平均实现了 **1.4 倍的代码覆盖率**。

**关键词**：软件安全 · 软件测试 · 模糊测试 · 有状态系统 · 网络协议

---

## 1 引言（Introduction）

模糊测试是一种广为人知的系统漏洞发现技术。模糊测试背后的核心理念非常朴素：向被测系统（System Under Test, SUT）发送意外的（例如格式畸变的）消息，以触发非预期的异常行为。尽管该技术在 30 多年前就已被提出，但随着 AFL [36]（及其重构版本 AFL++ [16]）的诞生，模糊测试真正迎来了爆发式流行。AFL/AFL++ 是一种基于智能变异的模糊测试工具，在发现现代系统安全漏洞方面表现极为出色。近年来，研究界针对各种不同系统设计了大量的模糊测试工具 [8, 15, 30, 19]（相关综述见文献 [38, 23, 21, 13]）。然而，由于兼具极高的吞吐速度与有效性，AFL++ 及其派生工具 LibAFL [17] 依然是对无状态目标（Stateless Targets）进行模糊测试的首选工具。

不幸的是，AFL++ 以及通用的智能变异模糊测试工具的高效性通常仅限于**无状态系统**——即正常运行无需实现内部状态模型的系统。无状态系统的经典案例包括 PDF 阅读器、MP3 播放器或图像处理库。

在面对**有状态系统**时，现有的智能变异模糊测试工具的效果往往大打折扣。有状态系统的本质特征是具备状态模型，典型代表包括实现网络协议的各类客户端或服务端（如 FTP、SSH、TLS 和 5G）。在这些系统中，消息序列（通常称为跟踪轨迹/跟踪序列，traces）起着至关重要的作用，因为非预期的序列交互也可能暴露安全漏洞。有状态模糊测试的难度要高得多，主要原因在于状态跟踪十分困难，且消息之间存在强依赖关系，这在常规模糊测试挑战之上又增加了一层复杂性 [7]。具体而言，有状态模糊测试工具必须：
- 理解并探索目标系统的状态模型（挑战 C1）；
- 重点聚焦在最关键/最有趣的状态上（挑战 C2）；
- 考虑状态与有价值消息之间的关联关系（挑战 C3）；
- 解决昂贵的被测系统重启与同步开销（挑战 C4）。

近年来，学术界提出了数种有状态模糊测试工具 [10, 37, 9]，但尚无任何一款工具能够完全解决上述四项挑战。事实上，大多数现有方法 [27, 35, 4] 每次提供新轨迹（即新的消息序列）时都需要关闭并重新启动 SUT，或者依赖开销高昂的快照（Snapshotting）机制 [31]。此外，上述所有工具均未采用 SUT 的真实状态模型，仅仅实现了对状态特性的浅层建模。

在本文中，我们提出了 **LibAFLstar**，一款快速且具备状态感知的协议模糊测试工具，通过结合以下四项技术全面解决了上述挑战：
1. **利用状态模型知识** —— 解决挑战 C1；
2. **利用状态调度器聚焦于最关键的状态** —— 解决挑战 C2；
3. **利用状态感知队列按状态对相关消息进行归组** —— 解决挑战 C3；
4. **利用持久模式（Persistent Mode）** 避免每次测试跟踪后都重置 SUT 及昂贵的快照操作，从而实现模糊测试器与 SUT 之间的极速同步 —— 解决挑战 C4。

我们在 LibAFL 框架之上实现了 LibAFLstar，并在来自 ProFuzzBench [26] 基准测试集的 6 个目标系统上进行了评估，将其性能与当前最先进的有状态模糊测试工具 AFLNet [27] 和 ChatAFL [25] 进行了详尽对比。

实验表明，LibAFLstar 的平均速度比同类工具快 **20 倍**，且获得的代码覆盖率*（注：论文中使用“代码覆盖率（code coverage）”一词代替“边覆盖率（edge coverage）”，以避免与状态模型中的边覆盖混淆）*最高达到了 AFLNet 和 ChatAFL 的 **3 倍**。

---

## 2 模糊测试背景（Background on Fuzzing）

### 无状态模糊测试（Stateless fuzzing）
根据生成测试消息的技术不同，模糊测试工具主要分为**基于语法的（Grammar-based）**和**基于变异的（Mutation-based）**两类。
- **基于语法的模糊测试器**利用输入的语法规则（由安全分析师人工提供或由算法自动推断），生成与既定语法略有偏差的输入 [34]，或者生成严格符合语法但能穿透代码中特定校验与约束的输入 [24]。
- **基于变异的模糊测试器**不需要显式语法；相反，它们采用样本消息（通常称为种子，seeds）作为输入来启动变异。像 AFL++ 这样的智能变异模糊测试工具（通常称为灰盒测试工具）不会进行盲目的暴力变异，而是使用启发式反馈（例如代码覆盖率）来引导消息生成，使其朝着最有可能发现漏洞的方向演化。具体而言，智能变异模糊测试器将代码覆盖信息存储在一个矩阵（位图，bitmap）中，并维护一个队列来保存触发了新代码覆盖率的消息，以便后续开展进一步变异。

对于无状态系统，模糊测试所需的先验信息很少：通常只需输入语法或少量种子便足以挖掘出海量漏洞。Google 发起的 OSS-Fuzz [32] 项目便是明证，该项目借助三款无状态模糊测试工具（AFL++ [16]、libFuzzer 和 Honggfuzz）在 1,000 个开源项目中挖掘出了 36,000 个漏洞。

### 有状态模糊测试（Stateful fuzzing）
尽管有状态系统与无状态系统之间的界限有时较为模糊 [10]，但显然对于某些系统而言，仅靠消息语法或种子文件远远无法实现高效测试。实际上，有状态系统（即需要依赖状态模型来约束特定行为的系统）必须引入专门的组件或启发式策略来管理其状态特征。例如，Daniele 等人 [10] 将实现此类针对性组件的有状态模糊测试器划分为七大类别。其中之一便是**演化型基于语法的模糊测试器（evolutionary grammar-based fuzzers）**。这类工具将反馈机制（类似于 AFL++）与 SUT 的状态模型规范相结合：利用反馈信息引导消息生成，同时借助状态模型知识驱动系统探索不同的状态。LibAFLstar 正属于此类范畴。

从更高维度来看，有状态模糊测试面临的核心难点在于必须同时处理两个不同维度的输入层级：**无状态系统只需对消息本身进行变异；而有状态系统不仅需要变异消息内容，还必须变异消息的发送顺序**。变异消息顺序引入了巨大的额外复杂性，因为相同的消息在不同的系统状态下均可被发送，且会触发截然不同的代码路径。

---

## 3 有状态模糊测试面临的挑战（Challenges in Stateful Fuzzing）

总体而言，有状态模糊测试比无状态模糊测试更具挑战性，直接使用无状态工具测试有状态系统通常并非良策 [10]。具体来说，针对有状态系统的模糊测试存在四大核心挑战：

- **C1 —— 状态模型探索（State model exploration）**：任何设计精良的有状态模糊测试工具都必须具备在状态空间中有效穿梭的能力，即能够驱动系统从一个状态转移至另一个状态。这要求具备以下二者之一：(i) SUT 实际实现的状态模型；或 (ii) 测试器在模糊测试运行过程中自动推断 SUT 状态模型的能力。然而，网络协议规范通常将状态模型信息零散地分布在冗长的自然语言文档中，使得测试器很难推断出高精度的模型。例如，AFLNet [27] 仅通过在运行时观察服务器的响应码来推断状态模型。尽管这种方式能勾勒出大致轮廓，但常常导致理解不准确：服务端返回不同的响应可能根本没有触发状态转移，而两次完全相同的响应反而可能已经引发了状态变化。
- **C2 —— 状态优先级排序（States prioritization）**：考虑到某些程序所实现的状态数量极为庞大，而在实际测试中可用时间通常有限，高效的测试器必须能够识别并优先测试最关键的状态。简单的贪心策略（如优先测试触发新覆盖率的状态）在某些系统上有效，但在另一些系统上可能表现不佳，从而错失重要状态。先进的有状态模糊测试工具应该能够根据状态覆盖大段代码（即发现更多漏洞）的概率来动态调度状态。例如，在测试 FTP 服务端实现时，将过多时间花费在初始未认证状态是不划算的，因为绝大多数功能命令只有在成功身份验证后才可被触发。
- **C3 —— 消息与状态之间的依赖关系（Dependencies between messages and states）**：无状态系统没有历史执行上下文的概念，每次只独立接收一条输入消息。因此，无状态测试器使用单一的全局队列（Global Queue）来保存对整个系统有价值的输入。相反，在有状态系统中，某些特定消息仅在特定状态下（即在前置消息之后）才具备测试意义。尽管像 AFLNet 或 ChatAFL [25] 等工具通过将多条消息串联为单条跟踪轨迹（trace）部分缓解了该问题，但这种方法要求在每条轨迹执行后都重启 SUT，从而带来了严重的性能瓶颈（如挑战 C4 所述）。
- **C4 —— SUT 重启与同步开销（SUT restarts and synchronizations）**：SUT 重启对于无状态和有状态模糊测试均构成瓶颈。重启目标系统所消耗的时间极大地削减了在既定时间预算内能够处理的测试用例数量，导致吞吐率大幅下降。更有甚者，有状态系统往往具有更复杂的内部运行机制，使得重启开销更加昂贵。雪上加霜的是，当测试需要客户端与服务端双向交互的有状态网络协议时，收发双方的同步等待至关重要：在对服务端进行测试时，测试器不能一口气无脑发送数百万条消息，而必须等待服务端对每条消息处理并确认完毕，造成大量网络等待空耗。

---

## 4 LibAFLstar：方法与架构设计（Methodology & Design）

在本节中，我们介绍 LibAFLstar，这是一款专门应对上述四大挑战的状态感知型模糊测试系统。

### 框架总体工作流（图 1）
系统的工作流程包含以下核心步骤：
1. **输入准备**：接收 SUT 的状态模型以及初始种子跟踪轨迹（seed traces），并据此构建**前缀集（Prefixes）**（即到达各个目标状态的部分消息序列）。
2. **第一阶段：状态与消息选择（State and Message Selection）**：状态调度器选定一个待测试的状态（图 1 中的 prefix selection），接着消息调度器从该状态专属的本地队列（Local Queue）中选取一条待变异的消息（图 1 中的 local message selection）。与维护单一全局队列的传统方法不同，LibAFLstar 为每个状态单独维护一个高价值消息队列。
3. **第二阶段：本地队列与位图更新（Local Queue and Bitmap Updates）**：在对选定状态进行变异测试时，捕获的代码覆盖率记录在专属的本地覆盖率位图（Local Bitmap）中，若产生新代码覆盖率，则将该输入加入该状态的本地消息队列。
4. **第三阶段：覆盖率分析与状态转移（Coverage Analysis）**：LibAFLstar 实时分析覆盖率增益，并动态决定是：(a) 继续在当前状态下开展测试（图 1 中绿色分支，无需重启 SUT，保持持久连接）；还是 (b) 切换并跳转到新的状态进行测试（图 1 中红色分支，通过发送对应前缀导航至新状态）。

下面我们以开源 FTP 服务端 **LightFTP**（广泛用于有状态模糊测试基准测试）为例，详细阐述各个阶段的设计机理。

---

### 4.1 预处理（Preprocessing）

与其它基于变异的工具类似，LibAFLstar 需要种子轨迹来引导启动。我们在正常的协议通信中通过网络抓包（Traffic Sniffing）捕获合法客户端与服务端之间的交互报文（与 AFLNet、ChatAFL 一致）。前期研究表明抓包流量质量极大影响种子生成和最终测试性能 [29]。为避免采集到残缺或失真的网络流量，我们由三名专业分析师分别执行客户端与服务端的正常交互，累计监控抓取 1 小时的网络通信流量。

除种子外，LibAFLstar 还需要**状态前缀（Prefixes）**以驱动系统探索状态模型。例如，针对 LightFTP（其状态模型见图 2），到达全部核心状态所需的前缀定义如下：
- $P_1$: `USER ubuntu` —— 到达状态 $S_1$（允许用户输入密码）；
- $P_2$: `USER ubuntu, PASS ubuntu` —— 到达状态 $S_2$（成功登录状态）；
- $P_3$: `USER ubuntu, PASS ubuntu, list` —— 到达状态 $S_3$（允许查看服务器目录仓库）；
- $P_4$: `USER ubuntu, PASS ubuntu, epsv` —— 到达状态 $S_4$（进入被动传输模式 Passive Mode）。

获取到达每个状态的前缀极具挑战，因为官方 FTP 协议规范并未给出明确的形式化状态模型，且软件的具体实现可能与规范存在细微偏差。在实验中：
- 对于 **live555** 和 **Lighttpd**，我们直接从协议规范中提取状态模型；
- 对于 4 个不同的 **FTP** 实现，我们使用主动自动机学习工具 **LearnLib** [33]（基于黑盒主动学习技术）自动推断状态模型。有趣的是，这 4 个 FTP 实现各自展现出了略有差异的状态机结构。

主动学习工具使用初始输入字母表，通过各种命令组合主动向 SUT 发起查询探测，观察请求和响应，并通过“反例”（Counterexamples）逐步修正并完善状态机推断。虽然主动学习严谨精确，但面对非确定性行为（如网络超时）时容易受阻，因此我们为其开发了专用测试 Harness，并编写了抽象映射函数（Abstraction Functions），将原始请求和响应映射为规范化的输入符号（例如将 `USER wrong_user1` 和 `USER wrong_user2` 均抽象映射为 `USER wrong_user`），有效防止状态爆炸。编写 Harness 与抽象函数的工作量仅约 2 小时。

主动学习能够输出最完备的前缀列表。相比之下，即使直接从抓包数据中提取前缀（例如 AFLNet 教程中的种子用例 `{USER ubuntu, PASS ubuntu, SYST, PWD, PORT ..., LIST, MKD test, QUIT}`），虽然也能覆盖 80% 的状态，但会漏掉像 $S_4$ 这种必须通过 $S_2$ 或 $S_3$ 发送 `PASV`/`EPSV` 才能进入的分支状态。因此，输入状态模型并提取前缀成功解决了**挑战 C1**。

---

### 4.2 状态与消息选择（State and Message Selection）

#### 状态选择（State Selection）
为了让测试聚焦在最有可能覆盖大面积代码的状态上，LibAFLstar 提出了**出边优先调度算法（Outgoing Edges, OE）**。该启发式调度器优先调度具有更多出边（Outgoing Edges）的状态。其核心逻辑在于：拥有越多出边的状态，意味着其支持更多的后续操作与交互分支，通常实现了更为复杂的业务逻辑，因此是极佳的漏洞挖掘温床。作为基线对照，我们还实现了一个朴素的**轮询调度器（Round Robin, RR）**，依次轮流选择各个目标状态。这种聚焦关键状态的能力解决了**挑战 C2**。

#### 消息选择（Message Selection）
LibAFLstar 继承了 LibAFL 的消息选择策略：在当前选定状态下，将触发了新代码覆盖率的消息追加到该状态的本地队列中，并对其持续变异，直到在该状态下不再产生新的覆盖率为止。未产生新覆盖率的消息不会被丢弃，而是移至队列末尾等待后续循环。

---

### 4.3 本地与全局队列及位图（Local/Global Queues and Bitmaps）

如挑战 C3 所述，某条消息在状态 A 下可能非常有价值，但在状态 B 下可能只是无意义的错误。若所有状态共用单一的全局队列和全局覆盖位图，则完全无法捕捉输入与状态之间的上下文依赖关系。

例如在 LightFTP 中：
- `PWD` 和 `EPSV` 只有在登录后的状态 $S_2$ 发送才具有实际意义，而在未认证状态 $S_0$ 发送只会得到相同的错误响应；
- 相反，`USER ubuntu` 在 $S_0$ 和 $S_2$ 下可能均有意义。如果全局共享位图，该消息在状态 $S_0$ 触发边覆盖后，位图便被置位；后续在 $S_2$ 发送时，即使执行了完全不同的状态迁移逻辑，由于该消息在全局层面“已不是新发现”，测试器将无法将其识别为新价值输入，从而无法加入队列。

为此，LibAFLstar **为每个状态维护独立的本地消息队列（Local Queue）与本地覆盖率位图（Local Bitmap）**（图 3）。这样实现了细粒度的覆盖率归属与追踪，精确管理每个状态专属的变异种子池，从而完美解决了**挑战 C3**。

---

### 4.4 覆盖率分析与持久模式（Coverage Analysis and Persistent Mode）

在发送变异消息后，LibAFLstar 有两种选择：
1. **继续在当前状态下模糊测试，不重启 SUT**（图 1 中的绿色路径）；
2. **选择一个新状态进行测试**（图 1 中的红色路径）。

为了实现极高的测试吞吐量，我们创新性地将 **AFL++ 持久模式（Persistent Mode）** 引入有状态协议测试中。值得注意的是，持久模式原本是专为无状态系统设计的（因为无状态系统执行前后内部状态不改变，循环执行特定代码段无需重启）。而 LibAFLstar 将其成功应用到了有状态协议场景：
- 通过在 SUT 源码的命令处理循环处加入 `while (__AFL_LOOP(UINT_MAX))` 环路（伪代码见图 4），无需重新创建进程或重置网络套接字，便能在同一个 SUT 实例中连续高速处理成百上千条消息；
- **解决同步等待开销**：传统网络模糊测试器通过休眠或等待网络超时来判定服务端是否处理完毕，而持久模式通过 SUT 与 Fuzzer 之间的管道信号（Pipe Message）进行确定性握手，一旦服务端完成本次处理即刻通知 Fuzzer 递送下一条消息，使得测试器能在一秒内安全发送数百条测试消息，彻底消除了网络同步停顿。

结合前缀导航与持久循环，LibAFLstar 彻底克服了 SUT 重启开销与同步瓶颈，攻克了**挑战 C4**。

---

## 5 实现细节（Implementation Details）

LibAFLstar 基于 Rust 语言编写，底层依托模块化模糊测试框架 LibAFL。系统架构（如图 5 所示）主要由三大组件构成：

1. **模糊测试核心（Fuzzer）**：系统的核心大脑，包含标准的 LibAFL 消息调度算法、我们新设计的状态调度算法（RR 与 OE），并支持 AFL++ 的各种标准变异算法（如破坏性变异 havoc）。同时包含反馈处理器（Feedback Handler，用于判定输入是否有趣）和目标处理器（Objective Handler，用于判定是否触发 Crash 等预定目标）。所有持久化及状态相关数据（崩溃记录、触发样本、种子轨迹、状态前缀、本地队列和本地覆盖率位图）均由此模块统一管理。
2. **执行器（Executor）**：全权负责 SUT 的进程生命周期管理、初始化与按需重启。其内置的观察者（Observer）负责在运行期间监控被测系统的代码覆盖率指标与执行行为。
3. **网络模块（Network Module）**：负责跨网络套接字的高效通信，支持客户端模式与服务端模式，使 LibAFLstar 既能测试协议服务端，也能按需对客户端发起测试。

在 LibAFL 的原始事件循环中，我们额外嵌套了一层状态调度主循环：测试器首先通过状态调度器选择目标状态，将 SUT 重置至初始状态，发送对应的前缀报文抵达该状态；随后，测试器从该状态的本地队列中抓取消息，在持久模式循环中对其进行变异、下发测试并观测反馈。

---

## 6 实验评估与结果分析（Experimental Results）

我们在 6 个广泛使用的真实网络协议实现上评估了 LibAFLstar，包括：
- 4 款 FTP 服务端：`LightFTP`、`BFTPD`、`ProFTPD`、`Pure-FTPd`；
- 1 款 HTTP 服务端：`Lighttpd`；
- 1 款 RTSP 流媒体服务端：`live555`。

所有实验均在配备 Intel Xeon (Ice Lake) 处理器（16 核 @ 2.6 GHz）、64 GB DDR4 内存的 VPS 实例上运行。实验分为两大部分：**消融实验（6.1 节）** 和 **对比实验（6.2 节）**。

---

### 6.1 消融实验（Ablation Study）

为了探究不同组件配置对性能与代码覆盖率的影响，我们针对每个被测目标测试了 24 种不同的配置组合，每次测试持续 1 小时。为消除随机性影响，所有实验均独立重复运行 3 次并取平均值。可配置的维度包括：
1. **状态调度算法**：轮询调度（RR） vs. 出边优先调度（OE）；
2. **队列与位图作用域**：全局（Global, G） vs. 本地（Local, L）；
3. **持久模式循环长度（Loop Length, LL）**：1（相当于禁用持久模式，每次均重启）、10、100、1000。

#### 表 1：LibAFLstar 1 小时消融实验结果
*(缩写说明：SS=状态调度器; LL=循环长度; B=位图; Q=队列; EC=代码覆盖率 %; E=执行次数，以千次/k为单位; G=全局; L=局部)*

| 调度算法 (SS) | 循环 (LL) | 位图 (B) | 队列 (Q) | BFTPD (EC% / E) | LightFTP (EC% / E) | lighttpd (EC% / E) | live555 (EC% / E) | ProFTPD (EC% / E) | PureFTPD (EC% / E) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Round Robin** | 1* | G | G | 13.64 / 47k | 28.79 / 132k | 3.86 / 239k | 4.61 / 201k | 9.46 / 39k | 7.44 / 4.92k |
| | 10 | G | G | 16.62 / 66k | 32.81 / 459k | 4.62 / 1k*k | 4.72 / 316k | 10.66 / 75k | 8.29 / 2.58k |
| | 100 | G | G | 17.19 / 365k | 34.38 / 2M | 5.37 / 4M | 4.85 / 329k | 11.65 / 465k | 7.47 / 2.28k |
| | 1000 | G | G | – / – | 34.38 / 4M | 5.12 / 9M | 4.61 / 303k | 12.01 / 3M | 7.47 / 2.28k |
| | 1* | G | L | 13.92 / 46k | 28.35 / 155k | 3.85 / 234k | 4.53 / 237k | – / – | 7.44 / 4.92k |
| | 10 | G | L | 16.62 / 84k | 32.59 / 557k | 4.64 / 1M | 4.87 / 361k | – / – | 7.47 / 2.58k |
| | 100 | G | L | 17.19 / 316k | 34.38 / 3M | 4.67 / 4M | 4.79 / 572k | – / – | 7.54 / 2.28k |
| | 1000 | G | L | 18.47 / 2M | 34.38 / 5M | 4.87 / 10M | 4.70 / 390k | – / – | 7.47 / 2.24k |
| | 1* | L | L | 14.06 / 47k | 28.91 / 155k | 4.26 / 234k | 4.41 / 221k | 9.73 / 40k | 7.44 / 4.92k |
| | 10 | L | L | 16.12 / 71k | 33.04 / 554k | 4.69 / 1M | 4.71 / 437k | 10.93 / 77k | 7.57 / 2.57k |
| | 100 | L | L | 16.69 / 429k | 34.38 / 2M | 5.39 / 4M | 4.85 / 538k | 11.44 / 455k | 7.57 / 2.30k |
| | 1000 | L | L | **21.16** / 3M | 34.38 / 5M | 5.18 / 9M | 4.71 / 498k | 12.12 / 3M | 7.64 / 2.24k |
| **Outgoing Edges** | 1* | G | G | 13.64 / 46k | 28.91 / 143k | 4.00 / 240k | 4.41 / 207k | 10.39 / 40k | 7.54 / 5.20k |
| | 10 | G | G | 16.69 / 71k | 33.26 / 466k | 4.51 / 1M | 4.70 / 290k | 10.64 / 77k | 7.47 / 2.59k |
| | 100 | G | G | 16.83 / 379k | 34.49 / 2M | 5.49 / 4M | 4.81 / 417k | 11.62 / 427k | 7.57 / 2.30k |
| | 1000 | G | G | 18.96 / 2M | 34.49 / 5M | 5.09 / 8M | 4.87 / 435k | 12.07 / 3M | 7.47 / 2.26k |
| | 1* | G | L | 14.20 / 46k | 30.13 / 169k | 4.06 / 235k | 4.41 / 237k | 9.22 / 1k | 7.44 / 5.11k |
| | 10 | G | L | 16.48 / 71k | 32.70 / 565k | 4.48 / 1M | 4.85 / 413k | 9.26 / 1k | 7.57 / 2.59k |
| | 100 | G | L | 16.76 / 286k | 34.49 / 3M | 4.71 / 4M | 4.82 / 591k | – / – | 7.47 / 2.30k |
| | 1000 | G | L | 17.97 / 2M | 34.38 / 5M | 5.01 / 9M | 4.84 / 384k | – / – | 7.87 / 2.22k |
| | 1* | L | L | 14.06 / 46k | 29.69 / 169k | 4.24 / 236k | 4.48 / 229k | 10.27 / 41k | 7.44 / 5.21k |
| | 10 | L | L | 16.69 / 71k | 33.04 / 560k | 4.71 / 1M | 4.77 / 435k | 10.90 / 77k | 7.57 / 2.56k |
| | 100 | L | L | 16.83 / 379k | 34.38 / 3M | 5.45 / 4M | 4.83 / 489k | 11.45 / 444k | 7.87 / 2.32k |
| | 1000 | L | L | 18.96 / 2M | **34.38** / 4M | **5.60** / 9M | **4.87** / 464k | **12.17** / 3M | 7.57 / 2.26k |

#### 消融实验结果核心发现：
1. **状态调度器评估**：RR 与 OE 在整体表现上差异不大，这主要是由于测试协议所实现的状态机规模相对较小；但细致观察代码覆盖率，OE 在多数情况下略优于 RR。
2. **全局 vs 本地队列与位图评估**：实验证实，采用本地队列与本地位图（L/L）平均而言在所有被测目标上取得了最优秀的代码覆盖率，充分印证了上下文隔离的重要性。
3. **持久循环长度评估**：循环长度（LL）与发送消息总数呈明显的正相关线性关系（如图 6 所示）。LL 越大，在 SUT 重启上损耗的时间就越少。作者进一步尝试了大于 1000 的循环长度，但覆盖率并未进一步提升，因此将 1000 确定为最佳折中值。
4. **网络开销评估**：网络系统调用开销占据了整体 CPU 开销的近 50%（如图 7 所示）。为了保证与基准测试工具对比的绝对公平，作者未在本次实验中直接替换底层网络调用。

---

### 6.2 与前沿工具 AFLNet 和 ChatAFL 的对比（Comparison with AFLNet and ChatAFL）

我们将 LibAFLstar（采用最佳组合：本地位图与队列、LL=1000、OE 出边调度）与当前学术界最顶尖的有状态测试工具 **AFLNet**（经典灰盒协议 Fuzzer）和 **ChatAFL**（NDSS 2024 基于大语言模型引导的最新 Fuzzer）进行了完整的 **24 小时长期测试**。实验数据为 3 次独立测试的均值。

#### 表 2：24 小时模糊测试最终对比结果
*(加粗为最优值；Na 表示直接从协议规范推断状态模型，无需 LearnLib 学习)*

| 被测系统 (Subject) | AFLNet 覆盖率 (%) | AFLNet 轨迹数 (k) | AFLNet 轨迹/秒 | ChatAFL 覆盖率 (%) | ChatAFL 轨迹数 (k) | ChatAFL 轨迹/秒 | LibAFLstar 覆盖率 (%) | LibAFLstar 消息数 (M) | LibAFLstar 消息/秒 (~) | 持久模式配置耗时 | LearnLib 配置耗时 (分) | LearnLib 学习耗时 (分) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **LightFTP** | 32.4% | 305k | 3.5 | 34.7% | 250k | 2.8 | **38.1%** | 67M | 775 | 1h | 30m | 30m |
| **BFTPD** | 17.5% | 233k | 2.7 | 20.4% | 239k | 2.7 | **25.4%** | 56M | 648 | 1h | 30m | 30m |
| **ProFTPD** | 15.3% | 162k | 3.4 | **17.4%** | 164k | 1.8 | 17.2% | 44M | 509 | 1h | 30m | 45m |
| **PureFTPd** | 4.8% | 297k | 3.4 | 4.7% | 138k | 1.6 | **14.1%** | 85M | 983 | 1h | 30m | 30m |
| **Lighttpd** | 5.4% | 209k | 2.4 | 5.3% | 241k | 2.8 | **5.9%** | 22M | 254 | 30m | Na | Na |
| **live555** | 5.1% | 839k | 10.1 | 5.2% | 667k | 8.6 | **5.8%** | 7M | 103 | 2h | Na | Na |

#### 深度结果剖析：
1. **吞吐量与执行速度**：LibAFLstar 发送的消息量比竞争对手高出数个数量级。AFLNet 和 ChatAFL 记录的是轨迹数（每个轨迹通常包含 5~6 条消息），即使将轨迹数乘以 5~6 进行换算，**LibAFLstar 的消息发送吞吐率依然比 AFLNet 和 ChatAFL 快上整整一个数量级（30 倍以上）**。这归功于持久模式几乎彻底消除了系统重启和网络同步轮询的巨额耗时。
2. **总代码覆盖率**：除了在 ProFTPD 上略低 0.2% 外，LibAFLstar 在其余 5 个测试目标上均取得了显著领先的最高覆盖率。在 PureFTPd 上覆盖率更是提升了将近 3 倍（从 4.8% 跃升至 14.1%）。总体而言，**LibAFLstar 平均比 AFLNet 提升了 48.6% 的代码覆盖率，比 ChatAFL 提升了 42.7% 的代码覆盖率**。
3. **人工成本极低**：持久模式打补丁耗时在 30 分钟到 2 小时之间；LearnLib 配置与学习均在 1 小时内搞定，投入产出比极高。

---

## 7 相关工作（Related Work）

- **状态感知（State awareness）**：此前有学者探索了模糊测试与状态学习的结合。例如 De Ruiter 等人 [11] 利用 LearnLib 挖掘 TLS 实现中的逻辑缺陷；Bastani 等人 [5] 利用主动学习器推导输入语法供模糊测试器使用；AFLNet [27]、SGPFuzzer [35] 和 Doupé 等人 [12] 通过在运行时监控（Web）服务端的响应来推断状态模型。然而，这些工具均未能实现针对关键状态的优先级调度；更重要的是，它们（除极少数采用快照者外）仍然高度依赖开销巨大的重启机制来重置测试轨迹，并依赖粗暴的超时机制进行客户端-服务端同步，导致执行效率极其低下。
- **状态调度器（State schedulers）**：AFLNet 依赖新发现的边数量来挑选状态，但迄今为止尚未有工具采用**出边（Outgoing Edges, OE）启发式算法**。该思路与 Google 衡量网页权重的 PageRank 算法 [6] 有异曲同工之妙。PageRank 依据入链数量衡量重要性，而我们的 OE 算法依据出边数量衡量业务复杂性：“拥有大量出边的状态很可能实现了繁多的功能特性并对应着海量代码行，因此是模糊测试的绝佳诱饵”。
- **有状态测试中的持久模式与快照（Persistent mode vs. Snapshotting）**：LibAFLstar 是首个将持久模式引入有状态协议模糊测试中的工具。另一种缓解重启开销的思路是快照技术（Snapshotting）[31, 18, 20]，即在特定状态下拷贝 SUT 的内存镜像以便后续快速回退。然而，快照恢复在现代操作系统上往往引入不可忽视的额外虚拟内存与状态恢复开销，使得快照恢复的成本往往并不比直接发送前缀报文更低。

---

## 8 局限性与未来工作（Limitations and Future Work）

1. **源码修补依赖**：启用持久模式需要修改 SUT 源码。对于大多数具有集中式收发主循环（send-receive loop）的协议服务端，打补丁非常简单（ProFTPD 仅需修改 7 行，live555 需修改 35 行）。但在面对完全事件驱动架构（Event-driven）的程序（如 OpenVPN [14]）时，定位命令处理循环较为复杂，需要对协议架构有更深入的理解。
2. **状态转移的不确定性**：在特定状态前缀引导下发送变异消息时，若前置变异意外触发了状态跳跃，测试器无法 100% 保证新覆盖率究竟是在预定状态还是在新状态中被激发的。此外，持久循环可能会对偶现 Bug 的单步重现造成一定干扰。为此，LibAFLstar 完整记录了持久循环期间发送的所有消息序列以确保漏洞的可复现性。
3. **未来拓展方向**：
   - 探索更高级的状态调度算法，例如引入 Liyanage 等人 [22] 的覆盖率预测算法；
   - 将 LibAFLstar 集成进标准的 ProFuzzBench [26] 评估基准中；
   - 结合 PREENY、Green-Fuzz [1] 或 Sabre [3] 等底层系统调用劫持库，进一步消除网络套接字带来的 50% 系统调用开销。

---

## 9 结论（Conclusion）

本文提出了 **LibAFLstar**，一款面向网络协议实现的高性能、状态感知型模糊测试工具。LibAFLstar 巧妙地利用状态模型前缀导航状态空间，通过出边优先启发式调度器定位代码最密集的关键状态，为不同状态建立独立的本地队列和位图以精准捕捉输入-状态依赖关系，并首创性地将持久模式与状态机前缀结合，最大限度消除了目标系统的重启与网络同步瓶颈。消融实验证实了各核心组件的显著效益。在 6 款现实主流网络协议服务端的 24 小时评测中，LibAFLstar 的执行吞吐率**比同类最先进工具快 30 倍以上**，平均代码覆盖率提升了 **40% 以上**。

---

## 数据可用性（Data Availability）
秉承开放科学的宗旨，本项目已全面开源：  
开源代码仓库：`https://github.com/LibAFLstar/LibAFLstar`

## 致谢（Acknowledgments）
感谢审稿专家的宝贵意见；感谢 GARR Consortium 为大规模实验提供的高性能云基础设施；感谢 Leonardo Cantarella 在 Lighttpd 测试用例配置方面所做的贡献。本项目受到荷兰研究理事会（NWO）资助的 INTERSECT 项目（NWA.1160.18.301）与 P6 项目（开放技术计划 No. 20475）、以及荷兰经济事务与气候政策部（EZK）通过 AVR 项目“FirmPatch”的联合资助。

---

## 参考文献（References）

1. S. B. Andarzian, C. Daniele, and E. Poll. Green-fuzz: Efficient fuzzing for network protocol implementations. In *International Symposium on Foundations and Practice of Security (FPS)*, Springer, pp. 253–268, 2023.
2. S. B. Andarzian, C. Daniele, and E. Poll. On the (in) efficiency of fuzzing network protocols.
3. P.-A. Arras, A. Andronidis, L. Pina, K. Mituzas, Q. Shu, D. Grumberg, and C. Cadar. Sabre: load-time selective binary rewriting. *International Journal on Software Tools for Technology Transfer*, 24(2):205–223, 2022.
4. J. Ba, M. Böhme, Z. Mirzamomen, and A. Roychoudhury. Stateful greybox fuzzing. In *31st USENIX Security Symposium (USENIX Security 22)*, 2022.
5. O. Bastani, R. Sharma, A. Aiken, and P. Liang. Synthesizing program input grammars. *ACM SIGPLAN Notices*, 2017.
6. M. Bianchini, M. Gori, and F. Scarselli. Inside pagerank. *ACM Transactions on Internet Technology (TOIT)*, 2005.
7. M. Böhme, C. Cadar, and A. Roychoudhury. Fuzzing: Challenges and reflections. *IEEE Software*, 2020.
8. J. Chen, W. Diao, Q. Zhao, C. Zuo, Z. Lin, X. Wang, W. C. Lau, M. Sun, R. Yang, and K. Zhang. Iotfuzzer: Discovering memory corruptions in iot through app-based fuzzing. In *NDSS*, 2018.
9. Y. Chen, T. Lan, and G. Venkataramani. Exploring effective fuzzing strategies to analyze communication protocols. In *ACM Workshop on Forming an Ecosystem Around Software Transformation*, 2019.
10. C. Daniele, S. B. Andarzian, and E. Poll. Fuzzers for stateful systems: Survey and research directions. *ACM Computing Surveys*, 2024.
11. J. De Ruiter and E. Poll. Protocol state fuzzing of tls implementations. In *24th USENIX Security Symposium*, 2015.
12. A. Doupé, L. Cavedon, C. Kruegel, and G. Vigna. Enemy of the state: A state-aware black-box web vulnerability scanner. In *21st USENIX Security Symposium*, 2012.
13. M. Eisele, M. Maugeri, R. Shriwas, C. Huth, and G. Bella. Embedded fuzzing: a review of challenges, tools, and solutions. *Cybersecurity*, 2022.
14. M. Feilner. *OpenVPN: Building and integrating virtual private networks*. Packt Publishing Ltd, 2006.
15. X. Feng, R. Sun, X. Zhu, M. Xue, S. Wen, D. Liu, S. Nepal, and Y. Xiang. Snipuzz: Black-box fuzzing of iot firmware via message snippet inference. In *ACM CCS*, 2021.
16. A. Fioraldi, D. Maier, H. Eißfeldt, and M. Heuse. AFL++: Combining incremental steps of fuzzing research. In *14th USENIX Workshop on Offensive Technologies (WOOT 20)*, 2020.
17. A. Fioraldi, D. C. Maier, D. Zhang, and D. Balzarotti. LibAFL: A framework to build modular and reusable fuzzers. In *ACM CCS*, 2022.
18. E. Geretto, C. Giuffrida, H. Bos, and E. Van Der Kouwe. Snappy: Efficient fuzzing with adaptive and mutable snapshots. In *Computer Security Applications Conference (ACSAC)*, 2022.
19. K. Kim, D. R. Jeong, C. H. Kim, Y. Jang, I. Shin, and B. Lee. Hfl: Hybrid fuzzing on the linux kernel. In *NDSS*, 2020.
20. J. Li, S. Li, G. Sun, T. Chen, and H. Yu. Snpsfuzzer: A fast greybox fuzzer for stateful network protocols using snapshots. *IEEE Transactions on Information Forensics and Security*, 2022.
21. J. Li, B. Zhao, and C. Zhang. Fuzzing: a survey. *Cybersecurity*, 2018.
22. D. Liyanage, S. Lee, C. Tantithamthavorn, and M. Böhme. Extrapolating coverage rate in greybox fuzzing. In *IEEE/ACM ICSE*, 2024.
23. V. J. Manès, H. Han, C. Han, S. K. Cha, M. Egele, E. J. Schwartz, and M. Woo. The art, science, and engineering of fuzzing: A survey. *IEEE Transactions on Software Engineering*, 2019.
24. B. Mathis, R. Gopinath, M. Mera, A. Kampmann, M. Höschele, and A. Zeller. Parser-directed fuzzing. In *ACM PLDI*, 2019.
25. R. Meng, M. Mirchev, M. Böhme, and A. Roychoudhury. Large language model guided protocol fuzzing. In *NDSS*, 2024.
26. R. Natella and V.-T. Pham. Profuzzbench: A benchmark for stateful protocol fuzzing. In *ACM ISSTA*, 2021.
27. V.-T. Pham, M. Böhme, and A. Roychoudhury. AFLNet: a greybox fuzzer for network protocols. In *IEEE ICST*, 2020.
28. H. Raffelt, B. Steffen, and T. Berg. Learnlib: A library for automata learning and experimentation. In *FMICS*, 2005.
29. A. Rebert, S. K. Cha, T. Avgerinos, J. Foote, D. Warren, G. Grieco, and D. Brumley. Optimizing seed selection for fuzzing. In *23rd USENIX Security Symposium*, 2014.
30. S. Schumilo, C. Aschermann, R. Gawlik, S. Schinzel, and T. Holz. kAFL: Hardware-assisted feedback fuzzing for os kernels. In *26th USENIX Security Symposium*, 2017.
31. S. Schumilo, C. Aschermann, A. Jemmett, A. Abbasi, and T. Holz. Nyx-net: network fuzzing with incremental snapshots. In *EuroSys*, 2022.
32. K. Serebryany. OSS-Fuzz: Google’s continuous fuzzing service for open source software.
33. B. Settles. Active learning literature survey.
34. P. Srivastava and M. Payer. Gramatron: Effective grammar-aware fuzzing. In *ACM ISSTA*, 2021.
35. Y. Yu, Z. Chen, S. Gan, and X. Wang. SGPFuzzer: A state-driven smart gray-box protocol fuzzer for network protocol implementations. *IEEE Access*, 2020.
36. M. Zalewski. American Fuzzy Lop - Whitepaper, 2016.
37. Z. Zhang, H. Zhang, J. Zhao, and Y. Yin. A survey on the development of network protocol fuzzing techniques. *Electronics*, 2023.
38. X. Zhu, S. Wen, S. Camtepe, and Y. Xiang. Fuzzing: a survey for roadmap. *ACM Computing Surveys (CSUR)*, 2022.
