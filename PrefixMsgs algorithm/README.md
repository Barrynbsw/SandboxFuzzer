# HSPFuzzer 前缀消息识别算法 —— 拆解与复现

针对 `https://github.com/hspfuzzer/hspfuzzer` 与论文
《HSPFuzzer: High-Speed Network Protocol Fuzzing with Connection Reuse》(IEEE IoT-J 2025)

---

## 一、核心结论：官方代码**未公开**该算法

论文 §III-B / Algorithm 2 描述的「前缀消息识别」是**预处理阶段**的独立工具，
公开仓库里没有这部分实现。全树（845 文件）检索结果：

| 检索项 | 命中数 |
|---|---|
| `NeedSplit` / `AllSplit` / `PrefixMsg` | **0** |
| `pcap` | **0** |
| `GETCOVERAGE` / `llvm-cov` 覆盖率差值 | **0** |
| `shm_hook.c`（连接复用，§III-C） | 1797 行，**存在** |
| `pre_queue`（前缀包队列，消费端） | **存在** |
| README 提到的 `old_shom_hook.c` | **不存在** |

仓库本质是 **AFLplusplus v4.09c 的 fork**，新增内容只有：

1. `shm_hook.c` —— LD_PRELOAD 桩，拦截 socket 系列调用，实现连接复用
2. `afl-fuzz` 增加 `-H <proto>:<port>` 与 `pre_queue` 前缀包队列
3. 环境变量 `AFL_NO_CONNECTION_REUSE` / `AFL_NO_MULTI_CONN` / `AFL_FORCED_KILL` / `AFL_EWMA_ENABLED`

所以：**论文的「识别」那半没开源，只有「使用」那半开源了。**

---

## 二、逆向出的接口契约（复现的锚点）

算法 2 的产物如何被 fuzzer 消费，是全开源的。这是复现必须满足的唯一接口：

### 1. 前缀消息的判定 —— 靠文件名

`src/afl-fuzz-queue.c:631`

```c
/* We should deal with pre-packet, disbale it to keep it away from mutate */
if (strstr(q->fname, "pre")) {
    ACTF("add pre-packet %s", q->fname);
    q->is_pre_packet = 1;
    q->disabled = 1;                  /* 不参与变异 */
    ++afl->queued_pre;
    pre_queue_buf[afl->queued_pre - 1] = q;
}
```

> **文件名含 `pre` → 前缀消息**。这就是全部约定。
> 只要导出 `pre_000.msg`、`pre_001.msg` …，fuzzer 会自动识别。

### 2. 前缀消息的发送时机 —— 每次新连接

`src/afl-fuzz-run.c:1086`

```c
if (afl->fsrv.need_new_conn || !pre_had_been_send) {
    pre_had_been_send = 1;
    for (u32 i = 0; i < afl->queued_pre; i++) {
        afl->pre_queue_cur = afl->pre_queue_buf[i];
        pre_buf = queue_testcase_get(afl, afl->pre_queue_cur);
        write_to_testcase(afl, (void **)&pre_buf, afl->pre_queue_cur->len, 0);
        fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);   /* 每条一次 exec */
    }
}
```

另有 `src/afl-fuzz-one.c:6489 send_pre_packet()` 做同样的事。

### 3. 数据结构

`include/afl-fuzz.h:673`

```c
// xzw:这里是普通种子的queue,现在我们创建前缀包专属的pre_queue
struct queue_entry *pre_queue, *pre_queue_cur, *pre_queue_top;
struct queue_entry **pre_queue_buf;
```

`include/afl-fuzz.h:173` — `queue_entry.is_pre_packet`

---

## 三、算法 2 的语义（论文复原）

```
输入 : PcapFile  →  消息序列 M0..MN-1
输出 : PrefixMsgs, NeedSplit, AllSplit
参数 : τ（缺前缀后仍能无条件处理的消息数上限，通常 1）
       δ（判定「覆盖率相近」的阈值，吸收网络抖动/多线程噪声）
```

**定义 III.1（前缀消息）**：在典型消息序列中，前缀消息是指必须存在的消息；
否则，剩余消息中最多只有 τ 条能被处理。

### 第一阶段：识别 PrefixMsgs

核心原理：**前缀消息显著影响后续消息的处理；缺失时后续消息达不到相同覆盖率**。

```
1. 按序发送全部 N 条，得每条的增量覆盖率 Cov(Mi)
2. for x = 0 .. N-2-τ:
3.     移除 Mx，重新按序发送，得 CovT(Mi)  (i ≠ x)
4.     Num = #{ y > x : DIFF(Cov(My), CovT(My)) ≤ δ }
5.     if Num > τ:  Mx 不是前缀 → break
6. PrefixMsgs = Msgs[0:x]
```

> 注意 `PrefixMsgs = SUBLIST(0, x)` 是**左闭右开**，不含 Mx 本身。
> 最终 x 停在「最后一个非前缀消息」的位置，其之前的所有消息都是前缀。

### 第二阶段：NeedSplit / AllSplit

```
CovA = Cov(M0) ∪ Cov(M1) ∪ … ∪ Cov(MN-1)      # 各条覆盖率之并
CovO = GETCOVERAGE(M0‖M1‖…‖MN-1)              # 全拼成一个包一次发出

if DIFF(CovA, CovO) > N·δ:
    NeedSplit = true          # SUT 无法在单包内解析多条消息
    CovOL = GETCOVERAGE(PrefixMsgs 逐条发,  Mx‖…‖MN-1 拼成一包)
    if DIFF(CovA, CovOL) > N·δ:
        AllSplit = true       # 非前缀消息也必须逐条拆开
```

### 结果的使用方式

| NeedSplit | AllSplit | 种子准备策略 |
|---|---|---|
| false | — | 整段 pcap 作一个种子即可（SUT 能单包解析多条） |
| true | false | 前缀单独成包，非前缀整段拼一个种子 |
| true | true | **所有**消息逐条拆成独立种子 |

无论哪种，前缀消息都要放进 `pre_queue`（文件名含 `pre`），
并**在 seed 准备阶段剔除 quit 类消息**，否则连接复用会被打断。

---

## 四、本目录提供的复现

`prefix_msg_identify.py` —— 依据 Algorithm 2 伪代码实现，含：

| 模块 | 说明 |
|---|---|
| `cov_diff()` | 论文 `DIFF()`：归一化对称差 `\|a Δ b\| / \|a ∪ b\|` |
| `identify_prefix_messages()` | 算法 2 主体，逐步打印决策过程 |
| `parse_pcap_messages()` | pcap/pcapng → 客户端方向应用层消息序列 |
| `ShowmapOracle` | 用 `afl-showmap` 采集真实 SUT 边覆盖（会话重放） |
| `SequenceSimulator` | 覆盖率后端抽象，可换成 llvm-cov |
| `export_for_hspfuzzer()` | 导出成 `pre_*.msg` + `seed_*.msg`，直接可喂 `-i` |
| `self_test()` | 构造已知前缀场景验证算法正确性 |

### 自测（无需真实 SUT）

```bash
python prefix_msg_identify.py --self-test
```

构造 N=6、M0 为前缀、τ=1 的场景，输出：

```
PrefixMsgs = [0]   (期望 [0])
cut_at x   = 1     (期望 1)
NeedSplit  = True  (期望 True)
自测通过 [OK]
```

### 对真实目标使用

```bash
# 1. 抓包得到 pcap（或用论文提到的 AFLNet 种子准备流程）
# 2. 运行算法 2
python prefix_msg_identify.py \
    -i capture.pcap \
    -o seeds_out \
    --target ./ftp_server -p 21 \
    --tau 1 --delta 0.05

# 3. 用导出的种子启动 HSPFuzzer
AFL_PRELOAD=./shm_hook.so ./afl-fuzz -H 0:21 \
    -i seeds_out -o out -- ./ftp_server -p 21
```

---

## 五、复现时的几个坑

1. **`GETCOVERAGE` 必须用「相同启动参数的 SUT 实例」**（论文原文）。
   多线程/网络抖动会让覆盖率不稳定，δ 就是为此设的容差；δ 过小会误判前缀过多。

2. **τ 的取值**。论文说 τ「通常是一个较小的值，例如 1」，对应 `quit` 这类
   无条件处理的消息。若协议里有更多无条件消息（如 `NOOP`），需调大。

3. **`run_sequence` 的语义是单次会话内逐条发送**，不是每条消息开一个新连接。
   `ShowmapOracle` 用「前缀重放 + bitmap 差分」近似，对确定性 SUT 等价；
   若 SUT 强状态（如 TLS 会话），需改用 `shm_hook.so` 驱动真实会话采集。

4. **pcap 消息切分**。论文只说 pcap 里是「交互过程中交换的数据包」，
   未给分界方法（引文 [23],[10]）。`parse_pcap_messages()` 按「单向 payload 即一条消息」
   简化处理；像 FTP 这种 `\r\n` 分界的协议需要在切分前按协议重切。

5. **UDP 不支持连接复用**（论文 §III-C 明说），
   所以前缀识别对 UDP 目标意义有限，主要服务于 TCP 协议。

---

## 六、状态集合 / 状态种子 / IPSM —— `protocol_seed_analyzer.py`

### 为什么要补这块

**HSPFuzzer 没有状态机。** 全树检索 `state_seq` / `extract_state` / `IPSM` / `state_seed`
**全部 0 命中**。`queue_entry` 里的 `focusing`/`focused` 是变异阶段的标记
（`src/afl-fuzz-queue.c:600` 注释「interesting stuff from focused stage」），
与协议状态无关。它靠**连接复用**提速，不靠状态反馈引导。

而 AFLNet 及其变种（含你手头的《AFLNeTrans：状态间关系感知》）靠状态反馈引导：

> 为了识别消息序列所触发的服务器状态，AFLNET 使用服务器的**响应码**。
> 根据此反馈，AFLNET 识别出状态空间中的进展区域，并系统性地导向这些区域。
> —— AFLNet-CN.pdf 摘要

做对比实验、或做状态感知调度，必须自己析出**状态集合**与**状态种子**。
`protocol_seed_analyzer.py` 把这套和算法 2 整合在一起。

### 状态的定义（两种粒度）

| `--state-mode` | 状态键 | 粒度 | 用途 |
|---|---|---|---|
| `code` | 本条消息响应的响应码 | 粗 | 快速看状态空间，一条消息可触达**多个**状态 |
| `sequence` | 累积响应码序列，如 `331>230>257` | 细 | AFLNet IPSM 的键空间，区分「同码不同路径」 |

**关键设计**：code 模式下一条消息的**每个**响应码都是状态。
FTP 的 `LIST` 返回两行 `150` + `226 Transfer complete.`，
二者都是协议状态（数据连接建立 / 传输完成），不能只留最后一个 ——
否则「数据连接建立」这个状态就从状态集合里消失了，无法定向探索。
IPSM 上的**落点**仍取最后一个（消息处理完后的状态）。

### 术语对照（AFLNet ↔ 本工具）

| AFLNet (AFLNet-CN.pdf) | 本工具 |
|---|---|
| 响应码 response code | `MessageState.codes` |
| 状态 state | `StateInfo.key` |
| 状态序列 state sequence | `MessageState.seq_state` |
| IPSM（协议状态机） | `Analysis.ipsm()` / `ipsm.csv` |
| 状态种子 | `Analysis.state_seeds` |
| 状态集合 | `Analysis.state_set` |
| 序列前缀 / 候选子序列 / 后缀 | 算法 2 的 `PrefixMsgs` + 其余 |

### 自测输出（FTP 登录 + PWD + LIST + QUIT）

```
状态集合 (6): ['331', '230', '257', '150', '226', '221']

状态种子 (state -> 到达它的种子下标):
  331     seeds=[0]      USER foo  -> User name okay
  230     seeds=[1]      PASS bar  -> User logged in
  257     seeds=[2]      PWD       -> "/" is current directory
  150     seeds=[3]      LIST      -> Here comes the listing   ← 中间码
  226     seeds=[3]      LIST      -> Transfer complete        ← 落点
  221     seeds=[4]      QUIT      -> Goodbye

状态机 IPSM:
  <INIT>   -> 331      : 1
  331      -> 230      : 1
  230      -> 257      : 1
  257      -> 226      : 1      ← 注意 257 直接跳 226（150 是中间码，非落点）
  226      -> 221      : 1
```

`sequence` 模式下状态集合变为 5 个累积键：
`331` → `331>230` → `331>230>257` → `331>230>257>150>226` → `…>221`

### 内置协议状态提取器

| 协议 | 提取规则 | 示例 |
|---|---|---|
| `ftp` `smtp` `numeric` | `^(\d{3})` 多行全收 | `220` `331` `230` `530` |
| `http` `rtsp` `sip` `statusline` | `PROTO/x.y CODE` | `HTTP/1.1 200` |
| `pop3` | `+OK` / `-ERR` | `+OK` |
| `redis` | RESP 首字节+首行 | `+OK` `$5` |
| `dns` | header flags + rcode | `DNS:qr=1,rcode=0,an=1` |
| `tls` | record + handshake type | `TLS:hs=2` ServerHello |
| `modbus` | func code + exception bit | `MB:func=3,exc=1,code=2` |
| `mysql` | OK/ERR/EOF + 错误码 | `MySQL:ERR,code=1045` |
| `generic` | 长度桶 + 哈希（兜底） | `GEN:b1,h=…` |

### 用法

```bash
# 从 pcap 析出状态集合 / 状态种子 / IPSM
python protocol_seed_analyzer.py analyze -i capture.pcap -p ftp -o out/

# 用累积序列做 AFLNet 风格 IPSM
python protocol_seed_analyzer.py analyze -i capture.pcap -p rtsp \
    --state-mode sequence -o out/

# 同时跑算法 2 精确识别前缀（需可采集覆盖率的 SUT）
python protocol_seed_analyzer.py analyze -i capture.pcap -p ftp -o out/ \
    --prefix --target ./ftp_server -p 21

# 自测
python protocol_seed_analyzer.py selftest
```

### 导出产物

| 文件 | 内容 |
|---|---|
| `seeds/pre_XXX.msg` | 前缀消息（文件名含 `pre`，HSPFuzzer 自动进 `pre_queue`） |
| `seeds/seed_XXX.msg` | 普通消息 |
| `state_meta.json` | `state_set` / `state_seeds` / `ipsm` / `seeds_states` / `rare_states` |
| `ipsm.csv` | `src_state,dst_state,count` 邻接表 |
| `seeds_index.csv` | 每条种子的 `codes` / `base_state` / `seq_state` / `is_prefix` |

`rare_states` 按到达次数升序，对应 AFLNet 的**目标状态选择器** —— 越罕见越该定向探索。

---

## 七、会话前缀重建（`perstate_prefix.py`）—— 对算法 2 的两处修正

算法 2 的复现（第四节）是**基线**，不是我们的方法。真机上它有两个坏假设，
本节的「会话前缀重建」把它们换掉。两个创新点的名字固定为：

| 名字 | 一句话 | 边界 |
|---|---|---|
| **会话前缀重建** / session prefix reconstruction | 前缀是**集合**不是切点，按状态求最短保序前置序列 | 就是 `perstate_prefix.py` |
| **状态分池种子管理** / state-partitioned seed pool | 种子池必须单状态，机器可以多状态 | 就是 `playable_in_state()` 这一条判据 |

> 边界提醒：反向贪心求最小前置序列是 Zeller 2002 那套 delta debugging 的
> **适配**，不作为算法创新宣称。第三段的拆包判定继承自算法 2 第 18–29 行。

### 7.1 算法 2 的两个坏假设（实测证伪）

| 假设 | 算法 2 | 实测 |
|---|---|---|
| **A** 前缀是会话的**前段连续子表** | `PrefixMsgs = Msgs.SUBLIST(0, x)` | 对 `[NOOP, USER, SYST, PASS, HELP, PWD]`，PWD 的正确前置是 USER+PASS（位置 1,3）。**任何** `msgs[:k]` 都给不对 |
| **B** 一个会话**一个**全局前缀 | 单个 `PrefixMsgs` | 不同目标命令需要不同前置。`PASS` 要 `[USER]`，`NOOP` 要 `[]` |

加上 τ 那一步：无条件噪声消息数超过 τ 就 break，实测 6 场景里算法 2 只对 2 个。

### 7.2 三段结构

```
A  依赖矩阵    i 是 j 的前置 ⟺ 移除 i 后 j 的自身覆盖变了
                → 产出是【集合】，不受连续性约束
B  按状态最小可达序列
                对每个目标命令 j，反向贪心删前置候选，得 1-最短保序序列
                → 一个状态 = 一个目标命令，prefix.raw 就是这条序列
C  拆包判定    NeedSplit / AllSplit（继承算法 2 第 18–29 行）
                真值必须【解析】出来（拼包语义 + 剩余条数），再跑 detect_split 交叉核对
```

### 7.3 「自身覆盖」而不是「增量覆盖」—— 这个差别是致命的

`_measure()` **每条发送前清零 SHM**，得到的是「处理本条消息点亮了哪些边」，
不是「本条新点亮了哪些边」：

```
cur - acc（增量）会把与前面消息共用的样板边（命令分发、应答发送…）全部去重掉。
实测 LightFTP 的 PWD 在登录/未登录下【增量覆盖完全相同】
  （都是 {196,197,737,739,745} 五条边，差异边正好被前面的消息点亮过了）
但自身覆盖不同 —— 未登录走 530 早退，登录后走 strcpy/strcat 拼 257。
```

A 段问的是「移除 Mx 后 My 还能不能达到同样的覆盖」，要的正是自身覆盖。
用增量会让 USER/PASS 被误判成非前缀。

### 7.4 测量层的四件事

| 件 | 作用 | 不做会怎样 |
|---|---|---|
| `__AFL_SHM_ID` 注入 | 目标用 afl-clang-fast 编译，启动时传段号，**源码零改动** | 得改靶机源码，结论不干净 |
| `consensus()` | 同一条件重复 K 次取**多数票**（默认 5 次 ≥3 票） | 单次抖动直接进矩阵 |
| `edge_threshold()` | 阈值按**边数**不按比例：`max(δ, (容差+0.5)/|union|)` | DIFF 是比值，最小非零值是 1/\|union\|，按比例卡会把 1 条杂散边当成依赖 |
| `calibrate_delta()` | δ 从决策统计量自己的**零分布**里测出来（两批独立跑，取噪声地板 × 2.5） | 手拍 δ 就成了「δ 是调出来的」 |

### 7.5 多线程靶机的跨会话污染（真机上的头号坑）

LightFTP 每条连接起一个线程，**监听线程与客户端线程并发写同一个 SHM**：

```
third_party/lightftp/Source/main.c:185    pthread_create(&thid, NULL, &ftpmain, NULL)
third_party/lightftp/Source/ftpserv.c:2026 pthread_create(&th, ..., &ftp_client_thread, &scb[i])
```

两类污染，修法不同：

| 污染源 | 现象 | 修法 |
|---|---|---|
| 客户端线程**退出**路径 | `s.close()` 后才落笔，下次清零 SHM 之后凭空多 1~2 条边 | `_quiesce()` —— 清零后轮询到连续静默 |
| 监听线程**常驻**运行 | 边 834 在消息处理中途冒出来，`_quiesce` 等不掉 | `_sample_background()` + `_snap()` —— 采「会话簿记边集」自动减掉 |

后果同形：DIFF 恰好 = 1/16 = 0.0625，看着像一条稳定的弱依赖，实测能把会话级
前置集从 `[USER, PASS]` 撑成 5 条假阳性，而且重跑又变回去 —— **输出不可复现**。

关键细节：834 这类边只在**有连接进出**时才走得到（accept / 建线程 / 线程退出），
所以纯空转采样大概率采不到它。`_sample_background()` 必须自带「连接抖动」阶段：
反复 connect→读 banner→close，一条命令都不发，把簿记路径的边采全。

减掉是安全的：base 与 drop 两次测量减的是同一个集合，`cov_diff` 的分子
`|a\b|` 不受影响（簿记边本就在两边都出现，是样板代码），只有分母 `|a∪b|` 略缩，
信号比只会**变大**。顺手把 recv/send/accept 这类每条消息都有的样板边去掉，
判别力反而更集中。

回归守卫：`../ECSSandbox/probe_coverage_stability.py`（A/B/C 三项确定性测试）。

### 7.6 状态分池种子管理

```python
prerequisites_of(res, j)                  # j 的前置集合（从依赖矩阵读）
playable_in_state(res, j, reaching)       # 前置被本状态的 reaching 序列满足
```

「**种子池必须单状态，机器可以多状态**」就是这一行的含义：一个状态池只收前置被
**本状态** reaching 序列满足的种子。混进别状态的种子会污染该池的可达性 ——
变异出来的载荷在本状态下打不响，整个池的反馈就废了。

归属判据是 `playable_in_state`（依赖矩阵），**不查 RFC 真值表**：真实目标上没有
那张表，拿它当判据等于把答案抄进产物。RFC 表在 `derive_prefix.py` 里只做校验
对照，不做生成依据。这条界线是「算法可用」和「算法自说自话」的分界。

### 7.7 证据链（LightFTP，源码零改动）

真值用**真实响应码**（RFC 959）定义 —— `i 是 j 的前置 ⟺ 去掉 i 后 j 的响应码变了`。
与覆盖率同源不同法，审稿人可以拿 RFC 逐条核对。

| 环节 | 脚本 | 判据 |
|---|---|---|
| 采集确定性 | `../ECSSandbox/probe_coverage_stability.py` | 三项全 PASS |
| 算法正确性（模拟器） | `perstate_prefix.py --self-test` / `counterexample_test.py` | A 段 5/5，拆包 5/5 |
| 算法正确性（真机） | `../ECSSandbox/validate_prefix.py` | A 段 6/6，B 段 33/33 |
| δ 不靠手调 | 同上 `--delta-sweep` | 全对区间 δ ∈ [0.02, 0.16]（最强非依赖 0.000 < δ < 最弱真依赖 0.200） |
| 产物可用 | `../ECSSandbox/derive_prefix.py` → `verify_prefix.py --check-seeds` | 试验组 6/6 + 对照组 6/6 + 单状态 25/25 |
| 抗噪 | `eval_rebuild.py` | p ∈ [0, 0.30] 全 5/5（算法 2 只 1~2/5） |
| **机制**（创新点 2） | `../ECSSandbox/run_state_partition_ablation.sh` + `reachability_probe.py` | 同一批 6 条种子：单状态池 **6/6** vs 混状态池 **2/6** |
| **机制**（各状态） | `../ECSSandbox/run_state_sweep.sh` level-1 | 六状态各自 2/2 / 3/3 / 6/6，自洽 |
| **结果**（创新点 2） | `../ECSSandbox/ablation_report.py` | corpus **+309.1%**、edges **+36.8%**，且付完前缀重放后 execs 还少 19.2% |
| **结果**（隔离 vs 不隔离） | 同上（主实验块） | 机器时间对齐到 0.6%；同态跑 3× 时长只多 2 条边（146→148） |
| **并集边覆盖**（替代 Σ） | `../ECSSandbox/union_coverage.py` | ISO 并集 **137** vs MIX **130**；只有 ISO 摸得到 **11** 条、反向 4 条；Σ 虚高 **41.2%** |

对照组那一栏不能省：没有对照，「通过」可能只是因为该命令本来就不需要前缀。
**对照组必须失败**才证明前缀是必要的，不是假阳性。

跑法（宿主机 glibc 2.31 编不动 fftp，必须进容器，且要挂**包根**）：

```bash
cd SandboxFuzzer                       # 挂包根，不是 ECSSandbox/：
docker run --rm --user "$(id -u):$(id -g)" \
    -v "$PWD":/sbfpkg --workdir /sbfpkg/ECSSandbox \
    --entrypoint python3 sbf-node /sbfpkg/ECSSandbox/validate_prefix.py --delta-sweep
```

---

## 八、文件清单

| 文件 | 说明 |
|---|---|
| `prefix_msg_identify.py` | 算法 2（前缀消息识别）**基线**复现，含 `--self-test` |
| `perstate_prefix.py` | **会话前缀重建**（第七节）：依赖矩阵 / 最小可达序列 / 拆包判定 / `playable_in_state` |
| `tcp_shm_oracle.py` | `__AFL_SHM_ID` 零侵入覆盖率注入的 TCP 后端：`_quiesce` / `_sample_background` / 自身覆盖语义 |
| `counterexample_test.py` | 算法 2 的反例构造 + 会话前缀重建对照（A 段 5/5 vs 2/5） |
| `eval_rebuild.py` | 抗噪评测：随机注入 p 比例杂散边，对比两算法 |
| `protocol_seed_analyzer.py` | **状态集合 / 状态种子 / IPSM** + 算法 2 接线，含 `selftest` |
| `_selftest_out/` | 算法 2 自测导出（`pre_*.msg` / `seed_*.msg`） |
| `_selftest_state_out/` | 状态分析自测导出（含 `ipsm.csv` / `seeds_index.csv`） |
| `../_hspfuzzer_clone/` | HSPFuzzer 官方源码（tarball 解压，拆解用） |

真机侧（`../ECSSandbox/`）：`validate_prefix.py`（ground truth 校验 + δ 扫描）、
`derive_prefix.py`（导出 `prefix.raw` / `seeds/`）、`verify_prefix.py`（产物验收 +
种子池单状态）、`probe_coverage_stability.py`（采集确定性回归探针）。

真 fuzz 侧（同在 `../ECSSandbox/`，用上面的产物做实验）：
`run_state_node.sh`（状态同质化节点启动器，含靶机定时回收 `SBF_TARGET_TTL`，
见其注释：真目标会自毒化）、`reachability_probe.py`（**level-1** 机制证据：一个
种子池在某状态下有多少条打到成功码）、`run_state_sweep.sh`（**主实验**：按状态
隔离 vs 不隔离，机器时间对齐）、`run_state_partition_ablation.sh`（**状态分池
ablation**：同一批种子只换「待在哪个状态池」）、`ablation_report.py`（汇总
`fuzzer_stats`，ΣISO 标为上界）、`run_tests.sh` + `tests/`（回归）、
`diag_wedge.sh` / `diag_stall.sh` / `diag_slot_leak.py`（吞吐诊断工具链）。
