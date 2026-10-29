# targets/ — 靶机适配器

一份配置描述"怎么把一个程序当成 fuzz 靶机"，`run_state_node.sh` 按它起靶机。
接新目标时**只加一个 `.conf`，不改任何 C 代码**。

```bash
./run_state_node.sh state_2_auth 3 300                # 默认 targets/stateful_server.conf
TARGET_CONF=targets/real_target.conf ./run_state_node.sh state_2_auth 3 300
```

## 字段

| 字段 | 含义 |
|---|---|
| `TARGET_NAME` | 进程名，清理时 `pkill -x` 用（**不能用 `pkill -f`**，会误杀并发编译） |
| `TARGET_SRC` | 要编译的**单个**源文件，相对仓库根 |
| `TARGET_BUILD_CMD` | 自定义构建命令（多文件 / 带库 / `make`）。优先级高于 `TARGET_SRC` |
| `TARGET_BIN` | 可执行文件路径。**也可以是启动脚本**（见下"端口从配置文件来"） |
| `TARGET_ARGS` | 启动参数；`$PORT` 会被替换成该实例的靶机端口 |
| `TARGET_PROBE_CMD` | 判活命令。必须是靶机在**任何协议状态**都会应答、且**一行一个应答**的命令，默认 `NOOP\r\n` |
| `TARGET_BANNER_LINES` | 连上后靶机主动送几行 banner（FTP/SSH/SMTP 都有）。无 banner = 0 |
| `TARGET_SHM_SIZE` | 覆盖率位图长度（对应 `__afl_final_loc`），harness 据此读写私有段 |
| `TARGET_RECV_IDLE_US` | 靶机 recv 空闲超时。harness 的 socket 超时要比它小，否则会撞空闲关连接 |
| `TARGET_COV_MODE` | 覆盖率来源，见下 |
| `TARGET_NEEDS_RESTART` | `1` = 崩溃后由保活循环拉起（代理自杀式崩溃检测的前提） |

三个字段都没给（`TARGET_BUILD_CMD` / `TARGET_SRC`）时，直接用 `TARGET_BIN`
指向的现成二进制 —— 真目标通常就是这样。

### `TARGET_BANNER_LINES`：为什么必须有

FTP 一连上就送 `220 ... ready`，SSH、SMTP 同理。harness 的 `recv_lines(n)` 是
**按行数**读的：不先把 banner 读掉，判活的 `recv_lines(...,1)` 读到的就是 banner
而不是 `PROBE_CMD` 的应答 —— **靶机死了都会被判成"活着"**，崩溃检测整个失效。

同理，探测/前缀命令要选**一命令一行应答**的。FTP 的 `HELP` 是多行
（`214-...` 若干行 ... `214 Help OK.`），用它当探活命令会留下应答残留。

### 端口从配置文件来的目标

有的目标（LightFTP）端口写在配置文件里，不接受命令行传参。做法是给 `TARGET_BIN`
指向一个**启动脚本**，由脚本按 `$PORT` 生成配置再 `exec` 真二进制 ——
`targets/lightftp.sh` 就是这么干的。这仍然属于"适配器"，靶机源码不动。

## `TARGET_COV_MODE`：覆盖率从哪来

这是接真靶机的关键。三种取值：

| 取值 | 机制 | 适用 |
|---|---|---|
| `instrument` | 只设 `__AFL_SHM_ID=<段号>`，AFL++ 运行时把 `__afl_area_ptr` 指到该段，插桩自动写 | **真目标**（零侵入） |
| `manual` | 只设 `TARGET_SHM_ID`，靶机源码自己调 `record_cov()` | 早期 mock |
| `both` | 两个都设 | 本仓库的 mock（插桩为主，`record_cov()` 补几条固定边） |

### 为什么真目标不能改源码

真靶机（第三方实现）不可能为了我们插一个 `record_cov()`。可行的做法只有一个：
**靠插桩**。目标用 `afl-clang-fast` 编译，启动时设 `__AFL_SHM_ID`，AFL++ 的
`compiler-rt` 在初始化时会 `shmat()` 那个段并赋给 `__afl_area_ptr` —— 覆盖率
自动落到我们的私有段里，靶机源码一个字不用动。

实测（`tests/poc/real_target.c`，零 SBF 代码）：

| 输入 | 私有段非零字节 |
|---|---|
| （对照）不给 `__AFL_SHM_ID` | **0** |
| `HELP` | 4 |
| `HELP`+`USER` | 8 |
| 再加 `PASS`/`STOR`/`NOOP`/未知 | 9 → 10 → 11 → 12 → 13 |

同一个 mock 靶机在两种模式下的对比：

| 覆盖率来源 | `NOOP` 一个命令的边数 |
|---|---|
| `__AFL_SHM_ID` 插桩 | **13** |
| 手写 `record_cov()` | 1 |

### 两个坑

1. **靶机源码里不能 `extern __afl_area_ptr`。** AFL++ 的 LLVM pass 会把插桩模块里
   的同名引用改名成 `__afl_area_ptr.N`（实测 `__afl_area_ptr.16`），链接直接失败。
   需要读写这个符号的场合（比如 harness 合并位图），必须放在**不参与插桩**的 TU 里
   单独编译 —— 本仓库的 `afl_map_bridge.c` 就是干这个的。
2. **`AFL_NO_FORKSRV=1`。** 靶机是常驻服务，不能进 AFL++ 的 forkserver 握手。
   不设的话 `__afl_start_forkserver()` 会往 fd 199 写握手包，行为不可预期。
