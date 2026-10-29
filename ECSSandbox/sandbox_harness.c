#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ipc.h>
#include <sys/shm.h>

// AFL++ 持久化模式宏
__AFL_FUZZ_INIT();

#define SHM_SIZE 65536

// ─── 载荷应答等待上限 ───
// 实测（timeit_target.py）：靶机应答一次正常命令只要 0.15~0.3ms，但【没有换行符】
// 的载荷会让服务器一直等"完整的一行"，永远不回包 —— 于是 recv 干等满 SO_RCVTIMEO。
// AFL havoc 变异出的输入大量没有换行，这 50ms 就是吞吐从 25/s 掉到 4.6/s 的主因。
// 因此载荷应答改用 poll() 短等待：正常应答 0.3ms 内就绪，等 5ms 绰绰有余；
// 等不到就当"无应答"，走后面的崩溃探测 —— 判活不依赖载荷是否回包，语义不变。
static int g_reply_wait_us = 5000;

// ─── 分段计时（诊断吞吐用，SBF_TIMING_FILE 设置时才写）───
static unsigned long long g_ph_connect, g_ph_banner, g_ph_prefix,
                          g_ph_payload, g_ph_probe, g_ph_misc;
static unsigned long g_ph_iters;
static const char *g_timing_file;

static unsigned long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000ULL + (unsigned long long)ts.tv_nsec / 1000ULL;
}

static void timing_dump(int final) {
    if (!g_timing_file || !g_ph_iters) return;
    FILE *f = fopen(g_timing_file, "w");
    if (!f) return;
    unsigned long long n = g_ph_iters;
    fprintf(f, "iters=%lu\n", g_ph_iters);
    fprintf(f, "avg_us connect=%llu banner=%llu prefix=%llu payload=%llu probe=%llu misc=%llu total=%llu\n",
            g_ph_connect / n, g_ph_banner / n, g_ph_prefix / n,
            g_ph_payload / n, g_ph_probe / n, g_ph_misc / n,
            (g_ph_connect + g_ph_banner + g_ph_prefix + g_ph_payload + g_ph_probe + g_ph_misc) / n);
    if (!final) fprintf(f, "partial\n");
    fclose(f);
}

// ─── AFL++ 自身覆盖率位图（经 afl_map_bridge.c 取得）───
// 关键：靶机覆盖率记录在"私有 SHM"（TARGET_SHM_ID）里，但必须合并进
// AFL++ 的 trace_bits 才能被 New Edge 判定看见。只有这样，
// "微观本地过滤"才是真的：没触发新边缘的变异 → 本地丢弃，零网络。
//
// 注意：不能在本 TU 里直接 extern __afl_area_ptr —— AFL++ 的 LLVM pass
// 会在插桩模块内创建同名全局，导致符号被唯一名化后链接失败。
// 由不参与插桩的 afl_map_bridge.c 负责引用，这里只调用取值函数。
extern unsigned char *sbf_afl_area_ptr(void);
extern unsigned int   sbf_afl_final_loc(void);

// 靶机覆盖率位图长度。默认 64KB，可由靶机适配器（targets/*.conf）用
// TARGET_SHM_SIZE 覆盖 —— 不同目标的 __afl_final_loc 不一样，写死会越界或漏读。
static unsigned int g_shm_size = SHM_SIZE;

static void merge_target_trace(const unsigned char *src) {
    unsigned char *area = sbf_afl_area_ptr();
    if (!src || !area) return;

    unsigned int limit = g_shm_size;
    unsigned int final_loc = sbf_afl_final_loc();
    // 不越过 AFL++ 实际位图长度，避免越界写
    if (final_loc && final_loc + 1 < limit) limit = final_loc + 1;

    for (unsigned int i = 0; i < limit; i++) {
        if (src[i]) area[i] = (unsigned char)(area[i] + src[i]);
    }
}

// ─── 目标端点 / 健康探测命令 ───
static struct sockaddr_in g_serv;
static const char *g_probe_cmd = "NOOP\r\n";

// 连上后靶机先送几行 banner（FTP 的 "220 ..."、SSH、SMTP 都是）。
// 不先读掉的话，recv_lines(...,1) 会把 banner 当成 PROBE_CMD 的应答 ——
// 靶机死了都会被判成"活着"，崩溃检测整个失效。由适配器 TARGET_BANNER_LINES 声明。
static int g_banner_lines = 0;

static void set_sock_timeout(int sock, int usec) {
    struct timeval tv = {.tv_sec = usec / 1000000, .tv_usec = usec % 1000000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    // SO_SNDTIMEO 必须一起设：send() 没有超时就会在对端读得慢/不读时无限期阻塞，
    // 载荷越大越容易撞上（AFL havoc 会生成大输入）。
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
}

// 载荷应答的短等待：poll() 判可读，等到才 recv。返回读到的字节数，0 = 无应答。
static ssize_t recv_reply_briefly(int sock, char *resp, size_t respsz) {
    struct pollfd pfd = {.fd = sock, .events = POLLIN};
    int pr = poll(&pfd, 1, g_reply_wait_us / 1000);
    if (pr <= 0) return 0;                 // 超时/出错 → 视为无应答
    return recv(sock, resp, respsz, 0);
}

// 读满 need 条应答行（靶机每条命令回一行，以 \n 结尾）。
// 必须按行数读干净：前缀是两条命令两条应答，只 recv 一次会把第二条应答
// 留在套接字里，下一次 recv 就会把它误当成"载荷的应答"，从而掩盖靶机死亡。
static int recv_lines(int sock, char *resp, size_t respsz, int need) {
    int got = 0;
    size_t total = 0;
    while (got < need && total + 1 < respsz) {
        ssize_t n = recv(sock, resp + total, respsz - 1 - total, 0);
        if (n <= 0) return -1;
        for (ssize_t i = 0; i < n; i++)
            if (resp[total + i] == '\n') got++;
        total += (size_t)n;
    }
    resp[total] = '\0';
    return (int)total;
}

// 前缀要【逐条报文】发，不能一整块 send() 出去。
//
// 实测 LightFTP（2026-10-28 探针）把一次 recv() 到的整个缓冲当成【一条】命令：
//     send("USER admin\r\nPASS 123456\r\n")
//       → '331 User admin\r\nPASS 123456 OK. Password required'
// 用户名被回显成 "admin\r\nPASS 123456" —— PASS 根本没执行，后面的载荷打在
// 【未登录会话】上（目标命令一律回 530）。整块发等于状态推演完全失效。
//
// 更阴的是这条应答里内嵌了一个 \r\n：下面 recv_lines() 是按 '\n' 计数的，
// 一次 recv 就数出 2 行，把"一条畸形应答"当成"两条命令都确认了"，于是静默
// 继续 —— 不报错、不超时，state-2 以上的 fuzz 全程在未登录会话上跑。
//
// 所以消息边界必须在【发送侧】保住：一条命令一次 send + 等一条应答。这才与
// "前缀 = 报文序列"（会话前缀重建的产物语义）一致，而不是一块字节。
// 消息边界取 '\n'，与 recv_lines 的行计数、TARGET_BANNER_LINES 同一约定。
static int send_prefix_msgs(int sock, const char *prefix, int prefix_len,
                            char *resp, size_t respsz) {
    int start = 0;
    while (start < prefix_len) {
        int end = start;
        while (end < prefix_len && prefix[end] != '\n') end++;
        if (end < prefix_len) end++;              // 含结尾 \n
        int msg_len = end - start;
        int body = (msg_len > 0 && prefix[end - 1] == '\n') ? msg_len - 1 : msg_len;
        if (body > 0) {                            // 空行（裸 \n）不是报文，跳过
            if (send(sock, prefix + start, msg_len, MSG_NOSIGNAL) < 0) return -1;
            if (recv_lines(sock, resp, respsz, 1) < 0) return -1;
        }
        start = end;
    }
    return 0;
}

// 吞掉同一连接上余下的应答/复位，避免残留污染下一轮
static void drain_pending(int sock) {
    char tmp[256];
    while (recv(sock, tmp, sizeof(tmp), MSG_DONTWAIT) > 0) { /* discard */ }
}

// 读掉连接建立后靶机主动送来的 banner（行数由 TARGET_BANNER_LINES 声明，无 banner 则为 0）
static void read_banner(int sock) {
    if (g_banner_lines <= 0) return;
    char tmp[256];
    recv_lines(sock, tmp, sizeof(tmp), g_banner_lines);
}

// ─── 靶机存活判定：能不能【应答】，不是能不能 connect ───
// 这里是崩溃检测的命门。只做 connect() 是不够的：abort() 落 core 大约要
// 115ms（strace 实测：tgkill(SIGABRT) → 进程真正被杀相隔 115ms），这段时间
// 进程还活着、listen 套接字还在，connect() 会成功，但它已经不会再应答任何
// 命令了。用 connect 判活会把"正在死"误判成"活着"，崩溃就被算到下一轮头上。
// 判据改成"连上 + 发一条无害探测命令 + 收到应答行"，三个阶段全覆盖：
//   落 core 中   → 连得上但无应答  → 不活
//   已死未重启   → 连不上          → 不活
//   保活拉起后   → 连得上且有应答  → 活
// 探测命令用 PROBE_CMD 覆盖（默认 NOOP，须是靶机在任何状态都会应答的命令）。
static int target_alive(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
    set_sock_timeout(s, 60000);
    if (connect(s, (struct sockaddr *)&g_serv, sizeof(g_serv)) < 0) {
        close(s);
        return 0;
    }
    read_banner(s);                 // banner 不能当成探测应答
    char resp[128];
    int ok = 0;
    size_t plen = strlen(g_probe_cmd);
    if (send(s, g_probe_cmd, plen, MSG_NOSIGNAL) == (ssize_t)plen)
        ok = (recv_lines(s, resp, sizeof(resp), 1) >= 0);
    close(s);
    return ok;
}

// 等靶机被 sbf-server-loop 拉起来并【恢复应答能力】
static int wait_target_up(int tries) {
    for (int i = 0; i < tries; i++) {
        if (target_alive()) return 1;
        usleep(10000);
    }
    return 0;
}

// ─── 崩溃确认：同一载荷再打一次，靶机【再次】死亡才算 ───
// 为什么必须复现确认，而不是"连不上就 abort"：
//   1) 多行载荷会先回包、后 abort（如 "HELP\r\nSTOR BUG\r\n"），单次 recv
//      看到响应就以为本轮没事，崩溃会被记到【下一个】样本头上；
//   2) 上一轮崩溃的余波（靶机还在落 core / 重启）会被记到无辜样本头上。
// 复现代价只在崩溃瞬间支付，正常迭代零额外网络开销。
// 确认要【两次】都判死才算：真崩溃落 core 的 115ms 内两次都不应答；而
// "慢但活着"的靶机在第二次探测时会应答，从而免于误报。
static int confirm_crash(const char *prefix, int prefix_len,
                         const unsigned char *payload, int len) {
    if (!wait_target_up(20)) return 0;      // 靶机起不来，无从复现，宁可漏报

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
    set_sock_timeout(s, 100000);
    if (connect(s, (struct sockaddr *)&g_serv, sizeof(g_serv)) < 0) {
        close(s);
        return 0;
    }
    read_banner(s);

    char resp[256];
    if (prefix_len > 0 &&
        send_prefix_msgs(s, prefix, prefix_len, resp, sizeof(resp)) < 0) {
        close(s);
        return 0;
    }
    send(s, payload, len, MSG_NOSIGNAL);
    recv_lines(s, resp, sizeof(resp), 1);   // 真崩溃时这里拿不到应答，忽略结果
    close(s);

    usleep(2000);                           // 让 abort() 发作
    if (target_alive()) return 0;           // 还能应答 → 不是本次载荷干的
    usleep(30000);                          // 30ms 远在落 core 窗口(≈115ms)内
    return !target_alive();                 // 仍不活 = 确实是这个载荷干的
}

int main(int argc, char *argv[]) {
    // SIGPIPE 必须忽略：靶机有 10ms 空闲超时，一旦 harness 因 CPU 争用在 connect()
    // 之后被调度延迟，靶机会先关掉连接，随后的 send() 直接用 SIGPIPE 杀死 harness，
    // AFL++ 就把这个良性载荷误记成 crash（文件名 sig:13）。所有 send() 同时带
    // MSG_NOSIGNAL，双保险。
    signal(SIGPIPE, SIG_IGN);

    // ─── 读取环境变量 ───
    char *prefix_file = getenv("PREFIX_FILE");
    char *target_shm_str = getenv("TARGET_SHM_ID");
    int target_port = 9001;
    char *port_str = getenv("TARGET_PORT");
    if (port_str) target_port = atoi(port_str);
    // 健康探测命令：必须是靶机在任何协议状态下都会应答的命令
    char *probe = getenv("PROBE_CMD");
    if (probe && probe[0]) g_probe_cmd = probe;

    // 连接建立后靶机主动送来的 banner 行数（FTP=1，无 banner=0）
    char *banner_str = getenv("TARGET_BANNER_LINES");
    if (banner_str && atoi(banner_str) > 0) g_banner_lines = atoi(banner_str);

    // 位图长度（由靶机适配器给出）
    char *shm_size_str = getenv("TARGET_SHM_SIZE");
    if (shm_size_str && atoi(shm_size_str) > 0) g_shm_size = (unsigned int)atoi(shm_size_str);

    // ─── 加载前缀报文 ───
    char prefix_buf[4096];
    int prefix_len = 0;
    int prefix_lines = 0;
    if (prefix_file && prefix_file[0] != '\0') {
        FILE *f = fopen(prefix_file, "rb");
        if (f) {
            prefix_len = fread(prefix_buf, 1, sizeof(prefix_buf), f);
            fclose(f);
            for (int i = 0; i < prefix_len; i++)
                if (prefix_buf[i] == '\n') prefix_lines++;
            fprintf(stderr, "[harness] Loaded prefix: %s (%d bytes, %d lines)\n",
                    prefix_file, prefix_len, prefix_lines);
        }
    }

    // ─── 挂接靶机覆盖率 SHM ───
    unsigned char *target_trace = NULL;
    if (target_shm_str) {
        int shmid = atoi(target_shm_str);
        target_trace = (unsigned char *)shmat(shmid, NULL, 0);
        if (target_trace == (void *)-1) target_trace = NULL;
    }

    // ─── AFL++ 初始化 ───
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    g_serv.sin_family = AF_INET;
    g_serv.sin_port = htons(target_port);
    g_serv.sin_addr.s_addr = inet_addr("127.0.0.1");

    char resp[256];

    const char *tf = getenv("SBF_TIMING_FILE");
    if (tf && *tf) g_timing_file = tf;
    const char *rw = getenv("SBF_REPLY_WAIT_US");
    if (rw && *rw) {
        int v = atoi(rw);
        if (v > 0) g_reply_wait_us = v;
    }

    // ─── 持久化高频循环 ───
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len <= 0) continue;

        unsigned long long t0 = now_us(), tmark = t0;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        set_sock_timeout(sock, 50000);

        if (connect(sock, (struct sockaddr *)&g_serv, sizeof(g_serv)) < 0) {
            // 靶机不在（多半是上一轮真崩溃后正在重启）。本轮载荷根本没发出去，
            // 不可能由它造成崩溃 —— 直接丢弃本轮，绝不把别人的崩溃算到它头上。
            close(sock);
            continue;
        }
        g_ph_connect += now_us() - tmark; tmark = now_us();

        int conn_ok = 1;

        // 先读掉 banner，否则后面 recv_lines 按行数读会错位
        read_banner(sock);
        g_ph_banner += now_us() - tmark; tmark = now_us();

        // 状态推演：发送前缀报文，使靶机进入目标状态（逐条报文发，见 send_prefix_msgs）
        if (prefix_len > 0) {
            if (send_prefix_msgs(sock, prefix_buf, prefix_len,
                                 resp, sizeof(resp)) < 0) {
                conn_ok = 0;
            }
        }
        g_ph_prefix += now_us() - tmark; tmark = now_us();

        // 清空前置握手覆盖率噪音（必须在【发前缀之后、发载荷之前】清）：
        // 前缀的 record_cov 是状态推演的固定开销，不应计入本次输入的覆盖率快照，
        // 否则每个输入都恒定多出前缀那几个伪边缘。
        if (target_trace) memset(target_trace, 0, g_shm_size);

        ssize_t r = -1;
        if (conn_ok) {
            // 变异打击：发送 AFL++ 变异载荷
            if (send(sock, buf, len, MSG_NOSIGNAL) < 0) {
                conn_ok = 0;
            } else if (memchr(buf, '\n', (size_t)len) != NULL) {
                // 有换行 → 服务器会按行处理并回包。等应答的作用是【确认它处理完了】，
                // 否则过早 close + 合并 SHM 会漏掉这轮的覆盖率。
                r = recv_reply_briefly(sock, resp, sizeof(resp));
            } else {
                // 无换行 → 服务器停在 read() 里等完整行，既不处理也不写覆盖率，
                // 等应答是纯浪费（实测白烧满 poll 超时）。直接进崩溃探测。
                r = 0;
            }
        }
        g_ph_payload += now_us() - tmark; tmark = now_us();

        // 多行载荷会有连续多条应答；吞干净，别留到下一轮
        if (conn_ok && r > 0) drain_pending(sock);
        close(sock);

        // ─── 微观本地过滤的落地点 ───
        // 把靶机私有 SHM 里的边缘合并进 AFL++ 位图，随后由 AFL++ 自行判定
        // 本次变异是否触发 New Edge。否 → 种子直接丢弃，不产生任何网络通信。
        // 是 → AFL++ 写入 queue/，交由 finding_sync.py 异步回传。
        // 注意：必须在存活探测【之前】合并 —— 探测用的 NOOP 也会写覆盖率。
        merge_target_trace(target_trace);

        // ─── 靶机崩溃检测 ───
        // 连接层的异常（recv 失败、send 被复位）【不能】直接当成崩溃：靶机
        // 10ms 空闲超时关连接是常态。反过来，多行载荷先回包后 abort 时连接层
        // 又毫无异常。所以不看连接层，只看"靶机此刻是否还能应答"，再用同一载荷
        // 复现确认归属，最后才代理自杀 —— 保证 crash 文件里的样本可复现。
        if (!target_alive()) {
            if (confirm_crash(prefix_buf, prefix_len, buf, len)) {
                abort(); // 代理自杀 → AFL++ 记录崩溃（归属准确）
            }
            // 复现不了 = 不是本次载荷干的，静默丢弃本轮
        }
        g_ph_probe += now_us() - tmark;

        g_ph_iters++;
        if ((g_ph_iters % 2000) == 0) timing_dump(0);
    }

    // 清理
    timing_dump(1);
    if (target_trace) shmdt(target_trace);
    return 0;
}
