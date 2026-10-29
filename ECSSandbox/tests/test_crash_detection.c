// tests/test_crash_detection.c — 崩溃判定链回归测试
//
// 用 #include 复用 sandbox_harness.c 里的【真代码】，不是复制粘贴：
// 改了 harness 的判定逻辑，这份测试会立刻跟着变，不会出现"测试绿、线上红"。
// 只把它的 main 改名，避免和本文件的 main 冲突。
//
// 覆盖的四个坑（任何一个回归都会挂）：
//   1. SIGPIPE 假崩溃    → T8
//   2. 落 core 窗口漏报   → T7（connect 通但不应答 → 必须判死）
//   3. 应答残留          → T2
//   4. 多行归属错误       → T4 / T6
//
// 用法: test_crash_detection <stateful_server> <port>
#define main harness_main
#include "sandbox_harness.c"
#undef main

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>

static int g_fail = 0, g_pass = 0;

#define CHECK(cond, ...) do {                                   \
        if (cond) {                                             \
            printf("  ✓ " __VA_ARGS__);                         \
            printf("\n");                                       \
            g_pass++;                                           \
        } else {                                                \
            printf("  ✗ " __VA_ARGS__);                         \
            printf("   [%s:%d]\n", __FILE__, __LINE__);         \
            g_fail++;                                           \
        }                                                       \
    } while (0)

// ─── 保活靶机：等价于 run_state_node.sh 里的 sbf-server-loop ───
// 崩溃判定依赖"靶机被打死后能被拉起来"，否则 confirm_crash 里的
// wait_target_up() 会一直失败、永远复现不了，真崩溃反而被当成良性。
static pid_t g_keepalive = -1;

static void start_keepalive(const char *bin, int port) {
    pid_t pid = fork();
    if (pid == 0) {
        for (;;) {
            pid_t srv = fork();
            if (srv == 0) {
                char pbuf[16];
                snprintf(pbuf, sizeof(pbuf), "%d", port);
                execl(bin, bin, pbuf, (char *)NULL);
                _exit(127);
            }
            int st;
            waitpid(srv, &st, 0);
            usleep(100000);          // 与 sbf-server-loop 一致
        }
    }
    g_keepalive = pid;
}

static void stop_keepalive(void) {
    if (g_keepalive > 0) {
        kill(g_keepalive, SIGKILL);
        waitpid(g_keepalive, NULL, 0);
        g_keepalive = -1;
    }
}

// 杀掉保活循环 + 靶机本体，制造"靶机已死"的局面
static void kill_target_everything(void) {
    stop_keepalive();
    system("pkill -x stateful_server 2>/dev/null");
    usleep(150000);
}

// 等靶机真正恢复应答能力
static void wait_up(void) {
    for (int i = 0; i < 50; i++) {
        if (target_alive()) return;
        usleep(20000);
    }
}

// 前缀：S1_user 状态推演（USER admin）；两条坑都靠它测多行残留
static const char *PFX = "USER admin\r\n";
static const int   PFX_LEN = 12;
static const int   PFX_LINES = 1;

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "用法: %s <stateful_server> <port>\n", argv[0]);
        return 2;
    }
    const char *bin = argv[1];
    int port = atoi(argv[2]);

    // ─── 坑 1：SIGPIPE 必须被忽略 ───
    // harness_main() 里做，但本测试不调 harness_main，这里显式等价设置；
    // T8 会验证这个设置真的挡住了 SIGPIPE。
    signal(SIGPIPE, SIG_IGN);

    // 让 harness 的判活函数指向我们的靶机
    memset(&g_serv, 0, sizeof(g_serv));
    g_serv.sin_family = AF_INET;
    g_serv.sin_port = htons(port);
    g_serv.sin_addr.s_addr = inet_addr("127.0.0.1");
    g_probe_cmd = "NOOP\r\n";

    start_keepalive(bin, port);
    wait_up();

    printf("════ 崩溃判定链回归测试 ════\n");
    printf("靶机: %s   端口: %d\n\n", bin, port);

    // ─── T1 判活：活着时必须为 1 ───
    printf("[T1] 判活正向\n");
    CHECK(target_alive() == 1, "靶机应答中 → target_alive()=1");

    // ─── T2 应答残留：按行读干净 ───
    // 前缀 1 条命令 1 条应答。若 recv_lines 不按行数读干净，会把应答留下，
    // 下一次读到它就以为"载荷有应答"，从而掩盖靶机死亡。
    printf("\n[T2] 应答残留\n");
    {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct timeval tv = {.tv_sec = 0, .tv_usec = 200000};
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        CHECK(connect(s, (struct sockaddr *)&g_serv, sizeof(g_serv)) == 0, "连接靶机");

        char resp[256];
        int n = send(s, PFX, PFX_LEN, MSG_NOSIGNAL);
        CHECK(n == PFX_LEN, "发送前缀 %d 字节", PFX_LEN);
        int got = recv_lines(s, resp, sizeof(resp), PFX_LINES);
        CHECK(got > 0, "recv_lines(%d) 读到 %d 字节应答", PFX_LINES, got);
        CHECK((int)strlen(resp) == got, "应答以 NUL 结尾、长度一致");

        // 关键：此刻套接字上不应再有残留应答
        char extra[64];
        ssize_t r = recv(s, extra, sizeof(extra), MSG_DONTWAIT);
        CHECK(r < 0, "读干净后无残留应答（recv 立即 EAGAIN，得到 %zd）", r);

        // 反向：故意只读一半，验证"残留"确实是可见的（说明 T2 的检查有意义）
        send(s, PFX, PFX_LEN, MSG_NOSIGNAL);
        recv(s, extra, sizeof(extra), MSG_DONTWAIT);   // 只 recv 一次
        close(s);

        s = socket(AF_INET, SOCK_STREAM, 0);
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        connect(s, (struct sockaddr *)&g_serv, sizeof(g_serv));
        // 新连接不会有上一条的残留；这里只确认 recv_lines 的行计数正确
        send(s, PFX, PFX_LEN, MSG_NOSIGNAL);
        got = recv_lines(s, resp, sizeof(resp), PFX_LINES);
        CHECK(got > 0, "新连接上 recv_lines 仍正常（%d 字节）", got);
        close(s);
    }

    // ─── T3 真崩溃：同载荷复现确认 → 判死 ───
    printf("\n[T3] 真崩溃确认\n");
    {
        wait_up();
        int ok = confirm_crash(PFX, PFX_LEN,
                               (const unsigned char *)"PASS CRASH\r\n", 12);
        CHECK(ok == 1, "PASS CRASH → confirm_crash()=1（可复现的真崩溃）");
    }

    // ─── T4 多行归属：先回包后崩，也必须判死 ───
    // 这是坑 4：单次 recv 看到 HELP 的响应就以为本轮没事，崩溃会记到
    // 【下一个无辜样本】头上 —— 归档里的载荷根本打不死靶机。
    printf("\n[T4] 多行载荷归属\n");
    {
        wait_up();
        const char *p = "HELP\r\nPASS CRASH\r\n";
        int ok = confirm_crash(PFX, PFX_LEN,
                               (const unsigned char *)p, (int)strlen(p));
        CHECK(ok == 1, "HELP+PASS CRASH（先回包后崩）→ confirm_crash()=1");
    }

    // ─── T5 良性零误报 ───
    // 坑 1 的另一面：连接层异常不能当崩溃。"PASS CRAS" 差一个字符不触发，
    // 但它和崩溃载荷一样会正常走完一轮，任何脆弱判据都可能误报。
    printf("\n[T5] 良性零误报\n");
    {
        wait_up();
        int ok = confirm_crash(PFX, PFX_LEN,
                               (const unsigned char *)"PASS CRAS\r\n", 11);
        CHECK(ok == 0, "PASS CRAS（不触发）→ confirm_crash()=0");
    }

    // ─── T6 多行良性：同样不能误报 ───
    printf("\n[T6] 多行良性零误报\n");
    {
        wait_up();
        const char *p = "HELP\r\nPASS CRAS\r\n";
        int ok = confirm_crash(PFX, PFX_LEN,
                               (const unsigned char *)p, (int)strlen(p));
        CHECK(ok == 0, "HELP+PASS CRAS（多行良性）→ confirm_crash()=0");
    }

    // ─── T7 落 core 窗口：connect 通但不应答 → 必须判死 ───
    // 这是坑 2 的核心回归。abort() 落 core 要约 115ms，这段时间 listen 套接字
    // 还在、connect() 照样成功。用 connect 判活会把"正在死"当"活着"。
    // 这里直接把靶机停在"进程在但不应答"的状态来复现这个窗口。
    printf("\n[T7] 落 core 窗口（connect 通但不应答）\n");
    {
        // 起一个"只 listen 不 accept/不 recv"的假靶机，模拟落 core 中
        kill_target_everything();

        int ls = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in a = {.sin_family = AF_INET,
                                .sin_port = htons(port),
                                .sin_addr.s_addr = inet_addr("127.0.0.1")};
        CHECK(bind(ls, (struct sockaddr *)&a, sizeof(a)) == 0, "假靶机 bind");
        CHECK(listen(ls, 8) == 0, "假靶机 listen（accept 队列灌满前 connect 都成功）");

        // connect 会成功 —— 这正是 bug 的来源
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct timeval tv = {.tv_sec = 0, .tv_usec = 150000};
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        int c = connect(s, (struct sockaddr *)&g_serv, sizeof(g_serv));
        CHECK(c == 0, "落 core 窗口内 connect() 成功（旧判据会误判为存活）");
        if (c == 0) {
            CHECK(target_alive() == 0, "但 target_alive()=0 —— 不应答就不算活");
        }
        close(s);
        close(ls);
        usleep(50000);
    }

    // ─── T8 SIGPIPE 不得杀死 harness ───
    // 坑 1：靶机 10ms 空闲超时关连接后 send() 触发 SIGPIPE，直接杀掉 harness，
    // AFL++ 把这个良性载荷记成 crash（文件名 sig:13）。
    printf("\n[T8] SIGPIPE 忽略\n");
    {
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        close(sv[1]);                       // 对端关掉
        errno = 0;
        ssize_t r = send(sv[0], "x", 1, 0); // 不带 MSG_NOSIGNAL，靠 SIG_IGN
        CHECK(r < 0 && errno == EPIPE, "send 到已关闭对端 → EPIPE 而非被信号杀死");
        // 如果 SIGPIPE 没被忽略，上面那行 send 之后根本走不到这里
        CHECK(1, "进程存活到 send() 返回之后（SIGPIPE 已被忽略）");
        close(sv[0]);
    }

    // ─── 收尾：真崩溃后靶机能被拉回来 ───
    printf("\n[T9] 崩溃后自动重启\n");
    {
        start_keepalive(bin, port);
        int up = 0;
        for (int i = 0; i < 60; i++) { if (target_alive()) { up = 1; break; } usleep(20000); }
        CHECK(up == 1, "靶机被打死后能被保活循环拉起");
    }
    kill_target_everything();

    // ─── T10 前缀逐条交付：消息边界必须保住 ───
    // 2026-10-28 踩的坑：前缀一整块 send() 出去，LightFTP 把一次 recv 的整个
    // 缓冲当成【一条】命令 —— USER 的用户名被回显成 "admin\r\nPASS 123456"，
    // PASS 根本没执行，载荷打在未登录会话上（目标命令一律回 530）。更阴的是
    // 这条畸形应答里内嵌 \r\n，recv_lines() 按 '\n' 计数反而数出两行，把一条
    // 畸形应答当成"两条命令都确认了"，于是静默继续 —— state-2 以上的 fuzz
    // 全程跑偏且不报错。所以这里钉的是【发送侧】的性质：
    //     一条命令一次 send，收满一条应答才发下一条。
    // 用 socketpair 直接测，不依赖服务端怎么解析：一旦退回整块发，父进程第一次
    // 读就会同时看到两行，第一条断言立刻挂。也不用真起靶机，没有端口/竞态。
    printf("\n[T10] 前缀逐条交付（消息边界）\n");
    {
        static const char PFX2[] = "USER admin\r\nPASS 123456\r\n";
        int sv[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

        pid_t pid = fork();
        if (pid == 0) {
            // 子进程跑【真代码】，阻塞等应答；超时兜底，免得父进程挂了卡死测试
            set_sock_timeout(sv[0], 2000000);
            char rbuf[256];
            int rc = send_prefix_msgs(sv[0], PFX2, (int)(sizeof(PFX2) - 1),
                                      rbuf, sizeof(rbuf));
            _exit(rc == 0 ? 0 : 1);
        }

        // 父进程扮演靶机：一次读一条报文，回一条应答
        set_sock_timeout(sv[1], 2000000);
        for (int k = 0; k < 2; k++) {
            char got[128];
            size_t used = 0;
            int truncated = 0;
            while (used < sizeof(got) - 1) {
                ssize_t n = recv(sv[1], got + used, 1, 0);
                if (n <= 0) { truncated = 1; break; }
                used += (size_t)n;
                if (got[used - 1] == '\n') break;
            }
            got[used] = '\0';
            const char *want = (k == 0) ? "USER admin\r\n" : "PASS 123456\r\n";
            CHECK(!truncated && strcmp(got, want) == 0,
                  "第 %d 条报文【单独】到达 = %s（实得 %s）",
                  k + 1, want, truncated ? "(超时/断连)" : got);

            // 关键反证：此刻后续报文必须还没到。子进程是收满应答才发下一条的，
            // 所以这里必然读空；若哪天改成整块发，两行会一起到，此检查即挂。
            char peek[64];
            ssize_t extra = recv(sv[1], peek, sizeof(peek), MSG_DONTWAIT);
            CHECK(extra <= 0, "第 %d 条之后无预发报文（边界没被压平）", k + 1);

            const char *reply = (k == 0) ? "331 x\r\n" : "230 y\r\n";
            send(sv[1], reply, strlen(reply), MSG_NOSIGNAL);
        }

        int st = 0;
        waitpid(pid, &st, 0);
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
              "send_prefix_msgs() 逐条收满应答并返回 0");
        close(sv[0]);
        close(sv[1]);
    }

    printf("\n════ 通过 %d  失败 %d ════\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
