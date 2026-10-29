// tests/poc/real_target.c — "真目标"PoC
//
// 一个【不含任何 SandboxFuzzer 代码、也不碰任何 __afl_* 符号】的 TCP 服务。
// 用来证明覆盖率注入可以做到"零侵入靶机源码"—— 这是接真靶机时唯一现实的做法。
//
// 编译：afl-clang-fast real_target.c -o real_target
// 运行：__AFL_SHM_ID=<私有段号> ./real_target <port>
//
// 注意本文件【不能】extern __afl_area_ptr —— AFL++ 的 LLVM pass 会把插桩模块里
// 的同名引用改名成 __afl_area_ptr.N，导致链接失败（实测 __afl_area_ptr.16）。
// 运行时自己会按 __AFL_SHM_ID 把 __afl_area_ptr 指过去，靶机侧什么都不用做。
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static int classify(const char *cmd) {
    if (!cmd || !*cmd) return 0;
    if (strncmp(cmd, "USER ", 5) == 0) return 1;
    if (strncmp(cmd, "PASS ", 5) == 0) {
        if (strncmp(cmd + 5, "CRASH", 5) == 0) abort();
        return 2;
    }
    if (strncmp(cmd, "STOR ", 5) == 0) {
        if (cmd[5] == 'B' && cmd[6] == 'U' && cmd[7] == 'G') abort();
        return 3;
    }
    if (strncmp(cmd, "HELP", 4) == 0) return 4;
    if (strncmp(cmd, "NOOP", 4) == 0) return 5;
    return 6;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    int port = (argc > 1) ? atoi(argv[1]) : 9701;

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = {.sin_family = AF_INET,
                            .sin_port = htons(port),
                            .sin_addr.s_addr = INADDR_ANY};
    if (bind(ls, (struct sockaddr *)&a, sizeof(a)) < 0) { perror("bind"); return 1; }
    listen(ls, 128);
    fprintf(stderr, "[real_target] port=%d  __AFL_SHM_ID=%s\n",
            port, getenv("__AFL_SHM_ID") ? getenv("__AFL_SHM_ID") : "(none)");

    char buf[1024];
    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) continue;
        struct timeval tv = {.tv_sec = 0, .tv_usec = 10000};
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ssize_t n;
        while ((n = recv(c, buf, sizeof(buf) - 1, 0)) > 0) {
            buf[n] = '\0';
            char *line = buf, *nl;
            while ((nl = strchr(line, '\n')) != NULL) {
                *nl = '\0';
                if (nl > line && nl[-1] == '\r') nl[-1] = '\0';
                int k = classify(line);
                const char *r = k==1 ? "331 name ok\r\n" : k==2 ? "230 logged in\r\n"
                              : k==3 ? "150 storing\r\n"  : k==4 ? "214 help\r\n"
                              : k==5 ? "200 noop ok\r\n"  : "500 unknown\r\n";
                send(c, r, strlen(r), MSG_NOSIGNAL);
                line = nl + 1;
            }
        }
        close(c);
    }
}
