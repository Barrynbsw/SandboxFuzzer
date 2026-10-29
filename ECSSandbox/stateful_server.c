#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/shm.h>

// ─── 协议状态定义 ───
#define STATE_INIT  0   // S0: 未认证态
#define STATE_USER  1   // S1: 已发送用户名，等待密码
#define STATE_AUTH  2   // S2: 已登录，深层数据传输态

// ─── AFL++ 覆盖率共享内存 ───
#define SHM_SIZE 65536
static unsigned char *trace_bits = NULL;

static void setup_shm(void) {
    char *shm_id_str = getenv("TARGET_SHM_ID");
    if (!shm_id_str) return;
    int shmid = atoi(shm_id_str);
    trace_bits = (unsigned char *)shmat(shmid, NULL, 0);
    if (trace_bits == (void *)-1) trace_bits = NULL;
}

static inline void record_cov(unsigned int idx) {
    if (trace_bits) trace_bits[idx % SHM_SIZE]++;
}

void handle_client(int client_fd) {
    int state = STATE_INIT;
    char buf[1024];
    size_t buf_used = 0;

    struct timeval tv = {.tv_sec = 0, .tv_usec = 10000}; // 10ms 超时
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (1) {
        ssize_t n = recv(client_fd, buf + buf_used, sizeof(buf) - buf_used - 1, 0);
        if (n <= 0) {
            // 超时或连接关闭：处理缓冲区中残留的数据
            if (buf_used > 0) {
                buf[buf_used] = '\0';
                // 残留数据处理（简化，只处理一条）
                if (strncmp(buf, "USER ", 5) == 0) {
                    state = STATE_USER;
                    record_cov(0x01);
                    send(client_fd, "331 USER OK\r\n", 13, MSG_NOSIGNAL);
                } else if (state == STATE_USER && strncmp(buf, "PASS ", 5) == 0) {
                    if (strncmp(buf + 5, "CRASH", 5) == 0) {
                        record_cov(0xA0);
                        abort(); // S1 浅层漏洞：PASS CRASH
                    }
                    state = STATE_AUTH;
                    record_cov(0x02);
                    send(client_fd, "230 LOGIN OK\r\n", 14, MSG_NOSIGNAL);
                } else if (state == STATE_AUTH && strncmp(buf, "STOR ", 5) == 0) {
                    if (buf[5] == 'B' && buf[6] == 'U' && buf[7] == 'G') {
                        record_cov(0xB0);
                        abort(); // S2 深层漏洞：STOR BUG
                    }
                    record_cov(0x10);
                    send(client_fd, "200 STOR OK\r\n", 13, MSG_NOSIGNAL);
                } else {
                    record_cov(0xFF);
                    send(client_fd, "500 UNKNOWN CMD\r\n", 17, MSG_NOSIGNAL);
                }
            }
            break;
        }
        buf_used += n;
        buf[buf_used] = '\0';

        char *line_start = buf;
        char *newline;
        while ((newline = strchr(line_start, '\n')) != NULL) {
            *newline = '\0';
            if (newline > line_start && *(newline - 1) == '\r') {
                *(newline - 1) = '\0';
            }

            // ─── S0: 初始未认证态 ───
            if (strncmp(line_start, "USER ", 5) == 0) {
                state = STATE_USER;
                record_cov(0x01);
                send(client_fd, "331 USER OK\r\n", 13, MSG_NOSIGNAL);
            }
            else if (strncmp(line_start, "HELP", 4) == 0) {
                record_cov(0x03);
                send(client_fd, "214 HELP: USER PASS STOR RETR DELE\r\n", 36, MSG_NOSIGNAL);
            }
            else if (strncmp(line_start, "NOOP", 4) == 0) {
                record_cov(0x04);
                send(client_fd, "200 NOOP OK\r\n", 13, MSG_NOSIGNAL);
            }
            // ─── S1: 已发送用户名，等待密码 ───
            else if (state == STATE_USER && strncmp(line_start, "PASS ", 5) == 0) {
                if (strncmp(line_start + 5, "CRASH", 5) == 0) {
                    record_cov(0xA0);
                    abort(); // S1 浅层漏洞
                }
                state = STATE_AUTH;
                record_cov(0x02);
                send(client_fd, "230 LOGIN OK\r\n", 14, MSG_NOSIGNAL);
            }
            else if (state == STATE_USER && strncmp(line_start, "ACCT ", 5) == 0) {
                record_cov(0x05);
                send(client_fd, "200 ACCT OK\r\n", 13, MSG_NOSIGNAL);
            }
            else if (state == STATE_USER && strncmp(line_start, "REIN", 4) == 0) {
                state = STATE_INIT;
                record_cov(0x06);
                send(client_fd, "220 REIN OK\r\n", 13, MSG_NOSIGNAL);
            }
            // ─── S2: 已登录，深层数据传输态 ───
            else if (state == STATE_AUTH && strncmp(line_start, "STOR ", 5) == 0) {
                if (line_start[5] == 'B' && line_start[6] == 'U' && line_start[7] == 'G') {
                    record_cov(0xB0);
                    abort(); // S2 深层漏洞
                }
                record_cov(0x10);
                send(client_fd, "200 STOR OK\r\n", 13, MSG_NOSIGNAL);
            }
            else if (state == STATE_AUTH && strncmp(line_start, "RETR ", 5) == 0) {
                record_cov(0x11);
                send(client_fd, "150 RETR OK\r\n", 13, MSG_NOSIGNAL);
            }
            else if (state == STATE_AUTH && strncmp(line_start, "DELE ", 5) == 0) {
                record_cov(0x12);
                send(client_fd, "250 DELE OK\r\n", 13, MSG_NOSIGNAL);
            }
            else if (state == STATE_AUTH && strncmp(line_start, "MKD ", 4) == 0) {
                record_cov(0x13);
                send(client_fd, "257 MKD OK\r\n", 12, MSG_NOSIGNAL);
            }
            else if (state == STATE_AUTH && strncmp(line_start, "LIST", 4) == 0) {
                record_cov(0x14);
                send(client_fd, "150 LIST OK\r\n", 13, MSG_NOSIGNAL);
            }
            else if (state == STATE_AUTH && strncmp(line_start, "PWD", 3) == 0) {
                record_cov(0x15);
                send(client_fd, "257 \"/\"\r\n", 9, MSG_NOSIGNAL);
            }
            // ─── 未登录态拒绝命令 ───
            else if (state != STATE_AUTH &&
                     (strncmp(line_start, "STOR ", 5) == 0 ||
                      strncmp(line_start, "RETR ", 5) == 0 ||
                      strncmp(line_start, "DELE ", 5) == 0)) {
                record_cov(0x20);
                send(client_fd, "530 NOT LOGGED IN\r\n", 19, MSG_NOSIGNAL);
            }
            // ─── 默认未知命令 ───
            else {
                record_cov(0xFF);
                send(client_fd, "500 UNKNOWN CMD\r\n", 17, MSG_NOSIGNAL);
            }

            line_start = newline + 1;
        }

        if (line_start > buf) {
            buf_used -= (line_start - buf);
            memmove(buf, line_start, buf_used);
            buf[buf_used] = '\0';
        }

        if (buf_used >= sizeof(buf) - 1) {
            buf_used = 0;
            buf[0] = '\0';
        }
    }
    close(client_fd);
}

int main(int argc, char *argv[]) {
    // SIGPIPE 必须忽略：harness 每轮测完就关连接（探测连接更是一触即关），
    // 靶机再往已关闭的连接 send() 响应会被 SIGPIPE 当场杀死，保活循环重启一次
    // 就留下 0.1s 空窗，harness 撞上空窗就会把良性载荷误判成崩溃。
    signal(SIGPIPE, SIG_IGN);

    setup_shm();

    int port = (argc > 1) ? atoi(argv[1]) : 9001;
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port)
    };

    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 128);

    fprintf(stderr, "[stateful_server] Listening on port %d (SHM=%s)\n",
            port, getenv("TARGET_SHM_ID") ? getenv("TARGET_SHM_ID") : "none");

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd >= 0) {
            handle_client(client_fd);
        }
    }
    return 0;
}