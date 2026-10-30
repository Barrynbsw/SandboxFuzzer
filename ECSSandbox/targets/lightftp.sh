#!/bin/bash
#
# targets/lightftp.sh — LightFTP 启动器（靶机适配器的一部分）
#
# 为什么要这个脚本，而不是直接 exec 二进制：
#   上游 main.c 的端口【从配置文件读】（`port=` 那一项），不接受命令行传参。
#   多实例要各占一个端口，就得每实例一份 conf。这里按 $PORT 生成，其余照抄上游。
#
#   这属于「适配器」而不是「改靶机」：LightFTP 源码一个字没动
#   （third_party/lightftp/ 里 `git diff` 为空，可自行核对）。
#
# 用法: lightftp.sh <port>
#
set -e

HERE=$(cd "$(dirname "$0")/.." && pwd)
PORT=${1:?用法: lightftp.sh <port>}

FFTP="$HERE/third_party/lightftp/fftp"
SRC_CONF="$HERE/third_party/lightftp/Source/fftp.conf"
CONF="$HERE/run/fftp_$PORT.conf"
FTP_ROOT="$HERE/run/ftproot_$PORT"

[ -x "$FFTP" ] || { echo "[lightftp] 二进制不存在: $FFTP（先跑 TARGET_BUILD_CMD）" >&2; exit 1; }
[ -f "$SRC_CONF" ] || { echo "[lightftp] 上游配置不存在: $SRC_CONF" >&2; exit 1; }

mkdir -p "$HERE/run" "$FTP_ROOT"
echo "hello from LightFTP sandbox" > "$FTP_ROOT/readme.txt"

# 只改五项，其余原样保留：
#   port          每实例自己的端口
#   logfilepath   上游默认写 /home/user/fftplog，打不开会直接退出 —— 关掉
#   root          FTP 根，指到本实例可写目录
#   [webadmin]→[admin]   让 state_2_auth 的前缀（USER admin / PASS 123456）真能
#                        登进管理态，否则状态推演打到 530，测的不是 S2。
#                        这是【配置】层面的调整，LightFTP 源码仍然零改动。
#   maxusers      10 → 1024，理由见下。同属【配置】层面，源码零改动。
#
# ── maxusers 放大到 1024 的理由（跟靶机失能【不是】一回事）────────────
# 靶机失能的真凶是 ftpmain 从不 pthread_join/detach ftp_client_thread，每个
#   FTP 会话泄漏一个线程的 VMA，攒到 pthread_create 直接 ENOMEM 才罢工
#   （详见 run_state_node.sh 的 SBF_TARGET_TTL 注释）——那件事 maxusers 救不了，
#   2026-10-29 实测 10→1024 失能点一模一样，只能靠定时回收靶机。
#
#   但 maxusers=10 另有一个【独立的】毛病，实测真的会咬到实验：
#   变异出 PASV + LIST/RETR/STOR 却不建数据连接时，worker 卡在无超时的
#   accept()（ftpserv.c:284），client 线程随之卡在 WorkerThreadCleanup 的
#   sleep(2)+pthread_join（ftpserv.c:381），这个会话【占着一个槽两秒】。
#   300 exec/s 下只要 2% 的变异体是这类载荷，就有 ~12 个会话同时活着 →
#   顶穿 maxusers=10，所有新连接收下 "MAXIMUM ALLOWED USERS CONNECTED" 就关。
#   实测 180s 里 p9003 两次 thr=12 + NOSLOTS，每次都白丢若干轮。
#
#   这是实验【混淆变量】：丢轮多少正比于"该臂有多爱生成数据传输载荷"，
#   MIX 臂前缀更深、更容易摸到 PASV/LIST，就会多吃亏 —— 偏向 ISO。
#   放大 maxusers 把这个混淆去掉；各臂同一配置，仍然是机器时间对齐。
#
# 诊断：SBF_FTP_LOG=1 时保留上游日志（writelogentry），可核对登录到底成没成。
if [ -n "${SBF_FTP_LOG:-}" ]; then
    LOG_LINE="logfilepath=$HERE/run/fftp_$PORT.log"
else
    LOG_LINE="#logfilepath 已由适配器关闭"
fi

sed -e "s|^port=.*|port=$PORT|" \
    -e "s|^logfilepath=.*|$LOG_LINE|" \
    -e "s|^root=.*|root=$FTP_ROOT|" \
    -e "s|^\[webadmin\]|[admin]|" \
    -e "s|^pswd=VeryStrongadminpassword222|pswd=123456|" \
    -e "s|^maxusers=.*|maxusers=1024|" \
    "$SRC_CONF" > "$CONF"

exec "$FFTP" "$CONF"
