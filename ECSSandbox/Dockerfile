# SandboxFuzzer — 有状态模糊测试沙箱侧镜像
#
# 镜像里装的是「状态同质化 ECS 节点」的完整运行环境：AFL++ 工具链 + 靶机 + harness
# + 种子枢纽。一个容器跑【一个】协议状态（状态同质化原则），要换状态就换容器参数，
# 或在容器里跑 ./switch_state.py。
#
# 构建：  docker build -t sbf-node .
# 跑：    docker run --rm -it sbf-node                          # 默认 state_2_auth，4 实例
#         docker run --rm -it sbf-node state_1_user 3 300       # 指定状态/实例数/时长
#         docker run --rm -it sbf-node ./run_tests.sh            # 跑回归测试
#
# ── 为什么不用 aflplusplus/aflplusplus 当底座 ──────────────────────────
# 那个镜像是最省事的选择（工具链全预装），但它有 2.5GB / 12 层，在受限网络里
# 反复拉不下来（实测多次停在 9/12 层）。这里改成 ubuntu:22.04 + 从源码构建
# AFL++：源码包随仓库走（third_party/AFLplusplus.tar.gz，3MB），构建期只需要
# apt 拉 clang/llvm —— 整条链路小一个数量级，而且不依赖 Docker Hub 上某个
# 特定镜像是否存在。要换回官方底座，把下面 FROM 和 AFL++ 构建段删掉即可。
#
# 注意：AFL++ 需要宿主机放开 core_pattern 才能正确记录崩溃
# （AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 已在启动脚本里设了，容器内不用再配）。

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# ─── 1. 系统依赖 ───
# local_seedhub.py / switch_state.py / replay_judge.py 要 python3；
# fuser 来自 psmisc，ipcrm/ipcs 来自 util-linux —— 少任何一个启动脚本都会中途失败。
# clang / llvm-dev 是给 AFL++ 的 LLVM 模式（afl-clang-fast）用的 ——
# 覆盖率零侵入注入（__AFL_SHM_ID）靠的就是它，没有它整套机制不成立。
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        clang-14 \
        llvm-14 \
        llvm-14-dev \
        python3 \
        psmisc \
        util-linux \
        iproute2 \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# clang-14 装出来的命令带版本号，而 AFL++ 的驱动（afl-cc）默认找 clang/llvm-config
RUN ln -sf /usr/bin/clang-14     /usr/bin/clang \
    && ln -sf /usr/bin/clang++-14  /usr/bin/clang++ \
    && ln -sf /usr/bin/llvm-config-14 /usr/bin/llvm-config

# ─── 2. 从源码构建 AFL++ ───
# make source-only 会编出 afl-clang-fast（LLVM 模式）与 afl-fuzz；
# 编译期不需要联网，源码包就在构建上下文里。
COPY third_party/AFLplusplus.tar.gz /tmp/aflpp.tar.gz
RUN tar xzf /tmp/aflpp.tar.gz -C /tmp \
    && mv /tmp/AFLplusplus-* /tmp/AFLplusplus-src \
    && cd /tmp/AFLplusplus-src \
    && make source-only -j"$(nproc)" \
    && make install \
    && rm -rf /tmp/AFLplusplus-src /tmp/aflpp.tar.gz

# 装到 /usr/local，run_state_node.sh 的 AFLPP_PATH 探测能直接在 PATH 里找到
RUN command -v afl-clang-fast && command -v afl-fuzz

# ─── 3. 真靶机的构建依赖 ───
# LightFTP（third_party/lightftp/，上游未改动）用 GnuTLS 做 FTPS。
# 单独一层放这儿：改它不会作废上面 AFL++ 的编译缓存。
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgnutls28-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /sandbox

# 只拷构建与运行必需的（.dockerignore 已经滤掉运行期产物和 legacy/）
COPY afl_map_bridge.c sandbox_harness.c stateful_server.c ./
COPY run_state_node.sh run_tests.sh switch_state.py local_seedhub.py replay_judge.py ./
COPY targets/ ./targets/
COPY tests/ ./tests/
COPY third_party/ ./third_party/
COPY prefix_analyzer_output/ ./prefix_analyzer_output/

RUN chmod +x run_state_node.sh run_tests.sh switch_state.py local_seedhub.py replay_judge.py \
    && mkdir -p tests/bin

# 预编真靶机：用适配器自己的 TARGET_BUILD_CMD，保证镜像里跑的和节点启动时跑的是同一条命令
RUN bash -c '. targets/lightftp.conf && eval "$TARGET_BUILD_CMD"' \
    && ls -la third_party/lightftp/fftp

# AFL++ 的常规运行期开关。注意【不要】设 AFL_NO_SYNC —— 它会连 -F 投喂一起关掉。
ENV AFL_SKIP_CPUFREQ=1 \
    AFL_NO_UI=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_NO_AFFINITY=1

# 每实例一个靶机端口，默认 4 实例
EXPOSE 9001-9016

ENTRYPOINT ["/sandbox/run_state_node.sh"]
CMD ["state_2_auth", "3", "0"]
