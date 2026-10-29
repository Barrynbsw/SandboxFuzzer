FROM aflplusplus/aflplusplus:latest

WORKDIR /sandbox

# 拷贝靶机源码、通用 Harness、启动脚本、平台下发数据
COPY stateful_server.c sandbox_harness.c run.sh /sandbox/
COPY prefix_state2.raw /sandbox/
COPY seeds_state2/ /sandbox/seeds_state2/

# 1. 编译靶机（注入覆盖率探针）
RUN afl-clang-fast stateful_server.c -o stateful_server

# 2. 编译通用 Harness 测试桩
RUN afl-clang-fast sandbox_harness.c -o sandbox_harness

RUN chmod +x run.sh

ENTRYPOINT ["/sandbox/run.sh"]