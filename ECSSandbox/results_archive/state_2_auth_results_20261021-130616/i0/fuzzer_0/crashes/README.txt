Command line used to find this crash:

afl-fuzz -i /home/barry/桌面/SandboxFuzzer/ECSSandbox/corpus/state_2_auth/init_shards/0 -o /home/barry/桌面/SandboxFuzzer/ECSSandbox/results/state_2_auth/i0 -M fuzzer_0 -F /home/barry/桌面/SandboxFuzzer/ECSSandbox/work/state_2_auth/0 -t 1000 -- /home/barry/桌面/SandboxFuzzer/ECSSandbox/sandbox_harness

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was 0 B.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please post
to https://github.com/AFLplusplus/AFLplusplus/issues/286 once the issues
 are fixed :)

