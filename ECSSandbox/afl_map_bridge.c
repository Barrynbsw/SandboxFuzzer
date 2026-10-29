/*
 * afl_map_bridge.c — AFL++ 覆盖率位图访问桥
 *
 * 必须用【普通 cc】编译，【绝不能】用 afl-clang-fast。
 *
 * 原因：AFL++ 的 LLVM pass 会在每个被插桩的模块里创建一个名为
 * `__afl_area_ptr` 的全局量。如果我们在被插桩的 TU 里再写
 * `extern ... __afl_area_ptr`，LLVM 会把其中一个改名成
 * `__afl_area_ptr.N`，链接期就会出现
 *   undefined reference to `__afl_area_ptr.8'
 *
 * 本文件不参与插桩，pass 看不到它，因此可以安全地引用运行时符号，
 * 再以普通函数的形式把访问权交给 harness。
 */

extern unsigned char *__afl_area_ptr;
extern unsigned int   __afl_final_loc;

/* 返回 AFL++ 覆盖率位图基址（未初始化时可能是静态哑数组） */
unsigned char *sbf_afl_area_ptr(void) {
    return __afl_area_ptr;
}

/* 返回位图最大合法下标（用于避免越界写） */
unsigned int sbf_afl_final_loc(void) {
    return __afl_final_loc;
}
