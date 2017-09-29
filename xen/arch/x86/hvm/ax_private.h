/*
 * Copyright 2017-2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifdef __x86_64__

/* Errors in this section indicate that struct cpu_user_regs is incompatible with struct ax_cpu_user_regs_v1 */

#define TEST_EQUAL(f, a, b) \
	static uint8_t __attribute__((unused)) cpu_regs_test_ ## f ## _1[ (a) - (b) ]; \
	static uint8_t __attribute__((unused)) cpu_regs_test_ ## f ## _1[ (b) - (a) ]

#define TEST_OFFSET(f) TEST_EQUAL(f, offsetof(struct cpu_user_regs, f), offsetof(struct ax_cpu_user_regs_v1, f))

TEST_OFFSET(r15);
TEST_OFFSET(r14);
TEST_OFFSET(r13);
TEST_OFFSET(r12);
TEST_OFFSET(rbp);
TEST_OFFSET(rbx);
TEST_OFFSET(r11);
TEST_OFFSET(r10);
TEST_OFFSET(r9);
TEST_OFFSET(r8);
TEST_OFFSET(rax);
TEST_OFFSET(rcx);
TEST_OFFSET(rdx);
TEST_OFFSET(rsi);
TEST_OFFSET(rdi);
TEST_OFFSET(error_code);
TEST_OFFSET(entry_vector);
TEST_OFFSET(rip);
TEST_OFFSET(cs);
/*TEST_OFFSET(saved_upcall_mask);*/
TEST_OFFSET(rflags);
TEST_OFFSET(rsp);
TEST_OFFSET(ss);
TEST_OFFSET(es);
TEST_OFFSET(ds);
TEST_OFFSET(fs);
TEST_OFFSET(gs);

#endif
