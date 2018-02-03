/*
 * Copyright 2017-2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <stdint.h>
#include <malloc.h>
#include <string.h>

const ax_config_node_t *ax_config_tree;
size_t ax_config_len;

static inline void
ax_config_fetch_cpuid (uint64_t *rax, uint64_t *rbx, uint64_t *rcx, uint64_t *rdx)
{
#ifdef __GNUC__
#ifdef __x86_64__
  asm volatile ("cpuid":"+a" (*rax), "=b" (*rbx), "+c" (*rcx),
                "=d" (*rdx)::"cc");
#elif  __i386__
  uint32_t eax = *rax, ebx = *rbx, ecx = *rcx, edx = *rdx;

  asm volatile ("cpuid":"+a" (eax), "=b" (ebx), "+c" (ecx),
                "=d" (edx)::"cc");

  *rax = eax;
  *rbx = ebx;
  *rcx = ecx;
  *rdx = edx;
#else
#error unknown architechture
#endif
#else
  /* No inline assembly in MSVC*/
  int regs[4]; /*MSDN assures me this is int?! */

  __cpuidex (regs, *rax, *rcx);

  *rax = (unsigned) regs[0];
  *rbx = (unsigned) regs[1];
  *rcx = (unsigned) regs[2];
  *rdx = (unsigned) regs[3];
#endif
}


size_t ax_config_fetch_len (void)
{
  uint64_t rcx = 0, rbx = 0, rax = 0, rdx = 0;
  size_t len;

  if (!hv_tests_ax_running())
    return 0;


  rax = AX_CPUID_CONFIG;
  rcx = 0;

  ax_config_fetch_cpuid (&rax, &rbx, &rcx, &rdx);

  len = rcx & 0xffffffff;

  return len;
}

int ax_config_fetch (void *buf, size_t buf_len)
{
  uint64_t rcx = 0, rbx = 0, rax = 0, rdx = 0;
  uint64_t i;
  uint8_t *ptr;
  size_t len;

  len = ax_config_fetch_len();

  if (!len)
    return -1;

  if (len > buf_len)
    return -1;

  for (ptr = buf, i = 0; i < len; i += 0x10) {

    rax = AX_CPUID_CONFIG;
    rcx = i;

    ax_config_fetch_cpuid (&rax, &rbx, &rcx, &rdx);

    memcpy (ptr, &rbx, sizeof (rbx));
    ptr += 0x8;
    memcpy (ptr, &rdx, sizeof (rdx));
    ptr += 0x8;
  }

  return 0;
}

