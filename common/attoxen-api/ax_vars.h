/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "ax_constants.h"
#include "ax_ga_types.h"

#ifdef __GNUC__
#ifdef __x86_64__
static void
ax_vars_cpuid (uint64_t *rax, uint64_t *rbx, uint64_t *rcx, uint64_t *rdx)
{
  asm volatile ("cpuid":"+a" (*rax), "+b" (*rbx), "+c" (*rcx),
                "+d" (*rdx)::"cc");
}
#else
#error unknown or unsupported architechture
#endif
#endif

static int ax_vars_contains_null (const void *_buf, size_t len)
{
  const char *buf = _buf;

  while (len--) if (!* (buf++)) return 1;

  return 0;
}


static void ax_vars_fetch_string (char *buf, size_t len, size_t offset)
{
  uint64_t rax, rbx, rcx, rdx;
  char *ptr = buf;

  len--;

  buf[len] = 0;
  rbx = rdx = 0;

  for (;;) {
    rax = AX_CPUID_GA_READ;
    rcx = offset;
    ax_vars_cpuid (&rax, &rbx, &rcx, &rdx);

    if (len > sizeof (rbx)) {
      memcpy (ptr, &rbx, sizeof (rbx));
      len -= sizeof (rbx);
      ptr += sizeof (rbx);
      offset += sizeof (rbx);
    } else {
      memcpy (ptr, &rbx, len);
      return;
    }


    if (ax_vars_contains_null (&rbx, sizeof (rbx))) return;

    if (len > sizeof (rdx)) {
      memcpy (ptr, &rdx, sizeof (rdx));
      len -= sizeof (rdx);
      ptr += sizeof (rdx);
      offset += sizeof (rdx);
    } else {
      memcpy (ptr, &rdx, len);
      return;
    }

    if (ax_vars_contains_null (&rdx, sizeof (rdx))) return;

  }

}

static void ax_vars_fetch (void *buf, size_t len, size_t offset)
{
  uint64_t rax, rbx, rcx, rdx;
  char *ptr = buf;

  rbx = rdx = 0;

  for (;;) {
    rax = AX_CPUID_GA_READ;
    rcx = offset;
    ax_vars_cpuid (&rax, &rbx, &rcx, &rdx);

    if (len > sizeof (rbx)) {
      memcpy (ptr, &rbx, sizeof (rbx));
      len -= sizeof (rbx);
      ptr += sizeof (rbx);
      offset += sizeof (rbx);
    } else {
      memcpy (ptr, &rbx, len);
      return;
    }

    if (len > sizeof (rdx)) {
      memcpy (ptr, &rdx, sizeof (rdx));
      len -= sizeof (rdx);
      ptr += sizeof (rdx);
      offset += sizeof (rdx);
    } else {
      memcpy (ptr, &rdx, len);
      return;
    }
  }
}


static size_t ax_vars_read_symbol (const char *search, ga_type_t type, void *buf, size_t len, size_t *symbol_len)
{
  char name[1024];
  unsigned i = 0;
  uint64_t rax, rbx, rcx, rdx;

  rbx = rdx = 0;

  for (;;) {
    rax = AX_CPUID_GA_LOOKUP;
    rcx = i++;

    ax_vars_cpuid (&rax, &rbx, &rcx, &rdx);

    if (!rax) return 0;

    if ((AX_GA_TYPE_FAIL_DATA & rax)) continue;

    ax_vars_fetch_string (name, sizeof (name), rbx);

    if (!strcmp (name, search)) {

      if (type != rax) continue;

      if (symbol_len)
        *symbol_len = rdx;

      if (rdx > len)
        rdx = len;

      ax_vars_fetch (buf, rdx, rcx);

      return rdx;
    }
  }

  return 0;
}



