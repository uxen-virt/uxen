/*
 * Copyright 2017-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "ax_constants.h"

#define HV_TESTS_FCC(d,c,b,a) ((((uint32_t) (a)) << 24) | (((uint32_t) (b)) << 16) | (((uint32_t) (c)) << 8) | (((uint32_t) (d)) << 0))

#ifdef __GNUC__
#define HV_TESTS_POSSIBLY_UNUSED __attribute__ ((unused))
#ifdef __i386__
#define HV_TESTS_STDCALL __attribute__ ((stdcall))
#else
#define HV_TESTS_STDCALL
#endif
#else
#define HV_TESTS_POSSIBLY_UNUSED
#ifdef __i386__
#define HV_TESTS_STDCALL __stdcall
#else
#define HV_TESTS_STDCALL
#endif
#endif

static void
hv_tests_cpuid (uint64_t *rax, uint64_t *rbx, uint64_t *rcx, uint64_t *rdx)
{
#ifdef __GNUC__
#ifdef __x86_64__
  asm volatile ("cpuid":"+a" (*rax), "+b" (*rbx), "+c" (*rcx),
                "+d" (*rdx)::"cc");
#elif  __i386__
  uint32_t eax = *rax, ebx = *rbx, ecx = *rcx, edx = *rdx;

  asm volatile ("cpuid":"+a" (eax), "+b" (ebx), "+c" (ecx),
                "+d" (edx)::"cc");

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

  __cpuidex (regs, (int) *rax, (int) *rcx);

  *rax = (unsigned) regs[0];
  *rbx = (unsigned) regs[1];
  *rcx = (unsigned) regs[2];
  *rdx = (unsigned) regs[3];
#endif
}

static void hv_tests_cpu_vendor (char *vendor)
{
  uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;

  hv_tests_cpuid (&rax, &rbx, &rcx, &rdx);

  vendor[0] = rbx & 0xff;
  vendor[1] = (rbx >> 8) & 0xff;
  vendor[2] = (rbx >> 16) & 0xff;
  vendor[3] = (rbx >> 24) & 0xff;

  vendor[4] = rdx & 0xff;
  vendor[5] = (rdx >> 8) & 0xff;
  vendor[6] = (rdx >> 16) & 0xff;
  vendor[7] = (rdx >> 24) & 0xff;

  vendor[8] = rcx & 0xff;
  vendor[9] = (rcx >> 8) & 0xff;
  vendor[10] = (rcx >> 16) & 0xff;
  vendor[11] = (rcx >> 24) & 0xff;

  vendor[12] = 0;

}

static int hv_tests_cpu_vendor_is (const char *want)
{
  char is[13], *isptr;
  hv_tests_cpu_vendor (is);

  for (isptr = is ; *want ; ++want, ++isptr)
    if (*want != *isptr) return 0;

  if (*want != *isptr) return 0;

  return 1;
}


static int hv_tests_cpu_is_intel (void)
{
  return hv_tests_cpu_vendor_is ("GenuineIntel");
}

static int hv_tests_cpu_is_amd (void)
{
  return hv_tests_cpu_vendor_is ("AuthenticAMD");
}



HV_TESTS_POSSIBLY_UNUSED static int hv_tests_hyperv_or_xen_faking_hyperv_running (void)
{
  uint64_t rcx = 0, rbx = 0, rax = 0x40000000, rdx = 0;

  hv_tests_cpuid (&rax, &rbx, &rcx, &rdx);

  rbx &= 0xffffffffUL;
  rcx &= 0xffffffffUL;
  rdx &= 0xffffffffUL;

  return ((rbx == HV_TESTS_FCC ('M', 'i', 'c', 'r')) && (rcx == HV_TESTS_FCC ('o', 's', 'o', 'f')) && (rdx == HV_TESTS_FCC ('t', ' ', 'H', 'v')));
}

HV_TESTS_POSSIBLY_UNUSED static int hv_tests_vmware_running (void)
{
  uint64_t rcx = 0, rbx = 0, rax = 0x40000000, rdx = 0;

  hv_tests_cpuid (&rax, &rbx, &rcx, &rdx);

  rbx &= 0xffffffffUL;
  rcx &= 0xffffffffUL;
  rdx &= 0xffffffffUL;

  return ((rbx == HV_TESTS_FCC ('V', 'M', 'w', 'a')) && (rcx == HV_TESTS_FCC ('r', 'e', 'V', 'M')) && (rdx == HV_TESTS_FCC ('w', 'a', 'r', 'e')));
}


HV_TESTS_POSSIBLY_UNUSED static int hv_tests_xen_running (void)
{
  uint64_t rcx = 0, rbx = 0, rax = 0, rdx = 0;
  uint64_t base;


  for (base = 0x40000000; base < 0x40010000; base += 0x100) {
    rax = base;
    rcx = 0;
    rbx = 0;
    rdx = 0;

    hv_tests_cpuid (&rax, &rbx, &rcx, &rdx);

    rbx &= 0xffffffffUL;
    rcx &= 0xffffffffUL;
    rdx &= 0xffffffffUL;

    if ((rbx == HV_TESTS_FCC ('X', 'e', 'n', 'V')) && (rcx == HV_TESTS_FCC ('M', 'M', 'X', 'e')) && (rdx == HV_TESTS_FCC ('n', 'V', 'M', 'M')))
      return 1;
  }

  return 0;
}


HV_TESTS_POSSIBLY_UNUSED static int hv_tests_hyperv_running (void)
{
  uint64_t rcx = 0, rbx = 0, rax = 0x40000000, rdx = 0;

  if (hv_tests_xen_running()) return 0;

  hv_tests_cpuid (&rax, &rbx, &rcx, &rdx);

  rbx &= 0xffffffffUL;
  rcx &= 0xffffffffUL;
  rdx &= 0xffffffffUL;

  return ((rbx == HV_TESTS_FCC ('M', 'i', 'c', 'r')) && (rcx == HV_TESTS_FCC ('o', 's', 'o', 'f')) && (rdx == HV_TESTS_FCC ('t', ' ', 'H', 'v')));
}


HV_TESTS_POSSIBLY_UNUSED static int hv_tests_ax_running (void)
{
  uint64_t rax = AX_CPUID_PRESENCE, rbx = 0, rcx = 0, rdx = 0;

  hv_tests_cpuid (&rax, &rbx, &rcx, &rdx);

  return (rdx == AX_CPUID_PRESENCE_RDX);
}


HV_TESTS_POSSIBLY_UNUSED static int hv_tests_cpu_has_vmx (void)
{

  if (hv_tests_cpu_is_intel()) {
    uint64_t rax = 1, rbx = 0, rcx = 0, rdx = 0;

    hv_tests_cpuid (&rax, &rbx, &rcx, &rdx);
    return !! (rcx & (1UL << 5));
  }

  if (hv_tests_cpu_is_amd()) {
    uint64_t rax = 0x80000001, rbx = 0, rcx = 0, rdx = 0;

    hv_tests_cpuid (&rax, &rbx, &rcx, &rdx);
    return !! (rcx & (1UL << 2));
  }

  return 0;
}

HV_TESTS_POSSIBLY_UNUSED static int hv_tests_cpu_has_nx (void)
{
  uint64_t rax = 0x80000001, rbx = 0, rcx = 0, rdx = 0;

  hv_tests_cpuid (&rax, &rbx, &rcx, &rdx);
  return !! (rdx & (1UL << 20));
}


#ifdef _WIN32
# ifndef _KERNEL_MODE
#  ifndef __UXEN__
#   define HV_TESTS_TEST_WHPX
#   include <windows.h>
#  else
#   undef HV_TESTS_TEST_WHPX
#  endif
# else
#  undef HV_TESTS_TEST_WHPX
# endif
#else
# undef HV_TESTS_TEST_WHPX
#endif

#ifdef HV_TESTS_TEST_WHPX
typedef HV_TESTS_STDCALL HRESULT (hv_tests_whvgetcapability_t) (int , void *, UINT32 , UINT32 *);;

static HRESULT hv_tests_whvgetcapability (int code, void *buffer, uint32_t buffer_size, uint32_t *written_size)
{
  hv_tests_whvgetcapability_t *fn;
  HMODULE whvplatform;
  HRESULT ret = -1;

  whvplatform = LoadLibraryW (L"winhvplatform.dll");

  if (whvplatform)  {

    fn = (hv_tests_whvgetcapability_t *) GetProcAddress (whvplatform, "WHvGetCapability");

    if (fn)
      ret = (*fn) (code, buffer, buffer_size, written_size);
  }

  FreeLibrary (whvplatform);

  return ret;

}

typedef HV_TESTS_STDCALL LONG (hv_tests_rtlgetversion_t) (PRTL_OSVERSIONINFOW);

static LONG hv_tests_rtlgetversion (PRTL_OSVERSIONINFOW version_info)
{
  hv_tests_rtlgetversion_t *fn;
  HMODULE ntdll;
  HRESULT ret = -1;

  ntdll = LoadLibraryW (L"ntdll.dll");

  if (ntdll) {
    fn = (hv_tests_rtlgetversion_t *)  GetProcAddress (ntdll, "RtlGetVersion");

    if (fn)
      ret = (*fn) (version_info);
  }

  FreeLibrary (ntdll);

  return ret;
}

#endif


HV_TESTS_POSSIBLY_UNUSED static int hv_tests_whpx_operational (void)
{
#ifdef HV_TESTS_TEST_WHPX
  int enabled;
  uint64_t cap = 0;

  HRESULT hr;

  hr = hv_tests_whvgetcapability (0 /*WHvCapabilityCodeHypervisorPresent*/, &cap, sizeof (cap), NULL);
  enabled = SUCCEEDED (hr) && (cap != 0);

  return enabled;
#else
  return 0;
#endif
}


HV_TESTS_POSSIBLY_UNUSED static int hv_tests_windows_supports_whp (void)
{
#ifdef HV_TESTS_TEST_WHPX
  RTL_OSVERSIONINFOW v;
  LONG st;

  st = hv_tests_rtlgetversion (&v);

  if (st) return 0;

  if (v.dwMajorVersion < 10) return 0;

  if (v.dwMajorVersion > 10) return 1;

  if (v.dwMinorVersion > 0) return 1;

  if (v.dwBuildNumber >= 18362) return 1;

#endif

  return 0;
}

HV_TESTS_POSSIBLY_UNUSED static int hv_tests_use_whp (void)
{
  if (!hv_tests_hyperv_running()) return 0;

  if (hv_tests_ax_running()) return 0;

  if (!hv_tests_windows_supports_whp()) return 0;

  if (hv_tests_whpx_operational() != 1) return 0;

  return 1;
}
