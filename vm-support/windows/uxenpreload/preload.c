/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>

#include <stdlib.h>
#include <stdio.h>

#include "hook.h"

unsigned int cpuid_base_leaf
    __attribute__ ((section(".shared"), shared)) = 0;

static inline void
cpuid(unsigned int op,
      unsigned int *eax,
      unsigned int *ebx,
      unsigned int *ecx,
      unsigned int *edx)
{
    asm volatile ("cpuid"
                  : "=a" (*eax),
                    "=b" (*ebx),
                    "=c" (*ecx),
                    "=d" (*edx)
                  : "0" (op)
                  : "memory");
}

static unsigned int
get_base_leaf(void)
{
    unsigned int leaf;
    unsigned int eax;
    char signature[13];

    for (leaf = 0x40000000; leaf < 0x40010000; leaf += 0x100) {
        cpuid(leaf, &eax, (unsigned int *)&signature[0],
                          (unsigned int *)&signature[4],
                          (unsigned int *)&signature[8]);
        signature[12] = 0;

        if (!strcmp(signature, "uXenisnotXen"))
            break;
    }

    if (leaf >= 0x40010000 || (eax - leaf) < 2)
        return 0;

    return leaf;
}

static void
get_rand_seed(unsigned char seed[16])
{
    unsigned int a, b, c, d;

    if (!cpuid_base_leaf)
        cpuid_base_leaf = get_base_leaf();

    cpuid(cpuid_base_leaf + 192, &a, &b, &c, &d);

    *(unsigned int *)(seed + 0) = a;
    *(unsigned int *)(seed + 4) = b;
    *(unsigned int *)(seed + 8) = c;
    *(unsigned int *)(seed + 12) = d;
}

static void
scramble_fwd(unsigned char *buf, size_t len, unsigned char key[16])
{
    static size_t kl = 0;
    size_t l = 0;

    while (l < len) {
        buf[l++] ^= key[kl++];
        if (kl == sizeof (key))
            kl = 0;
    }
}

static void
scramble_rev(unsigned char *buf, size_t len, unsigned char key[16])
{
    static size_t kl = sizeof (key);
    size_t l = 0;

    while (l < len) {
        buf[l++] ^= key[--kl];
        if (kl == 0)
            kl = sizeof (key);
    }
}

static struct iat_hook SystemFunction036_hook;

static BOOL WINAPI
hSystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength)
{
    BOOL WINAPI (*origSystemFunction036)(PVOID, ULONG);
    BOOL ret;
    unsigned char seed[16];

    get_rand_seed(seed);
    scramble_rev(RandomBuffer, RandomBufferLength, seed);

    origSystemFunction036 = SystemFunction036_hook.orig_fn;
    ret = origSystemFunction036(RandomBuffer, RandomBufferLength);

    return ret;
}

static struct iat_hook CryptGenRandom_hook;

static BOOL WINAPI
hCryptGenRandom(void *hProv, DWORD dwLen, BYTE *pbBuffer)
{
    BOOL WINAPI (*origCryptGenRandom)(void *, DWORD, BYTE *);
    BOOL ret;
    unsigned char seed[16];

    get_rand_seed(seed);
    scramble_fwd(pbBuffer, dwLen, seed);

    origCryptGenRandom = CryptGenRandom_hook.orig_fn;
    ret = origCryptGenRandom(hProv, dwLen, pbBuffer);

    return ret;
}

BOOL APIENTRY
DllMain(HMODULE module, DWORD reason, void *reserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        iat_hook_init(module);
        iat_hook_add(&SystemFunction036_hook,
                     "cryptbase.dll", "SystemFunction036",
                     hSystemFunction036);
        iat_hook_add(&CryptGenRandom_hook,
                     "cryptsp.dll", "CryptGenRandom",
                     hCryptGenRandom);
        break;

    case DLL_PROCESS_DETACH:
        iat_hook_remove(&SystemFunction036_hook);
        iat_hook_remove(&CryptGenRandom_hook);
        iat_hook_cleanup();
        break;
    }

    return TRUE;
}
