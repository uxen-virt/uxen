/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef WHPX_SHARED_H_
#define WHPX_SHARED_H_

/* memory for shared info page follows hvmloader allocs */
#define WHP_SHARED_INFO_ADDR 0xFC101000

struct whpx_shared_info {
    uint16_t cpu_mhz;
};

#define WHP_CPUID_SIGNATURE_EBX 0x78706857 /* "Whpx" */
#define WHP_CPUID_SIGNATURE_ECX 0x6f6e7369 /* "isno" */
#define WHP_CPUID_SIGNATURE_EDX 0x6e655874 /* "tXen" */

#endif
