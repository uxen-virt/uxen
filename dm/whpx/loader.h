/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef WHPX_LOADER_H_
#define WHPX_LOADER_H_

void load_hvmloader(void *membase, uint64_t *start_rip, uint64_t *hvmloader_end);
void load_pmode_trampoline(void *membase, uint64_t jmp_addr);

#endif
