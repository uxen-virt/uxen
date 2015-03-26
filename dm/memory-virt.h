/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef MEMORY_VIRT_H
#define MEMORY_VIRT_H
/* Set cr3 for future va resolution. If cr3==0, get current cr3 from the guest
via libxc. */
uint64_t set_cached_cr3(uint64_t cr3);

/* Read size bytes from guest va to dest. Multiple pages allowed. Optionally
call set_cached_cr3 before use. For now, assumes the guest is in long mode.*/
int virt_read(uint64_t va, void *dest, int size);
#define virt_read_type(x,y) virt_read(x, &(y), sizeof(y))
#endif


