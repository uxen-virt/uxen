/*
 * Copyright 2016, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __USER_VRAM_H__
#define __USER_VRAM_H__

PMDL user_vram_init(PHYSICAL_ADDRESS vram_start, SIZE_T vram_size);

PVOID user_vram_map(PMDL vram_mdl);
void user_vram_unmap(PMDL vram_mdl, PVOID mapped);

#endif //__USER_VRAM_H__
