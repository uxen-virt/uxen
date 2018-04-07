/*
 * Copyright 2018, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

typedef struct SwapMapTuple {
    uint32_t end;
    uint32_t size;
    uint32_t file_offset;
    uint32_t name_offset;
#ifdef _WIN32
    uint32_t file_id_highpart;
    uint32_t file_id_lowpart;
#endif
} SwapMapTuple;
