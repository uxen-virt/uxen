/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
typedef struct ShallowMapEntry {
    uint64_t start;
    uint32_t size, file_offset;
    uint64_t inode;
    char name[0];
} ShallowMapEntry;

typedef struct ShallowMap {
    ShallowMapEntry **map_entries;
    size_t num_map_entries;
    char map_name[1024];
    char watches_name[1024];
} ShallowMap;

const char *shallow_get_magic(void);
int shallow_check_magic(const char *buf);
int shallow_record_file(ShallowMap *sm, const char *fn, uint64_t inode, off_t aligned_offset, size_t aligned_count, off_t file_offset);
int shallow_flush_map(ShallowMap *sm);
int shallow_init(ShallowMap *sm, const char *map, const char *watches);
