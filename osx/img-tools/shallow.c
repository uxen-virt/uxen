/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "shallow.h"

#define BLOCK_SIZE 0x1000 //XXX

static int map_cmp(const void *a, const void *b)
{
    ShallowMapEntry *pa = *((ShallowMapEntry**) a);
    ShallowMapEntry *pb = *((ShallowMapEntry**) b);

    if (pa->start < pb->start) {
        return -1;
    } else if (pb->start < pa->start) {
        return 1;
    } else return 0;
}

static const char shallow_key[] = "thisIsTheSecretShallow#Stringj082q457q3846y8qnuo!!86gnbdsufgy83623q89t77sdfkjghskdhvnkjyeah.";
const char *shallow_get_magic(void)
{
    return shallow_key;
}

int shallow_check_magic(const char *buf)
{
    int len = sizeof(shallow_key) - 1;
    return !memcmp(buf, shallow_key, len) ? len : 0;
}


int shallow_record_file(ShallowMap *sm, const char *fn, uint64_t inode, off_t aligned_offset,
        size_t aligned_count, off_t file_offset)
{
    /* We keep the list of mapped files in memory, so that we can sort it
     * before writing it to the map.txt file on disk. */

    ShallowMapEntry *m = (ShallowMapEntry*) malloc(sizeof(ShallowMapEntry) + strlen(fn) + 1);

    if (m == NULL) {
        printf("out of memory for map entries!\n");
        return -1;
    }

    m->start = aligned_offset / BLOCK_SIZE;
    m->size = aligned_count / BLOCK_SIZE;
    m->file_offset = file_offset / BLOCK_SIZE;
    strcpy(m->name, fn);

    m->inode = inode;

    /* Is sm->map_entries value a power of two? If so we must double the array. */
    if ((sm->num_map_entries & (sm->num_map_entries - 1)) == 0) {

        size_t n = sm->num_map_entries ? 2 * sm->num_map_entries : 1;

        sm->map_entries = (ShallowMapEntry**)
            realloc(sm->map_entries, sizeof(ShallowMapEntry*) * n);

        if (sm->map_entries == NULL) {
            errx(1, "Out of memory for map entry  pointers");
        }
    }

    sm->map_entries[sm->num_map_entries++] = m;
    return 0;
}

int shallow_init(ShallowMap *sm, const char *map, const char *watches)
{
    strcpy(sm->map_name, map);
    strcpy(sm->watches_name, watches);
    sm->map_entries = NULL;
    sm->num_map_entries = 0;
    return 0;
}

int shallow_flush_map(ShallowMap *sm)
{
    size_t i;
    uint32_t string_offset = 0;

    if (sm->num_map_entries == 0) {
        return 0;
    }

    fprintf(stderr, "write map\n");
             
    FILE *f = fopen(sm->map_name, "wbx");
    if (!f) {
        fprintf(stderr, "warning: unable to write out shallow map to %s\n",
                sm->map_name);
        perror(sm->map_name);
        return -1;
    }

    fprintf(stderr, "write watches in %s\n", sm->watches_name);
    FILE *g = fopen(sm->watches_name, "wbx");
    if (!g) {
        fprintf(stderr, "unable to write file watchlist!\n");
        return -1;
    }

    qsort(sm->map_entries, sm->num_map_entries, sizeof(sm->map_entries[0]), map_cmp);
    fwrite(&sm->num_map_entries, sizeof(uint32_t), 1, f);

    for (i = 0; i < sm->num_map_entries; ++i) {

        ShallowMapEntry *m = sm->map_entries[i];
        uint32_t tuple[4];
        tuple[0] = m->start + m->size; /* index by END not start. */
        tuple[1] = m->size;
        tuple[2] = m->file_offset;
        tuple[3] = string_offset;

        fwrite(tuple, sizeof(tuple), 1, f);
        fprintf(g, "%llu\n", m->inode);

        string_offset += strlen(m->name) + 1;
    }

    for (i = 0; i < sm->num_map_entries; ++i) {
        ShallowMapEntry *m = sm->map_entries[i];
        fwrite(m->name, strlen(m->name) + 1, 1, f);
        free((void*) m);
    }

    free((void*) sm->map_entries);
    fclose(g);
    fclose(f);
    sm->map_entries = NULL;
    sm->num_map_entries = 0;
    return 0;
}

