/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __COPYBUFFER_H__
#define __COPYBUFFER_H__

#include "hashtable.h"

#define COPYBUFFER_CACHEUNIT 0x1000000ULL
#define COPYBUFFER_LOGLINES 8 /* Log2(cache size) */
#define COPYBUFFER_INNERNODES ((1<<COPYBUFFER_LOGLINES)-1)
#define COPYBUFFER_NUM_OVERLAPPING 128

typedef struct COPY {
    uint64_t from;
    uint64_t to;
    uint64_t size;
} COPY;

typedef struct COPYBUFFERCACHELINE {
    uint32_t page;
    uint32_t locked;
    int dirty;
    DUBTREE_FILE_HANDLE file;

} COPYBUFFERCACHELINE;

typedef struct COPYBUFFER {

    size_t n;
    size_t max;
    size_t offset;
    int temp; /* Open files in temp mode if supported by OS. */
    uint8_t *mem;
    uint8_t *dst; /* Copy destination if flushing to mem. */
    uint64_t limit; /* End of permanently mapped region. */
    char *filePrefix;
    char **fallbacks;
    COPY *heap;

    /* Cache of mapped views */
    HashTable cacheIndex;
    char bits[COPYBUFFER_INNERNODES];
    COPYBUFFERCACHELINE lines[1<<COPYBUFFER_LOGLINES];

#ifdef _WIN32
    OVERLAPPED ovl[COPYBUFFER_NUM_OVERLAPPING];
    HANDLE events[COPYBUFFER_NUM_OVERLAPPING];
    HANDLE files[COPYBUFFER_NUM_OVERLAPPING];
    uint64_t sizes[COPYBUFFER_NUM_OVERLAPPING];
    unsigned int idx;
#endif
    int broken;    /* remembers fatal errors. */

} COPYBUFFER;

int copyBufferInit(COPYBUFFER *cb, size_t max, char *filePrefix,
        char **fallbacks, uint64_t offset, void *mem, uint64_t limit, int temp);

void copyBufferRelease(COPYBUFFER *cb);
void copyBufferStart(COPYBUFFER *cb, void *dst);
void copyBufferInsert(COPYBUFFER *cb, uint64_t from, uint64_t to, size_t size);
int copyBufferFlush(COPYBUFFER *cb);
void copyBufferForget(COPYBUFFER *cb, uint64_t start, uint64_t end);
void copyBufferNuke(COPYBUFFER *cb, uint64_t end);

#endif /* __COPYBUFFER_H__ */
