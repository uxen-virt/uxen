/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _SG_H_
#define _SG_H_

typedef struct sg_entry {
    uint64_t base;
    uint64_t len;
    void (*completion_cb)(struct sg_entry *entry, void *opaque);
    void *opaque;
} ScatterGatherEntry;

typedef void (*SGEntryCompletion)(ScatterGatherEntry *, void *);

typedef struct {
    ScatterGatherEntry *sg;
    int nsg;
    int nalloc;
    uint64_t size;
} SGList;

void sglist_init(SGList *qsg, int alloc_hint);
void sglist_add(SGList *qsg, uint64_t base, uint64_t len);
void sglist_add_completion(SGList *qsg, uint64_t base, uint64_t len,
                           SGEntryCompletion cb, void *opaque);
void sglist_destroy(SGList *qsg);

#endif	/* _SG_H_ */
