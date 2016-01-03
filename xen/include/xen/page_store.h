/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _PAGE_STORE_H_
#define _PAGE_STORE_H_

#include <xen/spinlock.h>
#include <asm/mm.h>
#include <asm/page.h>

#define PAGE_STORE_MAX (PAGE_SIZE)

struct page_store
{
    struct page_list_head page_list;
    uint16_t offset;
    rwlock_t lock;              /* lock to prevent moving data in the
                                 * slot while an entry in the slot is
                                 * being accessed */
} __attribute__((packed));

#define page_store_init(store) do {             \
        page_store_clear(store);                \
        rwlock_init(&(store)->lock);            \
    } while (0)
#define page_store_empty(store) (page_list_empty(&(store)->page_list))
#define page_store_clear(store) do {                    \
        INIT_PAGE_LIST_HEAD(&(store)->page_list);       \
        (store)->offset = 0;                            \
    } while (0)

#define page_store_page(store) page_store_last(store)
#define page_store_offset(store) ((store)->offset)

static inline void
page_store_add_page(struct page_store *store, struct page_info *page)
{

    page_list_add_tail(page, &store->page_list);
    store->offset = 0;
}

static inline void
page_store_remove_page(struct page_store *store, struct page_info *page)
{

    page_list_del(page, &store->page_list);
}

static inline struct page_info *
page_store_first(struct page_store *store)
{

    return page_list_first(&store->page_list);
}

static inline struct page_info *
page_store_last(struct page_store *store)
{

    return page_list_last(&store->page_list);
}

static inline struct page_info *
page_store_next(struct page_store *store, struct page_info *page)
{

    return page_list_next(page, &store->page_list);
}

static inline struct page_info *
page_store_prev(struct page_store *store, struct page_info *page)
{

    return page_list_prev(page, &store->page_list);
}

/* ************************ */
/* discrete size page store */

struct dspage_store_info
{
};

#define MAX_DSPS_SLOTS (long)((PAGE_SIZE - sizeof(struct dspage_store_info)) / \
                              sizeof(struct page_store))
/* PAGE_SIZE must be a multiple of this */
#define DSPS_DSIZE 32
#define DSPS_SLOTS ((PAGE_SIZE + DSPS_DSIZE - 1) / DSPS_DSIZE)

#define DSPS_slot_data_offset sizeof(struct dspage_header)
#define DSPS_DSIZE_bytes_used(s)                                        \
    ((s) + DSPS_slot_data_offset -                                      \
     (((s) + DSPS_slot_data_offset - 1) % DSPS_DSIZE) + (DSPS_DSIZE - 1))

struct dspage_store
{
    struct dspage_store_info;
    struct page_store s[DSPS_SLOTS];
};

struct dspage_header
{
    uxen_mfn_t vframe;
};

void dsps_init(struct domain *d);
void dsps_release(struct domain *d);
void dsps_add(struct domain *d, uxen_mfn_t vframe,
              void *m_data, uint16_t m_size,
              uint8_t *c_data, uint16_t c_size,
              struct page_info **page, uint16_t *offset,
              struct page_info **new_page);
struct page_info *dsps_next(struct domain *d, uint16_t size,
                            struct page_info *page);
int dsps_teardown(struct domain *d,
                  int (*iter)(void *data, uint16_t size, struct domain *d,
                              void *opaque),
                  int *comp, void *opaque);
void dsps_lock(struct domain *d, uint16_t size, int take_write_lock);
void dsps_unlock(struct domain *d, uint16_t size, int take_write_lock);

#endif  /* _PAGE_STORE_H_ */
