/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _PAGE_STORE_H_
#define _PAGE_STORE_H_

#include <asm/mm.h>
#include <asm/page.h>

#define PAGE_STORE_MAX (PAGE_SIZE)

struct page_store
{
    struct page_list_head page_list;
    uint16_t offset;
};

#define page_store_empty(store) (page_list_empty(&(store)->page_list))
#define page_store_clear(store) INIT_PAGE_LIST_HEAD(&(store)->page_list)

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

#endif  /* _PAGE_STORE_H_ */
