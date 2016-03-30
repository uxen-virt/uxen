/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/page_store.h>
#include <asm/p2m.h>

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(_m) __mfn_to_page(mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))
#undef mfn_valid_page
#define mfn_valid_page(_mfn) __mfn_valid_page(mfn_x(_mfn))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))

#define DSPS_slot(s)                                                    \
    ((((s) + DSPS_slot_data_offset + DSPS_DSIZE - 1) / DSPS_DSIZE) - 1)
#define DSPS_slot_size(slot) (((slot) + 1) * DSPS_DSIZE)
#define DSPS_slot_data_size(slot)                       \
    (DSPS_slot_size(slot) - DSPS_slot_data_offset)
#define DSPS_DSIZE_roundup(s)                           \
    ((s) - (((s) + DSPS_DSIZE - 1) % DSPS_DSIZE) + (DSPS_DSIZE - 1))

void
dsps_init(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int slot;

    BUILD_BUG_ON(sizeof(struct dspage_store) > PAGE_SIZE);
    BUILD_BUG_ON(PAGE_SIZE % DSPS_DSIZE);

    printk(XENLOG_DEBUG "%s: vm%d slots %ld max %ld\n", __FUNCTION__,
           d->domain_id, DSPS_SLOTS, MAX_DSPS_SLOTS);

    p2m->dsps = alloc_xenheap_page();
    BUG_ON(!p2m->dsps);

    for (slot = 0; slot < DSPS_SLOTS; slot++)
        page_store_init(&p2m->dsps->s[slot]);
}

void
dsps_release(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if (p2m->dsps) {
        free_xenheap_page(p2m->dsps);
        p2m->dsps = NULL;
    }
}

void
dsps_add(struct domain *d, uxen_mfn_t vframe,
         void *m_data, uint16_t m_size,
         uint8_t *c_data, uint16_t c_size,
         struct page_info **s_page, uint16_t *s_offset,
         struct page_info **new_page)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    struct dspage_header header = { };
    uint16_t size = m_size + c_size;
    int slot;
    struct page_store *ps;
    uint8_t *data;

    BUILD_BUG_ON(sizeof(header) != DSPS_slot_data_offset);

    slot = DSPS_slot(size);
    ASSERT(slot < DSPS_SLOTS);
    ps = &p2m->dsps->s[slot];

    header.vframe = vframe;

    write_lock(&ps->lock);

    ASSERT(DSPS_slot_data_offset + m_size < DSPS_DSIZE);
    /* is there a current page store page to add the data to?  or is
     * the current page store page full? (full == none of the data
     * would be stored in it) */
    if (page_store_empty(ps) ||
        page_store_offset(ps) + DSPS_slot_data_offset + m_size >
        PAGE_STORE_MAX) {
        page_store_add_page(ps, *new_page);
        *new_page = NULL;
    }

    ASSERT(!(page_store_offset(ps) % DSPS_DSIZE));

    *s_page = page_store_page(ps);
    *s_offset = page_store_offset(ps) + DSPS_slot_data_offset;

    /* store header, meta and as much data as fits in current page */
    data = map_domain_page_direct(__page_to_mfn(page_store_page(ps)));
    memcpy(&data[page_store_offset(ps)], &header, DSPS_slot_data_offset);
    page_store_offset(ps) += DSPS_slot_data_offset;
    memcpy(&data[page_store_offset(ps)], m_data, m_size);
    page_store_offset(ps) += m_size;
    ASSERT(page_store_offset(ps) <= PAGE_STORE_MAX);
    size -= m_size;

    if (page_store_offset(ps) + size > PAGE_STORE_MAX)
        size = PAGE_STORE_MAX - page_store_offset(ps);
    memcpy(&data[page_store_offset(ps)], c_data, size);
    unmap_domain_page_direct(data);
    page_store_offset(ps) += size;

    /* store what didn't fit in new_page page */
    if (size != c_size) {
        perfc_incr(compressed_pages_split);

        /* if the data doesn't fit then we were filling a partial page
         * and mfn/target was not used above */
        ASSERT(*new_page);

        page_store_add_page(ps, *new_page);
        *new_page = NULL;

        data = map_domain_page_direct(__page_to_mfn(page_store_page(ps)));
        memcpy(data, c_data + size, c_size - size);
        unmap_domain_page_direct(data);

        page_store_offset(ps) = c_size - size;
    }

    page_store_offset(ps) = DSPS_DSIZE_roundup(page_store_offset(ps));

    write_unlock(&ps->lock);
}

struct page_info *
dsps_next(struct domain *d, uint16_t size, struct page_info *page)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int slot;
    struct page_store *ps;
    struct page_info *next;

    slot = DSPS_slot(size);
    ASSERT(slot < DSPS_SLOTS);
    ps = &p2m->dsps->s[slot];

    ASSERT(rw_is_locked(&ps->lock));
    next = page_store_next(ps, page);

    return next;
}

int
dsps_teardown(struct domain *d,
              int (*iter)(void *data, uint16_t size, struct domain *d,
                          void *opaque),
              int *processed, void *opaque)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int slot;
    struct page_store *ps;
    struct page_info *page, *next;
    uint8_t *data = NULL;
    uint16_t offset;
    int freed = 0;
    int ret;

    ASSERT(p2m->dsps);

    for (slot = 0; slot < DSPS_SLOTS; slot++) {
        ps = &p2m->dsps->s[slot];

        write_lock(&ps->lock);
        if (page_store_empty(ps)) {
            write_unlock(&ps->lock);
            continue;
        }

        page = page_store_first(ps);
        offset = 0;
        while (page != page_store_page(ps) || offset != page_store_offset(ps)) {
            if (offset >= PAGE_STORE_MAX) {
                unmap_domain_page(data);
                data = NULL;
                offset -= PAGE_STORE_MAX;
                next = page_store_next(ps, page);
                page_store_remove_page(ps, page);
                put_allocated_page(d, page);
                freed++;
                page = next;
                /* re-evaluate end condition */
                continue;
            }
            if (!data)
                data = map_domain_page(__page_to_mfn(page));
            (*processed)++;
            if (iter) {
                ret = iter(&data[offset + DSPS_slot_data_offset],
                           DSPS_slot_data_size(slot), d, opaque);
                if (ret < 0) {
                    write_unlock(&ps->lock);
                    goto out;
                }
            }
            offset += DSPS_slot_size(slot);
        }
        if (data) {
            unmap_domain_page(data);
            data = NULL;
        }
        page_store_remove_page(ps, page);
        put_allocated_page(d, page);
        freed++;
        page_store_clear(ps);
        write_unlock(&ps->lock);
    }

    ret = freed;
  out:
    return ret;
}

void
dsps_lock(struct domain *d, uint16_t size, int take_write_lock)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int slot;
    struct page_store *ps;

    slot = DSPS_slot(size);
    ASSERT(slot < DSPS_SLOTS);
    ps = &p2m->dsps->s[slot];

    if (take_write_lock)
        write_lock(&ps->lock);
    else
        read_lock(&ps->lock);
}

void
dsps_unlock(struct domain *d, uint16_t size, int take_write_lock)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int slot;
    struct page_store *ps;

    slot = DSPS_slot(size);
    ASSERT(slot < DSPS_SLOTS);
    ps = &p2m->dsps->s[slot];

    if (take_write_lock)
        write_unlock(&ps->lock);
    else
        read_unlock(&ps->lock);
}
