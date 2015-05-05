/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#pragma once

#define BITS_PER_LONG (IsPtr64() ? 64 : 32)

#define PG_shift(idx)   (BITS_PER_LONG - (idx))
#define PG_mask(x, idx) (x ## ULL << PG_shift(idx))

/* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated    PG_shift(1)
#define PGC_allocated     PG_mask(1, 1)

#define _PGC_xen_page     PG_shift(2)
#define PGC_xen_page      PG_mask(1, 2)

#define PGC_page_table 0
#define _PGC_mapcache     PG_shift(3)
#define PGC_mapcache      PG_mask(1, 3)

#define _PGC_host_page     PG_shift(7)
#define PGC_host_page      PG_mask(1, 7)

/* Mutually-exclusive page states: { host, inuse, free }. */
#define PGC_state         PG_mask(3, 9)
#define PGC_state_host    PG_mask(0, 9)
#define PGC_state_inuse   PG_mask(1, 9)
#define PGC_state_free    PG_mask(2, 9)

#define page_state_is(count_info, st) (((count_info) & PGC_state) == PGC_state_##st)

inline
void pgc2str(ULONG64 ci, char *out, size_t out_size)
{
    out[0] = '\0';
#define chk_set(f) if (ci & (f)) strcat_s(out, out_size, "[" #f "]")
    chk_set(PGC_allocated);
    chk_set(PGC_xen_page);
    chk_set(PGC_mapcache);
    chk_set(PGC_host_page);
    if ((ci & PGC_state) != PGC_state) {
        chk_set(PGC_state_host);
        chk_set(PGC_state_inuse);
        chk_set(PGC_state_free);
    } else
        strcat_s(out, out_size, "<invalid PGC state>");
#undef chk_set
}

