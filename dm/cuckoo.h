/*
 * Copyright 2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __CUCKOO_H__
#define __CUCKOO_H__

#include <stdint.h>
#include <uuid/uuid.h>

#define CUCKOO_LOG_MAX_VMS 9
#define CUCKOO_MAX_VMS (1<<CUCKOO_LOG_MAX_VMS)
#define CUCKOO_ZERO_BITMAP_SIZE (4<<(30-(12+3))) // bitmap for 4GiB max VM size
#define CUCKOO_NUM_THREADS 4
#define CUCKOO_TEMPLATE_PFN (1ULL << 63ULL)

//#define CUCKOO_VERIFY

#ifdef _WIN32
typedef HANDLE cuckoo_handle_t;
#else
typedef int cuckoo_handle_t;
#endif

struct filebuf;
struct page_fingerprint;

enum cuckoo_page_type {
    cuckoo_page_delta = 0,
    cuckoo_page_ref_template,
    cuckoo_page_ref_shared,
    cuckoo_page_ref_local,
};

struct cuckoo_page_common {
    uint16_t vm : CUCKOO_LOG_MAX_VMS; \
    uint32_t pfn : 21;                \
    uint16_t size : 13;               \
    uint16_t rotate : 10;             \
    enum cuckoo_page_type type : 2;   \
    uint16_t is_stable : 1;
} __attribute__((__packed__));

struct cuckoo_page_ext {
    uint64_t hash;
    uint32_t offset;
} __attribute__((__packed__));

struct cuckoo_page {
    struct cuckoo_page_common c;
    struct cuckoo_page_ext x;
} __attribute__((__packed__));

struct cuckoo_page_delta {
    struct cuckoo_page_common c;
} __attribute__((__packed__));

static inline const struct cuckoo_page *
nextc(const struct cuckoo_page *p)
{
    size_t sz = p->c.type ? sizeof(struct cuckoo_page) :
                            sizeof(struct cuckoo_page_delta);
    return (const struct cuckoo_page *) (((const uint8_t *) p) + sz);
}

static inline struct cuckoo_page *
next(struct cuckoo_page *p)
{
    return (struct cuckoo_page *) nextc(p);
}

static inline int
is_delta(const struct cuckoo_page *p)
{
    return p->c.type == cuckoo_page_delta;
}

static inline int
is_shared(const struct cuckoo_page *p)
{
    return p->c.type == cuckoo_page_ref_shared;
}

static inline int
is_local(const struct cuckoo_page *p)
{
    return p->c.type == cuckoo_page_ref_local;
}

static inline int
is_template(const struct cuckoo_page *p)
{
    return p->c.type == cuckoo_page_ref_template;
}

struct cuckoo_vm {
    int present;
    uuid_t uuid;
};

struct cuckoo_shared {
    int num_pages;
    uint32_t space_used;
    uint32_t pin_brk;
    struct cuckoo_vm vms[CUCKOO_MAX_VMS];
    int needs_gc;
    uint64_t version; // must be right before pages array
    struct cuckoo_page pages[0];
};

struct cuckoo_context {
    cuckoo_handle_t shared_handle[2];
    cuckoo_handle_t pin_handle;
    /* Mutexes must be taken in below order. */
    uint32_t pinned_metadata[2], pinned_data;

    /* Only valid between enter() and leave(). */
    const struct cuckoo_shared *passive;
    uint8_t *pin;
    /* Only valid between prepare() and commit(). */
    struct cuckoo_shared *active;
};

enum cuckoo_mutex_type {
    cuckoo_mutex_write = 0,
    cuckoo_mutex_read,
    cuckoo_num_mutexes,
};

enum cuckoo_section_type {
    cuckoo_section_idx0 = 0,
    cuckoo_section_idx1,
    cuckoo_section_pin,
    cuckoo_num_sections,
};

typedef int (*cancelled_callback) (void *);
typedef void* (*map_section_callback) (void *, enum cuckoo_section_type,
                                       size_t);
typedef void (*unmap_section_callback) (void *, enum cuckoo_section_type);
typedef void (*reset_section_callback) (void *, void *, size_t);
typedef void (*pin_section_callback) (void *, enum cuckoo_section_type,
                                      size_t);
typedef int (*capture_pfns_callback) (void *, int, int, void *, uint64_t *);
typedef void* (*get_buffer_callback) (void *, int, int *);
typedef int (*populate_pfns_callback) (void *, int, int, uint64_t *);
typedef void* (*malloc_callback) (void *, size_t );
typedef void (*free_callback) (void *, void *);
typedef int (*lock_callback) (void *, enum cuckoo_mutex_type);
typedef void (*unlock_callback) (void *, enum cuckoo_mutex_type);
typedef int (*is_alive_callback) (void *, const uuid_t);

struct cuckoo_callbacks {
    cancelled_callback cancelled;
    map_section_callback map_section;
    unmap_section_callback unmap_section;
    reset_section_callback reset_section;
    pin_section_callback pin_section;
    capture_pfns_callback capture_pfns;
    get_buffer_callback get_buffer;
    populate_pfns_callback populate_pfns;
    malloc_callback malloc;
    free_callback free;
    lock_callback lock;
    unlock_callback unlock;
    is_alive_callback is_alive;
};

int cuckoo_init(struct cuckoo_context *cc);
int cuckoo_compress_vm(struct cuckoo_context *cc, uuid_t uuid,
                       struct filebuf *fb,
                       int num_template, struct page_fingerprint *tfps,
                       int n, struct page_fingerprint *pages_info,
                       struct cuckoo_callbacks *ccb, void *opaque);

int cuckoo_reconstruct_vm(struct cuckoo_context *cc, uuid_t uuid,
                          struct filebuf *fb, int reusing_vm,
                          struct cuckoo_callbacks *ccb, void *opaque);

/* Simple API. */
int cuckoo_compress_vm_simple(struct filebuf *fb,
                              int na, struct page_fingerprint *a,
                              int nb, struct page_fingerprint *b,
                              struct cuckoo_callbacks *ccb, void *opaque);
int cuckoo_reconstruct_vm_simple(struct filebuf *fb, int reusing_vm,
                                 struct cuckoo_callbacks *ccb, void *opaque);

#endif /* __CUCKOO_H__ */
