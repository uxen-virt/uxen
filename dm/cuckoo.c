/*
 * Copyright 2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include "debug.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <uuid/uuid.h>
#include <fingerprint.h>
#include <lz4.h>
#include <lz4hc.h>

#include "cuckoo.h"
#include "filebuf.h"
#include "thread-event.h"

#define PAGE_SIZE 0x1000 /* You knew it */

#ifndef QEMU_UXEN
#define debug_printf printf
#endif

static const size_t idx_size = (128 << 20);
static const size_t pin_size = (128 << 20);

#ifdef _WIN32
static inline double rtc(void)
{
    LARGE_INTEGER time;
    LARGE_INTEGER freq;
    double t;

    QueryPerformanceCounter(&time);
    QueryPerformanceFrequency(&freq);

    t = ((double)time.LowPart) / ((double)freq.LowPart);
    return t;
}

#else
#include <sys/time.h>
#include <sys/mman.h>

static inline double rtc(void)
{
    struct timeval time;
    gettimeofday(&time,0);
    return ( (double)(time.tv_sec)+(double)(time.tv_usec)/1e6f );
}

#endif

static void open_mappings(struct cuckoo_context *cc,
                          struct cuckoo_callbacks *ccb, void *opaque)
{
    /* Must be called with read_mutex held. */
    struct cuckoo_shared *a, *b;
    cc->pin = ccb->map_section(opaque, cuckoo_section_pin, pin_size);
    a = ccb->map_section(opaque, cuckoo_section_idx0, idx_size);
    b = ccb->map_section(opaque, cuckoo_section_idx1, idx_size);

    if (a->version > b->version) {
        cc->passive = a;
        cc->active = b;
    } else {
        cc->passive = b;
        cc->active = a;
    }

    ccb->pin_section(opaque, cuckoo_section_pin, cc->active->pin_brk);
}

static void close_mappings(struct cuckoo_context *cc,
                           struct cuckoo_callbacks *ccb, void *opaque)
{
    enum cuckoo_section_type t;
    for (t = 0; t < cuckoo_num_sections; ++t) {
        ccb->unmap_section(opaque, t);
    }
    cc->active = NULL;
    cc->passive = NULL;
    cc->pin = NULL;
}


static void
prepare(struct cuckoo_context *cc)
{
    struct cuckoo_shared tmp = *cc->passive;
    tmp.version = 0;
    *cc->active = tmp;
}

static void
commit(struct cuckoo_context *cc, struct cuckoo_callbacks *ccb, void *opaque)
{
    struct cuckoo_shared *tmp;
    cc->active->version = cc->passive->version + 1;
    debug_printf("commit %"PRIx64"\n", cc->active->version);
    tmp = cc->active;
    cc->active = (struct cuckoo_shared *)cc->passive;
    cc->passive = tmp;
    ccb->reset_section(opaque, cc->active, idx_size);
    __sync_synchronize();
}

/* Because of the nature of the input, even LZ4-compressed data has lots
 * (17-20%) of zero bytes, so encode these as the set bits in a compressed
 * bitmap for 6-7% extra space savings. */
static inline
int zero_encode(uint8_t *out, const uint8_t *in, size_t sz)
{
    int i, j;
    uint8_t c;
    uint8_t byte;
    int count;
    uint8_t *o = out + sizeof(uint16_t);
    uint8_t bm[PAGE_SIZE];
    uint8_t last = 0;
    int set;

    for (i = j = count = byte = 0; i < sz; ++i) {

        c = in[i];
        if (c) {
            *o++ = c;
            set = 0;
        } else {
            set = 1;
        }

        if (byte) {
            if (count == 7) {
                last = bm[j++] = 0x80 | byte;
                count = 0;
                byte = 0;
            }
        } else if ((set && count > 6) || count == 127) {
            /* A single set bit between two unset ranges is often redundant. */
            if (last == 0xc0 && count < 120 && j >= 2 && bm[j - 2] < 127) {
                --j;
                count += 6;
            }
            last = bm[j++] = count;
            count = 0;
        }

        byte = (byte << 1) | set;
        ++count;
    }

    if (byte) {
        bm[j++] = 0x80 | (byte << (7 - count));
    } else if (count) {
        bm[j++] = count;
    }

    if ((o + j) - out < sz) {
        *((uint16_t *) out) = j;
        memcpy(o, bm, j);
        return (o + j) - out;
    } else {
        *((uint16_t *) out) = 0;
        memcpy(out + sizeof(uint16_t), in, sz);
        return sz + sizeof(uint16_t);
    }

}

static inline
size_t zero_decode(uint8_t *out, const uint8_t *in, size_t sz)
{
    int i, j;
    size_t bsz = *((uint16_t *) in);

    if (!bsz) {
        memcpy(out, in + sizeof(uint16_t), sz - sizeof(uint16_t));
        return sz - sizeof(uint16_t);
    }

    const uint8_t *bm = in + (sz - bsz);
    uint8_t *o = out;
    sz -= bsz;

    for (i = 0, j = sizeof(uint16_t); i < bsz; ++i) {

        int k;
        uint8_t b = bm[i];
        if (b & 0x80) {
            for (k = 0; k < 7; ++k) {
                b <<= 1;
                if (b & 0x80) {
                    *o++ = 0;
                } else if (j < sz) {
                    *o++ = in[j++];
                }
            }
        } else {
            if (i >= 1 && bm[i - 1] < 127) {
                /* Single set bit implied by surrounding zero ranges. */
                *o++ = 0;
            }
            for (k = 0; k < b && j < sz; ++k) {
                *o++ = in[j++];
            }
        }
    }
    return o - out;
}

static inline
size_t compress(void *out, const void *in, size_t in_sz, int high)
{
    /* Caller has allocated ample space for compression overhead, so we don't
     * worry about about running out of space. However, there is no point in
     * storing more than PAGE_SIZE bytes, so if we exceed that we
     * revert to a straight memcpy(). When uncompressing we treat PAGE_SIZE'd
     * pages as special, and use memcpy() there as well. */

    uint8_t tmp[2 * PAGE_SIZE];
    size_t sz = high ?
        LZ4_compressHC((const char *)in, (char *) tmp, in_sz) :
        LZ4_compress((const char *)in, (char *) tmp, in_sz);

    if (sz + 2 >= PAGE_SIZE) {
        memcpy(out, in, PAGE_SIZE);
        return PAGE_SIZE;
    } else {
        return zero_encode(out, tmp, sz);
    }
}

static inline
int expand(void *out, const void *in, size_t sz)
{
    if (sz == PAGE_SIZE) {
        memcpy(out, in, sz);
    } else {
        uint8_t tmp[PAGE_SIZE];
        size_t lz4_sz = zero_decode(tmp, in, sz);

        int unsz = LZ4_decompress_safe((const char *)tmp, (char *)out,
                                       lz4_sz, PAGE_SIZE);

        if (unsz < 0) {
            debug_printf("%s: %d\n", __FUNCTION__, unsz);
            return -1;
        }
        memset(out + unsz, 0, PAGE_SIZE - unsz);
    }
    return 0;
}

static inline
size_t diff(void *_out, const void *_base, const void *_version,
        int rotate)
{
    uint32_t *out = _out;
    const uint32_t *base = _base;
    const uint32_t *version = _version;
    const int n = PAGE_SIZE / sizeof(uint32_t);
    const int mask = n - 1;
    int i, j;
    for (i = j = 0; i < n; ++i) {
        uint32_t xor = out[i] =
            base[i] ^ version[(i + rotate) & mask];
        j = xor ? (1 + i) : j;
    }
    return sizeof(uint32_t) * j;
}

static inline
void undiff_32(void *_out, const void *_delta)
{
    uint32_t *out = _out;
    const uint32_t *delta = _delta;
    int i;
    for (i = 0; i < PAGE_SIZE / sizeof(delta[0]); ++i) {
        out[i] ^= delta[i];
    }
}

static inline
void undiff_64(void *_out, const void *_delta)
{
    uint64_t *out = _out;
    const uint64_t *delta = _delta;
    int i;
    for (i = 0; i < PAGE_SIZE / sizeof(delta[0]); ++i) {
        out[i] ^= delta[i];
    }
}

static inline
void undiff(void *_out, const void *_delta)
{
    if (sizeof(void *) == 8) {
        undiff_64(_out, _delta);
    } else {
        undiff_32(_out, _delta);
    }
}

static inline
void copy(void *_out, const void *_in, int rotate)
{
    uint32_t *out = _out;
    const uint32_t *in = _in;

    int i;
    for (i = 0; i < PAGE_SIZE / sizeof(uint32_t); ++i) {
        out[i] = in[(i + rotate) % (PAGE_SIZE / sizeof(uint32_t))] ;
    }
}

static void vm_presence_map(struct cuckoo_shared *s, uuid_t exclude,
                            uint8_t *present,
                            int *needs_gc,
                            struct cuckoo_callbacks *ccb, void *opaque)
{
    int i;
    memset(present, 0, CUCKOO_MAX_VMS);

    for (i = 1; i < CUCKOO_MAX_VMS; ++i) {
        struct cuckoo_vm *cvm = &s->vms[i];
        if (cvm->present && memcmp(cvm->uuid, exclude, sizeof(cvm->uuid))) {
            int p = ccb->is_alive(opaque, cvm->uuid);
            present[i] = cvm->present = p;
            if (!p) {
                *needs_gc = 1;
            }
        }
    }
}

struct work_unit { /* A unit of work. */
    int n;
    int start;
    int size;
    struct cuckoo_page *ref;
    struct cuckoo_page *p;
};

static inline
int valid_u(struct work_unit *u)
{
    return (u->ref != NULL);
}

static inline
struct work_unit *grow_us(struct work_unit *us, int n,
                          struct cuckoo_callbacks *ccb, void *opaque)
{
    if (!((n - 1) & n)) {
        struct work_unit *u;
        u = (struct work_unit *) ccb->malloc(opaque, sizeof(us[0]) *
                                             (n ? 2 * n : 1));
        if (us) {
            memcpy(u, us, sizeof(us[0]) * n);
            ccb->free(opaque, us);
        }
        return u;
    } else {
        return us;
    }
}

/* Create access plan for compressing or reconstructing a VM. */
static struct work_unit *create_plan(
        uint32_t vm,
        struct cuckoo_page *pages,
        int num_pages,
        int include_unstable,
        struct cuckoo_callbacks *ccb, void *opaque)
{
    int i;
    struct cuckoo_page *ref = NULL;
    struct cuckoo_page *p;
    struct work_unit *us = NULL;
    struct work_unit *u = NULL;

    /* NOTE
     *
     * We cannot assume that there is only going to be one ref per stretch of
     * identical hashes, because of how we promote later ones to be refs and
     * live in the pin.  Therefore, a simple hash-has-changed check is not
     * sufficient to track the location of the most recent ref. */

    for (i = 0, p = pages; p != pages + num_pages; ++p) {
        if (!p->is_stable && !include_unstable) {
            continue;
        }
        if (is_shared(p) || is_template(p) || (is_local(p) && p->vm ==vm)) {
            ref = p;
        }
        if (p->vm == vm) {
            if (ref) {
                us = grow_us(us, i, ccb, opaque);
                if (!us) {
                    return NULL;
                }
                u = &us[i];
                u->ref = ref;
                u->n = 0;
                u->start = -1;
                u->size = 0;
                u->p = p;
                ref = NULL;
                ++i;
            }
            u->n++;

            if (!is_shared(p) && !is_template(p) && p->size) {
                if (u->start == -1) {
                    u->start = p->offset;
                }
                u->size += p->size;
            }
        }
    }
    us = grow_us(us, i + 1, ccb, opaque);
    if (us) {
        us[i].ref = NULL;
    }
    return us;
}

/* Merge a hash-sorted array of new pages into the array of existing ones. */
int merge(struct cuckoo_page *out,
          const struct cuckoo_page *a, int na,
          const struct cuckoo_page *b, int nb,
          const uint8_t *present,
          struct cuckoo_callbacks *ccb, void *opaque)
{
    struct cuckoo_page *r = out;
    const struct cuckoo_page *end_a = a + na;
    int i;
    struct cuckoo_page *ref = NULL;
    const struct cuckoo_page *rescue = NULL;

    for (i = 0; a != end_a || i < nb; ) {
        /* Merge a before b if a <= b. */
        if (a != end_a && (i == nb || a->hash <= b[i].hash)) {
            /* Elide pages belonging to dead VMs, but keep a door open should
             * they get referenced later. */
            if  (!a->is_stable) {
                ++a;
                continue;
            } else if (!is_template(a)) {
                if (!present[a->vm]) {
                    if (is_shared(a)) {
                        rescue = a;
                    }
                    ++a;
                    continue;
                } else {
                    if (rescue && rescue->hash == a->hash) {
                        ref = r++;
                        *ref = *rescue;
                        ref->vm = 0;
                        rescue = NULL;
                    }
                }
            }

            if (!is_delta(a)) {
                ref = r;
            }
            *r = *a++;
        } else {
            /* Consume min from b. */
            *r = b[i];

            if (ref && ref->hash == r->hash) {
                if (ref->type == cuckoo_page_ref_local) {
                    /* r will be the new ref, but the existing one will still
                     * be kept around, because it refers to pages on disk that
                     * we cannot get to and re-encode. */
                    r->type = cuckoo_page_ref_shared;
                }
            } else {
                if (i == 0 || b[i - 1].hash != b[i].hash) {
                    r->type = cuckoo_page_ref_local;
                }
            }
            ref = NULL;
            ++i;
        }
        ++r;
    }

    return r - out;
}

const int num_slots = 32;
struct io_slot {
    thread_event metadata_ready, data_ready, processed;
    uint8_t *buffer;
    struct work_unit *first, *last;
    int start;
    int end;
    int done;
#ifdef _WIN32
    OVERLAPPED o;
#endif
};

struct thread_context {
    struct cuckoo_context *cc;
    struct filebuf *fb;
    struct cuckoo_callbacks *ccb;
    void *opaque;
    volatile int *idx;
    struct io_slot *slots;
    int tid;
    int reusing_vm;
};

#ifdef CUCKOO_VERIFY
static uint64_t strong_hash(const void *_p)
{
    const uint16_t *page = _p;
    uint64_t hash = 5381;
    int i;
    for (i = 0; i < PAGE_SIZE / sizeof(page[0]); ++i) {
        hash = ((hash << 5ULL) + hash) + page[i];
    }
    return hash;
}
#endif

static inline void
compress_range(struct thread_context *c, struct work_unit *u, uint8_t **src,
               uint8_t *buffer, uint32_t *buffer_offset)
{
    struct cuckoo_context *cc = c->cc;
    struct cuckoo_page *ref = u->ref;
    uint8_t b[PAGE_SIZE];
    uint8_t *base;
    uint8_t tmp[2* PAGE_SIZE];
    int skip = 0;

    if (is_template(ref)) {
        base = *src;
        *src += PAGE_SIZE;
    } else if (is_shared(ref)) {
        if (ref->is_stable) {
            if (ref->size) {
                if (expand(b, cc->pin + ref->offset, ref->size) < 0) {
                    debug_printf("expand failed line=%d\n", __LINE__);
                    assert(0);
                }
                base = b;
            } else {
                base = NULL;
            }
        } else {
            ref->size = compress(tmp, *src, PAGE_SIZE, 1);
            ref->offset = __sync_fetch_and_add(&cc->active->pin_brk,
                                               ref->size);
            if (ref->offset + ref->size < pin_size) {
                memcpy(cc->pin + ref->offset, tmp, ref->size);
            } else {
                memcpy(buffer + *buffer_offset, tmp, ref->size);
                ref->offset = *buffer_offset;
                *buffer_offset += ref->size;
                ref->type = cuckoo_page_ref_local;
            }

#ifdef CUCKOO_VERIFY
            ref->strong_hash = strong_hash(*src);
#endif
            ref->is_stable = 1;
            base = *src;
            *src += PAGE_SIZE;
            skip = 1;
        }
    } else {
        base = NULL;
    }

    int k;
    for (k = skip; k < u->n; ++k, *src += PAGE_SIZE) {
        struct cuckoo_page *p = u->p + k;
#ifdef CUCKOO_VERIFY
        p->strong_hash = strong_hash(*src);
#endif
        size_t sz0;
        uint8_t *t;
        if (base != NULL) {
            sz0 = diff(tmp, base, *src, p->rotate - ref->rotate);
            t = tmp;
        } else {
            /* No point actually XORing with zero page. */
            assert(ref->rotate == p->rotate);
            sz0 = PAGE_SIZE;
            t = *src;
        }
        if (sz0) {
            p->size = compress(buffer + *buffer_offset, t, sz0, 0);
            p->offset = *buffer_offset;
            *buffer_offset += p->size;
        } else {
            p->size = 0;
            assert(p->type == cuckoo_page_delta);
            p->type = cuckoo_page_delta;
            p->offset = 0;
        }
        p->is_stable = 1;

        if (p == ref) {
            base = *src;
        }
    }
}

#ifdef _WIN32
static DWORD WINAPI
#else
static void *
#endif
decompression_thread(void *_c)
{
    struct thread_context *c = _c;
    struct cuckoo_callbacks *ccb = c->ccb;
    void *opaque = c->opaque;
    uint64_t *template_pfns;
    uint64_t *pfns;
    uint8_t *template_pages, *t;
    uint8_t *pages;
    struct work_unit *u;
    int max;
    int i, j;

    pages = ccb->get_buffer(opaque, c->tid, &max);
    pfns = ccb->malloc(opaque, sizeof(pfns[0]) * max);

    for (;;) {
        int idx = __sync_fetch_and_add(c->idx, 1);
        int num_tpfns = 0;
        idx %= num_slots;
        struct io_slot *s = &c->slots[idx];

        thread_event_wait(&s->metadata_ready);
        if (s->done) {
            thread_event_set(&s->processed);
            break;
        }

        for (u = s->first, num_tpfns = 0; u != s->last; ++u) {
            if (is_template(u->ref)) {
                ++num_tpfns;
            }
        }

        template_pfns = ccb->malloc(opaque, sizeof(template_pfns[0]) *
                                    num_tpfns);
        template_pages = ccb->malloc(opaque, PAGE_SIZE * num_tpfns);

        for (u = s->first, num_tpfns = 0; u != s->last; ++u) {
            if (is_template(u->ref)) {
                template_pfns[num_tpfns++] = u->ref->pfn | CUCKOO_TEMPLATE_PFN;
            }
        }

        ccb->capture_pfns(opaque, c->tid, num_tpfns, template_pages,
                          template_pfns);

        if (s->start != s->end) {
            thread_event_wait(&s->data_ready);
#ifdef _WIN32
            DWORD got;
            if (!GetOverlappedResult(c->fb->file, &s->o, &got, FALSE)) {
                Wwarn("GetOverlappedResult failed line=%d", __LINE__);
                assert(0);
            }
#endif
        }

        for (u = s->first, i = j = 0, t = template_pages; u != s->last; ++u) {

            const struct cuckoo_page *ref = u->ref;
            uint8_t b[PAGE_SIZE];
            uint8_t *base;

            if (is_template(ref)) {
                base = t;
                t += PAGE_SIZE;
            } else if (ref->size) {
                void *src;
                if(is_shared(ref)) {
                    src = c->cc->pin + ref->offset;
                } else {
                    src = s->buffer + ref->offset - s->start;
                }

                if (expand(b, src, ref->size) < 0) {
                    debug_printf("failed to expand from %s!\n",
                                 is_shared(ref) ? "pin" : "file");
                    assert(0);
                }
                base = b;
            } else {
                base = NULL;
            }

            int k;
            for (k = 0; k < u->n; ++k) {
                const struct cuckoo_page *p = u->p + k;
                uint8_t *dst = pages + PAGE_SIZE * i;

                if (p != ref) {
                    if (p->size) {
                        if (expand(dst, s->buffer + p->offset - s->start,
                                   p->size) < 0) {
                            debug_printf("expand failed line=%d\n", __LINE__);
                            assert(0);
                        }
                        if (base != NULL) {
                            undiff(dst, base);
                        }
                    } else {
                        if (!c->reusing_vm && is_template(ref) && ref->pfn ==
                                p->pfn && ref->rotate == p->rotate) {
                            goto skip_template_ident;
                        }
                        memcpy(dst, base, PAGE_SIZE);
                    }
                    int rotate = - (p->rotate - ref->rotate);
                    if (rotate) {
                        uint8_t tmp[PAGE_SIZE];
                        memcpy(tmp, dst, PAGE_SIZE);
                        copy(dst, tmp, rotate);
                    }
                } else {
                    memcpy(dst, base, PAGE_SIZE);
                }
#ifdef CUCKOO_VERIFY
                assert(p->strong_hash == strong_hash(dst));
#endif

                pfns[i++] = p->pfn;
skip_template_ident:
                if (i == max || u + 1 == s->last) {
                    ccb->populate_pfns(opaque, c->tid, i, pfns);
                    j += i;
                    i = 0;
                }
            }
        }

        ccb->free(opaque, template_pfns);
        ccb->free(opaque, template_pages);

        if (s->buffer) {
            ccb->free(opaque, s->buffer);
            s->buffer = NULL;
            __sync_synchronize();
        }
        thread_event_set(&s->processed);
    }

    ccb->free(opaque, pfns);
    __sync_synchronize();
    return 0;
}

#ifdef _WIN32
static DWORD WINAPI
#else
static void *
#endif
compression_thread(void *_c)
{
    struct thread_context *c = _c;
    struct cuckoo_callbacks *ccb = c->ccb;
    void *opaque = c->opaque;
    uint64_t *pfns;
    uint8_t *pages;
    uint8_t *src;
    struct work_unit *u;
    uint32_t buffer_offset;

    for (;;) {
        int idx = __sync_fetch_and_add(c->idx, 1);
        int num_pfns = 0;
        idx %= num_slots;
        struct io_slot *s = &c->slots[idx];

        thread_event_wait(&s->metadata_ready);
        if (s->done) {
            thread_event_set(&s->processed);
            break;
        }

        for (u = s->first, num_pfns = 0; u != s->last; ++u) {
            if (is_template(u->ref)) {
                ++num_pfns;
            }
            num_pfns += u->n;
        }

        pfns = ccb->malloc(opaque, sizeof(pfns[0]) * num_pfns);
        pages = ccb->malloc(opaque, PAGE_SIZE * num_pfns);
        s->buffer = ccb->malloc(opaque, PAGE_SIZE * (1 + num_pfns));

        for (u = s->first, num_pfns = 0; u != s->last; ++u) {
            if (is_template(u->ref)) {
                pfns[num_pfns++] = u->ref->pfn | CUCKOO_TEMPLATE_PFN;
            }
            int j;
            for (j = 0; j < u->n; ++j) {
                pfns[num_pfns++] = u->p[j].pfn;
            }
        }

        ccb->capture_pfns(opaque, c->tid, num_pfns, pages, pfns);

        for (u = s->first, src = pages, buffer_offset = 0;
                u != s->last; ++u) {
            compress_range(c, u, &src, s->buffer, &buffer_offset);
        }
        assert(buffer_offset <= PAGE_SIZE * (1 + num_pfns));
        ccb->free(opaque, pfns);
        ccb->free(opaque, pages);

        s->start = 0;
        s->end = buffer_offset;
        thread_event_set(&s->processed);
    }

    __sync_synchronize();
    return 0;
}

static int
read_slot(struct filebuf *fb, struct io_slot *s)
{
    int r = 0;

#ifdef _WIN32
    memset(&s->o, 0, sizeof(OVERLAPPED));
    s->o.Offset = s->start;
    s->o.hEvent = s->data_ready;
    if (!ReadFile(fb->file, s->buffer, s->end - s->start, NULL, &s->o)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            Werr(1, "%s:%d ReadFile fails", __FUNCTION__, __LINE__);
            r = -1;
        }
    }
#else
    do {
        r = pread(fb->file, s->buffer, s->end - s->start, s->start);
    } while (r < 0 && errno == EINTR);
    if (r != s->end - s->start) {
        r = -1;
    }
    thread_event_set(&s->data_ready);
#endif
    return r;
}

static int
write_slot(struct filebuf *fb, struct io_slot *s)
{
    int r = 0;
    struct work_unit *u;

#ifdef _WIN32
    DWORD got;
    memset(&s->o, 0, sizeof(s->o));
    s->o.Offset = s->start;
    s->o.hEvent = s->data_ready;
    if (!WriteFile(fb->file, s->buffer, s->end - s->start, NULL, &s->o)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            Wwarn("WriteFilefails");
            r = -1;
        }
    }
    if (!GetOverlappedResult(fb->file, &s->o, &got, TRUE) ||
            got != s->end - s->start) {
        debug_printf("only wrote %u instead of %d\n",
                (uint32_t) got, s->end - s->start);
        Wwarn("GetOverlappedResult fails");
        r = -1;
    }
#else
    do {
        r = pwrite(fb->file, s->buffer, s->end - s->start, s->start);
    } while (r < 0 && errno == EINTR);
    if (r != s->end - s->start) {
        r = -1;
    }
#endif

    for (u = s->first; u != s->last; u++) {
        int j;
        for (j = 0; j < u->n; ++j) {
            struct cuckoo_page *p = u->p + j;
            if (!is_template(p) && !is_shared(p) && p->size) {
                p->offset += s->start;
            }
        }
    }
    return r;
}

static int
execute_plan(struct cuckoo_context *cc,
              struct work_unit *us,
              struct filebuf *fb,
              int compressing,
              int reusing_vm,
              struct cuckoo_callbacks *ccb, void *opaque)
{
    int i;
    int slot;
    int outstanding;
    struct work_unit *u;
    struct work_unit *first;

    const int max_template_pfns = 2048;
    const int max_pfns = 2048;

    uxen_thread tids[CUCKOO_NUM_THREADS];
    struct thread_context cs[CUCKOO_NUM_THREADS];
    int cancelled = 0;
    volatile int shared_i = 0;
    uint32_t initial_file_offset;
    uint32_t file_offset;

    /* We are accessing the file buffer internals, so make sure there
     * is no buffered state. */
    filebuf_flush(fb);
    file_offset = initial_file_offset = filebuf_tell(fb);

    struct io_slot slots[num_slots];
    memset(slots, 0, sizeof(slots));

    for (i = 0; i < num_slots; ++i) {
        thread_event_init(&slots[i].metadata_ready);
        thread_event_init(&slots[i].data_ready);
        thread_event_init(&slots[i].processed);
        thread_event_set(&slots[i].processed);
    }

    for (i = 0; i < CUCKOO_NUM_THREADS; ++i) {
        struct thread_context *c = &cs[i];
        c->cc = cc;
        c->fb = fb;
        c->ccb = ccb;
        c->opaque = opaque;
        c->idx = &shared_i;
        c->slots = slots;
        c->tid = i;
        c->reusing_vm = reusing_vm;
        __sync_synchronize();
        create_thread(&tids[i], compressing ? compression_thread :
                      decompression_thread, &cs[i]);
    }

    for (u = first = us, slot = 0, outstanding = num_slots; ;
            first = u, slot = (slot + 1) % num_slots) {

        struct io_slot *s = &slots[slot];
        int start = -1;
        int end = -1;
        int num_tpfns;
        int num_pfns;

        thread_event_wait(&s->processed);
        --outstanding;

        if (compressing && s->buffer) {
            s->start = file_offset;
            s->end += file_offset;
            if (write_slot(fb, s) < 0) {
                cancelled = 1;
            }
            file_offset = s->end;
            ccb->free(opaque, s->buffer);
            s->buffer = NULL;
        }

        cancelled |= ccb->cancelled(opaque);

        if (!valid_u(u) || cancelled) { /* End of unpacks list. */
            if (outstanding > 0) {
                s->done = 1;
                __sync_synchronize();
                thread_event_set(&s->metadata_ready);
                continue;
            } else {
                break;
            }
        }

        for (u = first, num_pfns = num_tpfns = 0; valid_u(u);) {
            num_pfns += u->n;
            num_tpfns += is_template(u->ref) ? 1 : 0;
            if (start == -1) {
                start = u->start;
            }
            if (u->start != -1) {
                if (u->start < end) {
                    break;
                }
                end = u->start + u->size;
            }

            ++u;
            /* Check after increasing u, to ensure progress. */
            if (num_pfns >= max_pfns ||
                    num_tpfns >= max_template_pfns ||
                    (end - start) >= (1<<19)) {
                break;
            }
        }

        s->first = first;
        s->last = u;
        s->start = start;
        s->end = end;
        s->buffer = NULL;
        __sync_synchronize();

        if (!compressing) {
            if (start != end) {
                s->buffer = ccb->malloc(opaque, end - start);
                assert(s->buffer);
                __sync_synchronize();
                read_slot(fb, s);
                file_offset = end;
            }
        }
        thread_event_set(&s->metadata_ready);
        ++outstanding;
    }

    for (i = 0; i < CUCKOO_NUM_THREADS; ++i) {
        wait_thread(tids[i]);
        close_thread_handle(tids[i]);
    }
    for (i = 0; i < num_slots; ++i) {
        struct io_slot *s = &slots[i];
        thread_event_close(&s->metadata_ready);
        thread_event_close(&s->data_ready);
        thread_event_close(&s->processed);
    }

    debug_printf("%s done, cancelled=%d\n", __FUNCTION__, cancelled);
    filebuf_seek(fb, file_offset, FILEBUF_SEEK_SET);
    return file_offset - initial_file_offset;
}

/* List of VMs management. */

static uint32_t insert_vm(struct cuckoo_shared *s, uuid_t uuid)
{
    uint32_t i, j;
    struct cuckoo_vm *cvm;

    /* vm 0 is special, start from 1. */
    for (i = 1, j = 0; i < CUCKOO_MAX_VMS; ++i) {
        cvm = &s->vms[i];
        if (j == 0 && !cvm->present) {
            j = i;
        }
        if (!memcmp(cvm->uuid, uuid, sizeof(cvm->uuid))) {
            cvm->present = 1;
            return i;
        }
    }
    if (j) {
        cvm = &s->vms[j];
        cvm->present = 1;
        memcpy(cvm->uuid, uuid, sizeof(cvm->uuid));
    }
    return j;
}

static uint32_t find_vm(const struct cuckoo_shared *s, uuid_t uuid)
{
    uint32_t i;

    /* vm 0 is special, start from 1. */
    for (i = 1; i < CUCKOO_MAX_VMS; ++i) {
        const struct cuckoo_vm *cvm = &s->vms[i];
        if (cvm->present && !memcmp(cvm->uuid, uuid, sizeof(cvm->uuid))) {
            return i;
        }
    }
    return 0;
}

static void forget_vm(struct cuckoo_shared *s, uint32_t vm)
{
    s->vms[vm].present = 0;
}

static int page_cmp_offset(const void *_a, const void *_b)
{
    struct cuckoo_page *a = *(struct cuckoo_page **) _a;
    struct cuckoo_page *b = *(struct cuckoo_page **) _b;

    if (a->offset < b->offset) {
        return -1;
    } else if (b->offset < a->offset) {
        return 1;
    } else {
        return 0;
    }
}

/* Compact away free space in pinned area, while being careful to keep
 * data crash-consistent. */
static void gc_pin(struct cuckoo_context *cc,
                   struct cuckoo_callbacks *ccb, void *opaque)
{
    double t0 = rtc();
    int i, j;
    int num_shared;
    uint32_t dst;
    struct cuckoo_page **pages;

    for (i = num_shared = 0; i < cc->passive->num_pages; ++i) {
        struct cuckoo_page *p = (struct cuckoo_page *) &cc->passive->pages[i];
        if (p->is_stable && is_shared(p)) {
            ++num_shared;
        }
    }

    pages = ccb->malloc(opaque, sizeof(pages[0]) * num_shared);
    for (i = j = 0; i < cc->passive->num_pages; ++i) {
        struct cuckoo_page *p = (struct cuckoo_page *) &cc->passive->pages[i];
        if (p->is_stable && is_shared(p)) {
            pages[j++] = p;
            assert(p->size);
        }
    }
    qsort(pages, num_shared, sizeof(pages[0]), page_cmp_offset);

    for (i = dst = 0; i < num_shared; ++i) {
        struct cuckoo_page *p = pages[i];
        assert(is_shared(p));
        assert(i == 0 || pages[i-1]->offset < p->offset);
        assert(dst <= p->offset);
        if (p->offset - dst >= p->size) {
            /* We can move atomically with no overlap. */
            memcpy(cc->pin + dst, cc->pin + p->offset, p->size);
            __sync_synchronize();
            p->offset = dst;
            dst += p->size;
        } else {
            /* Cannot move without violating crash-consistency. */
            dst = p->offset + p->size;
        }
    }
    ((struct cuckoo_shared *)cc->passive)->pin_brk = dst;
    ccb->reset_section(opaque, cc->pin + dst, pin_size - dst);
    ccb->free(opaque, pages);

    debug_printf("%s took %.2fs\n", __FUNCTION__, rtc() - t0);
}

static void print_stats(struct cuckoo_shared *s)
{
    const struct cuckoo_page *p, *ref, *begin, *end;
    int64_t size_pin = 0, size_unique = 0;
    int64_t saved_template = 0, saved_pin = 0, saved_local = 0;
    int num_shared = 0;
    int num_template = 0;
    int num_pin = 0;
    int num_local = 0;
    int num_template_ident = 0;

    begin = s->pages;
    end = s->pages + s->num_pages;
    for (p = begin, ref = NULL; p != end; ++p) {
        if (is_template(p)) {
            ref = p;
        } else if (is_shared(p)) {
            ref = p;
            size_pin += p->size;
            ++num_shared;
        } else if (p == begin || p[-1].hash != p->hash) {
            ref = p;
            size_unique += p->size;
        } else {
            int ref_size = is_template(ref) ? 1966 : 1730;
            int saved = ref_size - ((int) p->size + sizeof(*p));

            if (is_template(ref) && p->size == 0 && ref->rotate == p->rotate) {
                ++num_template_ident;
            }

            if (p[-1].vm == p->vm) {
                ++num_local;
                saved_local += saved;
            } else if (is_template(ref)) {
                ++num_template;
                saved_template += saved;
            } else if (is_shared(ref)) {
                ++num_pin;
                saved_pin += saved;
            }
        }
    }

    debug_printf("#pages=%d #pins=%d "
                 "nut=%d nup=%d nul=%d nuti=%d "
                 "szp=%"PRId64" szu=%"PRId64" "
                 "sat=%"PRId64" sap=%"PRId64" sal=%"PRId64" MiB\n",
            s->num_pages,
            num_shared,
            num_template,
            num_pin,
            num_local,
            num_template_ident,
            size_pin >> 20,
            size_unique >> 20,
            saved_template >> 20,
            saved_pin >> 20,
            saved_local >> 20);

}

int cuckoo_reconstruct_vm(struct cuckoo_context *cc, uuid_t uuid,
                          struct filebuf *fb, int reusing_vm,
                          struct cuckoo_callbacks *ccb, void *opaque)
{
    int ret = -1;
    /* To not risk getting serialized behind a compress, we treat the shared
     * structure as read-only here, even though we ideally would want to delete
     * the reconstructed VM when we are done. Instead, this happens lazily on
     * the next compress, where the is_alive() callback will return false. */
    if (ccb->lock(opaque, cuckoo_mutex_read) != 0) {
        debug_printf("lock read cancelled\n");
        return -1;
    }
    open_mappings(cc, ccb, opaque);

    uint32_t vm = find_vm(cc->passive, uuid);
    if (vm) {
        struct work_unit *us;
        double t0 = rtc();

        us = create_plan(vm, (struct cuckoo_page *) cc->passive->pages,
                cc->passive->num_pages, 0, ccb, opaque);
        if (us) {
            ret = execute_plan(cc, us, fb, 0, reusing_vm, ccb, opaque);
            ccb->free(opaque, us);
        }
        debug_printf("reconstruct took %.2fs\n", rtc() - t0);
    } else {
        debug_printf("trying to reconstruct unknown VM\n");
    }

    close_mappings(cc, ccb, opaque);
    ccb->unlock(opaque, cuckoo_mutex_read);
    return ret;
}

int cuckoo_init(struct cuckoo_context *cc)
{
    memset(cc, 0, sizeof(*cc));
    return 0;
}

static int
cmp_page_hash(const void *a, const void *b)
{
    const struct cuckoo_page *pa = a;
    const struct cuckoo_page *pb = b;

    if (pa->hash < pb->hash) {
        return -1;
    } else if (pb->hash < pa->hash) {
        return 1;
    } else {

        if (pa->pfn < pb->pfn) {
            return -1;
        } else if (pb->pfn < pa->pfn) {
            return 1;
        } else {
            return 0;
        }

    }
}

static int
prepare_pages(int num_pages,
              struct cuckoo_page *pages,
              struct page_fingerprint *fps,
              struct cuckoo_page proto,
              struct cuckoo_callbacks *ccb, void *opaque)
{
    struct cuckoo_page *p;
    struct cuckoo_page a = proto;
    int i;

    for (i = 0, p = pages; i < num_pages; ++i) {
        struct page_fingerprint *s = &fps[i];
        uint64_t hash = s->hash;
        uint64_t pfn = s->pfn;

        /* ~0ULL means no meaningful hash value. Use a unique id instead,
         * or skip entirely if priming template. */
        if (hash == ~0ULL) {
            if (a.vm == 0) {
                continue;
            } else {
                hash = (((uint64_t) a.vm << 48ULL) | pfn);
            }
        }

        a.hash = hash;
        a.pfn = pfn;
        a.rotate = s->rotate;
        *p++ = a;
    }
    qsort(pages, p - pages, sizeof(pages[0]), cmp_page_hash);
    return p - pages;
}

static int
uniq_pages(int num_pages, struct cuckoo_page *pages)
{
    int i;
    struct cuckoo_page *p, *q;
    for (i = 0, p = q = pages; i < num_pages; ++i, ++p) {
        if (i == 0 || p[-1].hash != p->hash) {
            *q++ = pages[i];
        }
    }
    return q - pages;
}

static inline int space_left(const struct cuckoo_shared *s)
{
    int total_space = ((idx_size - sizeof(struct cuckoo_shared)) /
            sizeof(struct cuckoo_page));
    return total_space - s->num_pages;
}

int cuckoo_compress_vm(struct cuckoo_context *cc, uuid_t uuid,
                       struct filebuf *fb,
                       int num_template, struct page_fingerprint *tfps,
                       int num_pages, struct page_fingerprint *fps,
                       struct cuckoo_callbacks *ccb, void *opaque)
{
    struct cuckoo_page *pages;
    int needs_gc = 0;
    int ret = -EINVAL;
    uint32_t vm;
    struct cuckoo_shared *active = NULL;
    const struct cuckoo_shared *passive = NULL;
    struct cuckoo_page proto = {};
    uint8_t present[CUCKOO_MAX_VMS];
    struct work_unit *us;
    double dt, t0 = rtc();

    if (!num_pages) {
        return 0;
    }

    pages = ccb->malloc(opaque, sizeof(pages[0]) * num_pages);
    if (!pages) {
        return -ENOMEM;
    }

    /* Write lock is held for the entire duration. */
    if (ccb->lock(opaque, cuckoo_mutex_write) != 0) {
        debug_printf("lock write cancelled\n");
        ccb->free(opaque, pages);
        return -EINTR;
    }

    if (ccb->lock(opaque, cuckoo_mutex_read) != 0) {
        debug_printf("lock read cancelled\n");
        ccb->unlock(opaque, cuckoo_mutex_write);
        ccb->free(opaque, pages);
        return -EINTR;
    }

    /* Prepare write transaction by copying passive to active. */
    open_mappings(cc, ccb, opaque);

    /* Do we need to import the template fingerprints first? */
    if (tfps && cc->passive->num_pages == 0 &&
            space_left(cc->passive) >= num_template) {

        debug_printf("priming template\n");
        int na;
        struct cuckoo_page tmpl_proto = {};
        tmpl_proto.type = cuckoo_page_ref_template;
        tmpl_proto.is_stable = 1;

        prepare(cc);
        na = prepare_pages(num_template, cc->active->pages,
                           tfps, tmpl_proto, ccb, opaque);
        cc->active->num_pages = uniq_pages(na, cc->active->pages);
        commit(cc, ccb, opaque);
    }

    prepare(cc);
    active = cc->active;
    passive = cc->passive;

    ccb->unlock(opaque, cuckoo_mutex_read);
    vm = insert_vm(active, uuid);
    vm_presence_map(active, uuid, present, &needs_gc, ccb, opaque);

    if (!vm) {
        debug_printf("cuckoo index VMs list full!\n");
        goto out;
    }

    if (space_left(passive) < num_pages) {
        debug_printf("cuckoo index is full!\n");
        ret = -ENOSPC;
        if (needs_gc) {
            forget_vm(active, vm);
            active->num_pages = merge(active->pages, passive->pages,
                                      passive->num_pages, NULL, 0, present,
                                      ccb, opaque);
            if (space_left(active) >= num_pages) {
                debug_printf("cuckoo caller should retry\n");
                ret = -EAGAIN;
            }
            goto out_force_commit;
        } else {
            goto out;
        }
    }

    proto.vm = vm;
    proto.type = cuckoo_page_delta;
    int n = prepare_pages(num_pages, pages, fps, proto, ccb, opaque);
    assert(n == num_pages);

    debug_printf("merge %d pages into %d existing\n",
                 num_pages, passive->num_pages);
    assert(space_left(passive) >= num_pages);

    /* Merge with existing set of hashes. */
    active->num_pages = merge(active->pages, passive->pages, passive->num_pages,
                              pages, num_pages, present, ccb, opaque);

    us = create_plan(vm, active->pages, active->num_pages, 1, ccb, opaque);
    if (!us) {
        goto out;
    }
    ret = execute_plan(cc, us, fb, 1, 0, ccb, opaque);
    if (active->pin_brk > pin_size) {
        active->pin_brk = pin_size;
    }
    ccb->free(opaque, us);

    debug_printf("wrote %2.fMiB for %d pages, %.2fx compression\n",
            (double) ret / (1024.0*1024.0), num_pages, (num_pages *
                PAGE_SIZE /(double) ret));
    print_stats(active);

out:
    if (ret >= 0) {
out_force_commit:
        commit(cc, ccb, opaque);
        if (needs_gc) {
            /* We have to GC the pin AFTER having committed the merge, because
             * gc_pin works directly on the passive data, being careful to keep
             * it crash-consistent. However, we must still protect access to
             * pin_brk, so we hold the write lock until after the GC. */
            if (ccb->lock(opaque, cuckoo_mutex_read) == 0) {
                gc_pin(cc, ccb, opaque);
                ccb->unlock(opaque, cuckoo_mutex_read);
            }
        }
    }

    ccb->free(opaque, pages);
    close_mappings(cc, ccb, opaque);

    if (ret >= 0) {
        dt = rtc() - t0;
        debug_printf("%s took %.2fs %.2f pages/s\n", __FUNCTION__, dt,
                     (double) num_pages / dt);
    }
    ccb->unlock(opaque, cuckoo_mutex_write);
    return ret;
}

static int
strip_unused_template(int num_pages, struct cuckoo_page *pages)
{
    int i;
    struct cuckoo_page *p, *q;
    for (i = 0, p = q = pages; i <num_pages; ++i, ++p) {
        if (!is_template(p) || (i < num_pages - 1 && p[1].hash == p->hash)) {
            *q++ = *p;
        }
    }
    return q - pages;
}

int cuckoo_compress_vm_simple(struct filebuf *fb,
                              int na, struct page_fingerprint *a,
                              int nb, struct page_fingerprint *b,
                              struct cuckoo_callbacks *ccb, void *opaque)
{
    int ret = -1;
    struct cuckoo_page *pa = NULL;
    struct cuckoo_page *pb = NULL;;
    struct cuckoo_page *pages = NULL;
    uint8_t present[] = {1,1};
    uint32_t n;
    uint64_t meta_offset;
    struct cuckoo_page tmpl_proto = {};
    struct cuckoo_page vm_proto = {};
    struct work_unit *us;
    int num_pages;

    /* sort | uniq of template (vm=0) pages. */
    tmpl_proto.type = cuckoo_page_ref_template;
    tmpl_proto.is_stable = 1;
    pa = ccb->malloc(opaque, sizeof(pa[0]) * na);
    if (!pa) {
        goto out;
    }
    pb = ccb->malloc(opaque, sizeof(pb[0]) * nb);
    if (!pb) {
        goto out;
    }
    na = prepare_pages(na, pa, a, tmpl_proto, ccb, opaque);
    na = uniq_pages(na, pa);

    /* sort of vm=1 pages. */
    vm_proto.vm = 1;
    nb = prepare_pages(nb, pb, b, vm_proto, ccb, opaque);

    /* merge sorted arrays. */
    pages = ccb->malloc(opaque, sizeof(pages[0]) * (na + nb));
    if (!pages) {
        goto out;
    }
    num_pages = merge(pages, pa, na, pb, nb, present, ccb, opaque);

    /* remove unreferenced template pages from array to save file space. */
    num_pages = strip_unused_template(num_pages, pages);

    filebuf_flush(fb);
    meta_offset = filebuf_tell(fb);
    filebuf_seek(fb, sizeof(n) + sizeof(pages[0]) * num_pages,
                 FILEBUF_SEEK_CUR);

    us = create_plan(1, pages, num_pages, 1, ccb, opaque);
    if (us) {
        ret = execute_plan(NULL, us, fb, 1, 0, ccb, opaque);
        ccb->free(opaque, us);
    }

    filebuf_seek(fb, meta_offset, FILEBUF_SEEK_SET);
    n = num_pages;
    filebuf_write(fb, &n, sizeof(n));
    filebuf_write(fb, pages, sizeof(pages[0]) * num_pages);
    filebuf_flush(fb);
    filebuf_seek(fb, ret, FILEBUF_SEEK_CUR);
    debug_printf("wrote %2.fMiB for %d pages, %.2fx compression\n",
            (double) ret / (1024.0*1024.0), nb, (nb * PAGE_SIZE /(double) ret));

out:
    ccb->free(opaque, pages);
    ccb->free(opaque, pb);
    ccb->free(opaque, pa);
    return ret;
}

int cuckoo_reconstruct_vm_simple(struct filebuf *fb, int reusing_vm,
                                 struct cuckoo_callbacks *ccb, void *opaque)
{
    int ret = -1;
    struct work_unit *us;
    double t0 = rtc();
    uint32_t n;
    struct cuckoo_page *pages;

    filebuf_read(fb, &n, sizeof(n));
    pages = ccb->malloc(opaque, sizeof(pages[0]) * n);
    filebuf_read(fb, pages, sizeof(pages[0]) * n);

    us = create_plan(1, pages, n, 0, ccb, opaque);
    if (us) {
        ret = execute_plan(NULL, us, fb, 0, reusing_vm, ccb, opaque);
        ccb->free(opaque, us);
    }
    ccb->free(opaque, pages);
    debug_printf("reconstruct took %.2fs\n", rtc() - t0);
    return ret;
}
