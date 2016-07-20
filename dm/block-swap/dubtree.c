/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "dubtree_sys.h"
#include "dubtree_io.h"

#include "dubtree.h"
#include "lrucache.h"
#include "simpletree.h"
#include "lz4.h"

#define DUBTREE_FILE_MAGIC_MMAP 0x73776170

#define DUBTREE_FILE_VERSION 12

#define DUBTREE_MMAPPED_NAME "top.lvl"


#ifndef _WIN32
#include <aio.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <errno.h>
#include <sys/uio.h>
#include <limits.h>
#include <fcntl.h>
#endif

void dubtree_close(DubTree *t)
{
    char **fb;

    hashtable_clear(&t->ht);
    lruCacheClose(&t->lru);

    free(t->buffered);

    fb = t->fallbacks;
    while (*fb) {
        free(*fb++);
    }

#ifdef _WIN32
    if (!FlushViewOfFile(t->header, 0)) {
        Wwarn("FlushViewOfFile");
    }
    UnmapViewOfFile(t->header);
#else
    if (msync(t->header, sizeof(DubTreeHeader), MS_SYNC) != 0) {
        warn("msync");
    }
    munmap(t->header, sizeof(DubTreeHeader));
#endif
}

int dubtree_init(DubTree *t, char **fallbacks,
        malloc_callback malloc_cb, free_callback free_cb,
        void *opaque)
{
    int i;
    char *fn;
    char **fb;
    DubTreeHeader *header;

    if (!malloc_cb || !free_cb) {
        return -1;
    }

    memset(t, 0, sizeof(DubTree));
    t->malloc_cb = malloc_cb;
    t->free_cb = free_cb;
    t->opaque = opaque;
    critical_section_init(&t->cache_lock);
    critical_section_init(&t->write_lock);

    critical_section_enter(&t->cache_lock);
    hashtable_init(&t->ht, NULL, NULL);
    lru_cache_init(&t->lru, 9);
    critical_section_leave(&t->cache_lock);

    fb = t->fallbacks;
    while (*fallbacks) {
        if (!(*fb = dubtree_realpath(*fallbacks))) {
            *fb = strdup(*fallbacks);
        }
        ++fb;
        ++fallbacks;
    }
    *fb = NULL;

    fn = t->fallbacks[0];
    dubtree_mkdir(fn);

    char *mn;
    void *m;
    asprintf(&mn, "%s/"DUBTREE_MMAPPED_NAME, fn);
    dubtree_handle_t f = dubtree_open_existing(mn);
    if (f == DUBTREE_INVALID_HANDLE) {
        f = dubtree_open_new(mn, 0);
        if (f == DUBTREE_INVALID_HANDLE) {
            printf("unable to open %s: %s\n", mn, strerror(errno));
            return -1;
        }
        dubtree_set_file_size(f, sizeof(DubTreeHeader));
    }

#ifdef _WIN32
    HANDLE h = CreateFileMappingA(f, NULL, PAGE_READWRITE, 0,
                                  sizeof(DubTreeHeader), NULL);
    if (!h) {
        Werr(1, "CreateFileMappingA fails");
    }
    m = MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, sizeof(DubTreeHeader));
    CloseHandle(h);
    CloseHandle(f);
    if (!m) {
        Wwarn("unable to map %s", mn);
        return -1;
    }
#else
    m = mmap(NULL, sizeof(DubTreeHeader), PROT_READ | PROT_WRITE,
                          MAP_SHARED, f, 0);
    close(f);
    if (m == MAP_FAILED) {
        warn("unable to map name=%s\n", mn);
        return -1;
    }
#endif

    header = m;
    t->header = header;
    t->levels = header->levels;

    if (!t->header->dubtree_initialized) {

        char **fb = t->fallbacks + 1;
        f = DUBTREE_INVALID_HANDLE;
        while (f == DUBTREE_INVALID_HANDLE && *fb) {
            asprintf(&fn, "%s/%s", *fb++, DUBTREE_MMAPPED_NAME);
            assert(fn);
            printf("attempt to open fallback %s\n", fn);
            f = dubtree_open_existing_readonly(fn);
            free(fn);
        }

        if (f != DUBTREE_INVALID_HANDLE) {
            dubtree_pread(f, t->header, sizeof(*(t->header)), 0);
            dubtree_close_file(f);
        }
    }

    if (!t->header->dubtree_initialized) {
        for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
            t->levels[i] = 0;
        }

        /* Magic header and version number. */
        t->header->magic = DUBTREE_FILE_MAGIC_MMAP;
        t->header->version = DUBTREE_FILE_VERSION;
        t->header->dubtree_m = DUBTREE_M;
        t->header->dubtree_slot_size = DUBTREE_SLOT_SIZE;
        t->header->dubtree_max_levels = DUBTREE_MAX_LEVELS;

        __sync_synchronize();
        t->header->dubtree_initialized = 1;
        __sync_synchronize();
    }

    /* Check that shared data structure matches current version and
     * configuration. */
    if ((t->header->magic == DUBTREE_FILE_MAGIC_MMAP) &&
        (t->header->version == DUBTREE_FILE_VERSION) &&
        (t->header->dubtree_slot_size == DUBTREE_SLOT_SIZE) &&
        (t->header->dubtree_max_levels == DUBTREE_MAX_LEVELS)) {

        for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
            if (t->levels[i]) {
                printf("level %d = %"PRIu64"\n", i, t->levels[i]);
            }
        }
        return 0;
    } else {
        printf("mismatched dubtree header!\n");
        return -1;
    }
}

void
dubtree_quiesce(DubTree *t)
{
}

static void __put_chunk(DubTree *t, dubtree_handle_t f, int line);
static void put_chunk(DubTree *t, dubtree_handle_t f, int line);
static dubtree_handle_t __get_chunk(DubTree *t, uint64_t chunk_id,
                                       int dirty, int *l);
static dubtree_handle_t get_chunk(DubTree *t, uint64_t chunk_id,
                                     int dirty, int *l);

typedef struct Read {
    int src_offset;
    int dst_offset;
    int size;
} Read;

typedef struct ChunkReads {
    uint64_t chunk_id;
    int num_reads;
    Read *reads;
} ChunkReads;

typedef struct Chunk {
    void *buf;
    HashTable ht;
    int n_crs;
    ChunkReads *crs;
} Chunk;

static inline void read_chunk(DubTree *t, Chunk *d, uint64_t chunk_id,
        uint32_t dst_offset, uint32_t src_offset,
        uint32_t size)
{
    ChunkReads *cr;
    Read *rd;
    uint64_t v;

    if (hashtable_find(&d->ht, chunk_id, &v)) {
        cr = &d->crs[v];
    } else {
        int n = d->n_crs++;
        if (!((n - 1) & n)) {
            /* XXX we do this once per find(). */
            d->crs = realloc(d->crs, sizeof(d->crs[0]) * (n ? 2 * n : 1));
            if (!d->crs) {
                errx(1, "%s: malloc failed line %d", __FUNCTION__, __LINE__);
            }
        }

        cr = &d->crs[n];
        memset(cr, 0, sizeof(*cr));
        cr->chunk_id = chunk_id;
        hashtable_insert(&d->ht, chunk_id, n);
    }

    int n = cr->num_reads;
    if (!((n - 1) & n)) {
        /* XXX we do this once per find(). */
        cr->reads = realloc(cr->reads,
                sizeof(cr->reads[0]) * (n ? 2 * n: 1));
        if (!cr->reads) {
            errx(1, "%s: malloc failed line %d", __FUNCTION__, __LINE__);
        }
    }

    rd = &cr->reads[cr->num_reads++];
    rd->src_offset = src_offset;
    rd->dst_offset = dst_offset;
    rd->size = size;
}

static void set_event_cb(void *opaque, int result)
{
#ifdef _WIN32
    SetEvent(opaque);
#endif
}

typedef struct CallbackState {
    read_callback cb;
    void *opaque;
    volatile uint32_t counter;
    int result;
} CallbackState;

static inline
void increment_counter(CallbackState *cs)
{
    __sync_fetch_and_add(&cs->counter, 1);
}

static inline
void decrement_counter(CallbackState *cs)
{
    if (__sync_fetch_and_sub(&cs->counter, 1) == 1) {
        if (cs->cb) {
            cs->cb(cs->opaque, cs->result);
        }
        free(cs);
    }
}

#ifdef _WIN32
typedef struct {
    OVERLAPPED o; // first
    DubTree *t;
    Read *first;
    int n;
    uint8_t *dst;
    uint8_t *buf;
    int size;
    CallbackState *cs;
} ReadContext;

static void CALLBACK read_complete_scatter(DWORD rc, DWORD got, OVERLAPPED *o)
{
    int i;
    Read *rd;
    ReadContext *ctx = (ReadContext *) o;
    DubTree *t = ctx->t;
    CallbackState *cs = ctx->cs;

    if (ctx->buf) {
        uint8_t *in = ctx->buf;
        int size = 0;

        for (i = 0, rd = ctx->first; i < ctx->n; ++i, ++rd) {
            size += rd->size;
            assert(size <= ctx->size);
            memcpy(ctx->dst + rd->dst_offset, in, rd->size);
            in += rd->size;
        }

        t->free_cb(t->opaque, ctx->buf);
    }
    free(ctx->first);
    free(ctx);
    decrement_counter(cs);
}
#endif

static int execute_reads(DubTree *t,
        uint8_t *dst,
        dubtree_handle_t f,
        Read *first, int n,
        CallbackState *cs)
{
    int i;
    Read *rd;

#ifdef _WIN32
    uint32_t size;
    int contig = 1;
    for (i = size = 0, rd = first; i < n; ++i, ++rd) {
        if (first->dst_offset + size != rd->dst_offset) {
            contig = 0;
        }
        size += rd->size;
    }
    ReadContext *ctx = calloc(1, sizeof(*ctx));
    ctx->t = t;
    ctx->first = first;
    ctx->n = n;
    ctx->dst = dst;
    if (contig) {
        ctx->buf = NULL;
    } else {
        ctx->buf = t->malloc_cb(t->opaque, size);
        if (!ctx->buf) {
            errx(1, "%s: malloc failed", __FUNCTION__);
            return -1;
        }
    }
    ctx->size = size;
    ctx->cs = cs;
    increment_counter(cs);

    ctx->o.Offset = first->src_offset;
    if (!ReadFileEx(f, ctx->buf ? ctx->buf : dst + first->dst_offset, size,
                &ctx->o, read_complete_scatter)) {
        Werr(1, "ReadFileEx failed");
        return -1;
    }
#else

#ifdef __APPLE__

    int r;

    if (n > 1) {
        struct radvisory ra = {first->src_offset,
            first[n - 1].src_offset + first[n - 1].size - first->src_offset};
        r = fcntl(f, F_RDADVISE, &ra);
        assert(r >= 0);
    }

    for (i = 0, rd = first; i < n; ++i, ++rd) {
        do {
            r = pread(f, dst + rd->dst_offset, rd->size, rd->src_offset);
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            err(1, "pread failed f=%d r %d", f, r);
        }
    }

#else

    int take;
    int r;
    for (i = 0, rd = first; i < n; i += take) {
        int j;
        uint32_t offset;
        struct iovec v[IOV_MAX];
        take = (n - i) < IOV_MAX ? (n - i): IOV_MAX;

        for (j = 0, offset = rd->src_offset; j < take; ++j, ++rd) {
            v[j].iov_base = dst + rd->dst_offset;
            v[j].iov_len = rd->size;
        }
        do {
            r = preadv(f, v, take, offset);
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            err(1, "preadv failed f=%d r %d", f, r);
        }
    }
#endif
    free(first);

#endif

    return 0;
}

static int flush_chunk(DubTree *t, uint8_t *dst, dubtree_handle_t f,
        ChunkReads *cr, CallbackState *cs)
{
    int i, j;
    int n = cr->num_reads;
    Read *reads = cr->reads;
    Read *first = reads;
    Read *rd, *prev;
    int r = 0;

    for (i = 1, j = 0; i < n + 1; ++i) {
        rd = &reads[i];
        prev = &reads[i - 1];

        if (i == n || rd->src_offset != prev->src_offset + prev->size) {
            if (j > 0 || i < n) {
                first = malloc((i - j) * sizeof(*first));
                memcpy(first, reads + j, (i - j) * sizeof(*first));
            }
            r = execute_reads(t, dst, f, first, i - j, cs);
            if (r < 0) {
                printf("execute_reads failed, r=%d\n", r);
                break;
            }
            j = i;
        }
    }

    if (first != reads) {
        free(reads);
    }
    return r;
}

int flush_reads(DubTree *t, Chunk *c, const uint8_t *chunk0, CallbackState *cs)
{
    int i, j;
    int r = 0;

    for (i = 0; i < c->n_crs; ++i) {
        ChunkReads *cr = &c->crs[i];
        if (cr->chunk_id == 0) {

            Read *first = cr->reads;
            Read *rd;
            for (j = 0, rd = first; j < cr->num_reads; ++j, ++rd) {
                memcpy(c->buf + rd->dst_offset, chunk0 + rd->src_offset,
                       rd->size);
            }
            free(first);
            r = 0;

        } else {
            dubtree_handle_t f;
            int l;

            f = get_chunk(t, cr->chunk_id, 0, &l);
            if (f != DUBTREE_INVALID_HANDLE) {
                r = flush_chunk(t, c->buf, f, cr, cs);
                put_chunk(t, f, l);
            } else {
                free(cr->reads);
                r = -1;
            }
            if (r < 0) {
                break;
            }
        }
    }

    hashtable_clear(&c->ht);
    free(c->crs);
    c->n_crs = 0;
    c->crs = NULL;
    return r;
}


static inline void *map_tree(dubtree_handle_t f)
{
    void *m;
    uint64_t sz;

    sz = dubtree_get_file_size(f);

#ifdef _WIN32
    HANDLE h = CreateFileMappingA(f, NULL, PAGE_READONLY, 0, sz, NULL);
    if (!h) {
        Werr(1, "CreateFileMappingA fails");
    }
    m = MapViewOfFile(h, FILE_MAP_READ, 0, 0, sz);
    assert(m);
    CloseHandle(h);
#else
    m = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, f, 0);
    if (m == MAP_FAILED) {
        err(1, "unable to map\n");
    }
#endif
    return m;
}

static inline void unmap_tree(void *mem, size_t size)
{
#ifdef _WIN32
    if (!UnmapViewOfFile(mem)) {
        printf("UnmapViewOfFile failed, err=%u\n", (uint32_t) GetLastError());
    }
#else
    munmap(mem, size);
#endif
}

typedef struct UserData {
    uint32_t fragments;
    uint64_t garbage;
    uint64_t size;        /* How many bytes are addressed by this tree. */
    uint32_t num_chunks;
    uint64_t chunk_ids[0];
} UserData;

static inline int add_chunk_id(UserData **pud, uint64_t chunk_id)
{
    UserData *ud = *pud;
    int n = ud->num_chunks++;
    if (!((n - 1) & n)) {
        *pud = ud = realloc(ud, sizeof(UserData) +
                sizeof(uint64_t) * (n ? 2 * n: 1));
        if (!ud) {
            errx(1, "%s: malloc failed", __FUNCTION__);
            return -1;
        }
    }
    ud->chunk_ids[n] = chunk_id;
    return ud->num_chunks;
}

static inline uint64_t get_chunk_id(const UserData *ud, int chunk)
{
    return ud->chunk_ids[chunk - 1];
}

static inline size_t ud_size(const UserData *cud, size_t n)
{
    return sizeof(*cud) + sizeof(cud->chunk_ids[0]) * n;
}

typedef struct CachedTree {
    struct SimpleTree st;
    uint64_t chunk;
    dubtree_handle_t f;
    int line;
} CachedTree;

typedef struct FindContext {
    CachedTree cached_trees[DUBTREE_MAX_LEVELS];
#ifdef _WIN32
    HANDLE event;
#endif
} FindContext;

void *dubtree_prepare_find(DubTree *t)
{
    FindContext *fx = calloc(1, sizeof(FindContext));
#ifdef _WIN32
    fx->event = CreateEvent(NULL, FALSE, FALSE, NULL);
#endif
    return fx;
}

void dubtree_end_find(DubTree *t, void *ctx)
{
    FindContext *fx = ctx;
    int i;

    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        CachedTree *ct = &fx->cached_trees[i];
        if (ct->chunk) {
            unmap_tree(ct->st.mem, simpletree_get_nodes_size(&ct->st));
            ct->chunk = 0;
            put_chunk(t, ct->f, ct->line);
        }
    }
#ifdef _WIN32
    CloseHandle(fx->event);
#endif
    free(fx);
}

int dubtree_find(DubTree *t, uint64_t start, int num_keys,
        uint8_t *out, uint8_t *map, uint32_t *sizes,
        read_callback cb, void *opaque, void *ctx)
{
    int i, r;
    struct source {
        uint64_t chunk_id;
        int offset;
        int size;
    };
    const int max_inline_keys = 8;
    struct source inline_sources[max_inline_keys];
    uint8_t inline_versions[max_inline_keys];
    struct source *sources = NULL;
    uint8_t *versions = NULL;
    int succeeded;
    int missing;

    FindContext *fx = ctx;
    char relevant[DUBTREE_MAX_LEVELS] = {};

    if (num_keys > max_inline_keys) {
        sources = calloc(num_keys, sizeof(sources[0]));
        if (!sources) {
            printf("%s: OOM line %d\n", __FUNCTION__, __LINE__);
            r = -1;
            goto out;
        }

        versions = calloc(num_keys, sizeof(versions[0]));
        if (!versions) {
            printf("%s: OOM line %d\n", __FUNCTION__, __LINE__);
            r = -1;
            goto out;
        }
    } else {
        memset(inline_sources, 0, sizeof(inline_sources));
        sources = inline_sources;
        memset(inline_versions, 0, sizeof(inline_versions));
        versions = inline_versions;
    }

    CallbackState *cs = calloc(1, sizeof(CallbackState));
    if (cb) {
        cs->cb = cb;
        cs->opaque = opaque;
    } else {
        cs->cb = set_event_cb;
#ifdef _WIN32
        cs->opaque = (void *) fx->event;
#else
        cs->opaque = NULL;
#endif

    }
    increment_counter(cs);

    succeeded = 1; // so far so good.

    /* Initialize result vectors. */
    memcpy(versions, map, sizeof(versions[0]) * num_keys);
    memset(sizes, 0, sizeof(sizes[0]) * num_keys);

    /* How many keys do we actually need to get? Some may have been
     * filled out already by the caller so do not count those. */

    for (i = missing = 0; i < num_keys; ++i) {
        if (map[i] == 0) ++missing;
    }

    /* Open all the trees. */
    critical_section_enter(&t->cache_lock);
    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        CachedTree *ct = &fx->cached_trees[i];
        if (ct->chunk) {
            if (ct->chunk != t->levels[i]) {
                unmap_tree(ct->st.mem, simpletree_get_nodes_size(&ct->st));
                ct->chunk = 0;
                if (ct->f != DUBTREE_INVALID_HANDLE) {
                    __put_chunk(t, ct->f, ct->line);
                    ct->f = DUBTREE_INVALID_HANDLE;
                }
            } else {
                lru_cache_touch_line(&t->lru, ct->line);
            }
        }
        if (ct->chunk == 0 && (ct->chunk = t->levels[i])) {
            ct->f = __get_chunk(t, ct->chunk, 0, &ct->line);
            assert (ct->f != DUBTREE_INVALID_HANDLE);
            simpletree_open(&ct->st, map_tree(ct->f));
        }
    }
    critical_section_leave(&t->cache_lock);

    /* Check for relevant keys in all fx->cached_trees. */
    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        CachedTree *ct = &fx->cached_trees[i];
        SimpleTree *st = ct->chunk ? &ct->st : NULL;
        SimpleTreeIterator it;

        if (st != NULL) {

            SimpleTreeResult k;
            if (simpletree_find(st, start, &it)) {
                const UserData *cud = simpletree_get_user(st);
                while (missing && !simpletree_at_end(st, &it)) {

                    uint64_t block;
                    int idx;

                    k = simpletree_read(st, &it);
                    block = k.key;
                    idx = block - start;

                    if (block >= start + num_keys) {
                        break;
                    }

                    /* The youngest data is always at the top of the tree,
                     * so only include a key into the returned result if we
                     * did not have one already. */
                    if (!versions[idx]) {
                        versions[idx] = 1;
                        sources[idx].chunk_id = get_chunk_id(cud, k.value.chunk);
                        sources[idx].offset = k.value.offset;
                        sources[idx].size = k.value.size;
                        relevant[i] = 1;
                        --missing;
                    }
                    simpletree_next(st, &it);
                }
            }
        }
    }


    /* Copy out the values we found. */
    Chunk c = {};
    c.buf = out;
    hashtable_init(&c.ht, NULL, NULL);

    int dst;
    for (i = dst = 0; i < num_keys; ++i) {
        int size = sources[i].size;
        if (size) {
            read_chunk(t, &c, sources[i].chunk_id, dst, sources[i].offset,
                       size);
        }
        sizes[i] = size;
        dst += size;
    }

    r = flush_reads(t, &c, NULL, cs);
    if (r < 0) {
        succeeded = 0;
    }

    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        CachedTree *ct = &fx->cached_trees[i];
        if (ct->chunk && ct->chunk != t->levels[i]) {
            if (relevant[i]) {
                succeeded = 0;
            }
        }
    }

    /* Return 0 or positive value indicating number of unresolved blocks on
     * succes. Negative return means error. */

    r = succeeded ? missing : -EAGAIN;
    /* Since versions array started out as a copy of map, it is safe to
     * copy it back wholesale. */
    if (succeeded) {
        memcpy(map, versions, sizeof(map[0]) * num_keys);
    }

    cs->result = r;
    decrement_counter(cs);
    cs = NULL;

#ifdef _WIN32
    if (!cb) {
        for (;;) {
            int r = WaitForSingleObjectEx(fx->event, INFINITE, TRUE);
            if (r == WAIT_OBJECT_0) {
                break;
            } else if (r == WAIT_IO_COMPLETION) {
                continue;
            } else {
                Werr(1, "r %x");
            }
        }
    }
#endif

out:
    if (num_keys > max_inline_keys) {
        free(sources);
        free(versions);
    }
    return r; /* negative for error, positive if unresolved blocks. */
}


/* Heap helper functions. */

typedef struct {
    SimpleTree *st;
    SimpleTreeIterator it;
    int level;
    uint64_t key;
    int chunk;
    int offset;
    int size;
    uint64_t chunk_id;
} HeapElem;

static inline int heap_less_than(DubTree *t, HeapElem *a,
        HeapElem *b)
{
    if (a->key != b->key) {
        return (a->key < b->key);
    } else {
        return (a->level < b->level);
    }
}

static inline void sift_up(DubTree *t, HeapElem **hp, size_t child)
{
    size_t parent;
    for (; child; child = parent) {
        parent = (child - 1) / 2;

        if (heap_less_than(t, hp[child], hp[parent])) {

            HeapElem *tmp = hp[parent];
            hp[parent] = hp[child];
            hp[child] = tmp;

        } else {
            break;
        }
    }
}

static inline void sift_down(DubTree *t, HeapElem **hp, size_t end)
{
    size_t parent = 0;
    size_t child;
    HeapElem *tmp;
    for (;; parent = child) {
        child = 2 * parent + 1;

        if (child >= end)
            break;

        /* point to the min child */
        if (child + 1 < end &&
                heap_less_than(t, hp[child + 1], hp[child])) {
            ++child;
        }

        /* heap condition restored? */
        if (heap_less_than(t, hp[parent], hp[child])) {
            break;
        }

        /* else swap and continue. */
        tmp = hp[parent];
        hp[parent] = hp[child];
        hp[child] = tmp;
    }
}

#define io_sz (1<<23)

static inline char *name_chunk(const char *prefix, uint64_t chunk_id)
{
    char *fn;
    asprintf(&fn, "%s/%"PRIx64".lvl", prefix, chunk_id);
    return fn;
}

static inline dubtree_handle_t __get_chunk(DubTree *t, uint64_t chunk_id, int dirty, int *l)
{
    dubtree_handle_t f = DUBTREE_INVALID_HANDLE;
    uint64_t line;
    LruCacheLine *cl;

    if (hashtable_find(&t->ht, chunk_id, &line)) {
        cl = lru_cache_touch_line(&t->lru, line);
        ++(cl->users);
        f = (dubtree_handle_t) cl->value;
    } else {
        char *fn = NULL;
        char **fb = t->fallbacks;
        while (f == DUBTREE_INVALID_HANDLE && *fb) {
            free(fn);
            fn = name_chunk(*fb, chunk_id);
            if (fb == t->fallbacks) {
                f = dirty ?
                    dubtree_open_new(fn, 0) :
                    dubtree_open_existing(fn);
            } else {
                f = dubtree_open_existing_readonly(fn);
            }
            ++fb;
        }

        if (f != DUBTREE_INVALID_HANDLE) {
            for (;;) {
                line = lru_cache_evict_line(&t->lru);
                cl = lru_cache_touch_line(&t->lru, line);
                if (cl->users == 0) {
                    break;
                }
            }
            if (cl->key) {
                hashtable_delete(&t->ht, cl->key);
                dubtree_close_file((dubtree_handle_t) cl->value);
            }

            cl->key = chunk_id;
            cl->value = (uint64_t) (uintptr_t) f;
            cl->users = 1;
            hashtable_insert(&t->ht, chunk_id, line);
        } else {
#ifdef _WIN32
            Wwarn("open chunk=%"PRIx64" failed, fn=%s", chunk_id, fn);
#else
            warn("open chunk=%"PRIx64" failed, fn=%s", chunk_id, fn);
#endif
        }
        free(fn);
    }

    if (f != DUBTREE_INVALID_HANDLE) {
        *l = line;
    }
    return f;
}

static dubtree_handle_t get_chunk(DubTree *t, uint64_t chunk_id, int dirty, int *l)
{
    dubtree_handle_t f;
    critical_section_enter(&t->cache_lock);
    f = __get_chunk(t, chunk_id, dirty, l);
    critical_section_leave(&t->cache_lock);
    return f;
}

static int unlink_chunk(DubTree *t, uint64_t chunk_id, dubtree_handle_t f)
{
    char *fn;

    if (f != DUBTREE_INVALID_HANDLE) {
#ifdef _WIN32
        FILE_DISPOSITION_INFO fdi = {1};
        if (!SetFileInformationByHandle(f, FileDispositionInfo, &fdi,
                                        sizeof(fdi)) &&
                GetLastError() != ERROR_ACCESS_DENIED) {
            Wwarn("err setting delete disposition for chunk=%"PRIx64"",
                  chunk_id);
        }
        dubtree_close_file(f);
        return 0;
#else
        ftruncate(f, 0);
#endif
    }

    fn = name_chunk(t->fallbacks[0], chunk_id);
    if (unlink(fn) < 0 && errno != ENOENT) {
        printf("unlink %s failed err %s\n", fn, strerror(errno));
    }
    free(fn);

#ifndef _WIN32
    dubtree_close_file(f);
#endif
    return 0;
}

static inline void __put_chunk(DubTree *t, dubtree_handle_t _f, int line)
{
    LruCacheLine *cl = &t->lru.lines[line];
    uint64_t chunk_id = 0;
    int delete = 0;
    dubtree_handle_t f = DUBTREE_INVALID_HANDLE;

    if (cl->users-- == 1) {
        if (cl->delete) {
            chunk_id = cl->key;
            f = (dubtree_handle_t) cl->value;
            assert(f == _f);
            hashtable_delete(&t->ht, cl->key);
            delete = 1;
            memset(cl, 0, sizeof(*cl));
        }
    }

    if (delete) {
        unlink_chunk(t, chunk_id, f);
    }
}

static void put_chunk(DubTree *t, dubtree_handle_t f, int line)
{
    critical_section_enter(&t->cache_lock);
    __put_chunk(t, f, line);
    critical_section_leave(&t->cache_lock);
}

static inline void __free_chunk(DubTree *t, uint64_t chunk_id)
{
    uint64_t line;
    int delete = 1;
    dubtree_handle_t f = DUBTREE_INVALID_HANDLE;

    if (hashtable_find(&t->ht, chunk_id, &line)) {
        LruCacheLine *cl = &t->lru.lines[line];
        if (cl->users > 0) {
            cl->delete = 1;
            delete = 0;
        } else {
            f = (dubtree_handle_t) cl->value;
            hashtable_delete(&t->ht, cl->key);
            cl->key = 0;
            cl->value = 0;
        }
    }

    if (delete) {
        unlink_chunk(t, chunk_id, f);
    }
}
static inline uint64_t alloc_chunk(DubTree *t)
{
    return __sync_add_and_fetch(&t->header->out_chunk, 1);
}

void write_chunk(DubTree *t, Chunk *c, const uint8_t *chunk0,
        uint64_t chunk_id, uint32_t size)
{
    int l;
    dubtree_handle_t f = get_chunk(t, chunk_id, 1, &l);
    if (f == DUBTREE_INVALID_HANDLE) {
        err(1, "unable to write chunk %"PRIx64, chunk_id);
        return;
    }

    CallbackState *cs = calloc(1, sizeof(*cs));
    if (!cs) {
        errx(1, "%s: calloc failed", __FUNCTION__);
        return;
    }

    increment_counter(cs);

#ifdef _WIN32
    HANDLE h = CreateFileMappingA(f, NULL, PAGE_READWRITE, 0, size, NULL);
    if (!h) {
        Werr(1, "CreateFileMappingA fails");
    }
    c->buf = MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, size);
    CloseHandle(h);

    HANDLE event = CreateEvent(NULL, TRUE, FALSE, NULL);
    cs->cb = set_event_cb;
    cs->opaque = (void *) event;

#else
    c->buf = t->malloc_cb(t->opaque, size);
    if (!c->buf) {
        errx(1, "%s: malloc failed", __FUNCTION__);
    }
#endif

    flush_reads(t, c, chunk0, cs);
    decrement_counter(cs);

#ifdef _WIN32
    for (;;) {
        int r = WaitForSingleObjectEx(event, INFINITE, TRUE);
        if (r == WAIT_OBJECT_0) {
            break;
        } else if (r == WAIT_IO_COMPLETION) {
            continue;
        } else {
            printf("r %x err %u\n", r, (uint32_t) GetLastError());
        }
    }
    CloseHandle(event);
    UnmapViewOfFile(c->buf);
#else
    dubtree_pwrite(f, c->buf, size, 0);
    t->free_cb(t->opaque, c->buf);
#endif

    free(c);
    put_chunk(t, f, l);
}


static inline int chunk_exceeded(size_t size)
{
    return (size + DUBTREE_BLOCK_SIZE - 1 > io_sz);
}

static inline void insert_kv(SimpleTree *st,
        uint64_t key, int chunk, int offset, int size)
{
    SimpleTreeValue v;
    v.chunk = chunk;
    v.offset = offset;
    v.size = size;
    simpletree_insert(st, key, v);
}

int dubtree_insert(DubTree *t, int num_keys, uint64_t* keys, uint8_t *values,
        uint32_t *sizes, int force_level)
{
    /* Find a free slot at the top level and copy the key there. */
    SimpleTree st;
    int i;
    int j = 0;
    uint64_t last_key = -1;
    uint64_t needed = 0;
    uint32_t fragments = 0;
    uint64_t garbage = 0;
    UserData *ud = NULL;
    HashTable keep;
    hashtable_init(&keep, NULL, NULL);

    HeapElem tuples[1 + DUBTREE_MAX_LEVELS];
    HeapElem *heap[1 + DUBTREE_MAX_LEVELS];
    HeapElem *min;
    SimpleTree trees[DUBTREE_MAX_LEVELS];
    SimpleTree *existing;
    const UserData *cud;
    dubtree_handle_t tree_handles[DUBTREE_MAX_LEVELS];
    int tree_lines[DUBTREE_MAX_LEVELS];

    uint64_t slot_size = DUBTREE_SLOT_SIZE;

    critical_section_enter(&t->write_lock);
    struct buf_elem {uint64_t key; int offset; int size;};
    struct buf_elem *buffered = t->buffered;

    if (num_keys > 0) {
        for (i = 0; i < num_keys; ++i) {
            needed += sizes[i];
        }

        min = &tuples[j];
        memset(min, 0, sizeof(*min));
        min->level = -1;
        min->key = keys[0];
        min->size = sizes[0];
        heap[j] = min;
        sift_up(t, heap, j++);
    }

    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        /* Figure out how many bytes are in use at this level. */

        uint64_t used = 0;
        if (t->levels[i]) {
            dubtree_handle_t f;
            SimpleTreeResult k;
            existing = &trees[i];

            f = get_chunk(t, t->levels[i], 0, &tree_lines[i]);
            if (f == DUBTREE_INVALID_HANDLE) {
#ifdef _WIN32
                Werr(1, "get_chunk failed");
#else
                err(1, "get_chunk failed");
#endif
            }
            tree_handles[i] = f;
            simpletree_open(existing, map_tree(f));

            cud = simpletree_get_user(existing);
            used = cud->size;
            garbage = cud->garbage;
            fragments = cud->fragments;
            if (used > garbage) {
                needed += used - garbage;
            }

            min = &tuples[j];
            min->level = i;
            min->st = existing;
            simpletree_begin(existing, &min->it);
            k = simpletree_read(existing, &min->it);
            min->key = k.key;
            min->chunk = k.value.chunk;
            min->chunk_id = get_chunk_id(cud, min->chunk);
            min->offset = k.value.offset;
            min->size = k.value.size;
            heap[j] = min;
            sift_up(t, heap, j++);
        } else {
            trees[i].mem = NULL;
            existing = NULL;
            fragments = 0;
            garbage = used = 0;
            cud = NULL;
        }

        if (slot_size >= needed && fragments < DUBTREE_M && used >= garbage &&
                i >= force_level) {
            if (existing) {
                int power;
                for (power = 1; power < cud->num_chunks; power *= 2);
                ud = malloc(ud_size(cud, power));
                if (!ud) {
                    warnx("%s: malloc failed on line %d", __FUNCTION__, __LINE__);
                    return -1;
                }
                memcpy(ud, cud, ud_size(cud, cud->num_chunks));
            } else {
                ud = calloc(1, sizeof(*ud));
                if (!ud) {
                    warnx("%s: calloc failed on line %d", __FUNCTION__, __LINE__);
                    return -1;
                }
            }

            break;
        }

        slot_size *= DUBTREE_M;
    }

    if (i == DUBTREE_MAX_LEVELS) {
        printf("all levels full!\n");
        return -1;
    }

    /* Create the new B-tree to index the destination level. */
    simpletree_init(&st);

    uint32_t b = 0;
    int n_buffered = 0;
    int t_buffered = 0;
    uint64_t total = 0;
    int min_idx = 0;
    uint32_t min_offset = 0;

    int done;
    uint64_t last_chunk_id = ~0ULL;
    Chunk *out = NULL;
    uint64_t out_id;
    int out_chunk;
    struct buf_elem *e;

    for (done = 0;;) {
        /* Loop and copy down until heap empty. */

        min = heap[0];
        int end = 0;

        /* Anything to flush before we consume input? */
        if (n_buffered && ((last_chunk_id != min->chunk_id) || done ||
                    chunk_exceeded(t_buffered))) {
            int q;

            if (chunk_exceeded(t_buffered) && last_chunk_id) {

                hashtable_insert(&keep, last_chunk_id, 0);
                int chunk = add_chunk_id(&ud, last_chunk_id);
                for (q = 0; q < n_buffered; ++q) {
                    e = &buffered[q];
                    insert_kv(&st, e->key, chunk, e->offset, e->size);
                    total += e->size;
                }

            } else {

                uint32_t b0 = b;
                uint32_t offset0 = buffered[0].offset;

                for (q = 0; q < n_buffered; ++q) {

                    if (!out) {
                        out_id = alloc_chunk(t);
                        out = calloc(1, sizeof(Chunk));
                        if (!out) {
                            warnx("%s: calloc failed on line %d",
                                    __FUNCTION__, __LINE__);
                            return -1;
                        }
                        out_chunk = add_chunk_id(&ud, out_id);
                    }

                    e = &buffered[q];
                    insert_kv(&st, e->key, out_chunk, b, e->size);
                    total += e->size;
                    b += e->size;

                    if (chunk_exceeded(b)) {
                        read_chunk(t, out, last_chunk_id, b0, offset0, b - b0);
                        offset0 = e->offset + e->size;

                        write_chunk(t, out, values, out_id, b);
                        out = NULL;
                        b0 = b = 0;
                    }

                }
                if (out) {
                    read_chunk(t, out, last_chunk_id, b0, offset0, b - b0);
                }
            }
            n_buffered = t_buffered = 0;
        }
        if (done) {
            if (out) {
                write_chunk(t, out, values, out_id, b);
                out = NULL;
            }
            break;
        }

        /* Process min element from incoming and existing trees. */
        /* The same key may be repeated across levels, so ignore
         * duplicates. */

        if (min->key != last_key) {
            last_key = min->key;

            if (min->level == i) {
                insert_kv(&st, min->key, min->chunk, min->offset, min->size);
                total += min->size;
            } else {

                if (n_buffered >= t->buffer_max) {
                    t->buffer_max = t->buffer_max ? 2 * t->buffer_max : 1;
                    buffered = t->buffered = realloc(t->buffered,
                                                     sizeof(buffered[0]) *
                                                     t->buffer_max);
                    if (!buffered) {
                        errx(1, "%s: malloc failed", __FUNCTION__);
                        return -1;
                    }
                }

                e = &buffered[n_buffered++];
                e->key = min->key;
                e->offset = min->offset;
                e->size = min->size;
                t_buffered += min->size;
            }
        } else {
            garbage += min->size;
        }

        last_chunk_id = min->chunk_id;

        /* Find next min for next round. */
        if (min->st) {
            simpletree_next(min->st, &min->it);
            end = simpletree_at_end(min->st, &min->it);
        } else {
            min_offset += sizes[min_idx++];
            end = (min_idx == num_keys);
        }
        if (end) {
            if (j == 1) {
                done = 1;
            } else {
                heap[0] = heap[--j];
            }
        } else {
            if (min->st) {
                SimpleTreeResult k;
                cud = simpletree_get_user(min->st);
                k = simpletree_read(min->st, &min->it);
                min->key = k.key;
                min->chunk = k.value.chunk;
                min->chunk_id = get_chunk_id(cud, min->chunk);
                min->offset = k.value.offset;
                min->size = k.value.size;
            } else {
                min->key = keys[min_idx];
                min->offset = min_offset;
                min->size = sizes[min_idx];
            }
        }
        sift_down(t, heap, j);
    }

    /* Finish the combined tree and commit the merge by
     * installing a globally visible reference to the merged
     * tree. */

    simpletree_finish(&st);
    ud->size = total;
    ud->fragments = fragments + 1;
    ud->garbage = garbage;
    simpletree_set_user(&st, ud, ud_size(ud, ud->num_chunks));
    free(ud);

    uint64_t tree_chunk = alloc_chunk(t);
    int l;
    dubtree_handle_t f = get_chunk(t, tree_chunk, 1, &l);
    if (f == DUBTREE_INVALID_HANDLE) {
        err(1, "unable to open tree chunk %"PRIx64" for write", tree_chunk);
        return -1;
    }
    dubtree_pwrite(f, st.mem, simpletree_get_nodes_size(&st), 0);
    put_chunk(t, f, l);
    simpletree_clear(&st);

    critical_section_enter(&t->cache_lock);

    /* Find the smallest level that this tree can fit in, and delete
     * the rest of the levels from i and up. */

    int dest;
    for (dest = i; ; --dest) {
        slot_size /= DUBTREE_M;
        if (dest == 0 || slot_size < total) {
            break;
        }
    }

    for (j = i; j >= 0; --j) {
        SimpleTree *st = &trees[j];
        uint64_t chunk_id = t->levels[j];

        t->levels[j] = dest == j ? tree_chunk : 0;
        __sync_synchronize();

        if (chunk_id) {
            if (j != i) {
                int k;
                cud = simpletree_get_user(st);
                for (k = 0; k < cud->num_chunks; ++k) {
                    uint64_t dead_chunk_id = cud->chunk_ids[k];
                    if (!hashtable_find_entry(&keep, dead_chunk_id)) {
                        __free_chunk(t, dead_chunk_id);
                    }
                }
            }

            unmap_tree(st->mem, simpletree_get_nodes_size(st));
            __put_chunk(t, tree_handles[j], tree_lines[j]);
            __free_chunk(t, chunk_id);
        }
    }
    critical_section_leave(&t->cache_lock);
    critical_section_leave(&t->write_lock);
    hashtable_clear(&keep);

    return 0;
}

int dubtree_delete(DubTree *t)
{
    int i, j;

    critical_section_enter(&t->cache_lock);
    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        uint64_t chunk_id = t->levels[i];
        if (chunk_id) {

            dubtree_handle_t f;
            int line;
            SimpleTree st;
            const UserData *cud;

            f = get_chunk(t, chunk_id, 0, &line);
            if (f == DUBTREE_INVALID_HANDLE) {
                warn("unable to delete tree-chunk=%"PRIx64, chunk_id);
                return -1;
            }
            simpletree_open(&st, map_tree(f));

            cud = simpletree_get_user(&st);
            for (j = 0; j < cud->num_chunks; ++j) {
                __free_chunk(t, cud->chunk_ids[j]);
            }

            unmap_tree(st.mem, simpletree_get_nodes_size(&st));
            __put_chunk(t, f, line);
            __free_chunk(t, chunk_id);
        }
    }
    critical_section_leave(&t->cache_lock);

    char *mn;
    asprintf(&mn, "%s/"DUBTREE_MMAPPED_NAME, t->fallbacks[0]);

    char *dn;
    dn = strdup(t->fallbacks[0]);

    dubtree_close(t);

    if (unlink(mn) < 0) {
        warn("unable to unlink %s", mn);
        return -1;
    }
    if (rmdir(dn) < 0) {
        warn("unable to rmdir %s", dn);
        return -1;
    }

    return 0;
}

int dubtree_sanity_check(DubTree *t)
{
    int i;
    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        /* Figure out how many bytes are in use at this level. */

        SimpleTree st;
        if (t->levels[i]) {
            dubtree_handle_t f, cf;
            SimpleTreeIterator it;
            const UserData *cud;
            int line;

            f = get_chunk(t, t->levels[i], 0, &line);
            if (f == DUBTREE_INVALID_HANDLE) {
                return -1;
            }
            simpletree_open(&st, map_tree(f));
            simpletree_begin(&st, &it);
            cud = simpletree_get_user(&st);
            while (!simpletree_at_end(&st, &it)) {
                SimpleTreeResult k;
                uint8_t in[DUBTREE_BLOCK_SIZE];
                uint8_t out[DUBTREE_BLOCK_SIZE];
                uint64_t chunk_id;
                int l;
                int got;

                k = simpletree_read(&st, &it);
                chunk_id = get_chunk_id(cud, k.value.chunk);
                cf = get_chunk(t, chunk_id, 0, &l);
                if (cf == DUBTREE_INVALID_HANDLE) {
                    warn("unable to read chunk %"PRIx64, chunk_id);
                    return -1;
                }
                got = dubtree_pread(cf, in, k.value.size, k.value.offset);
                assert(got == k.value.size);
                put_chunk(t, cf, l);

                int sz = k.value.size;
                if (sz < DUBTREE_BLOCK_SIZE) {
                    int unsz = LZ4_decompress_safe((const char*)in, (char*)out,
                                                   sz, DUBTREE_BLOCK_SIZE);
                    if (unsz != DUBTREE_BLOCK_SIZE) {
                        printf("%d vs %d, offset=%u size=%u\n", unsz, sz,
                               k.value.offset, sz);
                        return -1;
                    }
                }

                simpletree_next(&st, &it);
            }
            unmap_tree(st.mem, simpletree_get_nodes_size(&st));
            put_chunk(t, f, line);
        }
    }
    return 0;
}
