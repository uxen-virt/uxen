/*
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */
/*
 * Block driver for swap dubtree databases
 */

#include "config.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "aio.h"
#include "block-int.h"
#include "block.h"
#include "clock.h"
#include "os.h"
#include "qemu_bswap.h"
#include "thread-event.h"
#include "timer.h"

#ifndef _WIN32
#include <sys/mman.h>
#include <errno.h>
#endif

#include <uuid/uuid.h>

#include "block-swap/dubtree_io.h"
#include "block-swap/dubtree.h"
#include "block-swap/hashtable.h"
#include "block-swap/lrucache.h"
#include "block-swap/swapfmt.h"

#include <lz4.h>

#include "uuidgen.h"

#ifdef _WIN32
#include <winternl.h>
#define FILE_OPEN                         0x00000001
#define FILE_OPEN_BY_FILE_ID              0x00002000
#define FILE_NON_DIRECTORY_FILE           0x00000040
#define FILE_SEQUENTIAL_ONLY              0x00000004
#define FILE_OPEN_FOR_BACKUP_INTENT       0x00004000

typedef ULONG (__stdcall *pNtCreateFile)(
        PHANDLE FileHandle,
        ULONG DesiredAccess,
        PVOID ObjectAttributes,
        PVOID IoStatusBlock,
        PLARGE_INTEGER AllocationSize,
        ULONG FileAttributes,
        ULONG ShareAccess,
        ULONG CreateDisposition,
        ULONG CreateOptions,
        PVOID EaBuffer,
        ULONG EaLength
        );

extern HRESULT WINAPI FilterConnectCommunicationPort(
    LPCWSTR lpPortName,
    DWORD dwOptions,
    LPCVOID lpContext,
    WORD wSizeOfContext,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes ,
    HANDLE *hPort
    );

#endif

#define WRITE_RATELIMIT_THR_BYTES (32 << 20)
#define WRITE_BLOCK_THR_BYTES (WRITE_RATELIMIT_THR_BYTES * 2)
#define WRITE_RATELIMIT_GAP_MS 10

#define SWAP_SIZE_SHIFT (51ULL)
#define SWAP_SIZE_MASK (((1ULL<<(64-SWAP_SIZE_SHIFT))-1) << SWAP_SIZE_SHIFT)

uint64_t log_swap_fills = 0;
static int swap_backend_active = 0;

#if !defined(LIBIMG) && defined(CONFIG_DUMP_SWAP_STAT)
  #define SWAP_STATS
#endif

#define SWAP_SECTOR_SIZE DUBTREE_BLOCK_SIZE
#ifdef LIBIMG
  #define SWAP_LOG_BLOCK_CACHE_LINES 10
#else
  #define SWAP_LOG_BLOCK_CACHE_LINES 8
#endif

struct heap_elem {
    uint64_t key, value;
    uint32_t timestamp;
}__attribute__((__packed__));

static inline int less_than(struct heap_elem *a,
        struct heap_elem *b)
{
    if (a->key != b->key) {
        return a->key < b->key;
    } else {
        return a->timestamp < b->timestamp;
    }
}

static inline void sift_up(struct heap_elem *hp, size_t child)
{
    size_t parent;
    for (; child; child = parent) {
        parent = (child - 1) / 2;

        if (less_than(&hp[child], &hp[parent])) {
            struct heap_elem tmp = hp[parent];
            hp[parent] = hp[child];
            hp[child] = tmp;
        } else {
            break;
        }
    }
}

static inline void sift_down(struct heap_elem *hp, size_t end)
{
    size_t parent = 0;
    size_t child;
    struct heap_elem tmp;
    for (;; parent = child) {
        child = 2 * parent + 1;

        if (child >= end)
            break;

        /* point to the min child */
        if (child + 1 < end &&
                less_than(&hp[child + 1], &hp[child])) {
            ++child;
        }

        /* heap condition restored? */
        if (less_than(&hp[parent], &hp[child])) {
            break;
        }

        /* else swap and continue. */
        tmp = hp[parent];
        hp[parent] = hp[child];
        hp[child] = tmp;
    }
}

struct pq {
    struct heap_elem *heap;
    int max_heap;
    int n_heap;
    uint32_t timestamp;
};

static void pq_init(struct pq *pq)
{
    pq->heap = NULL;
    pq->max_heap = pq->n_heap = 0;
    pq->timestamp = 0;
}

static void pq_push(struct pq *pq, uint64_t key, uint64_t value)
{
    struct heap_elem *he;

    if (pq->n_heap == pq->max_heap) {
        pq->max_heap = pq->max_heap ? 2 * pq->max_heap : 1;
        pq->heap = realloc(pq->heap, sizeof(pq->heap[0]) * pq->max_heap);
    }

    he = pq->heap + pq->n_heap;
    he->key = key;
    he->value = value;
    he->timestamp = pq->timestamp++;
    sift_up(pq->heap, pq->n_heap++);
}

static inline int pq_len(struct pq *pq)
{
    return pq->n_heap;
}

static inline int pq_empty(struct pq *pq)
{
    return (pq_len(pq) == 0);
}

static inline struct heap_elem *pq_min(struct pq *pq)
{
    return pq->n_heap ? &pq->heap[0] : NULL;
}

static void pq_pop(struct pq *pq)
{
    pq->heap[0] = pq->heap[--(pq->n_heap)];
    sift_down(pq->heap, pq->n_heap);

    if (pq->n_heap == pq->max_heap / 2) {
        pq->max_heap = pq->n_heap;
        pq->heap = realloc(pq->heap, sizeof(pq->heap[0]) * pq->max_heap);
    }
    if (pq->n_heap == 0) {
        pq->timestamp = 0;
    }
}

typedef struct SwapMappedFile {
    void *mapping;
    uint64_t modulo;
    uint64_t size;
} SwapMappedFile;

typedef struct BDRVSwapState {

    /** Image name. */
    char *filename;
    char *swapdata;
    int num_fallbacks;
    char *fallbacks[DUBTREE_MAX_FALLBACKS + 1];
    /* Where the CoW kernel module places files. */
    char *cow_backup;
    uuid_t uuid;
    uint64_t size;

    SwapMappedFile shallow_map;
    size_t shallow_map_size;
    size_t num_maps;
    SwapMapTuple *map_idx;
    const char *map_strings;
    HashTable open_files;
    LruCache fc;
    HashTable cached_blocks;
    HashTable busy_blocks;
    LruCache bc;
    struct pq pqs[2];
    int pq_switch;
    uint64_t pq_cutoff;
    critical_section mutex;
    critical_section shallow_mutex;
    volatile int flush;
    volatile int quit;
    volatile int alloced;
    void *insert_context;

    thread_event write_event;
    thread_event can_write_event;
    uxen_thread write_thread;

    thread_event insert_event;
    thread_event can_insert_event;
    uxen_thread insert_thread;

    thread_event read_event;
    uxen_thread read_thread;

    thread_event all_flushed_event;

    DubTree t;
    void *find_context;

    int ios_outstanding;
    struct SwapAIOCB *read_queue_head;
    struct SwapAIOCB *read_queue_tail;
    TAILQ_HEAD(, SwapAIOCB) rlimit_write_queue;

    int log_swap_fills;
    int store_uncompressed;

#ifdef _WIN32
    HANDLE heap;
    dubtree_handle_t volume; /* Volume for opening by id. */
    LARGE_INTEGER map_file_creation_time; /* map.idx creation timestamp. */
#endif

} BDRVSwapState;


#ifdef SWAP_STATS
struct {
    uint64_t blocked_time;
    uint64_t compressed, decompressed, shallowed;
    uint64_t shallow_miss, shallow_read, dubtree_read, pre_proc_wait, post_proc_wait;
} swap_stats = {0,};
#endif

typedef struct SwapAIOCB {
    BlockDriverAIOCB common; /* must go first. */
    struct SwapAIOCB *next;
    TAILQ_ENTRY(SwapAIOCB) rlimit_write_entry;
    BlockDriverState *bs;
    uint64_t block;
    uint32_t size;
    uint8_t *buffer;
    uint8_t *tmp;
    uint32_t modulo;
    uint8_t *decomp;
    uint32_t *sizes;
    uint8_t *map;
    size_t orig_size;
    ioh_event event;
    int result;
    volatile int splits;
    Timer *ratelimit_complete_timer;
#ifdef _WIN32
    OVERLAPPED ovl;
#endif

#ifdef SWAP_STATS
    uint64_t t0, t1;
#endif

} SwapAIOCB;
/* Forward declarations. */
#ifdef _WIN32
static DWORD WINAPI swap_read_thread(void *_s);
#else
static void *swap_read_thread(void *_s);
#endif

/* Wrappers for compress and expand functions. */

static inline
size_t swap_set_key(void *out, const void *in)
{
    /* Caller has allocated ample space for compression overhead, so we don't
     * worry about about running out of space. However, there is no point in
     * storing more than DUBTREE_BLOCK_SIZE bytes, so if we exceed that we
     * revert to a straight memcpy(). When uncompressing we treat DUBTREE_BLOCK_SIZE'd
     * keys as special, and use memcpy() there as well. */

#ifdef SWAP_STATS
    swap_stats.compressed += DUBTREE_BLOCK_SIZE;
#endif

    size_t sz = LZ4_compress((const char*)in, (char*) out, DUBTREE_BLOCK_SIZE);
    if (sz >= DUBTREE_BLOCK_SIZE) {
        memcpy(out, in, DUBTREE_BLOCK_SIZE);
        sz = DUBTREE_BLOCK_SIZE;
    }

    return sz;
}

static inline int swap_get_key(void *out, const void *in, size_t sz)
{
#ifdef SWAP_STATS
    swap_stats.decompressed += DUBTREE_BLOCK_SIZE;
#endif

    if (sz == DUBTREE_BLOCK_SIZE) {
        memcpy(out, in, DUBTREE_BLOCK_SIZE);
    } else {
        int unsz = LZ4_decompress_safe((const char*)in, (char*)out,
                sz, DUBTREE_BLOCK_SIZE);
        if (unsz != DUBTREE_BLOCK_SIZE) {
#ifndef __APPLE__
            /* On OSX we don't like unclean exists, but on Windows our guest
             * will BSOD if we throw a read error. */
            errx(1, "swap: bad block size %d", unsz);
#else
            warnx("swap: bad block size %d", unsz);
#endif
            return -1;
        }
    }
    return 0;
}

static inline void swap_lock(BDRVSwapState *s)
{
    critical_section_enter(&s->mutex);
}

static inline void swap_unlock(BDRVSwapState *s)
{
    critical_section_leave(&s->mutex);
}

static inline void swap_signal_write(BDRVSwapState *s)
{
    thread_event_set(&s->write_event);
}

static inline void swap_signal_can_write(BDRVSwapState *s)
{
    thread_event_set(&s->can_write_event);
}

static inline void swap_signal_insert(BDRVSwapState *s)
{
    thread_event_set(&s->insert_event);
}

static inline void swap_signal_can_insert(BDRVSwapState *s)
{
    thread_event_set(&s->can_insert_event);
}

static inline void swap_signal_read(BDRVSwapState *s)
{
    thread_event_set(&s->read_event);
}

static inline void swap_wait_write(BDRVSwapState *s)
{
    thread_event_wait(&s->write_event);
}

#ifdef LIBIMG
static inline void swap_wait_can_write(BDRVSwapState *s)
{
    thread_event_wait(&s->can_write_event);
}
#endif

static inline void swap_wait_insert(BDRVSwapState *s)
{
    thread_event_wait(&s->insert_event);
}

static inline void swap_wait_can_insert(BDRVSwapState *s)
{
    thread_event_wait(&s->can_insert_event);
}

static inline void swap_wait_read(BDRVSwapState *s)
{
    thread_event_wait(&s->read_event);
}

static inline void swap_signal_all_flushed(BDRVSwapState *s)
{
    thread_event_set(&s->all_flushed_event);
}

static inline void swap_wait_all_flushed(BDRVSwapState *s)
{
    thread_event_wait(&s->all_flushed_event);
}

static void *swap_malloc(void *_s, size_t sz)
{
    BDRVSwapState *s = _s;
    __sync_fetch_and_add(&s->alloced, 1);
#ifdef _WIN32
    return HeapAlloc(s->heap, 0, sz);
#else
    return malloc(sz);
#endif
}

static void swap_free(void *_s, void *b)
{
    BDRVSwapState *s = _s;
    if (b) {
        __sync_fetch_and_sub(&s->alloced, 1);
#ifdef _WIN32
        HeapFree(s->heap, 0, b);
#else
        free(b);
#endif
    }
}

struct insert_context {
    int n;
    BDRVSwapState *s;
    uint8_t *cbuf;
    uint64_t *keys;
    uint32_t *sizes;
    size_t total_size;
};

#ifdef _WIN32
static DWORD WINAPI
#else
static void *
#endif
swap_insert_thread(void * _s)
{
    BDRVSwapState *s = _s;
    struct insert_context *c;
    int quit;
    int r;

    for (;;) {

        swap_signal_can_insert(s);
        swap_wait_insert(s);

        swap_lock(s);
        c = s->insert_context;
        s->insert_context = NULL;
        quit = s->quit;
        swap_unlock(s);
        if (!c) {
            if (quit) {
                break;
            }
            continue;
        }

        uint64_t *keys = c->keys;
        uint8_t *cbuf = c->cbuf;
        int n = c->n;
        int i;
        uint32_t load;

        r = dubtree_insert(&s->t, n, keys, cbuf, c->sizes, 0);
        free(c->sizes);

        swap_lock(s);
        for (i = 0; i < n; ++i) {
            HashEntry *e;
            e = hashtable_find_entry(&s->busy_blocks, keys[i]);
            assert(e);
            uint8_t *ptr = (uint8_t *) (uintptr_t) (e->value & ~SWAP_SIZE_MASK);

            if (cbuf <= ptr && ptr < cbuf + c->total_size) {
                hashtable_delete_entry(&s->busy_blocks, e);
            }
        }

        free(keys);
        swap_free(c->s, c->cbuf);
        free(c);
        load = s->busy_blocks.load;
        swap_unlock(s);

        if (load == 0) {
            swap_signal_all_flushed(s);
        }
        if (r < 0) {
            err(1, "dubtree_insert failed, r=%d!", r);
        }
    }
    debug_printf("%s exiting cleanly\n", __FUNCTION__);
    return 0;
}
static inline uint32_t buffered_size(BDRVSwapState *s)
{
    struct pq *pq1 = &s->pqs[s->pq_switch];
    struct pq *pq2 = &s->pqs[s->pq_switch ^ 1];;
    return SWAP_SECTOR_SIZE * (pq_len(pq1) + pq_len(pq2));
}

static inline int is_ratelimited_hard(BDRVSwapState *s)
{
    return (buffered_size(s) > WRITE_BLOCK_THR_BYTES);
}

static inline int is_ratelimited_soft(BDRVSwapState *s)
{
    return (buffered_size(s) > WRITE_RATELIMIT_THR_BYTES);
}

#ifdef _WIN32
static DWORD WINAPI
#else
static void *
#endif
swap_write_thread(void *_s)
{
    BDRVSwapState *s = (BDRVSwapState*) _s;
    size_t max_sz = 4<<20;
    uint8_t *cbuf = NULL;
    uint64_t *keys = NULL;
    uint32_t *sizes = NULL;
    uint32_t total_size = 0;
    int max = 0;
    int n = 0;

    swap_signal_can_write(s);

    for (;;) {
        /* Wait for more work? */
        uint64_t key;
        int flush = 0;
        HashEntry *e;
        uint64_t value;
        struct pq *pq1 = &s->pqs[s->pq_switch];
        struct pq *pq2 = &s->pqs[s->pq_switch ^ 1];;
        void *ptr = NULL;
        int quit;
        uint32_t size;

        swap_lock(s);
        if (n == 0 && pq_empty(pq1) && pq_empty(pq2)) {
wait:
            quit = s->quit;
            swap_unlock(s);

            swap_signal_can_write(s);
            if (quit) {
                break;
            }
            swap_wait_write(s);
            continue;
        }

        struct heap_elem *min = pq_min(pq1);
        if (min) {

            key = s->pq_cutoff = min->key;
            for (;;) {
                value = min->value;
                pq_pop(pq1);
                ptr = (void *) (uintptr_t) value;

                min = pq_min(pq1);
                if (!min || min->key != key) {
                    break;
                } else {
                    swap_free(s, ptr);
                }
            }

        } else {
            if (s->flush || is_ratelimited_soft(s)) {
                s->pq_switch ^= 1;
                s->pq_cutoff = ~0ULL;
                flush = 1;
            } else {
                goto wait;
            }
        }

        swap_unlock(s);

        if (flush || total_size + 2 * SWAP_SECTOR_SIZE > max_sz) {

            struct insert_context *c = malloc(sizeof(*c));
            c->n = n;
            c->s = s;
            c->cbuf = cbuf;
            c->keys = keys;
            c->sizes = sizes;
            c->total_size = total_size;

            swap_wait_can_insert(s);
            s->insert_context = c;
            swap_signal_insert(s);

            cbuf = NULL;
            keys = NULL;
            sizes = NULL;
            max = n = 0;
            total_size = 0;
        }

        if (!ptr) {
            continue;
        }

        if (!cbuf) {
            cbuf = swap_malloc(s, max_sz);
        }

        if (n == max) {
            max = max ? 2 * max : 1;
            keys = realloc(keys, sizeof(keys[0]) * max);
            sizes = realloc(sizes, sizeof(sizes[0]) * max);
        }

        /* The skip check about only works for duplicates already queued,
         * not ones that could arrive when not holding lock. So we have to
         * re-check here. */
        if (n && keys[n - 1] == key) {
            --n;
            total_size -= sizes[n];
        }

        keys[n] = key;
        if (s->store_uncompressed) {
            memcpy(cbuf + total_size, ptr, DUBTREE_BLOCK_SIZE);
            size = DUBTREE_BLOCK_SIZE;
        } else {
            size = swap_set_key(cbuf + total_size, ptr);
        }

        swap_lock(s);
        e = hashtable_find_entry(&s->busy_blocks, key);
        if (e && e->value == value) {
            e->value = (((uint64_t ) size) << SWAP_SIZE_SHIFT) |
                (uintptr_t) (cbuf + total_size);
        }
        swap_unlock(s);

        swap_free(s, ptr);

        sizes[n] = size;
        total_size += size;
        ++n;
    }

    assert(!cbuf);

    debug_printf("%s exiting cleanly\n", __FUNCTION__);
    return 0;
}

#ifdef _WIN32
static char *strsep(char **stringp, const char *delim)
{
    char *begin, *end;

    begin = *stringp;
    if (!begin)
        return NULL;

    if (!delim[0] || !delim[1]) {
        char ch = delim[0];

        if (ch == '\0')
            end = NULL;
        else {
            if (*begin == ch)
                end = begin;
            else if (*begin == '\0')
                end = NULL;
            else
                end = strchr(begin + 1, ch);
        }
    } else
        end = strpbrk(begin, delim);

    if (end) {
        *end++ = '\0';
        *stringp = end;
    } else
        *stringp = NULL;

    return begin;
}
#endif

static int swap_read_header(BDRVSwapState *s)
{
    ssize_t got;
    FILE *file;
    char *buff;
    size_t len;
    char *next;
    char *line;
    struct stat st;

    file = fopen(s->filename, "r");
    if (!file) {
        warn("swap: unable to open %s", s->filename);
        return -1;
    }

    if (fstat(fileno(file), &st) < 0) {
        warn("swap: unable to stat %s", s->filename);
        fclose(file);
        return -1;
    }
    len = st.st_size;

    buff = malloc(len ? len + 1 : 0);
    if (!buff) {
        warn("swap: no memory or file empty");
        fclose(file);
        return -1;
    }

    got = fread(buff, 1, len, file);
    if (got < len) {
        warn("swap: unable to read %s", s->filename);
        fclose(file);
        free(buff);
        return -1;
    }
    fclose(file);
    buff[len] = '\0';

    next = buff;
    while ((line = strsep(&next, "\r\n"))) {
        if (!strncmp(line, "size=", 5)) {
            s->size = strtoll(line + 5, NULL, 0);
        } else if (!strncmp(line, "uuid=", 5)) {
            uuid_parse(line + 5 + (line[5]=='{'), s->uuid);
        } else if (!strncmp(line, "swapdata=", 9)) {
            s->swapdata = strdup(line + 9);
            if (!s->swapdata) {
                errx(1, "OOM error %s line %d", __FUNCTION__, __LINE__);
            }
        } else if (!strncmp(line, "fallback=", 9)) {
            s->fallbacks[s->num_fallbacks++] = strdup(line + 9);
        }
    }

    free(buff);

    return 0;
}

/* Map a file into memory, closing the file handle whether we succeed or not.
 * If caller supplies 0 as length, maps the entire file. If caller supplies
 * length > actual file length (likely for shallow maps, as these are 4kIB
 * block aligned), we map as much as we have. */
#ifdef _WIN32
int swap_map_file(HANDLE file,
        uint64_t offset, uint64_t length,
        SwapMappedFile *mf)
{
    int r = 0;
    HANDLE h = INVALID_HANDLE_VALUE;
    uint64_t file_size;
    SYSTEM_INFO si;
    static uint64_t granularity = 0;

    file_size = GetFileSize(file, NULL) - offset;  /* XXX 32-bit only. */
    /* Check for no caller-supplied length, or one exceeding file size. */
    mf->size = (!length || file_size < length) ? file_size : length;

    /* Windows usually has 64kiB mapping granularity, and the offset into
     * the file must be aligned to this. */
    if (!granularity) {
        GetSystemInfo(&si);
        granularity = si.dwAllocationGranularity;
    }
    mf->modulo = offset & (granularity - 1);
    offset -= mf->modulo;
    mf->size += mf->modulo;

    h = CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!h) {
        Werr(1, "swap: unable to map file");
        r = -1;
        goto out;
    }

    mf->mapping = MapViewOfFile(h, FILE_MAP_COPY, 0, offset, mf->size);
    if (!mf->mapping) {
        debug_printf("failed offset=%"PRIx64" size=%"PRIx64"\n", offset, mf->size);
        Werr(1, "swap: unable to map view");
        r = -1;
    }

    /* No longer need the mapping and file handles. */
out:
    if (h) {
        CloseHandle(h);
    }
    CloseHandle(file);
    return r;
}

void swap_unmap_file(SwapMappedFile *mf)
{
    UnmapViewOfFile(mf->mapping);
}

static inline HANDLE open_file_readonly(const char *fn)
{
    return CreateFile(fn, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
            OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
}

static inline void close_file(HANDLE f)
{
    CloseHandle(f);
}

#else
/* See comment for win32 version above. */
int swap_map_file(int file,
        uint64_t offset,
        uint64_t length,
        SwapMappedFile *mf)
{
    struct stat st;
    static uint64_t granularity = 0;

    if (fstat(file, &st) < 0) {
        close(file);
        return -1;
    }

    /* Check for no caller-supplied length, or one exceeding file size. */
    mf->size = (!length || st.st_size < length) ? st.st_size : length;

    /* Adjust supplied offset to match system mapping granularity. */
    if (!granularity) {
        granularity = sysconf(_SC_PAGESIZE);
    }
    mf->modulo = offset & (granularity - 1);
    offset -= mf->modulo;
    mf->size += mf->modulo;

    mf->mapping = mmap(NULL, mf->size, PROT_READ, MAP_PRIVATE, file, offset);
    /* Always close fd as we no longer need it. */
    close(file);
    if (mf->mapping == MAP_FAILED) {
        err(1, "unable to map file");
        return -1;
    }
    return 0;
}

void swap_unmap_file(SwapMappedFile *mf)
{
    munmap(mf->mapping, mf->size);
}

static inline int open_file_readonly(const char *fn)
{
    int f = open(fn, O_RDONLY | O_NOATIME);
    return f < 0 ? DUBTREE_INVALID_HANDLE : f;
}

static inline void close_file(int f)
{
    close(f);
}
#endif

static int swap_init_map(BDRVSwapState *s, char *path, char *cow_backup)
{
    uint32_t *idx;
    dubtree_handle_t map_file;

    /* Is there a 'cow' dir under swapdata? */
    if (file_exists(cow_backup)) {
        s->cow_backup = strdup(cow_backup);
        if (!s->cow_backup) {
            warnx("OOM error %s line %d", __FUNCTION__, __LINE__);
            return -1;
        }
    } else {
        s->cow_backup = NULL;
    }

    /* Map the binary-searchable index over shallow mapped files. */
    map_file = open_file_readonly(path);
    if (map_file == DUBTREE_INVALID_HANDLE) {
        return -1;
    }

#ifdef _WIN32
    char vol[8];
    /* Open the volume that holds the cow directory. */
    if (s->cow_backup && (strlen(s->cow_backup) > 1) && (s->cow_backup[1] == ':')) {
        sprintf(vol, "\\\\.\\%2.2s", s->cow_backup);
    } else {
        sprintf(vol, "\\\\.\\C:");
    }
    debug_printf("swap: opening volume\n");
    s->volume = CreateFile(
                    vol,
                    0, /* This needs to be zero else low-privilege processes will get ERROR_ACCESS_DENIED */
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    NULL);
    debug_printf("swap: opening volume done\n");
    if (s->volume == INVALID_HANDLE_VALUE) {
        Wwarn("swap: error opening volume %s", vol);
        return -1;
    }

    if (!GetFileTime(map_file, (LPFILETIME)&s->map_file_creation_time, NULL, NULL)) {
        Werr(1, "unable to get creation time of map.idx");
        return -1;
    }
#endif

    /* swap_map_file() always closes the file handle. */
    if (swap_map_file(map_file, 0, 0, &s->shallow_map) < 0) {
        Werr(1, "unable to map map.idx!");
        return -1;
    }

    idx = (uint32_t*) s->shallow_map.mapping;
    s->num_maps= idx[0];
    s->map_idx = (SwapMapTuple*) &idx[1];
    s->map_strings = (const char*) &s->map_idx[s->num_maps];
    return 0;
}

static inline
char *swap_resolve_via_fallback(BDRVSwapState *s, const char *fn)
{
    char **fb;
    char *check = NULL;
    for (fb = s->fallbacks; *fb; ++fb) {
        asprintf(&check, "%s/%s", *fb, fn);
        if (!check) {
            break;
        }
        if (file_exists(check)) {
            break;
        } else {
            free(check);
            check = NULL;
        }
    }
    return check;
}


static int swap_open(BlockDriverState *bs, const char *filename, int flags)
{
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    int r = 0;
    char *path, *real_path;
    char *swapdata = NULL;
    char *cow = NULL;
    char *map;
    char *c, *last;
    int i;
    /* Start out with well-defined state. */
    memset(s, 0, sizeof(*s));
    TAILQ_INIT(&s->rlimit_write_queue);

    s->log_swap_fills = log_swap_fills;

#ifdef _WIN32
    s->heap = HeapCreate(0, 0, 0);
#endif

    /* Strip swap: prefix from path if given. */
    if (strncmp(filename, "swap:", 5) == 0) {
        s->filename = strdup(filename + 5);
    } else {
        s->filename = strdup(filename);
    }
    if (!s->filename) {
        errx(1, "OOM out %s line %d", __FUNCTION__, __LINE__);
    }

    s->num_fallbacks = 1;

    /* Read the .swap header file from disk, there is no data there,
     * just some pointers into the shared swapdata structure. */
    r = swap_read_header(s);
    if (r != 0) {
        r = -1;
        warn("unable to parse header %s", s->filename);
        goto out;
    }

    /* Chop off filename to reveal dir. */
    path = strdup(s->filename);
    if (!path) {
        errx(1, "OOM error %s line %d", __FUNCTION__, __LINE__);
    }
    for (c = last = path; *c; ++c) {
#ifdef _WIN32
        if (*c == '/' || *c == '\\') {
#else
        if (*c == '/') {
#endif
            last = c;
        }
    }
    *last = '\0';
    real_path = dubtree_realpath(path[0] ? path : ".");

    /* Generate swapdata path, taking into account user override
     * of "swapdata" component. */
    char *default_swapdata;
    char uuid_str[37];
    uuid_unparse_lower(s->uuid, uuid_str);
    asprintf(&default_swapdata, "swapdata-%s", uuid_str);
    asprintf(&swapdata, "%s/%s",
            real_path, s->swapdata ? s->swapdata : default_swapdata);
    free(default_swapdata);
    free(real_path);
    free(path);

    if (!swapdata) {
        errx(1, "OOM out %s line %d", __FUNCTION__, __LINE__);
    }

    /* Setting the head of the fallbacks list last, the tail was possibly
     * filled out by swap_read_header(). */
    s->fallbacks[0] = swapdata;

    debug_printf("swap: swapdata at %s\n", swapdata);
    for (i = 1; i < s->num_fallbacks; ++i) {
        const char *fb = s->fallbacks[i];
        debug_printf("swap: fallback %d %s\n", i, fb);
        if (!file_exists(fb)) {
            errx(1, "swap: fallback %s does not exist!", fb);
        }
    }

    debug_printf("swap: initializing dubtree\n");
    if (dubtree_init(&s->t, s->fallbacks, swap_malloc, swap_free, s) != 0) {
        warn("swap: failed to init dubtree");
        r = -1;
        goto out;
    }

    debug_printf("swap: resolving map.idx\n");
    map = swap_resolve_via_fallback(s, "map.idx");
    debug_printf("swap: resolving cow\n");
    cow = swap_resolve_via_fallback(s, "cow");

    debug_printf("swap: initializing map\n");
    /* Try to set up map.idx shallow index mapping, if present. */
    if (swap_init_map(s, map, cow) != 0) {
        debug_printf("swap: no map file found at '%s'\n", map);
    }

    debug_printf("swap: initializing hashtable for map\n");
    /* Cache of open shallow file handles. */
    if (hashtable_init(&s->open_files, NULL, NULL) < 0) {
        warn("swap: unable to create hashtable for map");
        return -1;
    }
    debug_printf("swap: initializing lrucache for map\n");
    if (lru_cache_init(&s->fc, 6) < 0) {
        warn("swap: unable to create lrucache for map");
        return -1;
    }

    /* A small write-back block cache, this is mainly to keep hot blocks such
     * as FS superblocks from getting inserted into the dubtree over and over.
     * This has large impact on the performance the libimg tools, and also
     * helps with e.g. USN journaling from a Windows guest. We cache only
     * blocks we write, on the assumption that the host OS takes care of normal
     * read caching and that decompression with LZ4 is cheap. */
    debug_printf("swap: initializing wb cache\n");
    if (hashtable_init(&s->cached_blocks, NULL, NULL) < 0) {
        warn("swap: unable to create hashtable for block cache");
        return -1;
    }
    if (hashtable_init(&s->busy_blocks, NULL, NULL) < 0) {
        warn("swap: unable to create hashtable for busy blocks index");
        return -1;
    }
    if (lru_cache_init(&s->bc, SWAP_LOG_BLOCK_CACHE_LINES) < 0) {
        warn("swap: unable to create lrucache for blocks");
        return -1;
    }

    for (i = 0; i < 2; ++i) {
        pq_init(&s->pqs[i]);
    }
    s->pq_switch = 0;
    s->pq_cutoff = ~0ULL;

    s->quit = 0;
    s->flush = 0;

    critical_section_init(&s->mutex); /* big lock. */
    critical_section_init(&s->shallow_mutex); /* protects shallow cache. */

    thread_event *events[] = {
        &s->write_event,
        &s->can_write_event,
        &s->insert_event,
        &s->can_insert_event,
        &s->read_event,
        &s->all_flushed_event,
    };

    for (i = 0; i < sizeof(events) / sizeof(events[0]); ++i) {
        thread_event *ev = events[i];
        if (thread_event_init(ev) < 0) {
            Werr(1, "swap: unable to create event!");
        }
    }

    debug_printf("swap: creating threads\n");
    if (create_thread(&s->write_thread, swap_write_thread, (void*) s) < 0) {
        Werr(1, "swap: unable to create thread!");
    }

    if (create_thread(&s->insert_thread, swap_insert_thread, (void*) s) < 0) {
        Werr(1, "swap: unable to create thread!");
    }

    if (create_thread(&s->read_thread, swap_read_thread, (void*) s) < 0) {
        Werr(1, "swap: unable to create read thread!");
    }
    elevate_thread(s->read_thread);

    bs->total_sectors = s->size >> BDRV_SECTOR_BITS;

    debug_printf("%s: done\n", __FUNCTION__);
out:
    if (r < 0) {
        warnx("swap: failed to open %s", filename);
    }

    free(cow);
    swap_backend_active = 1; /* activates stats logging. */
    return r;
}

/* Delete the snapshot referenced by this backend instance,
 * and the .swap file on disk. */
static int swap_remove(BlockDriverState *bs)
{
    int r;
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    dubtree_delete(&s->t);
    r = unlink(s->filename);
    if (r < 0) {
        debug_printf("swap: unable to unlink %s\n", s->filename);
        return r;
    }
    return 0;
}

void dump_swapstat(void)
{
#ifdef SWAP_STATS
    if (swap_backend_active) {
        debug_printf("SWAP blocked=%"PRId64"ms "
                "sh_open=%"PRId64"ms "
                "sh_read=%"PRId64"ms "
                "read=%"PRId64"ms "
                "sched_pre=%"PRId64"ms "
                "sched_post=%"PRId64"ms "
                "(out=%"PRId64"MiB,in=%"PRId64"MiB,sh_in=%"PRId64"MiB)\n",
                swap_stats.blocked_time / SCALE_MS,
                swap_stats.shallow_miss / SCALE_MS,
                swap_stats.shallow_read / SCALE_MS,
                swap_stats.dubtree_read / SCALE_MS,
                swap_stats.pre_proc_wait / SCALE_MS,
                swap_stats.post_proc_wait / SCALE_MS,
                swap_stats.compressed >> 20ULL,
                swap_stats.decompressed >> 20ULL,
                swap_stats.shallowed >> 20ULL);
    }
#endif
}

static inline const SwapMapTuple *swap_resolve_mapped_file(
        BDRVSwapState *s, uint64_t block)
{
    size_t half;
    size_t len = s->num_maps;
    const SwapMapTuple *first = s->map_idx;
    const SwapMapTuple *middle;
    const SwapMapTuple *end = first + len;

    /* Perform binary search over the sorted memory mapped array of file extent
     * descriptor tuples. The extents are indexed by the end (first block to
     * the right of the extent, ie. start+length), which fits with how a
     * STL-type lower_bound() binary search works. Note that we search here for
     * block+1. */

    while (len > 0) {
        half = len >> 1;
        middle = first + half;

        if (middle->end < (block + 1)) {
            first = middle + 1;
            len = len - half - 1;
        } else
            len = half;
    }

    if (first != end && block >= first->end - first->size && block != first->end) {
        /* We found an extent covered by a host-side file. */
        return first;
    } else {
        return NULL;
    }
}

#ifdef _WIN32
static dubtree_handle_t
swap_open_file_by_id(HANDLE volume, uint64_t file_id)
{
    static pNtCreateFile NtCreateFile = NULL;
    HANDLE h;
    IO_STATUS_BLOCK iosb = {{0}};
    OBJECT_ATTRIBUTES oa = {sizeof(oa), 0};
    UNICODE_STRING name;

    name.Buffer = (PWSTR)&file_id;
    name.Length = name.MaximumLength = sizeof(file_id);
    oa.ObjectName = &name;
    oa.RootDirectory = volume;

    if (!NtCreateFile) {
    /* ntdll.dll will always be loaded! */
        NtCreateFile = (pNtCreateFile)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtCreateFile");
        assert(NtCreateFile);
    }

    NTSTATUS rc = NtCreateFile(
            &h,
            GENERIC_READ,
            &oa,
            &iosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_OPEN_BY_FILE_ID | FILE_OPEN_FOR_BACKUP_INTENT | FILE_NON_DIRECTORY_FILE,
            NULL,
            0);

    if (rc) {
        debug_printf("rc %x for file_id %"PRIx64"\n",
            (uint32_t) rc, (uint64_t) file_id);
        h = DUBTREE_INVALID_HANDLE;
    }
    return h;
}

#if !defined(LIBIMG)
initcall(swap_early_init)
{
    HANDLE cow_port;

    /* Connect to the BrCoW driver. Connecting to it enables the current process to read files
       that have been opened exclusively by some other process. */
    (HRESULT)FilterConnectCommunicationPort(L"\\CoWAllowReadPort", 0, NULL, 0,
        NULL, &cow_port);

    /* If successful cow_port will be released at process exit. */
}
#endif /* !defined(LIBIMG) */

#endif

/* Fill in blocks that are missing after dubtree_find() call, by looking for
 * shallow files that would fit in the 'holes' in our read result.
 *
 * Loop over length of IO, where "map" describes which blocks still need
 * reading. Create IOs or memset-with-zero'es to fill the remaining holes.  We
 * memory map files of non-trivial size, so that once we have them open, we can
 * safely cache them for future use without worrying that they might change on
 * the host. The caching is there mainly to avoid opening and close the file
 * multiple times when a VM scans through a big file, not to try and compete
 * with the VM's buffer cache.
 *
 * So far the memory mapping is mainly useful on OSX, where we have a kernel
 * module that makes CoW-backups of files we have shallowed, placing them in
 * the swapdata/cow directory. Each time we lookup a shallow file, we look
 * under the cow directory first. Because memory mappings are not free, we
 * fast-path small files under 4kiB, especially OSX has many of those. */

static int swap_fill_read_holes(BDRVSwapState *s, uint64_t offset, uint64_t count,
        uint8_t *buffer, uint8_t *map)
{
    critical_section_enter(&s->shallow_mutex);
    uint64_t start = offset / SWAP_SECTOR_SIZE;
    uint64_t end = (offset + count + SWAP_SECTOR_SIZE - 1) / SWAP_SECTOR_SIZE;
    uint64_t length = end - start;
    int r = 0;

    size_t i, j;
    int reading = 0;
    LruCache *fc = &s->fc;

    for (i = j = 0; ; ++i) {

        if (reading && (i == length || map[i] != 0)) {

            /* We need to fill the blocks between j to i. */

            while (j < i) {

                const SwapMapTuple *tuple;
                uint64_t readOffset = SWAP_SECTOR_SIZE * j;
                uint64_t take = i * SWAP_SECTOR_SIZE;
                uint64_t block = (offset + readOffset) / SWAP_SECTOR_SIZE;

                /* Don't read more bytes than caller requested. */
                take = take < count ? take : count;
                /* Account for bytes read already. */
                take -= readOffset;

                /* Clear output buffer so that we don't leak data to the VM. */
                memset(buffer + readOffset, 0, take);

                /* See if these blocks are backed by a shallow mapped file. */
                if (s->map_idx && (tuple = swap_resolve_mapped_file(s, block))) {

                    uint64_t line;
                    SwapMappedFile *evicted = NULL;
                    SwapMappedFile *file = NULL;
                    dubtree_handle_t handle = DUBTREE_INVALID_HANDLE;
                    uint64_t map_offset;
                    uint64_t tuple_start = tuple->end - tuple->size;
                    uint64_t blocks_available = tuple->size - (block - tuple_start);

                    if (take > (blocks_available * SWAP_SECTOR_SIZE)) {
                        take = blocks_available * SWAP_SECTOR_SIZE;
                    }

                    /* Do we already have the file open? We protect the cache
                     * against concurrent access from sync and async threads. */
#ifdef SWAP_STATS
                    uint64_t t0 = os_get_clock();
#endif
                    if (hashtable_find(&s->open_files, (uint64_t)(uintptr_t)tuple,
                                &line)) {
                        /* We had a mapping cached already. */
                        file = (SwapMappedFile*) lru_cache_touch_line(fc, line)->value;
                    }

                    if (!file) {
                        /* No cached mapping for the file. Need to create one. */
                        const char *filename = s->map_strings + tuple->name_offset;

                        /* Completely seperate the file open logic of WIN32 from OSX. This helps
                           quite a bit with readability. */
#ifdef _WIN32
                        dubtree_handle_t tmp_handle = DUBTREE_INVALID_HANDLE;
                        /* In the case of WIN32, open the original file and compare its timestamp
                           with the timestamp of map.idx. If the creation-time of the file is newer,
                           use the copy from the cow directory. Since CoWed files are expected to
                           be much lesser in number than original files this approach is better. */

#if !defined(LIBIMG) && defined(SWAP_STATS)
                        debug_printf("swap: open %s\n", filename);
#endif

                        /* Open by file-id */
                        LARGE_INTEGER file_id;
                        file_id.HighPart = tuple->file_id_highpart;
                        file_id.LowPart = tuple->file_id_lowpart;

                        handle = swap_open_file_by_id(s->volume, file_id.QuadPart);

                        if (handle != DUBTREE_INVALID_HANDLE) {
                            /* Check that the file was modified before the template was created. */
                            LARGE_INTEGER file_modification_time;
                            if (!GetFileTime(handle, NULL, NULL, (LPFILETIME)&file_modification_time)) {
                                debug_printf("Error in getting file modification time for [0x%"PRIx64"] : [%d]\n",
                                                file_id.QuadPart, (int)GetLastError());
                                debug_printf("Will use file without caring about if it is newer or not.\n");
                            } else if (file_modification_time.QuadPart > s->map_file_creation_time.QuadPart){
                                /* This file was modified after the init. The original copy will be CoWed.
                                   Hence cache this handle and go ahead and open from cow directory.
                                   Note that a difference in timezones could also cause this symptom. */
                                tmp_handle = handle;
                                handle = DUBTREE_INVALID_HANDLE;
                            }
                        }

                        /* Check if a CoW backup is needed and exists. */
                        if (handle == DUBTREE_INVALID_HANDLE && s->cow_backup) {
                            /* 16 bytes for name, ".copy" is 5, '/' is 1, '\0' is 1 */
                            char cow[strlen(s->cow_backup) + 24];
                            sprintf(cow, "%s/%08X%08X.copy", s->cow_backup,
                                        tuple->file_id_highpart, tuple->file_id_lowpart);

                            handle = open_file_readonly(cow);
                            if (handle != DUBTREE_INVALID_HANDLE) {
                                debug_printf("swap: open [%s] backed up by cow file [%s]\n", filename, cow);
                            }
                        }

                        if (handle == DUBTREE_INVALID_HANDLE) {
                            /* Ultimately try opening the file from the path or cached file-id.
                               Note that it may just be due to timezone issues that the
                               file has a newer time-stamp and has not been CoWed. */
                            debug_printf("swap: unable to open shallow %s"
                                  " from cow; opening using file-id or path.\n",
                                  filename);
                            if (tmp_handle != DUBTREE_INVALID_HANDLE) {
                                /* small optimization: use the open from file-id*/
                                handle = tmp_handle;
                                tmp_handle = DUBTREE_INVALID_HANDLE;
                            } else {
                                handle = open_file_readonly(filename);
                            }
                        }

                        if (tmp_handle != DUBTREE_INVALID_HANDLE) {
                            close_file(tmp_handle);
                            tmp_handle = DUBTREE_INVALID_HANDLE;
                        }

#else

                        /* First see if a CoW backup exists for this file. */
                        if (s->cow_backup) {
                            /* Use the index into the map as the file id,
                             * kernel module uses same naming convention. */

                            /* 8 bytes for name, ".copy" is 5, '/' is 1, '\0' is 1 */
                            char cow[strlen(s->cow_backup) + 16];
                            uint32_t id = tuple - s->map_idx;
                            sprintf(cow, "%s/%u.copy", s->cow_backup, id);

                            handle = open_file_readonly(cow);
                        }

                        if (handle == DUBTREE_INVALID_HANDLE) {
                            /* When no CoW backup, use the normal shallow file name. */
                            handle = open_file_readonly(filename);
                        }
#endif

                        /* No CoW file and no orig. shallow file. We're doomed. */
                        if (handle == DUBTREE_INVALID_HANDLE) {
                            Wwarn("swap: failed to open shallow %s", filename);
                            goto next;
                        }

                        /* Is this a small file that we can always read in one go,
                         * then we will perform the read now and continue to the
                         * next block without caching anything. */
                        if (SWAP_SECTOR_SIZE * tuple->size <= take) {
                            if (dubtree_pread(handle, buffer + readOffset, take,
                                        SWAP_SECTOR_SIZE *
                                        ((block - tuple_start) +
                                        tuple->file_offset)) < 0) {
                                Wwarn("swap: failed to read shallow %s",
                                      filename);
                                close_file(handle);
                                goto next;
                            }
                            close_file(handle);
                            /* On to the next block in our read. */
                            ++j;
#ifdef SWAP_STATS
                            swap_stats.shallow_miss += os_get_clock() - t0;
#endif
                            continue;
                        }

                        /* File is big enough that we will bother with mapping
                         * it. The swap_map_file() function will close the file
                         * handle after use. */
                        file = malloc(sizeof(SwapMappedFile));
                        if (!file) {
                            /* Treat malloc failing here just like an open or
                             * read error, by returning zeroes to the VM. Because
                             * we're not on the main thread, we cannot throw an
                             * err(), but quite likely the other threads are
                             * going to fail soon anyway. */
                            warnx("swap: OOM %s %d", __FUNCTION__, __LINE__);
                            goto next;
                        }

                        r = swap_map_file(handle,
                                SWAP_SECTOR_SIZE * tuple->file_offset,
                                SWAP_SECTOR_SIZE * tuple->size, file);
                        if (r < 0) {
                            Wwarn("swap: mapping %s fails", filename);
                            free(file);
                            goto next;
                        }
#ifndef _WIN32
                        /* Under POSIX, tell the OS we will likely be needing the
                         * whole file, so it can start prefetching. XXX measure
                         * this. */
                        posix_madvise(file->mapping, file->size,
                                POSIX_MADV_SEQUENTIAL | POSIX_MADV_WILLNEED);
#endif

                        /* Insert newly mapped file into file cache. */
                        line = lru_cache_evict_line(fc);
                        LruCacheLine *cl = lru_cache_touch_line(fc, line);

                        if (cl->key) {
                            /* Remove evicted entry's key from hash table. */
                            hashtable_delete(&s->open_files, (uint64_t)(uintptr_t)cl->key);
                            evicted = (SwapMappedFile*) cl->value;
                        }
                        cl->value = (uintptr_t) file;
                        cl->key = (uintptr_t) tuple;

                        hashtable_insert(&s->open_files, (uint64_t)(uintptr_t)tuple, line);
#ifdef SWAP_STATS
                        swap_stats.shallow_miss += os_get_clock() - t0;
#endif
                    }

                    if (evicted) {
                        swap_unmap_file(evicted);
                        free(evicted);
                    }

                    /* Figure out what to copy from file mapping, taking into account
                     * the offset of the shallow mapping and the modulo wrt the host
                     * OS' page granularity. */
                    map_offset = SWAP_SECTOR_SIZE * (block - tuple_start) +
                        file->modulo;

                    /* Only begin read before EOF. */
                    if (map_offset < file->size) {
                        /* Cap read to not go past EOF. */
                        if (map_offset + take > file->size) {
                            take = file->size - map_offset;
                        }
                        /* Read from the mapping. */
#ifdef SWAP_STATS
                        uint64_t t0 = os_get_clock();
#if 0
                        debug_printf("swap-stat: read fn=%s offset=%"PRIx64" take=%"PRIx64"\n",
                                filename,
                                map_offset, take);
#endif
#endif
                        if (s->log_swap_fills) {
                            const char *filename = s->map_strings + tuple->name_offset;
                            debug_printf("swap_fill_read_holes {\"filename\":\"%s\","
                                    " \"take\":0x%"PRIx64","
                                    " \"offset\":0x%"PRIx64"}\n",
                                    filename,
                                    take,
                                    map_offset);
                        }
                        memcpy(buffer + readOffset,
                                (uint8_t*)file->mapping + map_offset, take);
#ifdef SWAP_STATS
                        swap_stats.shallowed += take;
                        swap_stats.shallow_read += os_get_clock() - t0;
#endif
                    }

                    /* Increment j by how many blocks we were supposed to read,
                     * as we have zero-filled any blocks we did not manage to
                     * get from shallow files (memset above). */
next:
                    j += blocks_available;

                } else {
                    /* try next block, really, don't just silently
                     * skip...  because guess what, that actually
                     * causes incorrect data to be returned *sigh* */
                    j++;
                }

            }

            reading = 0;
            j = 0;

        }

        if (i == length) break;

        if (!reading && map[i] == 0) {
            reading = 1;
            j = i;
        }
    }
    critical_section_leave(&s->shallow_mutex);
    return 0;
}

static inline void swap_common_cb(SwapAIOCB *acb)
{
    BDRVSwapState *s = (BDRVSwapState*) acb->bs->opaque;
#ifdef SWAP_STATS
    int64_t dt = os_get_clock() - acb->t0;
    if (dt / SCALE_MS > 1000) {
        debug_printf("%s: aio waited %"PRId64"ms\n", __FUNCTION__,
                dt / SCALE_MS);
    }
    swap_stats.blocked_time += dt;
#endif
    --(s->ios_outstanding);
    if (TAILQ_ACTIVE(acb, rlimit_write_entry)) {
        TAILQ_REMOVE(&s->rlimit_write_queue, acb,
                     rlimit_write_entry);
    }
    aio_del_wait_object(&acb->event);
    aio_release(acb);
}

static void bdrv_swap_aio_cancel(BlockDriverAIOCB *_acb)
{
    SwapAIOCB *acb = (SwapAIOCB *)_acb;
    swap_common_cb(acb);
}

static AIOPool swap_aio_pool = {
    .aiocb_size = sizeof(SwapAIOCB),
    .cancel = bdrv_swap_aio_cancel,
};


static inline void complete_read_acb(SwapAIOCB *acb)
{
    if (__sync_fetch_and_sub(&acb->splits, 1) == 1) {
        ioh_event_set(&acb->event);
    }
}

#ifdef _WIN32
static DWORD WINAPI swap_read_thread(void *_s)
#else
static void * swap_read_thread(void *_s)
#endif
{
    BDRVSwapState *s = (BDRVSwapState*) _s;
    SwapAIOCB *acb;

    for (;;) {

        for (;;) {
            int quit;

            swap_lock(s);
            acb = s->read_queue_head;
            quit = s->quit;
            s->read_queue_head = NULL;
            swap_unlock(s);

            if (acb)
                break; /* process reads. */
            else if (quit) {
                debug_printf("%s exiting cleanly\n", __FUNCTION__);
                return 0; /* quit. */
            } else
                swap_wait_read(s);
        }


#ifdef SWAP_STATS
        SwapAIOCB *a = acb;
        while (a) {
            swap_stats.pre_proc_wait += os_get_clock() - acb->t0;
            a = a->next;
       }
#endif

        while (acb) {
            /* Squirrel acb->next for the case where acb may get freed
             * by a callback triggered by IO completion. */
            SwapAIOCB *next = acb->next;

            uint8_t *b = acb->tmp ? acb->tmp : acb->buffer;
            int r = swap_fill_read_holes(s, acb->block * SWAP_SECTOR_SIZE,
                    acb->size, b, acb->map);
            if (r < 0) {
                acb->result = r;
            }

#ifdef SWAP_STATS
            acb->t1 = os_get_clock();
#endif
            complete_read_acb(acb);
            acb = next;
        }
    }
    /* Never reached. */
}


static SwapAIOCB *swap_aio_get(BlockDriverState *bs,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    SwapAIOCB *acb;
    acb = aio_get(&swap_aio_pool, bs, cb, opaque);
    assert(acb);
    if (!ioh_event_valid(&acb->event)) {
        ioh_event_init(&acb->event);
    } else {
        ioh_event_reset(&acb->event);
    }
    acb->bs = bs;
    acb->result = -1;
    acb->map = NULL;
    acb->splits = 0;
    memset(&acb->rlimit_write_entry, 0, sizeof(acb->rlimit_write_entry));

    ++(s->ios_outstanding);

#ifdef SWAP_STATS
    acb->t0 = os_get_clock();
    acb->t1 = 0;
#endif
    return acb;
}

static void swap_read_cb(void *opaque)
{
    SwapAIOCB *acb = opaque;

#ifdef SWAP_STATS
    swap_stats.post_proc_wait += os_get_clock() - acb->t1;
#endif

    if (acb->tmp) {
        memcpy(acb->buffer, acb->tmp + acb->modulo, acb->size - acb->modulo);
        free(acb->tmp);
    }
    free(acb->map);
    acb->common.cb(acb->common.opaque, 0);
    swap_common_cb(acb);
}
static int __swap_nonblocking_write(BDRVSwapState *s, const uint8_t *buf,
                                    uint64_t block, size_t size, int dirty);

static void swap_rmw_cb(void *opaque)
{
    SwapAIOCB *acb = opaque;
    BlockDriverState *bs = acb->bs;
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    int n;

    memcpy(acb->tmp + acb->modulo, acb->buffer, acb->orig_size);
    swap_lock(s);
    n = __swap_nonblocking_write(s, acb->tmp, acb->block, acb->size, 1);
    swap_unlock(s);
    if (n) {
        swap_signal_write(s);
    }
    free(acb->tmp);
    acb->common.cb(acb->common.opaque, 0);
    swap_common_cb(acb);
}

#ifndef LIBIMG
static void swap_write_cb(void *opaque)
{
    SwapAIOCB *acb = opaque;

    acb->common.cb(acb->common.opaque, 0);
    swap_common_cb(acb);
}
#endif

static void dubtree_read_complete_cb(void *opaque, int result)
{
    SwapAIOCB *acb = opaque;
    BDRVSwapState *s = acb->bs->opaque;
    uint8_t *o = acb->tmp ? acb->tmp : acb->buffer;
    uint8_t *t = acb->decomp;
    int64_t count = acb->size;
    uint32_t *sizes = acb->sizes;
    uint8_t tmp[SWAP_SECTOR_SIZE];
    uint64_t key = acb->block;
    int r = 0;

    if (result < 0) {
        return;
    }
    if (result >= 0) {

        swap_lock(s);
        while (count > 0) {
            size_t sz = *sizes++;

            //debug_printf("sz %x\n", (uint32_t) sz);
            if (sz != 0) {
#ifdef SWAP_STATS
                swap_stats.decompressed += DUBTREE_BLOCK_SIZE;
#endif
                uint8_t *dst = (count < SWAP_SECTOR_SIZE) ? tmp : o;
                r = swap_get_key(dst, t, sz);
                assert(r >= 0);

                if (dst == tmp) {
                    memcpy(o, tmp, count);
                }
                __swap_nonblocking_write(s, dst, key, SWAP_SECTOR_SIZE, 0);
                t += sz;
            }

            o += SWAP_SECTOR_SIZE;
            count -= SWAP_SECTOR_SIZE;
            ++key;
        }
        swap_unlock(s);
    }

#ifdef SWAP_STATS
    acb->t1 = os_get_clock();
    swap_stats.dubtree_read += acb->t1 - acb->t0;
#endif

    free(acb->decomp);
    complete_read_acb(acb);
}

static int __swap_dubtree_read(BDRVSwapState *s, SwapAIOCB *acb)
{
    int r = 0;
    uint64_t offset = acb->block * SWAP_SECTOR_SIZE;
    uint64_t count = acb->size;
    uint8_t *map = acb->map;
    uint64_t start = offset / SWAP_SECTOR_SIZE;
    uint64_t end = (offset + count + SWAP_SECTOR_SIZE - 1) / SWAP_SECTOR_SIZE;
    uint32_t *sizes;
    void *decomp;

    /* Returns number of unresolved blocks, or negative on
     * error. */

    /* 'sizes' array must be initialized with zeroes. */
    sizes = calloc(end - start, sizeof(sizes[0]));
    if (!sizes) {
        errx(1, "OOM error %s line %d", __FUNCTION__, __LINE__);
    }
    acb->sizes = sizes;

    decomp = malloc(DUBTREE_BLOCK_SIZE * (end - start));
    if (!decomp) {
        errx(1, "OOM error %s line %d", __FUNCTION__, __LINE__);
    }
    acb->decomp = decomp;

    if (!s->find_context) {
        s->find_context = dubtree_prepare_find(&s->t);
        if (!s->find_context) {
            errx(1, "swap: failed to create find context");
        }
    }

    do {
        r = dubtree_find(&s->t, start, end - start, decomp, map, sizes,
                dubtree_read_complete_cb, acb, s->find_context);
    } while (r == -EAGAIN);

    /* dubtree_find returns 0 for success, <0 for error, >0 if some blocks
     * were unresolved. */
    if (r < 0) {
        errx(1, "swap: dubtree read failed!!");
    }
    return r;
}

static inline void __swap_queue_read_acb(BlockDriverState *bs, SwapAIOCB *acb)
{
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;

    acb->next = NULL;
    int r;

    __sync_fetch_and_add(&acb->splits, 2);
    r = __swap_dubtree_read(s, acb);
    if (r > 0) {
        __sync_fetch_and_add(&acb->splits, 1);
        if (s->read_queue_head == NULL) {
            s->read_queue_head = s->read_queue_tail = acb;
        } else {
            s->read_queue_tail->next = acb;
            s->read_queue_tail = acb;
        }
        swap_signal_read(s);
    }
    complete_read_acb(acb);
}

static int __swap_nonblocking_read(BDRVSwapState *s, uint8_t *buf,
                                   uint64_t block, size_t size,
                                   uint8_t **ret_map)
{
    int i;
    uint64_t found = 0;
    uint8_t *map;
    size_t take;

    /* We need a map array to keep track of which blocks have been resolved
     * or not, and to which snapshot versions. */
    map = calloc(((size + SWAP_SECTOR_SIZE-1) / SWAP_SECTOR_SIZE),
                 sizeof(uint64_t));
    if (!map) {
        errx(1, "swap: OOM error in %s", __FUNCTION__);
        return -1;
    }

    for (i = 0; size > 0; ++i, size -= take, buf += SWAP_SECTOR_SIZE) {
        take = size < SWAP_SECTOR_SIZE ? size : SWAP_SECTOR_SIZE;
        uint8_t *b;
        uint64_t line;
        uint64_t value;
        uint64_t key = block + i;
        uint8_t tmp[SWAP_SECTOR_SIZE];

        if (hashtable_find(&s->cached_blocks, key, &line)) {
            b = (void*) lru_cache_touch_line(&s->bc, line)->value;
            memcpy(buf, b, take);
            map[i] = 1;
            found += take;
        } else if (hashtable_find(&s->busy_blocks, key, &value)) {
            uint8_t *dst;
            if (value & SWAP_SIZE_MASK) {
                dst = take < SWAP_SECTOR_SIZE ? tmp : buf;
                b = (void *) (uintptr_t) (value & ~SWAP_SIZE_MASK);
                int sz = value >> SWAP_SIZE_SHIFT;
                swap_get_key(dst, b, sz);
                if (dst == tmp) {
                    memcpy(buf, tmp, take);
                }
            } else {
                b = (void *) (uintptr_t) value;
                dst = b;
                memcpy(buf, b, take);
            }
            __swap_nonblocking_write(s, dst, key, SWAP_SECTOR_SIZE, 0);

            map[i] = 1;
            found += take;
        }
    }
    *ret_map = map;
    return found;
}

SwapAIOCB dummy_acb;
static BlockDriverAIOCB *swap_aio_read(BlockDriverState *bs,
        int64_t sector_num, uint8_t *buf, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    //debug_printf("%s %"PRIx64" %d\n", __FUNCTION__, sector_num, nb_sectors);
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    SwapAIOCB *acb = NULL;
    const uint64_t mask = SWAP_SECTOR_SIZE - 1;
    uint64_t offset = sector_num << BDRV_SECTOR_BITS;
    uint64_t block = offset / SWAP_SECTOR_SIZE;
    uint32_t modulo = offset & mask;
    uint32_t size = (nb_sectors << BDRV_SECTOR_BITS) + modulo;
    uint8_t *tmp = NULL;
    uint8_t *map;
    ssize_t found;

    if (modulo) {
        tmp = malloc(size);
        if (!tmp) {
            debug_printf("swap: unable to allocate tmp on line %d\n", __LINE__);
            return NULL;
        }
    }

    swap_lock(s);
    found = __swap_nonblocking_read(s, tmp ? tmp : buf, block, size, &map);
    if (found < 0) {
        assert(0);
        swap_unlock(s);
        free(tmp);
        return NULL;
    } else if (found == size) {
        swap_unlock(s);
        if (tmp) {
            memcpy(buf, tmp + modulo, size - modulo);
            free(tmp);
        }
        free(map);
        cb(opaque, 0);
        acb = &dummy_acb;
    } else {
        acb = swap_aio_get(bs, cb, opaque);
        if (!acb) {
            debug_printf("swap: unable to allocate acb on line %d\n", __LINE__);
            free(tmp);
            swap_unlock(s);
            return NULL;
        }
        acb->block = block;
        acb->modulo = modulo;
        acb->size = size;
        acb->buffer = buf;
        acb->tmp = tmp;
        acb->map = map;
        aio_add_wait_object(&acb->event, swap_read_cb, acb);

        __swap_queue_read_acb(bs, acb);
        swap_unlock(s);
    }

    return (BlockDriverAIOCB *)acb;
}

static void
swap_complete_write_acb(SwapAIOCB *acb)
{
#ifndef LIBIMG
    if (acb->ratelimit_complete_timer) {
        free_timer(acb->ratelimit_complete_timer);
        acb->ratelimit_complete_timer = NULL;
    }
#endif
    ioh_event_set(&acb->event);
}

#ifndef LIBIMG
static void
swap_ratelimit_complete_timer_notify(void *opaque)
{
    SwapAIOCB *acb = (SwapAIOCB*)opaque;
    BDRVSwapState *s = (BDRVSwapState*) acb->bs->opaque;
    int ratelimited;

    swap_signal_write(s);

    swap_lock(s);
    ratelimited = is_ratelimited_hard(s);
    swap_unlock(s);

    if (ratelimited) {
        /* we're over block threshold of buffered data, hold writes off */
        mod_timer(acb->ratelimit_complete_timer,
                  get_clock_ms(rt_clock) + WRITE_RATELIMIT_GAP_MS);
    } else {
        swap_complete_write_acb(acb);
    }
}
#endif

static int queue_write(BDRVSwapState *s, uint64_t key, uint64_t value)
{
    HashEntry *e;

    //debug_printf("queue %"PRIx64"\n", key);
    e = hashtable_find_entry(&s->busy_blocks, key);
    if (e) {
        e->value = value;
    } else {
        hashtable_insert(&s->busy_blocks, key, value);
    }

    struct pq *pq1 = &s->pqs[s->pq_switch];
    struct pq *pq2 = &s->pqs[s->pq_switch ^ 1];;
    pq_push((s->pq_cutoff == ~0ULL || s->pq_cutoff <= key) ? pq1 : pq2, key, value); 

    return 0;
}

static int __swap_nonblocking_write(BDRVSwapState *s, const uint8_t *buf,
                                        uint64_t block, size_t size, int dirty)
{
    int i;
    LruCache *bc = &s->bc;
    int n = 0;

    for (i = 0; i < size / SWAP_SECTOR_SIZE; ++i) {

        uint8_t *b;
        uint64_t line;
        LruCacheLine *cl;

        if (hashtable_find(&s->cached_blocks, block + i, &line)) {
            cl = lru_cache_touch_line(bc, line);
            /* Do not overwrite previously cached entry on read. */
            if (dirty) {
                cl->dirty = dirty;
                b = (void *) cl->value;
                memcpy(b, buf + SWAP_SECTOR_SIZE * i, SWAP_SECTOR_SIZE);
            }
            continue;
        }

        if (!(b = swap_malloc(s, SWAP_SECTOR_SIZE))) {
            warn("swap: OOM error in %s", __FUNCTION__);
            return -ENOMEM;
        }

        line = lru_cache_evict_line(bc);
        cl = lru_cache_touch_line(bc, line);

        if (cl->value) {
            hashtable_delete(&s->cached_blocks, cl->key);
            if (cl->dirty) {
                queue_write(s, cl->key, cl->value);
                ++n;
            } else {
                swap_free(s, (void *) (uintptr_t) cl->value);
            }
        }

        memcpy(b, buf + SWAP_SECTOR_SIZE * i, SWAP_SECTOR_SIZE);
        cl->key = (uintptr_t) block + i;
        cl->value = (uintptr_t) b;
        cl->dirty = dirty;
        hashtable_insert(&s->cached_blocks, block + i, line);
    }
    return n;
}

static BlockDriverAIOCB *swap_aio_write(BlockDriverState *bs,
        int64_t sector_num, const uint8_t *buf, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    //debug_printf("%s %I64x %d\n", __FUNCTION__, sector_num, nb_sectors);
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    SwapAIOCB *acb = NULL;

    if ((sector_num & 7) || (nb_sectors & 7)) {
        const uint64_t mask = SWAP_SECTOR_SIZE - 1;
        uint64_t offset = sector_num << BDRV_SECTOR_BITS;
        uint64_t count = nb_sectors << BDRV_SECTOR_BITS;
        uint64_t aligned_offset = offset & ~mask;
        uint64_t aligned_end = (offset + count + mask) & ~mask;
        uint64_t aligned_count = aligned_end - aligned_offset;
        ssize_t found;

        acb = swap_aio_get(bs, cb, opaque);
        if (!acb) {
            debug_printf("swap: unable to allocate acb on line %d\n", __LINE__);
            return NULL;
        }

        acb->block = aligned_offset / SWAP_SECTOR_SIZE;
        acb->modulo = offset & mask;
        acb->size = aligned_count;
        acb->orig_size = nb_sectors << BDRV_SECTOR_BITS;
        acb->buffer = (void*) buf;
        acb->tmp = malloc(acb->size);
        if (!acb->tmp) {
            /* XXX potential DoS here if VM does a lot of big unaligned writes.
             * Could be solved by only reading head and tail of affected
             * section and thus not needing a variable sized tmp buffer. */
            errx(1, "swap: OOM on line %d", __LINE__);
        }

        aio_add_wait_object(&acb->event, swap_rmw_cb, acb);

        swap_lock(s);
        found = __swap_nonblocking_read(s, acb->tmp ? acb->tmp : acb->buffer,
                                        acb->block, acb->size, &acb->map);
        if (found < 0) {
            free(acb->tmp);
            aio_release(acb);
            acb = NULL;
        } else if (found == acb->size) {
            ioh_event_set(&acb->event);
        } else {
            __swap_queue_read_acb(bs, acb);
        }
        swap_unlock(s);
    } else {
        /* Already done. */

        int ratelimited;
        int n;
        swap_lock(s);
        n = __swap_nonblocking_write(s, buf, sector_num / 8,
                                     nb_sectors << BDRV_SECTOR_BITS, 1);
        ratelimited = is_ratelimited_hard(s);
        swap_unlock(s);
        if (n) {
            swap_signal_write(s);
        }

        if (ratelimited) {
#ifdef LIBIMG
            swap_wait_can_write(s);
            cb(opaque, 0);
            acb = &dummy_acb;
#else
            /* late completion in order to rate limit writes */

            acb = swap_aio_get(bs, cb, opaque);
            if (!acb) {
                debug_printf("swap: unable to allocate acb on line %d\n",
                             __LINE__);
                return NULL;
            }

            aio_add_wait_object(&acb->event, swap_write_cb, acb);
            acb->ratelimit_complete_timer = new_timer_ms(
                    rt_clock, swap_ratelimit_complete_timer_notify, acb);
            mod_timer(acb->ratelimit_complete_timer,
                    get_clock_ms(rt_clock) + WRITE_RATELIMIT_GAP_MS);
            TAILQ_INSERT_TAIL(&s->rlimit_write_queue, acb, rlimit_write_entry);
#endif
        } else {
            /* immediate completion */
            cb(opaque, 0);
            acb = &dummy_acb;
        }

#ifdef SWAP_STATS
        acb->t1 = os_get_clock();
#endif
    }
    return (BlockDriverAIOCB *) acb;
}

static int swap_flush(BlockDriverState *bs)
{
    debug_printf("%s\n", __FUNCTION__);
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    LruCache *bc = &s->bc;
    SwapAIOCB *acb, *next;
    int i;

    /* Complete ratelimited writes */

    /* Wait for all outstanding ios completing. */
    aio_wait_start();
    aio_poll();
    debug_printf("swap: finishing %d outstanding IOs\n", s->ios_outstanding);
    while (s->ios_outstanding) {
        TAILQ_FOREACH_SAFE(acb, &s->rlimit_write_queue, rlimit_write_entry,
                           next)
            swap_complete_write_acb(acb);
        aio_wait();
    }
    aio_wait_end();

    debug_printf("swap: emptying cache lines\n");
    swap_lock(s);
    for (i = 0; i < (1 << bc->log_lines); ++i) {
        LruCacheLine *cl = &bc->lines[i];
        if (cl->value) {
            hashtable_delete(&s->cached_blocks, (uint64_t) cl->key);
            if (cl->dirty) {
                queue_write(s, cl->key, cl->value);
            } else {
                swap_free(s, (void *) (uintptr_t) cl->value);
            }
        }
        cl->key = 0;
        cl->value = 0;
    }
    s->flush = 1;
    swap_unlock(s);

    debug_printf("swap: wait for all writes to complete\n");
    for (;;) {
        uint32_t load;
        swap_lock(s);
        load = s->busy_blocks.load;
        swap_unlock(s);
        if (!load) {
            break;
        }
        swap_signal_write(s);
        swap_wait_all_flushed(s);
    }
    debug_printf("swap: finished waiting for write threads\n");

    assert(s->pqs[0].n_heap == 0);
    assert(s->pqs[1].n_heap == 0);
    assert(s->busy_blocks.load == 0);

#ifdef _WIN32
    /* Release the heap used for buffers back to OS. */
    int nleaks = __sync_fetch_and_add(&s->alloced, 0);
    if (nleaks) {
        debug_printf("swap: leaked %d allocs\n", nleaks);
        assert(0);
    }
    swap_lock(s);
    HeapDestroy(s->heap);
    s->heap = HeapCreate(0, 0, 0);
    swap_unlock(s);
#endif

    /* Quiesce dubtree and release caches. */
    swap_lock(s);
    critical_section_enter(&s->shallow_mutex);
    /* Close cached file mappings. */
    for (i = 0; i < (1 << s->fc.log_lines); ++i) {
        SwapMappedFile *mf = (SwapMappedFile*) s->fc.lines[i].value;
        if (mf) {
            swap_unmap_file(mf);
            free(mf);
        }
    }
    lru_cache_clear(&s->fc);
    hashtable_clear(&s->open_files);
    /* Close cached dubtree file handles. */
    dubtree_quiesce(&s->t);
    if (s->find_context) {
        dubtree_end_find(&s->t, s->find_context);
        s->find_context = NULL;
    }
    critical_section_leave(&s->shallow_mutex);
    s->flush = 0;
    swap_unlock(s);

    debug_printf("%s done, %d allocs\n", __FUNCTION__,
            __sync_fetch_and_add(&s->alloced, 0));
    return 0;
}

static void swap_close(BlockDriverState *bs)
{
    debug_printf("%s\n", __FUNCTION__);
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    int i;

    /* Signal write thread to quit and wait for it. */
    s->quit = 1;

    swap_signal_write(s);
    wait_thread(s->write_thread);

    swap_signal_insert(s);
    wait_thread(s->insert_thread);

    swap_signal_read(s);
    wait_thread(s->read_thread);

    if (s->find_context) {
        dubtree_end_find(&s->t, s->find_context);
        s->find_context = NULL;
    }
    dubtree_close(&s->t);

    if (s->shallow_map.mapping) {
        swap_unmap_file(&s->shallow_map);
    }
    free(s->cow_backup);

#ifdef _WIN32
    if (s->volume != INVALID_HANDLE_VALUE) {
        CloseHandle(s->volume);
    }
#endif

    thread_event_close(&s->all_flushed_event);
    thread_event_close(&s->read_event);
    thread_event_close(&s->write_event);
    thread_event_close(&s->can_write_event);

    critical_section_free(&s->mutex);
    critical_section_free(&s->shallow_mutex);

    /* Close cached file mappings. */
    for (i = 0; i < (1 << s->fc.log_lines); ++i) {
        SwapMappedFile *mf = (SwapMappedFile*) s->fc.lines[i].value;
        if (mf) {
            swap_unmap_file(mf);
        }
    }
    lruCacheClose(&s->bc);
    hashtable_clear(&s->cached_blocks);
    lruCacheClose(&s->fc);
    hashtable_clear(&s->open_files);
}

static int
swap_create(const char *filename, int64_t size, int flags)
{
    FILE *file;
    uuid_t uuid;
    char uuid_str[37];
    int ret;

    if (!strncmp(filename, "swap:", 5))
        filename = &filename[5];

    file = fopen(filename, "wb");
    if (file == NULL) {
        warn("%s: unable to create %s", __FUNCTION__, filename);
        return -errno;
    }

    uuid_generate_truly_random(uuid);
    uuid_unparse_lower(uuid, uuid_str);

#undef fprintf
    ret = fprintf(file, "uuid=%s\n", uuid_str);
    if (ret < 0) {
        warn("%s: fprintf failed", __FUNCTION__);
        ret = -errno;
        goto out;
    }

    ret = fprintf(file, "size=%"PRId64"\n", size);
    if (ret < 0) {
        warn("%s: fprintf failed", __FUNCTION__);
        ret = -errno;
        goto out;
    }

    ret = 0;
  out:
    if (file)
        fclose(file);
    return ret;
}

static int swap_ioctl(BlockDriverState *bs, unsigned long int req, void *buf)
{
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    if (req == 0) {
        if (!buf) {
            return -EINVAL;
        }
        memcpy(buf, s->uuid, sizeof(uuid_t));
        return sizeof(uuid_t);
    } else if (req == 1) {
        if (!buf) {
            return -EINVAL;
        }
        int sl = *((int *) buf);
        return dubtree_insert(&s->t, 0, NULL, NULL, NULL, sl);
    } else if (req == 2) {
        return dubtree_sanity_check(&s->t);
    } else if (req == 3) {
        s->store_uncompressed = 1;
        return 0;
    }
    return -ENOTSUP;
}

BlockDriver bdrv_swap = {
    .format_name = "swap",
    .instance_size = sizeof(BDRVSwapState),
    .bdrv_probe = NULL, /* no probe for protocols */
    .bdrv_open = swap_open,
    .bdrv_close = swap_close,
    .bdrv_create = swap_create,
    .bdrv_flush = swap_flush,
    .bdrv_remove = swap_remove,

    .bdrv_aio_read = swap_aio_read,
    .bdrv_aio_write = swap_aio_write,

    .bdrv_ioctl = swap_ioctl,

    .protocol_name = "swap",
};
