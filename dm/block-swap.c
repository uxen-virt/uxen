/*
 * Copyright 2012-2016, Bromium, Inc.
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
#include "block-swap/md5.h"

#include <lz4.h>

#include "uuidgen.h"

#ifdef _WIN32
#include <ntdef.h>
#define FILE_OPEN                         0x00000001
#define FILE_OPEN_BY_FILE_ID              0x00002000
#define FILE_NON_DIRECTORY_FILE           0x00000040
#define FILE_SEQUENTIAL_ONLY              0x00000004
#define FILE_OPEN_FOR_BACKUP_INTENT       0x00004000

typedef struct IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS stat;
        PVOID pointer;
    };
    ULONG_PTR info;
} IO_STATUS_BLOCK;

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

uint64_t log_swap_fills = 0;

#if !defined(LIBIMG) && defined(CONFIG_DUMP_SWAP_STAT)
  #define SWAP_STATS
#endif

#define SWAP_SECTOR_SIZE DUBTREE_BLOCK_SIZE
#ifdef LIBIMG
  #define SWAP_LOG_BLOCK_CACHE_LINES 16
#else
  #define SWAP_LOG_BLOCK_CACHE_LINES 8
#endif

typedef struct SwapMapTuple {
    uint32_t end;
    uint32_t size;
    uint32_t file_offset;
    uint32_t name_offset;
#ifdef _WIN32
    uint32_t file_id_highpart;
    uint32_t file_id_lowpart;
#endif
} SwapMapTuple;

#define SWAP_RADIX_LEVELS 7ULL
#define SWAP_RADIX_BITS 8ULL

typedef struct SwapRadix {
    void *children[1 << SWAP_RADIX_BITS];
} SwapRadix;


static int swap_backend_active = 0;

typedef struct SwapMappedFile {
    void *mapping;
    uint64_t modulo;
    uint64_t size;
} SwapMappedFile;

typedef struct BDRVSwapState {

    /** Image name. */
    char *filename;
    char *swapdata;
    char *fallbacks[DUBTREE_MAX_FALLBACKS + 1];
    /* Where the CoW kernel module places files. */
    char *cow_backup;
    uuid_t uuid;
    uuid_t parent_uuid;
    uint64_t version;
    uint64_t parent;
    uint64_t size;

    SwapMappedFile shallow_map;
    size_t shallow_map_size;
    size_t num_maps;
    SwapMapTuple *map_idx;
    const char *map_strings;
    HashTable open_files;
    LruCache fc;
    HashTable cached_blocks;
    LruCache bc;
    SwapRadix *radix[2];
    critical_section mutex;
    critical_section find_mutex;
    critical_section shallow_mutex;
    volatile int active_radix;
    volatile int quit;
    volatile size_t buffered;

    thread_event write_event;
    thread_event can_write_event;
    uxen_thread write_thread;

    thread_event read_event;
    uxen_thread read_thread;

    DUBTREE t;
    DUBTREECONTEXT *find_context;

    int ios_outstanding;
    struct SwapAIOCB *read_queue_head;
    struct SwapAIOCB *read_queue_tail;
    TAILQ_HEAD(, SwapAIOCB) rlimit_write_queue;

    int log_swap_fills;

#ifdef _WIN32
    HANDLE heap;
    DUBTREE_FILE_HANDLE volume; /* Volume for opening by id. */
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
    uint64_t *map;
    size_t orig_size;
    ioh_event event;
    int result;
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
static void swap_free_block(BDRVSwapState *s, void *b);

/* Wrappers for compress and expand functions. */

static inline
size_t swap_set_key(void *out, const void *in)
{
    /* Caller has allocated ample space for compression overhead, so we don't
     * worry about about running out of space. However, there is no point in
     * storing more than DUBTREE_BLOCK_SIZE bytes, so if we exceed that we
     * revert to a straight memcpy(). When uncompressing we treat DUBTREE_BLOCK_SIZE'd
     * keys as special, and use memcpy() there as well. */

    size_t sz = LZ4_compress((const char*)in, (char*) out, DUBTREE_BLOCK_SIZE);
    if (sz >= DUBTREE_BLOCK_SIZE) {
        memcpy(out, in, DUBTREE_BLOCK_SIZE);
        sz = DUBTREE_BLOCK_SIZE;
    }
    return sz;
}

static inline int swap_get_key(void *out, const void *in, size_t sz)
{
    if (sz == DUBTREE_BLOCK_SIZE) {
        memcpy(out, in, sz);
    } else {
        int unsz = LZ4_decompress_fast((const char*)in, (char*)out,
                                       DUBTREE_BLOCK_SIZE);
        if (unsz!=sz) {
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

static inline void swap_signal_read(BDRVSwapState *s)
{
    thread_event_set(&s->read_event);
}

static inline void swap_wait_write(BDRVSwapState *s)
{
    thread_event_wait(&s->write_event);
}

static inline void swap_wait_can_write(BDRVSwapState *s)
{
    thread_event_wait(&s->can_write_event);
}

static inline void swap_wait_read(BDRVSwapState *s)
{
    thread_event_wait(&s->read_event);
}

/*** Simple radix tree for buffered writes. */

static inline SwapRadix *swap_make_radix(void)
{
    SwapRadix *rx = (SwapRadix*) malloc(sizeof(SwapRadix));
    assert(rx);
    memset(rx, 0, sizeof(SwapRadix));
    return rx;
}


static inline int
swap_radix_insert(BDRVSwapState *s, SwapRadix *root, int depth, uint64_t key, void *value)
{
    uint64_t idx = (key >> ((SWAP_RADIX_LEVELS-1) * SWAP_RADIX_BITS) & ((1<<SWAP_RADIX_BITS)-1));
    int r = 1;
    SwapRadix *rx;

    if (depth == SWAP_RADIX_LEVELS - 1) {
        if (root->children[idx] != NULL) {
            swap_free_block(s, root->children[idx]);
            r = 0;
        }
        root->children[idx] = value;
        return r;
    }

    rx = root->children[idx];

    if (rx == NULL) {
        root->children[idx] = rx = swap_make_radix();
    }

    return swap_radix_insert(s, rx, depth + 1, key << SWAP_RADIX_BITS, value);
}


static inline void*
swap_radix_find(SwapRadix *root, int depth, uint64_t key)
{
    uint64_t idx = (key >> ((SWAP_RADIX_LEVELS-1) * SWAP_RADIX_BITS) & ((1<<SWAP_RADIX_BITS)-1));
    SwapRadix *rx;

    if (depth == SWAP_RADIX_LEVELS - 1) {
        return root->children[idx];
    }

    rx = root->children[idx];
    return rx ? swap_radix_find(rx, depth + 1, key << SWAP_RADIX_BITS) : NULL;
}


typedef struct {
    int n;
    uint8_t *b;
    BDRVSwapState *s;
    uint64_t keys[DUBTREE_M];
    size_t sizes[DUBTREE_M];
    /* Buffer for M compressed keys. Compression may temporarily expand the
     * data (we shrink it back to DUBTREE_BLOCK_SIZE if that happens), so we
     * make room for M+1 blocks. */
    uint8_t buffer[(1 + DUBTREE_M) * DUBTREE_BLOCK_SIZE];
} SwapWriteBuffer;

static void *swap_alloc_block(BDRVSwapState *s)
{
#ifdef _WIN32
    return HeapAlloc(s->heap, 0, SWAP_SECTOR_SIZE);
#else
    return malloc(SWAP_SECTOR_SIZE);
#endif
}

static void swap_free_block(BDRVSwapState *s, void *b)
{
#ifdef _WIN32
    HeapFree(s->heap, 0, b);
#else
    free(b);
#endif
}

int swap_flush_buffered(SwapWriteBuffer *wb)
{
    BDRVSwapState *s = wb->s;
    int r = dubtreeInsert(&s->t, wb->n, wb->keys, s->version, wb->buffer, wb->sizes);
    assert(r>=0);
    wb->n = 0;
    wb->b = wb->buffer;
    return r;
}

int swap_radix_walk(const SwapRadix *rx, int depth, uint64_t key, SwapWriteBuffer *wb)
{
    int i;
    int r = 0;

    for (i = 0; i < (1<<SWAP_RADIX_BITS); ++i) {

        if (rx->children[i] != NULL) {

            uint64_t subKey = (key << SWAP_RADIX_BITS) | i;
            assert(!( (key<<SWAP_RADIX_BITS) & i));

            if (depth == SWAP_RADIX_LEVELS - 1) {

                wb->keys[wb->n] = subKey;
                wb->sizes[wb->n] = swap_set_key(wb->b, rx->children[i]);
                wb->b += wb->sizes[wb->n];

                ++(wb->n);

                /* When we have collected enough keys to insert, flush. */

                if (wb->n == DUBTREE_M) {
                    swap_flush_buffered(wb);
                }

                ++r; /* count and return how many inserts we did. */

            } else {
                int sr = swap_radix_walk(rx->children[i], depth + 1, subKey, wb);

                if (sr < 0) return sr;
                else r += sr;
            }
        }
    }
    return r;
}

static inline
void swap_radix_clear0(BDRVSwapState *s, SwapRadix *rx, int depth)
{
    int i;

    if (depth < SWAP_RADIX_LEVELS) {

        for (i = 0; i < (1<<SWAP_RADIX_BITS); ++i) {
            if (rx->children[i] != NULL) {
                swap_radix_clear0(s, rx->children[i], depth + 1);
            }
        }
    }

    /* Leave the root in place, but empty. */
    if (depth > 0) {
        if (depth == SWAP_RADIX_LEVELS) {
            swap_free_block(s, rx);
        } else {
            free(rx);
        }
    } else {
        memset(rx, 0, sizeof(*rx));
    }
}

static void swap_radix_clear(BDRVSwapState *s, SwapRadix *rx)
{
    swap_radix_clear0(s, rx, 0);
}


#ifdef _WIN32
static DWORD WINAPI swap_write_thread(void *_s)
#else
static void *swap_write_thread(void *_s)
#endif
{
    BDRVSwapState *s = (BDRVSwapState*) _s;
    SwapWriteBuffer *wb = (SwapWriteBuffer*) malloc(sizeof(SwapWriteBuffer));
    int r;

    assert(wb);

    wb->n = 0;
    wb->s = s;
    wb->b = wb->buffer;

    for (;;) {

        /* Wait for more work? */
        size_t buffered = __sync_add_and_fetch(&s->buffered, 0);
        if (buffered == 0 && !s->quit) {
            swap_wait_write(s);
            continue;
        }

        /* Atomically swap the radixes, so that we can walk one of them in
         * peace without needing to hold any locks. */
        swap_lock(s);
        SwapRadix *rx = s->radix[s->active_radix];
        s->active_radix ^= 1;
        swap_unlock(s);

        /* Now walk the inactive tree. There may be concurrent readers, but
         * we don't make any changes, so this is safe. */
        r = swap_radix_walk(rx, 0, 0, wb);
#ifdef SWAP_STATS
        swap_stats.compressed += DUBTREE_BLOCK_SIZE * r;
#endif

        /* Make sure nothing is left. */
        if (wb->n > 0) {
            swap_flush_buffered(wb);
        }

        /* Clear the inactive one we just walked. We need the lock to prevent
         * concurrent reads while the tree is getting cleared. */
        swap_lock(s);
        swap_radix_clear(s, rx);
        swap_unlock(s);

        /* Adjust buffered count by how many blocks we flushed and freed. */
        if (r > 0) {
            buffered = __sync_sub_and_fetch(&s->buffered, SWAP_SECTOR_SIZE * r);
        }

        /* Only consider quitting when nothing is buffered. */
        if (buffered == 0 && s->quit) {
            break;
        }

        /* Everything all right? */
        if (r < 0) {
            errx(1, "swap: flush returns error %d", r);
            break;
        }

        swap_signal_can_write(s);
    }
    free(wb);

    debug_printf("%s exiting cleanly\n", __FUNCTION__);

    return 0;
}
/*** end of radix tree. */

/* Convert a UUID to a 64-bit hash using MD5. We use MD5 and some convoluted
 * byte-swapping to be compatible with what we did for VBox, when I thought
 * that there was no SHA-1 support, and before I realized that their UUID
 * parsing was broken wrt endianness. */

static inline uint64_t swap_uuid_to_hash(uuid_t uuid)
{
    uint8_t nil[16] = {0,};
    union {
        uint8_t hash[16];
        uint64_t bits[2];
    } u;

    struct  __attribute__ ((__packed__)) quad {
        uint32_t a;
        uint16_t b, c;
        uint8_t d, e;
        uint8_t f[6];
    };

    struct quad *in = (struct quad* ) uuid;
    struct quad out = *in;

    /* The zero uuid maps to 0. */
    if (!memcmp(uuid, nil, 16)) {
        return 0;
    }

    /* Because of a bug in how VBox lays out UUIDs, we need to byteswap
     * some of the UUID struct members, to get an MD5sum that is compatible
     * with VBox-swap images. */

    out.a = be32_to_cpu(in->a);
    out.b = be16_to_cpu(in->b);
    out.c = be16_to_cpu(in->c);

    md5_sum((uint8_t*) &out, 16, u.hash);

    return u.bits[0];
}

static inline uint64_t swap_name_to_hash(const char *s)
{
    union {
        uint8_t hash[16];
        uint64_t bits[2];
    } u;

    size_t len = 0;
    while (s[len] && s[len] != '\n') {
        ++len;
    }

    md5_sum((uint8_t*) s, len, u.hash);

    return u.bits[0];
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
            if (uuid_parse(line + 5 + (line[5]=='{'), s->uuid) == 0) {
                s->version = swap_uuid_to_hash(s->uuid);
            } else {
                s->version = swap_name_to_hash(line + 5);
            }
        } else if (!strncmp(line, "parentuuid=", 11)) {
            if (uuid_parse(line + 11 + (line[11]=='{'), s->parent_uuid) == 0) {
                s->parent = swap_uuid_to_hash(s->parent_uuid);
            } else {
                s->parent = swap_name_to_hash(line + 11);
            }
        } else if (!strncmp(line, "swapdata=", 9)) {
            s->swapdata = strdup(line + 9);
            if (!s->swapdata) {
                errx(1, "OOM error %s line %d", __FUNCTION__, __LINE__);
            }
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
int swap_map_file(DUBTREE_FILE_HANDLE file,
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

#else
/* See comment for win32 version above. */
int swap_map_file(DUBTREE_FILE_HANDLE file,
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
#endif

static int swap_init_map(BDRVSwapState *s, char *path, char *cow_backup)
{
    uint32_t *idx;
    DUBTREE_FILE_HANDLE map_file;

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
    map_file = dubtreeOpenExistingFileReadOnly(path);
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
    s->volume = CreateFile(
                    vol,
                    0, /* This needs to be zero else low-privilege processes will get ERROR_ACCESS_DENIED */
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    NULL);
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

static int swap_parse_fallback(const char *fn, char **path)
{
    int i = 0;
    FILE *f = fopen(fn, "r");
    if (f) {
        struct stat st;
        char *line;
        size_t sz;
        char *c;
        int assigned;
        if (fstat(fileno(f), &st) < 0) {
            warn("swap: unable to stat %s", fn);
            fclose(f);
            return 0;
        }
        sz = st.st_size;
        line = calloc(1, sz + 1);
        if (!line) {
            errx(1, "OOM error %s line %d", __FUNCTION__, __LINE__);
        }
        line[sz] = '\0';
        fread(line, 1, sz, f);

        for (c = line, assigned = 0; *c; ++c) {
            if (*c == '\n') {
                *c = '\0';
                assigned = 0;
            } else if (!assigned) {
                assert(i < DUBTREE_MAX_FALLBACKS);
                path[i++] = c;
                assigned = 1;
            }
        }
        fclose(f);
    }
    path[i] = NULL;
    return i;
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
    char *path;
    char *swapdata = NULL;
    char *fallback = NULL;
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

    /* Generate swapdata path, taking into account user override
     * of "swapdata" component. */
    asprintf(&swapdata, "%s%s%s",
            path,
            path[0] ? "/" : "", /* needs delim if path non-empty. */
            s->swapdata ? s->swapdata : "swapdata");

    if (!swapdata) {
        errx(1, "OOM out %s line %d", __FUNCTION__, __LINE__);
    }

    /* Generate path to fallback file within swapdata. */
    asprintf(&fallback, "%s/fallback", swapdata);
    if (!fallback) {
        errx(1, "OOM out %s line %d", __FUNCTION__, __LINE__);
    }

    /* Parse list of fallback directories optionally provided in the 'fallback'
     * file. Array contains current swapdata before call, and gets
     * NULL-terminated after it. dubtreeInit() needs the list head as a
     * separate argument, XXX change that. */
    s->fallbacks[0] = swapdata;
    swap_parse_fallback(fallback, s->fallbacks + 1);
    if (dubtreeInit(&s->t, s->fallbacks[0], s->fallbacks + 1) != 0) {
        warn("swap: failed to init dubtree");
        r = -1;
        goto out;
    }

    /* Make sure the tree has s->version setup with s->parent as fallback. */
    if (dubtreeCreateVersion(&s->t, s->version, s->parent) != 0)
    {
        warn("swap: failed to create new version");
        r = -1;
        goto out;
    }

    /* Prepare a find context for dubtree reads. This will fail if an ancestor
     * of s->version is not in the tree. */
    s->find_context = dubtreePrepareFind(&s->t, s->version);
    if (!s->find_context) {
        warnx("swap: failed to create find context");
        r = -1;
        goto out;
    }

    map = swap_resolve_via_fallback(s, "map.idx");
    cow = swap_resolve_via_fallback(s, "cow");

    /* Try to set up map.idx shallow index mapping, if present. */
    if (swap_init_map(s, map, cow) != 0) {
        //warn("swap: no map file found at '%s'", map);
    }

    /* Cache of open shallow file handles. */
    if (hashtableInit(&s->open_files, NULL, NULL) < 0) {
        warn("swap: unable to create hashtable for map");
        return -1;
    }
    if (lruCacheInit(&s->fc, 6) < 0) {
        warn("swap: unable to create lrucache for map");
        return -1;
    }

    /* A small write-back block cache, this is mainly to keep hot blocks such
     * as FS superblocks from getting inserted into the dubtree over and over.
     * This has large impact on the performance the libimg tools, and also
     * helps with e.g. USN journaling from a Windows guest. We cache only
     * blocks we write, on the assumption that the host OS takes care of normal
     * read caching and that decompression with LZ4 is cheap. */
    if (hashtableInit(&s->cached_blocks, NULL, NULL) < 0) {
        warn("swap: unable to create hashtable for block cache");
        return -1;
    }
    if (lruCacheInit(&s->bc, SWAP_LOG_BLOCK_CACHE_LINES) < 0) {
        warn("swap: unable to create lrucache for blocks");
        return -1;
    }

    for (i = 0; i < 2; ++i) {
        if (!(s->radix[i] = swap_make_radix())) {
            errx(1, "swap: unable to create radix tree for buffer!");
        }
    }
    s->active_radix = 0;
    s->quit = 0;
    s->buffered = 0;

    critical_section_init(&s->mutex); /* big lock. */
    critical_section_init(&s->find_mutex); /* protects s->find_context. */
    critical_section_init(&s->shallow_mutex); /* protects shallow cache. */

    thread_event *events[] = {
        &s->write_event,
        &s->can_write_event,
        &s->read_event
    };

    for (i = 0; i < sizeof(events) / sizeof(events[0]); ++i) {
        thread_event *ev = events[i];
        if (thread_event_init(ev) < 0) {
            Werr(1, "swap: unable to create event!");
        }
    }

    if (create_thread(&s->write_thread, swap_write_thread, (void*) s) < 0) {
        Werr(1, "swap: unable to create thread!");
    }
    elevate_thread(s->write_thread);
    
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

    free(fallback);
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
    r = dubtreeDeleteVersion(&s->t, s->version);
    if (r < 0) {
        debug_printf("swap: attempt to delete unknown version!\n");
        return r;
    }
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

static int
swap_do_read(BDRVSwapState *s, uint64_t offset, uint64_t count, 
             uint8_t *buf, uint64_t *map)
{
    int i;
    int r = 0;
    uint64_t start = offset / SWAP_SECTOR_SIZE;
    uint64_t end = (offset + count + SWAP_SECTOR_SIZE - 1) / SWAP_SECTOR_SIZE;
    size_t *sizes = NULL;
    void *tmp = NULL;

    /* Returns number of unresolved blocks, or negative on
     * error. */

    /* 'sizes' array must be initialized with zeroes. */
    sizes = (size_t*) calloc(end - start, sizeof(size_t));
    if (!sizes) {
        errx(1, "OOM error %s line %d", __FUNCTION__, __LINE__);
    }

    tmp = (uint8_t*) malloc(DUBTREE_BLOCK_SIZE * (end - start));
    if (!tmp) {
        errx(1, "OOM error %s line %d", __FUNCTION__, __LINE__);
    }

#ifdef SWAP_STATS
    uint64_t t0 = os_get_clock();
#endif
    critical_section_enter(&s->find_mutex);
    r = dubtreeFind(&s->t, start, end - start, tmp, map, sizes,
            s->find_context);
    critical_section_leave(&s->find_mutex);
#ifdef SWAP_STATS
    swap_stats.dubtree_read += os_get_clock() - t0;
#endif

    /* dubtreeFind returns >= 0 for success, <0 for error. Getting an error
     * means that our tree or the snapshot version we are trying to access is
     * in a bad state (perhaps it got deleted), so we have to give up. */
    if (r < 0) {
        errx(1, "swap: dubtree read failed!!");
    }

    uint8_t *o = buf;
    uint8_t *t = tmp;

    for (i = 0; i < (end - start); ++i) {

        uint64_t take = count < DUBTREE_BLOCK_SIZE ? count : DUBTREE_BLOCK_SIZE;
        size_t sz = sizes[i];

        /* We rely on the fact that at present nothing compresses down to 0
         * bytes here, to determine if we got a block back from the dubtree or
         * not. Note that we CANNOT just inspect the map array, as that may not
         * have been all zeroes before the dubtreeFind() call. */

        if (sz != 0) {
#ifdef SWAP_STATS
            swap_stats.decompressed += DUBTREE_BLOCK_SIZE;
#endif
            if (count < DUBTREE_BLOCK_SIZE) {
                /* Shorter than 4kB read. */
                uint8_t b[DUBTREE_BLOCK_SIZE];
                r = swap_get_key(b, t, sz);
                if (r < 0)
                    goto out;
                memcpy(o, b, count);
            } else {
                /* Normal 4kB read. */
                r = swap_get_key(o, t, sz);
                if (r < 0)
                    goto out;
            }

            t += sz;
        }

        o += SWAP_SECTOR_SIZE;
        count -= take;
    }

out:
    free((void*) tmp);
    free((void*) sizes);
    return r;
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
static DUBTREE_FILE_HANDLE
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
static void __attribute__((constructor))
swap_early_init(void)
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

/* Fill in blocks that are missing after dubtreeFind() call, by looking for
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
        uint8_t *buffer, uint64_t *map)
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
                    DUBTREE_FILE_HANDLE handle = DUBTREE_INVALID_HANDLE;
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
                    swap_lock(s);
                    if (hashtableFind(&s->open_files, (uint64_t)(uintptr_t)tuple,
                                &line)) {
                        /* We had a mapping cached already. */
                        file = (SwapMappedFile*) lruCacheTouchLine(fc, line)->value;
                    }

                    if (!file) {
                        /* No cached mapping for the file. Need to create one. */
                        const char *filename = s->map_strings + tuple->name_offset;

                        /* Completely seperate the file open logic of WIN32 from OSX. This helps
                           quite a bit with readability. */
#ifdef _WIN32
                        DUBTREE_FILE_HANDLE tmp_handle = DUBTREE_INVALID_HANDLE;
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
#ifdef SWAP_STATS
                        if (handle != DUBTREE_INVALID_HANDLE) {
                            debug_printf("Opened file [%s] by file-id [0x%"PRIx64"]\n",
                                            filename, file_id.QuadPart);
                        }
#endif

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

                            handle = dubtreeOpenExistingFileReadOnly(cow);
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
                                handle = dubtreeOpenExistingFileReadOnly(filename);
                            }
                        }

                        if (tmp_handle != DUBTREE_INVALID_HANDLE) {
                            dubtreeCloseFile(tmp_handle);
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

                            handle = dubtreeOpenExistingFileReadOnly(cow);
                        }

                        if (handle == DUBTREE_INVALID_HANDLE) {
                            /* When no CoW backup, use the normal shallow file name. */
                            handle = dubtreeOpenExistingFileReadOnly(filename);
                        }

#endif

                        /* No CoW file and no orig. shallow file. We're doomed. */
                        if (handle == DUBTREE_INVALID_HANDLE) {
                            Wwarn("swap: failed to open shallow %s", filename);
                            swap_unlock(s);
                            goto next;
                        }

                        /* Is this a small file that we can always read in one go,
                         * then we will perform the read now and continue to the
                         * next block without caching anything. */
                        if (SWAP_SECTOR_SIZE * tuple->size <= take) {
                            /* Drop the lock, we are done with the cache. */
                            swap_unlock(s);

                            if (dubtreeReadFileAt(handle, buffer + readOffset, take,
                                        SWAP_SECTOR_SIZE *
                                        ((block - tuple_start) + tuple->file_offset),
                                        NULL) < 0) {
                                Wwarn("swap: failed to read shallow %s",
                                      filename);
                                dubtreeCloseFile(handle);
                                goto next;
                            }
                            dubtreeCloseFile(handle);
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
                            swap_unlock(s);
                            goto next;
                        }

                        r = swap_map_file(handle,
                                SWAP_SECTOR_SIZE * tuple->file_offset,
                                SWAP_SECTOR_SIZE * tuple->size, file);
                        if (r < 0) {
                            Wwarn("swap: mapping %s fails", filename);
                            free(file);
                            swap_unlock(s);
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
                        line = lruCacheEvictLine(fc);
                        LruCacheLine *cl = lruCacheTouchLine(fc, line);

                        if (cl->key) {
                            /* Remove evicted entry's key from hash table. */
                            hashtableDelete(&s->open_files, (uint64_t)(uintptr_t)cl->key);
                            evicted = (SwapMappedFile*) cl->value;
                        }
                        cl->value = (uintptr_t) file;
                        cl->key = (uintptr_t) tuple;

                        hashtableInsert(&s->open_files, (uint64_t)(uintptr_t)tuple, line);
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
                    swap_unlock(s);

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
    swap_stats.blocked_time += os_get_clock() - acb->t0;
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
            int r = swap_do_read(s, acb->block * SWAP_SECTOR_SIZE, acb->size, b,
                    acb->map);

            if (r < 0) {
                warnx("swap: read error %d", r);
                acb->result = r;
            } else {
                acb->result = acb->size - acb->modulo;
            }

            r = swap_fill_read_holes(s, acb->block * SWAP_SECTOR_SIZE,
                    acb->size, b, acb->map);
            if (r < 0) {
                acb->result = r;
            }

#ifdef SWAP_STATS
            acb->t1 = os_get_clock();
#endif

            ioh_event_set(&acb->event);
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
    memset(&acb->rlimit_write_entry, 0, sizeof(acb->rlimit_write_entry));

    ++(s->ios_outstanding);
#ifdef SWAP_STATS
    acb->t0 = os_get_clock();
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
static ssize_t __swap_nonblocking_write(BDRVSwapState *s, const uint8_t *buf,
                                        uint64_t block, size_t size);

static void swap_rmw_cb(void *opaque)
{
    SwapAIOCB *acb = opaque;
    BlockDriverState *bs = acb->bs;
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;

    memcpy(acb->tmp + acb->modulo, acb->buffer, acb->orig_size);
    swap_lock(s);
    __swap_nonblocking_write(s, acb->tmp, acb->block, acb->size);
    swap_unlock(s);
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

static inline void __swap_queue_read_acb(BlockDriverState *bs, SwapAIOCB *acb)
{
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    acb->next = NULL;
    if (s->read_queue_head == NULL) {
        s->read_queue_head = s->read_queue_tail = acb;
    } else {
        s->read_queue_tail->next = acb;
        s->read_queue_tail = acb;
    }
    swap_signal_read(s);
}

static ssize_t __swap_nonblocking_read(BDRVSwapState *s, uint8_t *buf,
                                   uint64_t block, size_t size,
                                   uint64_t **ret_map)
{
    int i;
    uint64_t found = 0;
    uint64_t *map;
    size_t take;

    /* We need a map array to keep track of which blocks have been resolved
     * or not, and to which snapshot versions. */
    map = calloc(((size + SWAP_SECTOR_SIZE-1) / SWAP_SECTOR_SIZE),
                 sizeof(uint64_t));
    if (!map) {
        errx(1, "swap: OOM error in %s", __FUNCTION__);
        return -1;
    }

    for (i = 0; size > 0; ++i, size -= take) {
        int j;
        take = size < SWAP_SECTOR_SIZE ? size : SWAP_SECTOR_SIZE;
        const uint8_t *b;
        uint64_t line;

        if (hashtableFind(&s->cached_blocks, block + i, &line)) {
            b = (void*) lruCacheTouchLine(&s->bc, line)->value;
            memcpy(buf + SWAP_SECTOR_SIZE * i, b, take);
            map[i] = s->version;
            found += take;
        } else {
            int a;
            for (j = 0, a = s->active_radix; j < 2; ++j, a ^= 1) {
                const uint8_t *b = swap_radix_find(s->radix[a], 0, block + i);
                if (b) {
                    memcpy(buf + SWAP_SECTOR_SIZE * i, b, take);
                    map[i] = s->version;
                    found += take;
                    break; /* Don't look in other radix, we found it already. */
                }
            }
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
    //printf("%s %"PRIx64" %d\n", __FUNCTION__, sector_num, nb_sectors);
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    SwapAIOCB *acb = NULL;
    const uint64_t mask = SWAP_SECTOR_SIZE - 1;
    uint64_t offset = sector_num << BDRV_SECTOR_BITS;
    uint64_t block = offset / SWAP_SECTOR_SIZE;
    uint32_t modulo = offset & mask;
    uint32_t size = (nb_sectors << BDRV_SECTOR_BITS) + modulo;
    uint8_t *tmp = NULL;
    uint64_t *map;
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

    swap_signal_write(s);
    if (__sync_add_and_fetch(&s->buffered, 0) > WRITE_BLOCK_THR_BYTES) {
        /* we're over block threshold of buffered data, hold writes off */
        mod_timer(acb->ratelimit_complete_timer,
                  get_clock_ms(rt_clock) + WRITE_RATELIMIT_GAP_MS);
    } else {
        swap_complete_write_acb(acb);
    }
}
#endif

static ssize_t __swap_nonblocking_write(BDRVSwapState *s, const uint8_t *buf,
                                        uint64_t block, size_t size)
{
    int i;
    SwapRadix *rx;
    LruCache *bc = &s->bc;

    rx = s->radix[s->active_radix];

    for (i = 0; i < size / SWAP_SECTOR_SIZE; ++i) {

        uint64_t line;
        uint8_t *b;
        LruCacheLine *cl;

        if (hashtableFind(&s->cached_blocks, block + i, &line)) {
            b = (void*) lruCacheTouchLine(&s->bc, line)->value;
            memcpy(b, buf + SWAP_SECTOR_SIZE * i, SWAP_SECTOR_SIZE);
            continue;
        }

        if (!(b = swap_alloc_block(s))) {
            warn("swap: OOM error in %s", __FUNCTION__);
            return -ENOMEM;
        }

        /* Evict a cache line to the radix tree, and replace it with the
         * incoming block. */
        line = lruCacheEvictLine(bc);
        cl = lruCacheTouchLine(bc, line);

        if (cl->value) {
            uint64_t evicted_block = (uint64_t) cl->key;
            __sync_add_and_fetch(&s->buffered, SWAP_SECTOR_SIZE *
                    swap_radix_insert(s, rx, 0, evicted_block,
                        (void*) cl->value));
            hashtableDelete(&s->cached_blocks, evicted_block);
        }

        memcpy(b, buf + SWAP_SECTOR_SIZE * i, SWAP_SECTOR_SIZE);
        cl->key = (uintptr_t) block + i;
        cl->value = (uintptr_t) b;
        hashtableInsert(&s->cached_blocks, block + i, line);
    }
    return 0;
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

        swap_lock(s);
        __swap_nonblocking_write(s, buf, sector_num / 8,
                                 nb_sectors << BDRV_SECTOR_BITS);
        swap_unlock(s);
        swap_signal_write(s);
        if (__sync_add_and_fetch(&s->buffered, 0) > WRITE_RATELIMIT_THR_BYTES) {
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
    SwapRadix *rx;
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
    debug_printf("swap: finished outstanding ios\n");

    /* Move all cache lines to radix tree. */
    swap_lock(s);
    debug_printf("swap: emptying cache lines\n");
    rx = s->radix[s->active_radix];
    for (i = 0; i < (1 << bc->log_lines); ++i) {
        LruCacheLine *cl = &bc->lines[i];
        if (cl->value) {
            __sync_add_and_fetch(&s->buffered,
                    SWAP_SECTOR_SIZE * swap_radix_insert(s, rx, 0, (uint64_t) cl->key,
                        (void*) cl->value));
            hashtableDelete(&s->cached_blocks, (uint64_t) cl->key);
        }
        cl->key = 0;
        cl->value = 0;
    }
    swap_unlock(s);

    /* Wait for write thread finishing its queue. */
    while (__sync_add_and_fetch(&s->buffered, 0) > 0) {
        swap_signal_write(s);
        swap_wait_can_write(s);
    }
    debug_printf("swap: finished waiting for write thread\n");
#ifdef _WIN32
    /* Release the heap used for buffers back to OS. */
    swap_lock(s);
    if (__sync_add_and_fetch(&s->buffered, 0) == 0) {
        HeapDestroy(s->heap);
        s->heap = HeapCreate(0, 0, 0);
    }
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
    lruCacheClear(&s->fc);
    hashtableClear(&s->open_files);
    /* Close cached dubtree file handles. */
    dubtreeQuiesce(&s->t);
    dubtreeQuiesceFind(&s->t, s->find_context);
    critical_section_leave(&s->shallow_mutex);
    swap_unlock(s);

    debug_printf("%s done\n", __FUNCTION__);
    return 0;
}

static void swap_close(BlockDriverState *bs)
{
    BDRVSwapState *s = (BDRVSwapState*) bs->opaque;
    int i;

    /* Signal write thread to quit and wait for it. */
    s->quit = 1;

    swap_signal_write(s);
    wait_thread(s->write_thread);

    swap_signal_read(s);
    wait_thread(s->read_thread);

    dubtreeEndFind(&s->t, s->find_context);
    dubtreeClose(&s->t);

    if (s->shallow_map.mapping) {
        swap_unmap_file(&s->shallow_map);
    }
    free(s->cow_backup);

#ifdef _WIN32
    if (s->volume != INVALID_HANDLE_VALUE) {
        CloseHandle(s->volume);
    }
#endif

    thread_event_close(&s->read_event);
    thread_event_close(&s->write_event);
    thread_event_close(&s->can_write_event);

    critical_section_free(&s->mutex);
    critical_section_free(&s->find_mutex);
    critical_section_free(&s->shallow_mutex);

    /* Close cached file mappings. */
    for (i = 0; i < (1 << s->fc.log_lines); ++i) {
        SwapMappedFile *mf = (SwapMappedFile*) s->fc.lines[i].value;
        if (mf) {
            swap_unmap_file(mf);
        }
    }
    lruCacheClose(&s->bc);
    hashtableClear(&s->cached_blocks);
    lruCacheClose(&s->fc);
    hashtableClear(&s->open_files);
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

    uuid_clear(uuid);
    uuid_unparse_lower(uuid, uuid_str);

    ret = fprintf(file, "parentuuid=%s\n", uuid_str);
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

    .protocol_name = "swap",
};
