/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "dubtree_sys.h"
#include "dubtree_io.h"

#include "dubtree.h"
#include "simpletree.h"
#include "copybuffer.h"
#include "md5.h"

#include <lz4.h>

#define DUBTREE_FILE_MAGIC_MMAP 0x73776170
#define DUBTREE_FILE_MAGIC_SAVE 0x73776171

/* XXX: Fix KRY-12506 and then make versions consistent. */
#ifdef _WIN32
#define DUBTREE_FILE_VERSION 8
#else
#define DUBTREE_FILE_VERSION 7
#endif

#define DUBTREE_MMAPPED_NAME "top.lvl"
#define DUBTREE_TMP_NAME "top.tmp"
#define DUBTREE_SEALED_NAME "top.save"
#define DUBTREE_MUTEX_NAME "mutex"

#ifndef _WIN32
#include <sys/mman.h>
#include <sys/file.h>
#include <errno.h>
#endif

static inline void dubtreeLockForWrite(DUBTREE *t)
{
#ifdef _WIN32
    WaitForSingleObject(t->mutex, INFINITE);
#else
    int r = flock(t->lockfile, LOCK_EX);
    assert(r == 0);
#endif
}

static inline void dubtreeUnlockForWrite(DUBTREE *t)
{
#ifdef _WIN32
    ReleaseMutex(t->mutex);
#else
    int r = flock(t->lockfile, LOCK_UN);
    assert(r == 0);
#endif
}


static inline uint64_t dubtreeGetSlot(DUBTREE *t, int level)
{
    uint64_t howMany;
    uint64_t d = 0;
    int i;

    for (i = 0, howMany = DUBTREE_M; i < level; ++i, howMany *= DUBTREE_M) {
        d += DUBTREE_M * howMany * DUBTREE_BLOCK_SIZE;
    }

    return d;
}


static inline
int dubtreeIsMutable(DUBTREE *t)
{
    int r;
    char *lockfn;
    asprintf(&lockfn, "%s/" DUBTREE_SEALED_NAME, t->fn);
    assert(lockfn);
    r = file_exists(lockfn) ? 0 : 1;
    printf("checking for %s, mutable = %d\n", lockfn, r);
    free(lockfn);
    return r;
}

#ifdef _WIN32

void *dubtreeCreateSharedMemRegion(DUBTREE *t, int *created_mmap)
{
    DUBTREE_FILE_HANDLE hMap = NULL;
    PVOID pvFile = NULL;
    uint64_t limit;
    uint8_t hash[16];
    char mutex_name[64];
    char mapping_name[64];

    t->file = INVALID_HANDLE_VALUE;
    *created_mmap = 0;

    /* Calculate limit between permanently mapped top of tree
     * and rest. */

    limit = t->arraysOffset + dubtreeGetSlot(t, DUBTREE_CORELIMIT);

    /* Use md5(filename) to make mutex and address space identifiers globally
     * unique. */

    md5_sum((uint8_t*) t->fn, strlen(t->fn), hash);

    sprintf(mutex_name,
            "mutex-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7],
            hash[8], hash[9], hash[10], hash[11],
            hash[12], hash[13], hash[14], hash[15]);

    sprintf(mapping_name,
            "map-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7],
            hash[8], hash[9], hash[10], hash[11],
            hash[12], hash[13], hash[14], hash[15]);

    /* We can use CreateMutex to both create a new and open an existing mutex,
     * and we will know what happened by checking GetLastError() even if the
     * return value is non-NULL. Mysterious Windows-world. */

    if ((t->mutex = CreateMutexA(NULL, FALSE, mutex_name))) {

        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            printf("swap: created new mutex\n");
        }

        /* Create the swapdata directory if not there already. */
        dubtreeCreateDirectory(t->fn);

        t->is_mutable = dubtreeIsMutable(t);

        /* Create a file to back the shared memory segment. */

        char *topfn;
        asprintf(&topfn, t->is_mutable ?
                "%s/" DUBTREE_MMAPPED_NAME :
                "%s/" DUBTREE_TMP_NAME, t->fn);
        assert(topfn);
        printf("swap: using mmapped file: %s\n", topfn);

        t->file = dubtreeOpenNewFile(topfn, !t->is_mutable);

        if (t->file == DUBTREE_INVALID_HANDLE) {
            printf("swap: could not open file %s (%u).\n", topfn,
                    (uint32_t)GetLastError());
            free(topfn);
            return NULL;
        }
        free(topfn);

        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            *created_mmap = 0;
        } else {
            printf("created mapping file!\n");
            *created_mmap = t->is_mutable;
        }

        /* Same as above, Create may in fact mean Open if the mapping already
         * exists. We are happy as long as the result is non-NULL. */

        hMap = CreateFileMappingA(
                t->file,                 /* use system pagefile or file opened above */
                NULL,                    /* default security */
                PAGE_READWRITE,          /* read/write access */
                (DWORD) ((uint64_t)limit>>32ULL),  /* maximum object size (high-order DWORD) */
                (DWORD) limit,           /* maximum object size (low-order DWORD) */
                mapping_name);           /* name of mapping object */

        if (hMap == NULL) {
            printf("Could not create file mapping object (%x).\n",
                    (uint32_t)GetLastError());
            goto out;
        }

    } else {
        printf("swap: could not open or create mutex\n");
        goto out;
    }

    t->map = hMap;
    assert(t->arraysOffset > 0);

    pvFile = MapViewOfFile(hMap,   /* handle to map object */
            FILE_MAP_ALL_ACCESS,            /* read/write permission */
            0,
            0,
            limit);

    if (pvFile == NULL) {
        printf("swap: could not map view of file (%x)!\n", (uint32_t)GetLastError());

        goto out;
    }

    /* On success we return with the tree locked for write. */
    return pvFile;

    /* On failure we unlock the tree and return NULL. */
out:
    if (pvFile) {
        UnmapViewOfFile(pvFile);
    }
    if (hMap != INVALID_HANDLE_VALUE) {
        CloseHandle(hMap);
    }
    CloseHandle(t->mutex);
    return NULL;
}

void dubtreeClose(DUBTREE *t)
{
    char **fb;
    copyBufferRelease(t->cb);
    free(t->cb);
    free(t->fn);
    fb = t->fallbacks;
    while (*fb) {
        free(*fb++);
    }
    if (t->is_mutable) {
        FlushViewOfFile(t->mem, 0);
    }
    UnmapViewOfFile(t->mem);
    CloseHandle(t->map);
    CloseHandle(t->file);
    CloseHandle(t->mutex);
}

#else

void *dubtreeCreateSharedMemRegion(DUBTREE *t,
        int *created_mmap)
{
    DUBTREE_HEADER *h;
    void *m = NULL;
    uint64_t limit = t->arraysOffset + dubtreeGetSlot(t, DUBTREE_CORELIMIT);
    char *top;
    uint8_t hash[16];
    char mapping_name[64];
    char *lockfile_name;
    char *filename;
    int first_lock = 0;
    int exflags;
    int file = -1;

    dubtreeCreateDirectory(t->fn);

    asprintf(&top, "%s/" DUBTREE_MMAPPED_NAME, t->fn);
    assert(top);

    *created_mmap = 0;
    t->is_mutable = dubtreeIsMutable(t);

    md5_sum((uint8_t*) t->fn, strlen(t->fn), hash);

    sprintf(mapping_name,
            "/dubtree-%02x%02x%02x%02x%02x%02x%02x%02x",
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7]);

    /* First we need a lock file to use flock() on, as we cannot do
     * that for shm fds on OSX. */
    asprintf(&lockfile_name, "%s/" DUBTREE_MUTEX_NAME, t->fn);
    assert(lockfile_name);
    exflags = O_EXCL | O_CREAT | O_EXLOCK;
    t->lockfile = open(lockfile_name, exflags, 0600);
    if (t->lockfile >= 0) {
        /* We managed to create exclusive, so this must be the first
         * open ever. */
        first_lock = 1;
    } else {
        exflags &= ~O_EXCL;
        t->lockfile = open(lockfile_name, exflags, 0600);
        if (t->lockfile < 0) {
            printf("unable to open %s: %d (%s)\n",
                   lockfile_name, errno, strerror(errno));
            goto out;
        }
    }

    if (t->is_mutable) {
        /* Mmap a named existing file. */
        filename = top;
        t->mapping_name = NULL;
        file = open(filename, O_EXCL | O_CREAT | O_RDWR, 0644);
        if (file >= 0) {
            printf("created new file %s\n", filename);
            if (ftruncate(file, limit) < 0) {
                printf("unable to truncate %s: %d (%s)\n",
                        filename, errno, strerror(errno));
                goto out;
            }
            *created_mmap = 1;
        } else {
            printf("reopen existing file %s\n", filename);
            file = open(filename, O_CREAT | O_RDWR, 0644);
        }
    } else {
        /* Mmap a shared shm object. */
        filename = mapping_name;
        t->mapping_name = strdup(filename);

        if (first_lock) {
            /* Unlink any stale object by the same name. */
            shm_unlink(filename);
        }

        file = shm_open(filename, O_EXCL | O_CREAT | O_RDWR, 0600);
        if (file >= 0) {
            printf("created new shm %s\n", filename);
            if (ftruncate(file, limit) < 0) {
                printf("unable to truncate %s: %d (%s)\n",
                        filename, errno, strerror(errno));
                goto out;
            }
        } else {
            printf("reopen existing shm %s\n", filename);
            file = shm_open(filename, O_CREAT | O_RDWR, 0600);
        }
    }

    if (file < 0) {
        printf("unable to open shm or file %s: %d (%s)\n",
               filename, errno, strerror(errno));
        goto out;
    }

    m = mmap(0, limit, PROT_WRITE | PROT_READ, MAP_SHARED, file, 0);
    if (m == MAP_FAILED) {
        printf("unable to map name=%s, fd=%d, limit=0x%"PRIx64": %d (%s)\n",
               filename, file, limit, errno, strerror(errno));
        m = NULL;
        goto out;
    }

    /* Ideally the OS would allow us to create a refcounted shmem segment, but
     * on non-Windows we have to fake that by maintaining a manual refcount and
     * unlinking the shm region on last close. */
    h = (DUBTREE_HEADER*) m;
    __sync_fetch_and_add(&h->refcount, 1);
out:
    if (t->lockfile >= 0 && flock(t->lockfile, LOCK_UN) < 0) {
        printf("swap: failed to unlock %s, %s\n", lockfile_name, strerror(errno));
    }

    if (file >= 0 && close(file)) {
        printf("unable to close fd %d: %d (%s)\n",
               file, errno, strerror(errno));
    }
    free(top);
    free(lockfile_name);
    return m;
}

void dubtreeClose(DUBTREE *t)
{
    char **fb;
    
    dubtreeLockForWrite(t);
    /* Do we have a shared memory mapping that should get unlinked on last
     * close? Unlike on Windows, we have to try and handle this manually. */
    if (__sync_fetch_and_add(&t->header->refcount, -1) == 1 && t->mapping_name) {
        printf("unlink shm %s\n", t->mapping_name);
        shm_unlink(t->mapping_name);
        free(t->mapping_name);
    }
    if (t->is_mutable) {
        uint64_t limit = t->arraysOffset + dubtreeGetSlot(t, DUBTREE_CORELIMIT);
        msync(t->mem, limit, MS_SYNC);
    }
    /* Closing will release the flock too. */
    close(t->lockfile);
    free(t->fn);
    fb = t->fallbacks;
    while (*fb) {
        free(*fb++);
    }
}


#endif


/* Must be called with tree locked. Return 0 for success. */

static int dubtreeLoad(DUBTREE *t, int force_fallback)
{
    int r = -1;
    DUBTREE_FILE_HANDLE file = DUBTREE_INVALID_HANDLE;
    char *fn = NULL;
    void *buffer;
    size_t sz;
    uint64_t offset;
    uint32_t p;
    uint8_t *page;

    buffer = malloc(LZ4_compressBound(simpletreeNodeSize()));
    if (!buffer) {
        printf("swap: OOM on line %d\n", __LINE__);
        goto out;
    }

    asprintf(&fn, "%s/" DUBTREE_SEALED_NAME, t->fn); 
    assert(fn);

    printf("swap: loading compressed tree state from %s force=%d\n", fn, force_fallback);

    /* Fall back to global shared location. */
    if (force_fallback ||
            ((file = dubtreeOpenExistingFileReadOnly(fn)) == DUBTREE_INVALID_HANDLE)) {

        char **fb = t->fallbacks;
        while (*fb && file == DUBTREE_INVALID_HANDLE) {
            char *path;
            asprintf(&path, "%s/" DUBTREE_SEALED_NAME, *fb++);
            printf("swap: fall back to loading %s\n", path);
            file = dubtreeOpenExistingFileReadOnly(path);
            free(path);
        }
    }

    if (file == DUBTREE_INVALID_HANDLE)
        goto out;

    /* Read the dubtree header. */
    offset = 0;
    sz = sizeof(DUBTREE_HEADER);
    r = dubtreeReadFileAt(file, t->header, sz, offset, NULL);
    if (r != sz)
        goto out;
    offset += sz;

    /* Check the magic cookie for save files, as well as the settings
     * that affect the save format here. The rest will be checked by
     * dubtreeInit() that called us. */
    if (t->header->magic != DUBTREE_FILE_MAGIC_SAVE) {
        printf("bad dubtree file magic!\n");
        r = -1;
        goto out;
    }
    if (t->header->dubtree_max_treenodes != DUBTREE_TREENODES) {
        printf("bad dubtree file #treenodes!\n");
        r = -1;
        goto out;
    }
    if (t->header->dubtree_max_levels != DUBTREE_MAX_LEVELS) {
        printf("bad dubtree file #levels!\n");
        r = -1;
        goto out;
    }

    /* Read the level tree root references. */
    sz = sizeof(t->levels[0]) * DUBTREE_MAX_LEVELS;
    r = dubtreeReadFileAt(file, (void*)t->levels, sz, offset, NULL);
    if (r < 0)
        goto out;
    offset += sz;

    /* Read the list of snapshot relations. */
    sz = sizeof(DUBTREEVERSION) * DUBTREE_MAX_VERSIONS;
    r = dubtreeReadFileAt(file, t->versions, sz, offset, NULL);
    if (r < 0)
        goto out;
    offset += sz;

    /* Read the freelist of B-tree nodes. */
    sz = sizeof(node_t) * DUBTREE_TREENODES;
    r = dubtreeReadFileAt(file, (void*) t->freelist, sz, offset, NULL);
    if (r < 0)
        goto out;
    offset += sz;

    /* Read and uncompress B-tree pages. */
    for (p = 0; p < DUBTREE_TREENODES; ++p) {

        uint32_t compressed_size;
        page = t->treeMem + p * simpletreeNodeSize();

        /* Read compressed size. */
        sz = sizeof(compressed_size);
        r = dubtreeReadFileAt(file, &compressed_size, sz, offset, NULL);
        if (r != sz)
            goto out;
        offset += sz;

        /* Read compressed bytes, if any. */
        if (compressed_size > 0) {
            sz = compressed_size;
            r = dubtreeReadFileAt(file, buffer, sz, offset, NULL);
            if (r != sz)
                goto out;
            offset += sz;

            if (LZ4_decompress_fast((char*)buffer, (char*)page, simpletreeNodeSize())
                    != compressed_size) {
                errx(1, "failed to uncompress B-tree page!");
            }
        }
    }

    /* Initialize refcount to 1, this is for the unix-like systems that cannot
     * figure out how to refcount shared mem sections. */
    t->header->magic = DUBTREE_FILE_MAGIC_MMAP;
    t->header->refcount = 1;
    r = 0;
out:
    free(fn);
    free(buffer);
    if (file != DUBTREE_INVALID_HANDLE) {
        dubtreeCloseFile(file);
    }
    return r ? -1 : 0;
}

int dubtreeInit(DUBTREE *t, const char *fn, char **fallbacks)
{
    int i;
    uint8_t *m;
    int created_mmap = 0;
    char **fb;
    DUBTREE_HEADER *header;
    int locked = 0;

    memset(t, 0, sizeof(DUBTREE));

    /* Resolve swapdata location to absolute path, as we may link
     * with tools that like to call chdir... */
    t->fn = dubtreeRealPath(fn);
    if (!t->fn) {
        printf("swap: OOM on line %d\n", __LINE__);
        return -1;
    }

    /* Give fallbacks same treatment as above, if supplied. */
    fb = t->fallbacks;
    if (fallbacks) {
        while (*fallbacks) {
            if (!(*fb++ = dubtreeRealPath(*fallbacks++))) {
                printf("swap: OOM on line %d\n", __LINE__);
                return -1;
            }
        }
    }
    *fb = NULL;

    /* Create a buffer for copying between arrays. */
    t->cb = (COPYBUFFER*) malloc(sizeof(COPYBUFFER));
    if (!t->cb) {
        printf("swap: OOM on line %d\n", __LINE__);
        return -1;
    }

    /* The levels with compressed value data. We start those at an offset aligned
     * with COPYBUFFER_CACHEUNIT (16MB). */
    t->arraysOffset = COPYBUFFER_CACHEUNIT +
        (SIMPLETREE_NODESIZE * DUBTREE_TREENODES);

    assert(((SIMPLETREE_NODESIZE * DUBTREE_TREENODES) % COPYBUFFER_CACHEUNIT) == 0);

    /* Get a new or existing shared memory buffer for tree data. */
    m = dubtreeCreateSharedMemRegion(t, &created_mmap);

    if (m == NULL) {
        printf("swap: dubtree unable to create shared mem region!\n");
        return 1;
    }
    t->mem = m;

    /* To not have to compute these offsets again and again, we
     * pre-compute a table of them. */
    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        t->offsets[i] = dubtreeGetSlot(t, i);
    }

    copyBufferInit(t->cb, 0x1000, t->fn, t->fallbacks, t->arraysOffset, m,
            dubtreeGetSlot(t, DUBTREE_CORELIMIT), !t->is_mutable);

    /* The shared structure contains a DUBTREE_HEADER struct to begin with. */
    header = (DUBTREE_HEADER*) m;
    t->header = header;
    t->head = &header->freeListHead; /* t->head kept as shorthand for now. */

    /* Per-level counters and tree root pointers. */
    t->levels = (volatile uint32_t*) m + sizeof(DUBTREE_HEADER);
    t->versions = ((uint8_t*)t->levels) + sizeof(uint32_t) * DUBTREE_MAX_LEVELS;
    t->freelist = (volatile node_t*)
        (uint8_t*)t->versions + sizeof(DUBTREEVERSION) * DUBTREE_MAX_VERSIONS;

    /* Actual tree nodes, 16MB in. */
    t->treeMem = m + COPYBUFFER_CACHEUNIT;

    /* Arrays with data in them. */
    t->data = m + t->arraysOffset;

    /* Init a hash table of known versions. dubtreeInsert() will use the
     * generation counter to decide if to reinit the contents. */
    hashtableInit(&t->vht, NULL, NULL);
    t->vht_generation = ~0ULL;

    /* The top-of-tree region is shared across all processes accessing the
     * tree, so if we came first we have to initialize its state, loading
     * from disk if there is anything to load. We lock the tree if it needs
     * initialization, to avoid others trying to use it before it is ready. */

    if (!t->header->dubtree_initialized) {
        dubtreeLockForWrite(t);
        locked = 1;
    }

    if (!t->header->dubtree_initialized) {

        /* This is first create of the tree. */

        if (dubtreeLoad(t, created_mmap) == 0) {

            //printf("swap: loaded persisted tree state\n");

        } else {

            /* Unable to load existing state from disk. */

            //printf("swap: reinit tree\n");

            /* Initialize tree node free list. This is a simple linked list with
             * t->head pointing to node 1 to begin with. Allocs atomically pop the
             * head element, and Frees push the freed element as new head. */

            for (i = 0; i < DUBTREE_TREENODES; ++i) {
                t->freelist[i] = (i < DUBTREE_TREENODES - 1) ?  i + 1 : 0;
            }

            for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
                t->levels[i] = 0;
            }

            /* Magic header and version number. */
            t->header->magic = DUBTREE_FILE_MAGIC_MMAP;
            t->header->version = DUBTREE_FILE_VERSION;
            /* Tree node allocs start at node 1, so that 0==nil. */
            t->header->freeListHead = 1;
            t->header->transaction = 0;
            t->header->dubtree_m = DUBTREE_M;
            t->header->dubtree_corelimit = DUBTREE_CORELIMIT;
            t->header->dubtree_max_levels = DUBTREE_MAX_LEVELS;
            t->header->dubtree_max_versions = DUBTREE_MAX_VERSIONS;
            t->header->dubtree_max_treenodes = DUBTREE_TREENODES;
        }

        t->header->versions_generation = 1;
        __sync_synchronize();
        t->header->dubtree_initialized = 1;
        __sync_synchronize();
    }

    if (locked) {
        dubtreeUnlockForWrite(t);
    }

    /* Check that shared data structure matches current version and
     * configuration. */
    if ((t->header->magic == DUBTREE_FILE_MAGIC_MMAP || t->header->magic ==
                DUBTREE_FILE_MAGIC_SAVE) &&
        (t->header->version == DUBTREE_FILE_VERSION) &&
        (t->header->dubtree_m == DUBTREE_M) &&
        (t->header->dubtree_corelimit = DUBTREE_CORELIMIT) &&
        (t->header->dubtree_max_levels == DUBTREE_MAX_LEVELS) &&
        (t->header->dubtree_max_versions == DUBTREE_MAX_VERSIONS) &&
        (t->header->dubtree_max_treenodes == DUBTREE_TREENODES)) {
        return 0;
    } else {
        printf("swap: mismatched dubtree header!\n");
        return -1;
    }
}

/* Only needed by swap-fsck. */
uint64_t
dubtreeGetVersionByIndex(const DUBTREE* t, int idx)
{
    DUBTREEVERSION *vs = t->versions;
    return vs[idx].id;
}

void dubtreePrepareVersionsHash(DUBTREE* t, HashTable *ht);

/* Prepare a context used when calling dubtreeFind(). */
DUBTREECONTEXT *dubtreePrepareFind(DUBTREE *t, uint64_t version)
{
    int i;
    uint64_t parent;
    HashTable ht;
    DUBTREECONTEXT *cx = malloc(sizeof(DUBTREECONTEXT));
    if (!cx) {
        printf("%s: OOM line %d\n", __FUNCTION__, __LINE__);
        return NULL;
    }

    /* Need a hash table mapping versions to their parents to compute
     * the path to the root. We are using our own copy here, to avoid
     * racing with dubtreeInsert(), in case someone should choose to call
     * that function in parallel. */
    hashtableInit(&ht, NULL, NULL);
    dubtreePrepareVersionsHash(t, &ht);

    /* Compute the path for chasing keys up the snapshot hierarchy. */
    for (i = 0; i < sizeof(cx->path) / sizeof(cx->path[0]); ++i) {
        cx->path[i] = version;
        if (!version) {
            break;
        }
        if (!hashtableFind(&ht, version, &parent)) {
            printf("swap: unknown version step=%d v=%"PRIx64" ???\n", i, version);
            free(cx);
            cx = NULL;
            goto out;
        } else {
            version = parent;
        }
    }
    hashtableClear(&ht);

    cx->cb = malloc(sizeof(COPYBUFFER));
    if (!cx->cb) {
        printf("%s: OOM line %d\n", __FUNCTION__, __LINE__);
        free(cx);
        return NULL;
    }
    copyBufferInit(cx->cb, 0x1000, t->fn, t->fallbacks, t->arraysOffset, t->mem,
            dubtreeGetSlot(t, DUBTREE_CORELIMIT), 1);
out:
    return cx;
}

void dubtreeEndFind(DUBTREE *t, DUBTREECONTEXT *cx)
{
    copyBufferRelease(cx->cb);
    free(cx->cb);
    free(cx);
}

static inline SIMPLETREE *dubtreeGetSimpleTree(DUBTREE *t, int level)
{
    return simpletreeOpen(&t->levels[level], t->head, t->freelist,
            t->treeMem);
}

static inline void dubtreeSetSimpleTree(DUBTREE *t, int level, SIMPLETREE *st)
{
    simpletreeReference(&t->levels[level], st, t->head, t->freelist, t->treeMem);
}

int dubtreeFind(DUBTREE *t, uint64_t start, uint64_t numKeys,
        uint8_t *out, uint64_t *map, size_t *sizes, DUBTREECONTEXT *cx)
{
    int i, r;
    size_t metaSz = numKeys * sizeof(uint64_t);
    uint64_t *sources = NULL;
    uint64_t *versions = NULL;
    COPYBUFFER *cb = cx->cb;
    SIMPLETREE *trees[DUBTREE_MAX_LEVELS];
    int succeeded;
    uint64_t d;
    int missing;

    /* Array of pointers to copy from, one per key in the range queried. */

    sources = (uint64_t*) malloc(metaSz);
    if (sources == NULL) {
        printf("%s: OOM line %d\n", __FUNCTION__, __LINE__);
        r = -1;
        goto out;
    }

    versions = (uint64_t*) malloc(metaSz);
    if (versions == NULL) {
        printf("%s: OOM line %d\n", __FUNCTION__, __LINE__);
        r = -1;
        goto out;
    }

    for (;;) {

        /* Initialize result vectors. */
        memset(sizes, 0, sizeof(size_t) * numKeys);
        memcpy(versions, map, metaSz);
        memset(trees, 0, sizeof(trees));

        /* How many keys do we actually need to get? Some may have been
         * filled out already by the caller so do not count those. */

        for (i = missing = 0; i < numKeys; ++i) {
            if (map[i] == 0) ++missing;
        }

        /* Open all the trees. */
        for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
            trees[i] = dubtreeGetSimpleTree(t, i);
        }

        /* Check for relevant keys in all trees. */
        for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
            SIMPLETREE *st = trees[i];
            SIMPLETREEITERATOR it;

            if (st != NULL) {
                int relevant = 0; /* anything at all for us this level? */
                uint64_t *path = cx->path;
                uint64_t version;

                while (missing && (version = *path++)) {

                    SIMPLETREERESULT k;
                    if (simpletreeFind(st, start, version, &it)) {
                        while (missing && !simpletreeAtEnd(st, &it)) {

                            uint64_t block;
                            size_t idx;

                            simpletreeRead(st, &k, &it);
                            block = k.key.key;
                            idx = block - start;

                            if (k.key.version > version || block >= start + numKeys) {
                                break;
                            }

                            /* The youngest data is always at the top of the tree,
                             * so only include a key into the returned result if we
                             * did not have one already. */
                            if (!versions[idx]) {
                                versions[idx] = k.key.version;
                                sources[idx] = t->offsets[i] + k.value.a;
                                sizes[idx] = k.value.b;

                                /* We need this tree to stick around until we are done. */
                                relevant = 1;
                                --missing;
                            }

                            simpletreeNext(st, &it);
                        }
                    }
                }

                /* We don't need to hold a reference to this tree any longer. */
                if (!relevant) {
                    simpletreeClose(st, &t->levels[i]);
                    trees[i] = NULL;
                }
            }
        }

        /* Copy out the values we found. */
        copyBufferStart(cb, out);
        for (i = 0, d = 0; i < numKeys; ++i) {
            if (sizes[i] != 0) {
                copyBufferInsert(cb, sources[i], d, sizes[i]);
                d += sizes[i];
            }
        }

        /* Flush buffered up copies to out buffer. Failure either means data
         * structures on disk are corrupted, or, in case of EOF, that the
         * writer truncated files while we were trying to read them, which is
         * can because we let reads run in parallel with a single writer.  The
         * 'succeeded' check is supposed to catch this case, so we only
         * propagate the error up if we were not going to retry anyway. */

        r = copyBufferFlush(cb);

        /* Close the remaining open trees. If a close fails it means we
         * cannot assume the data we just copied is current, and we must
         * redo the entire lookup. */

        for (i = 0, succeeded = 1; i < DUBTREE_MAX_LEVELS; ++i) {
            if (trees[i]) {
                succeeded &= (!simpletreeClose(trees[i], &t->levels[i]));
            }
        }

        /* Wait with checking the flush result until we know if are supposed
         * to have succeeded with our lookup at all. */

        if (succeeded && r < 0) {
            goto out;
        }

        /* Are we done yet, or do we need to retry? */
        if (succeeded) break;
    }

    /* Return 0 or positive value indicating number of unresolved blocks on
     * succes. Negative return means error. */

    r = missing;

    /* Since versions array started out as a copy of map, it is safe to
     * copy it back wholesale. */
    memcpy(map, versions, metaSz);

out:
    if (sources) free(sources);
    if (versions) free(versions);

    if (r < 0) {
        printf("swap: dubtreeFind fails %d on line %d\n", r, __LINE__);
    }
    return r;///XXX left; /* all OK, return >= 0 blocks not found. */
}


/* Heap helper functions. */

typedef struct DUBTREEITERTUPLE {
    SIMPLETREE *st;
    SIMPLETREEITERATOR it;
    int level;
} DUBTREEITERTUPLE;

static inline int dubtreeIterLessThan(DUBTREE *t, DUBTREEITERTUPLE *a,
        DUBTREEITERTUPLE *b)
{
    SIMPLETREERESULT ka, kb;
    simpletreeRead(a->st, &ka, &a->it);
    simpletreeRead(b->st, &kb, &b->it);

    if (ka.key.version != kb.key.version) {
        return (ka.key.version < kb.key.version);
    } else if (ka.key.key != kb.key.key) {
        return (ka.key.key < kb.key.key);
    } else {
        return (a->level < b->level);
    }
}

static inline void dubtreeSiftUp(DUBTREE *t, DUBTREEITERTUPLE *hp, size_t child)
{
    size_t parent;
    for (; child; child = parent) {
        parent = (child - 1) / 2;

        if (dubtreeIterLessThan(t, &hp[child], &hp[parent])) {

            DUBTREEITERTUPLE tmp = hp[parent];
            hp[parent] = hp[child];
            hp[child] = tmp;

        } else {
            break;
        }
    }
}

static inline void dubtreeSiftDown(DUBTREE *t, DUBTREEITERTUPLE *hp, size_t end)
{
    size_t parent = 0;
    size_t child;
    DUBTREEITERTUPLE tmp;
    for (;; parent = child) {
        child = 2 * parent + 1;

        if (child >= end)
            break;

        /* point to the min child */
        if (child + 1 < end &&
                dubtreeIterLessThan(t, &hp[child + 1], &hp[child])) {
            ++child;
        }

        /* heap condition restored? */
        if (dubtreeIterLessThan(t, &hp[parent], &hp[child])) {
            break;
        }

        /* else swap and continue. */
        tmp = hp[parent];
        hp[parent] = hp[child];
        hp[child] = tmp;
    }
}


/* During normal use, keys will be spread over the different levels, and some
 * keys may exist in multiple levels. To optimize, and for reasons of crash
 * tolerance, we supply this function that performs an N-way merge from the
 * top to what is assumed to be the bottommost level. The result will be a
 * single level will all keys tightly packed and totally sorted. */

int dubtreeSeal(DUBTREE *t, int destLevel)
{
    int i, j;
    int r = -1;
    uint32_t p;
    DUBTREEITERTUPLE heap[DUBTREE_MAX_LEVELS];
    SIMPLETREE combinedTree;
    uint64_t d;
    uint64_t lastBlock = -1;
    uint64_t lastVersion = 0;
    uint8_t *treeBuffer = NULL;
    volatile node_t head;
    char *sealed_name = NULL;
    char *mapped_name = NULL;
    char *mutex_name = NULL;
    COPYBUFFER *cb = t->cb;
    DUBTREE_FILE_HANDLE file = DUBTREE_INVALID_HANDLE;
    DUBTREE_HEADER header;
    size_t sz;
    void *buffer = NULL;
    uint8_t *page;
    uint64_t offset;

    /* Bit of sanity checking at first. */

    if (destLevel < DUBTREE_CORELIMIT) {
        printf("destination level must be at least %d!\n", DUBTREE_CORELIMIT);
        goto out;
    }

    if (!dubtreeIsMutable(t)) {
        printf("tree is not mutable!\n");
        goto out;
    }

    if (t->levels[destLevel] != 0) {
        printf("destination level %d not empty!\n", destLevel);
        goto out;
    }

    /* Some strings we are going to need. */
    asprintf(&sealed_name, "%s/" DUBTREE_SEALED_NAME, t->fn);
    if (!sealed_name) {
        printf("swap: OOM on line %d\n", __LINE__);
        goto out;
    }
    asprintf(&mapped_name, "%s/" DUBTREE_MMAPPED_NAME, t->fn);
    if (!mapped_name) {
        printf("swap: OOM on line %d\n", __LINE__);
        goto out;
    }
    asprintf(&mutex_name, "%s/" DUBTREE_MUTEX_NAME, t->fn);
    if (!mutex_name) {
        printf("swap: OOM on line %d\n", __LINE__);
        goto out;
    }

    /* We will persist tree state when done. */
    file = dubtreeOpenNewFile(sealed_name, 0);
    if (file == DUBTREE_INVALID_HANDLE) {
        printf("unable to open %s for write\n", sealed_name);
        goto out;
    }

    buffer = malloc(LZ4_compressBound(simpletreeNodeSize()));
    if (!buffer) {
        printf("swap: OOM on line %d\n", __LINE__);
        goto out;
    }

    node_t *freelist = malloc(sizeof(node_t) * DUBTREE_TREENODES);
    if (!freelist) {
        printf("swap: OOM on line %d\n", __LINE__);
        goto out;
    }

    dubtreeLockForWrite(t);

    /* Set up a binary heap for the n-way merge from existing to the
     * destination level. We will use the simpletree (B-tree) indexes in each
     * level to guide the merge. Each heap element points to a level B-tree,
     * and the top-of-heap element points to the B-tree iterator with the
     * smallest key. */

    for (i = j = 0; i < destLevel; ++i) {

        SIMPLETREE *st;
        if ((st = dubtreeGetSimpleTree(t, i))) {
            DUBTREEITERTUPLE *tuple = &heap[j];
            tuple->level = i;
            tuple->st = st;
            simpletreeBegin(st, &tuple->it);
            assert(!simpletreeAtEnd(st,&tuple->it));
            dubtreeSiftUp(t, heap, j);
            ++j;
        }
    }

    /* We create the new B-tree in temporary RAM, and memcpy() it over the old
     * one when it is ready. This saves us from worrying about running out of
     * B-tree nodes, and also means we get a nicely unfragmented tree at the
     * destination level when done. We will have to overwrite the old tree
     * buffer with the new one when we are done. */

    treeBuffer = (uint8_t*) malloc(simpletreeNodeSize() * DUBTREE_TREENODES);
    memset(treeBuffer, 0, simpletreeNodeSize() * DUBTREE_TREENODES);

    /* The head of the B-tree node freelist starts out pointing to node #1. */
    head = 1;
    /* Initialize linked list of free nodes. */
    for (i = 0; i < DUBTREE_TREENODES; ++i) {
        freelist[i] = (i < DUBTREE_TREENODES - 1) ? i + 1 : 0;
    }

    /* Create the new B-tree to index the destination level. */
    simpletreeInit(&combinedTree, &head, freelist, treeBuffer, 0);

    /* When we are done, everything will be inside a single slot at the
     * destination level. */

    copyBufferStart(cb, NULL);
    for (d = 0; j > 0;) {

        /* Loop and copy down until heap empty. */

        SIMPLETREERESULT k;
        DUBTREEITERTUPLE *tuple = &heap[0];

        simpletreeRead(tuple->st, &k, &tuple->it);

        sz = k.value.b;

        /* The same key may be repeated across levels, so ignore
         * duplicates. */

        if (k.key.key != lastBlock || k.key.version != lastVersion) {
            SIMPLETREEVALUE v;
            uint64_t src = t->offsets[tuple->level] + k.value.a;
            uint64_t dst = t->offsets[destLevel] + d;
            v.a = d;
            v.b = sz;

            simpletreeInsert(&combinedTree, k.key.key, k.key.version, v);

            copyBufferInsert(cb, src, dst, sz);
            d += sz;

            lastBlock = k.key.key;
            lastVersion = k.key.version;
        }

        simpletreeNext(tuple->st, &tuple->it);

        if (simpletreeAtEnd(tuple->st, &tuple->it)) {
            simpletreeRelease(&tuple->st);
            heap[0] = heap[--j];
        }

        dubtreeSiftDown(t, heap, j);
    }

    if (copyBufferFlush(cb) < 0) {
        /* Failing to flush is fatal. */
        printf("swap: copyBufferFlush fails on line %d\n", __LINE__);
        return -1;
    }

    /* Finish the combinedTree before installing a reference to it. */
    simpletreeFinish(&combinedTree, d, 0);

    /* Install reference to single combined tree at destination level. */
    /* Last 3 args can be NULL, only needed for clearing existing tree. */
    simpletreeReference(&t->levels[destLevel], &combinedTree, NULL, NULL, NULL);

    /* Clear all old tree references and free up disk space. */
    for (i = j = 0; i < destLevel; ++i) {
        if (t->levels[i]) {
            j = i;
            t->levels[i] = 0;
        }
    }
    printf("nuke to and including %d\n", j);
    copyBufferNuke(cb, t->offsets[j + 1]);

    /* Migrate any lower level trees over to treeBuffer. */
    for (i = destLevel + 1; i < DUBTREE_MAX_LEVELS; ++i) {

        SIMPLETREE *st;
        if ((st = dubtreeGetSimpleTree(t, i))) {
            SIMPLETREE out;
            SIMPLETREEITERATOR it;
            SIMPLETREERESULT k;

            simpletreeInit(&out, &head, freelist, treeBuffer, 0);

            simpletreeBegin(st, &it);
            while (!simpletreeAtEnd(st,&it)) {

                simpletreeRead(st, &k, &it);
                simpletreeInsert(&out, k.key.key, k.key.version, k.value);
                simpletreeNext(st, &it);
            }

            simpletreeClose(st, &t->levels[i]);
            simpletreeFinish(&out, simpletreeGetSize(st), 0);
            t->levels[i] = 0;
            /* Last 3 args can be NULL, only needed for clearing existing tree. */
            simpletreeReference(&t->levels[i], &out, NULL, NULL, NULL);
        }
    }


    /* Now that we reorganized everything, we will write out the compressed
     * meta-data to top.save. */

    /* Write dubtree header. */
    offset = 0;
    memcpy(&header, t->header, sizeof(header));
    header.magic = DUBTREE_FILE_MAGIC_SAVE;
    header.freeListHead = head;
    header.dubtree_initialized = 0;
    r = dubtreeWriteFileAt(file, &header, sizeof(header), offset, NULL);
    if (r < 0)
        goto out;
    offset += sizeof(header);

    /* Write the level tree root references. */
    sz = sizeof(t->levels[0]) * DUBTREE_MAX_LEVELS;
    r = dubtreeWriteFileAt(file, (void*)t->levels, sz, offset, NULL);
    if (r < 0)
        goto out;
    offset += sz;

    /* Write the list of snapshot relations. */
    sz = sizeof(DUBTREEVERSION) * DUBTREE_MAX_VERSIONS;
    r = dubtreeWriteFileAt(file, t->versions, sz, offset, NULL);
    if (r < 0)
        goto out;
    offset += sz;

    /* Write the freelist of B-tree nodes. */
    sz = sizeof(node_t) * DUBTREE_TREENODES;
    r = dubtreeWriteFileAt(file, freelist, sz, offset, NULL);
    if (r < 0)
        goto out;
    offset += sz;

    /* Compress and write B-tree pages. */
    for (p = 0; p < DUBTREE_TREENODES; ++p) {

        uint32_t compressed_size = 0;
        int j;
        page = treeBuffer + p * simpletreeNodeSize();

        /* Find and compress non-zero pages. */
        for (j = 0; j < simpletreeNodeSize() / sizeof(uint64_t); ++j) {
            if (((uint64_t*) page)[j]) {
                compressed_size = LZ4_compress((char*)page, buffer, simpletreeNodeSize());
                break;
            }
        }

        /* Write compressed size. */
        sz = sizeof(compressed_size);
        r = dubtreeWriteFileAt(file, &compressed_size, sz, offset, NULL);
        if (r != sz)
            goto out;
        offset += sz;

        if (compressed_size > 0) {
            /* Write compressed bytes. */
            sz = compressed_size;
            r = dubtreeWriteFileAt(file, buffer, sz, offset, NULL);
            if (r != sz)
                goto out;
            offset += sz;
        }
    }

    r = 0;

out:
    if (file != DUBTREE_INVALID_HANDLE) {
        dubtreeCloseFile(file);
    }
    free(buffer);
    free(treeBuffer);
    dubtreeUnlockForWrite(t);

    dubtreeClose(t);

    /* Unlink original top.lvl to prevent future use. */
    r = unlink(mapped_name);
    if (r < 0) {
        printf("unlinking %s failed\n", mapped_name);
    }
#ifndef _WIN32
    r = unlink(mutex_name);
    if (r < 0) {
        printf("unlinking %s failed\n", mutex_name);
    }
#endif

    free(sealed_name);
    free(mapped_name);
    free(mutex_name);

    return r ? -1 : 0;
}

static inline
int dubtreeKeyLessThan(SIMPLETREEKEY *a, SIMPLETREEKEY *b)
{
    if (!a) {
        return 0;
    } else if (!b) {
        return 1;
    } else if (a->version != b->version) {
        return a->version < b->version;
    } else {
        return a->key < b->key;
    }
}

/* Single-element cache wrapper around expensive dubtreeGetVersion() call. */
static inline
int dubtreeIsLiveVersion(DUBTREE *t, uint64_t version,
        uint64_t *last_version, int *last_live)
{
    if (version != *last_version) {
        uint64_t dummy;
        *last_live = (hashtableFind(&t->vht, version, &dummy));
        *last_version = version;
    }
    return *last_live;
}

/* Merge two simpletrees while keeping track of the accummulated garbage. */
static
SIMPLETREE *dubtreeMergeTrees(DUBTREE *t, SIMPLETREE *st,
        const SIMPLETREE* sta, const SIMPLETREE *stb)
{
    SIMPLETREERESULT ra, rb;
    SIMPLETREEKEY *a, *b;
    SIMPLETREEITERATOR i, j;
    uint64_t last_a = 0;
    int last_live_a = 0;
    uint64_t garbage = simpletreeGetGarbage(sta);
    simpletreeInit(st, t->head, t->freelist, t->treeMem,
            t->header->transaction);

    simpletreeBegin(sta, &i);
    simpletreeBegin(stb, &j);

    for (;;) {
        /* Deref iterators, setting key pointers to NULL if end reached. */
        if (!simpletreeAtEnd(sta, &i)) {
            simpletreeRead(sta, &ra, &i);
            a = &ra.key;

            /* The old tree we merge into may contain non-live versions, and
             * because we want to bound the number of versions in a tree, we
             * must check for and skip over them during the merge. */
            if (!dubtreeIsLiveVersion(t, a->version, &last_a, &last_live_a)) {
                garbage += ra.value.b;
                simpletreeNext(sta, &i);
                continue;
            }

        } else {
            a = NULL;
        }

        if (!simpletreeAtEnd(stb, &j)) {
            simpletreeRead(stb, &rb, &j);
            b = &rb.key;
        } else {
            b = NULL;
        }

        /* Both trees at end, we are done. */
        if (!a && !b) {
            break;
        }

        /* Consume the lesser value, or both if equal. In that case discard
         * the value from the first tree, and count its size towards garbage. */
        if (dubtreeKeyLessThan(a, b)) {
            simpletreeInsert(st, a->key, a->version, ra.value);
            simpletreeNext(sta, &i);
        } else if (dubtreeKeyLessThan(b, a)) {
            simpletreeInsert(st, b->key, b->version, rb.value);
            simpletreeNext(sta, &j);
        } else {
            simpletreeInsert(st, b->key, b->version, rb.value);
            garbage += ra.value.b;
            simpletreeNext(sta, &i);
            simpletreeNext(stb, &j);
        }
    }
    simpletreeFinish(st, simpletreeGetSize(sta) +
            simpletreeGetSize(stb), garbage);
    return st;
}

static void dubtreeMergeIntoTree(DUBTREE *t, int level, SIMPLETREE *oldTree, SIMPLETREE *st)
{
    if (oldTree) {
        SIMPLETREE combinedTree;
        dubtreeMergeTrees(t, &combinedTree, oldTree, st);
        simpletreeClose(oldTree, &t->levels[level]);
        simpletreeClear(st);
        dubtreeSetSimpleTree(t, level, &combinedTree);
    } else {
        dubtreeSetSimpleTree(t, level, st);
    }
}

/* Update local hashtable, mapping sversion ids to parent ids,
 * from the shared state in t->versions array. */
void dubtreePrepareVersionsHash(DUBTREE* t, HashTable *ht)
{
    int i;
    DUBTREEVERSION *vs = t->versions;

    hashtableClear(ht);
    for (i = 0; i < DUBTREE_MAX_VERSIONS; ++i) {
        DUBTREEVERSION *v = vs + i;
        uint64_t dummy;
        uint64_t id, parent;

        id = v->id;
        parent = v->parent;
        if (id && id != ~0ULL && parent != ~0ULL && !hashtableFind(ht, id, &dummy)) {
            hashtableInsert(ht, id, parent);
        }
    }
}

/* Create a new tree version, to insert keys under. Returns
 * 0 if all OK, negative otherwise. Inserts are idempotent. */
int dubtreeCreateVersion(DUBTREE *t, uint64_t id, uint64_t parent)
{
    int i;
    DUBTREEVERSION *vs = t->versions;

    for (i = 0; i < DUBTREE_MAX_VERSIONS; ++i) {
        DUBTREEVERSION *v = vs + i;
        if (v->id == id) {
            printf("swap: re-added version %016"PRIx64" ok.\n", id);
            return 0;
        }
        if (!v->id && __sync_val_compare_and_swap(&v->id, 0, id) == 0) {
            /* An entry is valid if id and parent are !=0 && != ~0. */
            v->parent = parent;
            __sync_fetch_and_add(&t->header->versions_generation, 1);
            return 0;
        }
    }
    return -1;
}

int dubtreeDeleteVersion(DUBTREE *t, uint64_t id)
{
    int i;
    int r = -1;
    DUBTREEVERSION *vs = t->versions;

    printf("swap: delete version %"PRIx64"\n", id);
    for (i = 0; i < DUBTREE_MAX_VERSIONS; ++i) {
        DUBTREEVERSION *v = vs + i;
        if (v->id == id) {
            /* Delete by first setting id and parent to ~0 ("busy"), and when that has
             * been made visible, set id to 0 to mark the slot free. */
            if (__sync_val_compare_and_swap(&v->id, id, ~0ULL) == id) {
                v->parent = ~0ULL;
                __sync_synchronize();
                v->id = 0;
                r = 0;
            }
        }
    }
    __sync_fetch_and_add(&t->header->versions_generation, 1);
    return r;
}


/* Check invariants:
 *
 * - Each level should have size and garbage counters that match
 *   the sum of the sizes of the values referenced from that level.
 *
 * - No referenced value should exceed 4kiB.
 *
 * - The size of each level i should be no more than (M*4kIB)^(i+1).
 */ 

int dubtreeSanityCheck(DUBTREE *t)
{
    SIMPLETREE *existing;
    int i;
    uint64_t levelSize = DUBTREE_M * DUBTREE_BLOCK_SIZE * DUBTREE_M;
    int r = 0;

    dubtreeLockForWrite(t);
    for (i = 0; i < DUBTREE_MAX_LEVELS; ++i) {
        if ((existing = dubtreeGetSimpleTree(t, i))) {
            SIMPLETREEITERATOR it;
            SIMPLETREERESULT k;
            uint64_t used = simpletreeGetSize(existing);
            uint64_t garbage = simpletreeGetGarbage(existing);
            uint64_t sum = 0;

            simpletreeBegin(existing, &it);
            while (!simpletreeAtEnd(existing, &it)) {
                simpletreeRead(existing, &k, &it);
                sum += k.value.b;
                if (k.value.b > 0x1000) {
                    printf("too big value found in tree!\n");
                    r = -1;
                }
                simpletreeNext(existing, &it);
            }

            if (used - garbage != sum) {
                printf("garbage accounting error in level %d\n", i);
                r = -1;
            }
            if (used > levelSize) {
                printf("level overflow detected in level %d\n", i);
                r = -1;
            }

            simpletreeClose(existing, &t->levels[i]);
        }
        levelSize *= DUBTREE_M;
    }
    dubtreeUnlockForWrite(t);
    return r;
}

int dubtreeInsert(DUBTREE *t, int numKeys, uint64_t* keys, uint64_t version,
        uint8_t *values, size_t *sizes)
{
    /* Find a free slot at the top level and copy the key there. */
    SIMPLETREE st;
    SIMPLETREE *existing;
    int r = 0; // ok
    int i;
    int j;
    uint8_t *s;
    uint64_t d;
    uint64_t begin;
    uint64_t lastBlock = -1;
    uint64_t lastVersion = 0;
    uint64_t needed;
    SIMPLETREERESULT k;
    SIMPLETREEVALUE v;
    uint64_t src, dst;
    size_t sz;
    COPYBUFFER *cb = t->cb;
    uint64_t *offsets = t->offsets;

    DUBTREEITERTUPLE heap[DUBTREE_MAX_LEVELS];
    uint64_t slotSize = DUBTREE_M * DUBTREE_BLOCK_SIZE;
    uint64_t generation = t->header->versions_generation;

    assert(numKeys <= DUBTREE_M);
    for (i = 0, needed = 0; i < numKeys; ++i) {
        assert(sizes[i] <= DUBTREE_BLOCK_SIZE);
        needed += sizes[i];
    }

    if (t->vht_generation != generation) {
        /* We need to update our versions hash table. */
        dubtreePrepareVersionsHash(t, &t->vht);
        t->vht_generation = generation;
    }

    dubtreeLockForWrite(t);

    if (t->header->transaction & 1) {
        /* Detected crashed insert transaction. */
        simpletreeGC(t->head, t->freelist, t->treeMem, t->levels, DUBTREE_MAX_LEVELS,
                t->header->transaction, DUBTREE_TREENODES);
        simpletreeTransact(&t->header->transaction);
    }

    for (i = j = 0; i < DUBTREE_MAX_LEVELS; ++i) {

        /* Figure out how many bytes are in use at this level. */
        uint64_t used;
        uint64_t garbage;

        if ((existing = dubtreeGetSimpleTree(t, i))) {
            used = simpletreeGetSize(existing);
            garbage = simpletreeGetGarbage(existing);

        } else {
            used = 0;
            garbage = 0;
        }
        assert(used >= garbage);

        /* Is this level full enough to need merging, or is it so full of
         * garbage that we may as well vacuum out while we are at it? */
        if (DUBTREE_M * slotSize < used + needed || garbage > used / 2) {
            DUBTREEITERTUPLE *tuple = &heap[j];
            tuple->level = i;
            tuple->st = existing;
            simpletreeBegin(existing, &tuple->it);
            dubtreeSiftUp(t, heap, j);
            ++j;

        } else {
            /* We found a level with free space to merge the upper levels to,
             * so we can stop here. 'existing' will point to an open B-tree
             * at the destination level, or NULL if the level is empty. */
            d = used;
            break;
        }

        needed += used - garbage;
        slotSize *= DUBTREE_M;
    }
    if (i == DUBTREE_MAX_LEVELS) {
        printf("all levels full!\n");
        return -1;
    }

    /* Did loop above result in a non-empty heap of levels to merge? */
    if (j > 0) {

        /* Start a new transaction for the merge. */
        simpletreeTransact(&t->header->transaction);
        begin = d;
        dst = offsets[i] + d;

        /* Create the new B-tree to index the destination level. */
        simpletreeInit(&st, t->head, t->freelist, t->treeMem, t->header->transaction);

        copyBufferStart(cb, NULL);
        for (;;) {
            /* Loop and copy down until heap empty. */

            uint64_t dummy;
            DUBTREEITERTUPLE *tuple = &heap[0];
            simpletreeRead(tuple->st, &k, &tuple->it);

            /* Single-element cache to avoid calling dubtreeGetVersion() too
             * often. If the key to be merged does not have a corresponding
             * version, it means we should skip over it. */

            if (k.key.version == lastVersion ||
                    hashtableFind(&t->vht, k.key.version, &dummy)) {

                /* The same key may be repeated across levels, so ignore
                 * duplicates. */
                if (k.key.key != lastBlock || k.key.version != lastVersion) {

                    src = offsets[tuple->level] + k.value.a;
                    sz = k.value.b;

                    v.a = d;
                    v.b = sz;
                    assert(d + sz <= offsets[i + 1] - offsets[i]);
                    simpletreeInsert(&st, k.key.key, k.key.version, v);
                    copyBufferInsert(cb, src, dst, sz);

                    lastBlock = k.key.key;
                    lastVersion = k.key.version;
                    d += sz;
                    dst += sz;
                }
            }
            simpletreeNext(tuple->st, &tuple->it);

            if (simpletreeAtEnd(tuple->st, &tuple->it)) {
                simpletreeClose(tuple->st, &t->levels[tuple->level]);

                /* Did we reach the end of the last element on the heap? */
                if (j == 1) break;
                heap[0] = heap[--j];
            }

            /* Restore heap condition. */
            dubtreeSiftDown(t, heap, j);
        }

        if (copyBufferFlush(cb)) {
            /* Failing to flush is fatal. */
            return -1;
        }

        /* Finish the combined tree and commit the merge by
         * installing a globally visible reference to the merged
         * tree. */

        simpletreeFinish(&st, d - begin, 0);

        if (existing) {
            /* There was already a tree at the destination level, so merge st
             * into that. We keep st and existing valid until we have decided
             * if we want to compact back our newly inserted data to the
             * previous level. */
            SIMPLETREE combinedTree;
            dubtreeMergeTrees(t, &combinedTree, existing, &st);
            dubtreeSetSimpleTree(t, i, &combinedTree);
        } else {
            /* The destination level was empty, just install a reference to st
             * there. */
            dubtreeSetSimpleTree(t, i, &st);
        }

        /* Clear all tree references above this level. Ideally, this step would
         * be atomic wrt the referencing of the merged tree, but if we free up
         * the upper level trees bottom-up the worst that can happen, should we
         * crash now, is that duplicates of keys will exist in multiple levels.
         * This will waste some space that will eventually get reclaimed by
         * future merges. */

        for (j = i - 1; j >= 0; --j) {
            dubtreeSetSimpleTree(t, j, NULL);
        }
        /* Free up disk space used by now-merged levels. */
        if (i > DUBTREE_CORELIMIT) {
            copyBufferForget(cb, offsets[DUBTREE_CORELIMIT], offsets[i]);
        }

        /* Figure out if we need to compact up one level. */
        if (d - begin < slotSize / 2) {
            SIMPLETREE compactedTree;
            SIMPLETREEITERATOR it;
            uint64_t d2 = 0;

            /* Create a new empty tree, and copy the keys from the target
             * buffer back there. The trees will be identical, expect for the
             * values pointers. Perhaps we could optimize this to avoid the
             * copying, but not clear it would be worth it. */

            simpletreeInit(&compactedTree, t->head, t->freelist, t->treeMem,
                    t->header->transaction);

            simpletreeBegin(&st, &it);
            copyBufferStart(cb, NULL);

            while (!simpletreeAtEnd(&st, &it)) {
                simpletreeRead(&st, &k, &it);

                src = offsets[i] + k.value.a;
                dst = offsets[i - 1] + d2;

                sz = k.value.b;
                v.a = d2;
                v.b = sz;

                simpletreeInsert(&compactedTree, k.key.key, k.key.version, v);
                copyBufferInsert(cb, src, dst, sz);

                d2 += sz;
                simpletreeNext(&st, &it);
            }

            r = copyBufferFlush(cb);
            if (r < 0) {
                printf("swap: flush failed during compaction!\n");
                return r;
            }
            simpletreeFinish(&compactedTree, d2, 0);
            /* Install reference to compactedTree at level above. */
            dubtreeSetSimpleTree(t, i - 1, &compactedTree);

            /* Revert back to the tree at this level the way it looked
             * before we merged into it. Unfortunately we cannot just
             * install a new reference to 'existing', as that will break
             * the refcounting of concurrent readers. Instead we make a
             * copy by merging with an empty tree and use that. */
            
            if (existing) {
                SIMPLETREE empty;
                SIMPLETREE copy;
                simpletreeInit(&empty, t->head, t->freelist, t->treeMem,
                        t->header->transaction);
                simpletreeFinish(&empty, 0, 0);
                dubtreeMergeTrees(t, &copy, existing, &empty);
                dubtreeSetSimpleTree(t, i, &copy);
                simpletreeClear(&empty);
            } else {
                dubtreeSetSimpleTree(t, i, NULL);
            }

            /* Finally free up disk space used by the blocks we compacted up
             * one level. */
            copyBufferForget(cb, offsets[i] + begin, offsets[i] + d);

        }

        /* We use 'existing' to determine if 'st' got merged into the destination
         * level, in which case it is no longer relevant and must be freed, or
         * installed there and thus should be left alone. */
        if (existing) {
            simpletreeClear(&st);
            /* Also make sure we release the reference to existing. */
            simpletreeClose(existing, &t->levels[i]);
        }

        simpletreeTransact(&t->header->transaction);

    } else {
        /* Close last open tree. Don't be tempted to reuse it for the
         * actual insert below, because if there was a compaction above
         * it will no longer be valid! */

        if (existing) {
            simpletreeClose(existing, &t->levels[0]);
        }
    }


    /******** The actual insert into level 0. *************************/
    simpletreeTransact(&t->header->transaction);

    d = offsets[0];
    if ((existing = dubtreeGetSimpleTree(t, 0))) {
        d += simpletreeGetSize(existing);
    }
    begin = d;

    simpletreeInit(&st, t->head, t->freelist, t->treeMem, t->header->transaction);

    /* Loop over the input data to find the offsets of individual compressed
     * blocks, and create a B-tree indexing them. */

    for (s = values, i = 0; i < numKeys; ++i) {
        sz = sizes[i];
        memcpy(t->data + d, s, sz);

        v.a = d;
        v.b = sz;
        simpletreeInsert(&st, keys[i], version, v);

        s += sz;
        d += sz;
    }

    simpletreeFinish(&st, d - begin, 0);

    /* Since this is only one of M slots at the top level, merge the new B-tree
     * into the existing one, to get a complete index for the level. Other than
     * lookups, the index is also used when merging down to a the next level,
     * when this one runs full. */

    dubtreeMergeIntoTree(t, 0, existing, &st);

    simpletreeTransact(&t->header->transaction);
    dubtreeUnlockForWrite(t);
    return r;
}
