/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "dubtree_sys.h"
#include "dubtree_io.h"
#include "copybuffer.h"
#include "hashtable.h"

/* Sift-up / percolate up operation for binary heap. "child"
 * is the index of the child to start from, normally the
 * last element in the heap. */

static inline int lessThan(COPYBUFFER *cb, const COPY *a, const COPY *b)
{
#ifndef _WIN32 // working disk scheduler
    return (a->from < b->from);
#else // not so much
    return (a->to < b->to);
#endif
}

static inline void copyBufferSiftUp(COPYBUFFER *cb, COPY *hp, size_t child)
{
    size_t parent;
    for (; child; child = parent) {
        parent = (child - 1) / 2;

        if (lessThan(cb, &hp[child], &hp[parent])) {
            COPY tmp = hp[parent];
            hp[parent] = hp[child];
            hp[child] = tmp;

        } else {
            break;
        }
    }
}

/* Sift-down / percolate down operation for binary heap. "end"
 * is the index of the first element not in the heap. */

static inline void copyBufferSiftDown(COPYBUFFER *cb, COPY *hp, size_t end)
{
    size_t parent = 0;
    size_t child;
    COPY tmp;
    for (;; parent = child) {
        child = 2 * parent + 1;

        if (child >= end)
            break;

        /* point to the min child */
        if (child + 1 < end && lessThan(cb, &hp[child + 1], &hp [child])) {
            ++child;
        }

        /* heap condition restored? */
        if (lessThan(cb, &hp[parent], &hp[child])) {
            break;
        }

        /* else swap and continue. */
        tmp = hp[parent];
        hp[parent] = hp[child];
        hp[child] = tmp;
    }
}


void copyBufferStart(COPYBUFFER *cb, void *dst)
{
    cb->broken = 0;
    cb->n = 0;
    cb->dst = dst;
}


int copyBufferInit(COPYBUFFER *cb,
        size_t max,             // max num of entries before flush
        char *filePrefix, // where we store the files
        char **fallbacks,       // where we may look for file as a fallback
        uint64_t offset,          // where tree meta-data ends and the arrays start
        void *mem,              // where the top-of-tree is already mapped
        uint64_t limit,           // where the permanent mapping ends
        int temp                // open output files in temp mode (Windows only)? */
        )
{
    int i;
    memset(cb, 0, sizeof(COPYBUFFER));
    cb->max = max;
    cb->offset = offset;
    cb->mem = mem;
    cb->limit = limit;
    cb->temp = temp;
    cb->filePrefix = filePrefix;
    cb->fallbacks = fallbacks;

    cb->heap = (COPY*) malloc(sizeof(COPY) * max);
    if (cb->heap == NULL) {
        return -1;
    }
    memset(cb->heap, 0, sizeof(COPY) * max);

    if (hashtableInit(&cb->cacheIndex, NULL, NULL) < 0) {
        free(cb->heap);
        return -1;
    }

    for (i = 0; i < (1<<COPYBUFFER_LOGLINES); ++i) {
        COPYBUFFERCACHELINE *cl = &cb->lines[i];
        cl->page = 0;
        cl->locked = 0;
        cl->dirty = 0;
        cl->file = DUBTREE_INVALID_HANDLE;
    }
    memset(cb->bits, 0, sizeof(cb->bits));

#ifdef _WIN32
    for (i = 0; i < COPYBUFFER_NUM_OVERLAPPING; ++i) {
        cb->files[i] = DUBTREE_INVALID_HANDLE;
        cb->events[i] = CreateEvent(NULL, TRUE, TRUE, NULL);
        if (cb->events[i] == NULL) {

            printf("unable to create event handle!\n");
            /* Roll back handle creates. */
            while (--i >= 0) {
                CloseHandle(cb->events[i]);
            }
            free(cb->heap);
            return -1;
        }
    }
#endif

    return 0;
}


void copyBufferRelease(COPYBUFFER *cb)
{
    int i;
    for (i = 0; i < (1<<COPYBUFFER_LOGLINES); ++i) {
        COPYBUFFERCACHELINE *cl = &cb->lines[i];
        if (cl->file != DUBTREE_INVALID_HANDLE) {
#ifdef _WIN32
            CloseHandle(cl->file);
#else
            close(cl->file);
#endif
        }
    }

#ifdef _WIN32
    for (i = 0; i < COPYBUFFER_NUM_OVERLAPPING; ++i) {
        CloseHandle(cb->events[i]);
    }
#endif
    free(cb->heap);
}


/* Find a cache line to evict. */

static inline
int copyBufferEvictLine(COPYBUFFER *cb)
{
    int i;
    int child;
    for (i = 0, child = 0; i < COPYBUFFER_LOGLINES; i++) {
        int parent = child;
        child = 2 * parent + 1 + cb->bits[parent];
        cb->bits[parent] ^= 1;
    }
    return child - COPYBUFFER_INNERNODES;
}


/* Touch a cache line to make eviction unlikely. */

static inline
COPYBUFFERCACHELINE *copyBufferTouchLine(COPYBUFFER *cb, int line, int dirty, int locked)
{
    /* Flip the bits in the reverse path from leaf to root */
    COPYBUFFERCACHELINE *cl = &cb->lines[line];

    int child;
    for (child = line + COPYBUFFER_INNERNODES; child != 0;) {
        int parent = (child - 1) / 2;

        assert(parent < COPYBUFFER_INNERNODES);
        cb->bits[parent] = (child == (2 * parent + 1));  /* inverse test to save xor */
        child = parent;
    }

    cl->dirty |= dirty;
    cl->locked += locked;
    return cl;
}


/* Forget (or zero) a region that is no longer referenced. This
 * will zero-size the corresponding chunks on disk to reclaim space. */
void copyBufferForget(COPYBUFFER *cb, uint64_t start, uint64_t end)
{
    const uint64_t mask = COPYBUFFER_CACHEUNIT - 1;

    uint64_t s, e, page;

    s = (start + cb->offset + mask) / COPYBUFFER_CACHEUNIT;
    e = (end + cb->offset - mask) / COPYBUFFER_CACHEUNIT;

    for (page = s; page < e; ++page) {

        DUBTREE_FILE_HANDLE hFile;
        COPYBUFFERCACHELINE *cl;
        uint64_t line;

        if (hashtableFind(&cb->cacheIndex, page, &line)) {
            /* Truncate file on disk to reclaim space. Deleting the file will
             * not work, because different process may end up disagreeing about
             * which file contains what. */

            cl = &cb->lines[line];
            if (cl->file != DUBTREE_INVALID_HANDLE) {
                dubtreeSetFileSize(cl->file, 0);
                dubtreeCloseFile(cl->file);
            }

            hashtableDelete(&cb->cacheIndex, page);
            memset(cl, 0, sizeof(*cl));
            cl->file = DUBTREE_INVALID_HANDLE;

        } else {
            char *fn;
            asprintf(&fn, "%s/%08x.lvl", cb->filePrefix, (unsigned int)page);
            assert(fn);
            hFile = dubtreeOpenExistingFile(fn);
            free(fn);

            if (hFile != DUBTREE_INVALID_HANDLE) {
                dubtreeSetFileSize(hFile, 0);
                dubtreeCloseFile(hFile);
            }
        }

    }
}

/* More thorough verson of copyBufferForget, used by dubtreeSeal() to delete
 * unreferenced chunks. Not safe to use for anything else. */
void copyBufferNuke(COPYBUFFER *cb, uint64_t end)
{
    const uint64_t mask = COPYBUFFER_CACHEUNIT - 1;
    uint64_t s, e, page;

    s = (cb->offset + mask) / COPYBUFFER_CACHEUNIT;
    e = (end + cb->offset - mask) / COPYBUFFER_CACHEUNIT;

    for (page = s; page < e; ++page) {
        char *fn;
        uint64_t line;
        COPYBUFFERCACHELINE *cl;

        /* Close cached file handle if we have one. */
        if (hashtableFind(&cb->cacheIndex, page, &line)) {
            cl = &cb->lines[line];
            if (cl->file != DUBTREE_INVALID_HANDLE) {
                dubtreeCloseFile(cl->file);
            }
            hashtableDelete(&cb->cacheIndex, page);
            memset(cl, 0, sizeof(*cl));
            cl->file = DUBTREE_INVALID_HANDLE;
        }

        asprintf(&fn, "%s/%08x.lvl", cb->filePrefix, (unsigned int)page);
        assert(fn);
        unlink(fn);
        free(fn);
    }
}

/* Get the file mapping for a chunk of tree data, creating the underlying file
 * if necessary. */

COPYBUFFERCACHELINE *copyBufferGetCacheMapping(COPYBUFFER *cb, uint64_t bottom, int dirty)
{
    COPYBUFFERCACHELINE *cl;
    uint64_t page = bottom / COPYBUFFER_CACHEUNIT;
    uint64_t line;

    if (!hashtableFind(&cb->cacheIndex, page, &line)) {
        /* Not in cache */
        DUBTREE_FILE_HANDLE hFile;
        char *fn = NULL;

        for (;;) {
            line = copyBufferEvictLine(cb);
            cl = &cb->lines[line];

            /* pseudo-LRU is only approximately LRU, so there is a
             * tiny chance we are going to evict a cache line that is
             * in use. Use a 'locked' counter to work around that. */

            if (cl->locked) {
                copyBufferTouchLine(cb, line, 0, 0);
            } else break;
        }

        if (cl->file != DUBTREE_INVALID_HANDLE) {
            dubtreeCloseFile(cl->file);
            hashtableDelete(&cb->cacheIndex, cl->page);
        }

        /* We know fn is large enough for this. */
        asprintf(&fn, "%s/%08x.lvl", cb->filePrefix,
                (unsigned int)page);
        assert(fn);

        hFile = dirty ? dubtreeOpenNewFile(fn, cb->temp) :
                        dubtreeOpenExistingFile(fn);
        free(fn);

        if (hFile != DUBTREE_INVALID_HANDLE) {
            dubtreeSetFileSize(hFile, COPYBUFFER_CACHEUNIT);
        }


        if (!dirty) {
            char **fb = cb->fallbacks;
            /* Until we have found the file, walk through the
             * list of fallback dirs. */
            while (hFile == DUBTREE_INVALID_HANDLE && *fb) {
                asprintf(&fn, "%s/%08x.lvl", *fb++, (unsigned int)page);
                assert(fn);
                hFile = dubtreeOpenExistingFileReadOnly(fn);
                free(fn);
            }
        }

        if (hFile == DUBTREE_INVALID_HANDLE) {
            Wwarn("swap: FAILED getting dubtree chunk %08x dirty=%d",
                  (uint32_t)page, dirty);
            return NULL;
        }

        cl->file = hFile;
        cl->page = page;
        cl->dirty = 0;

        hashtableInsert(&cb->cacheIndex, page, line);
    }

    return copyBufferTouchLine(cb, line, dirty, 1);
}


static inline
void copyBufferPutCacheMapping(COPYBUFFERCACHELINE *cl)
{
    cl->locked--;
}


#ifdef _WIN32
static inline void *copyBufferGetIoContext(COPYBUFFER *cb, DUBTREE_FILE_HANDLE f,
        uint64_t size)
{
    unsigned int i = cb->idx;
    OVERLAPPED *o;
    HANDLE old_f;
    DWORD got;

    WaitForSingleObject(cb->events[i], INFINITE);
    old_f = cb->files[i];
    o = &cb->ovl[i];
    cb->files[i] = DUBTREE_INVALID_HANDLE;

    /* Do we have to wait and check IO status? */
    if (old_f != DUBTREE_INVALID_HANDLE) {
        if (!GetOverlappedResult(old_f, o, &got, 1)) {
            printf("swap: bad IO result, line=%d error=%u\n", __LINE__,
                    (uint32_t) GetLastError());
            return NULL;
        }
    }

    ResetEvent(cb->events[i]);
    memset(o, 0, sizeof(OVERLAPPED));
    o->hEvent = cb->events[i];
    cb->files[i] = f;
    cb->sizes[i] = size;

    cb->idx = (cb->idx + 1) % COPYBUFFER_NUM_OVERLAPPING;
    return o;
}
#endif

/* Copy from memory buffer to chunk area on disk. */

int copyBufferMemcpyToFile(COPYBUFFER *cb, uint64_t to,
        const uint8_t *from, uint64_t size)
{

    to += cb->offset;

    while (size > 0) {

        void *context = NULL;
        uint64_t offset = to & (COPYBUFFER_CACHEUNIT-1);
        uint64_t take = (COPYBUFFER_CACHEUNIT - offset < size) ?
            COPYBUFFER_CACHEUNIT - offset : size;

        COPYBUFFERCACHELINE* cl = copyBufferGetCacheMapping(cb, to, 1);
        if (cl == NULL) {
            Wwarn("swap: %s fails on line %d", __FUNCTION__, __LINE__);
            return -1;
        }

#ifdef _WIN32
        context = copyBufferGetIoContext(cb, cl->file, take);
        if (!context) {
            printf("swap: %s fails on line %d\n", __FUNCTION__, __LINE__);
            return -1;
        }
#else
        context = NULL;
#endif
        if (dubtreeWriteFileAt(cl->file, from, take, offset, context) < 0) {
            Wwarn("swap: %s fails on line %d", __FUNCTION__, __LINE__);
            return -1;
        }
        copyBufferPutCacheMapping(cl);

        to += take;
        from += take;
        size -= take;

    }
    return 0; // ok
}


/* Copy from chunk(s) on disk back to memory. */

int copyBufferMemcpyFromFile(COPYBUFFER *cb, uint8_t *to,
        uint64_t from, uint64_t size)
{
    from += cb->offset;

    while (size > 0) {

        void *context = NULL;
        uint64_t offset = from & (COPYBUFFER_CACHEUNIT-1);
        uint64_t take = (COPYBUFFER_CACHEUNIT - offset < size) ?
            COPYBUFFER_CACHEUNIT - offset : size;

        COPYBUFFERCACHELINE *cl = copyBufferGetCacheMapping(cb, from, 0);
        if (cl == NULL) {
            Wwarn("swap: %s fails on line %d", __FUNCTION__, __LINE__);
            return -1;
        }

#ifdef _WIN32
        context = copyBufferGetIoContext(cb, cl->file, take);
        if (!context) {
            printf("swap: %s fails on line %d\n", __FUNCTION__, __LINE__);
            return -1;
        }
#else
        context = NULL;
#endif
        if (dubtreeReadFileAt(cl->file, to, take, offset, context) < 0) {
            Wwarn("swap: %s fails on line %d", __FUNCTION__, __LINE__);
            return -1;
        }
        copyBufferPutCacheMapping(cl);

        to += take;
        from += take;
        size -= take;

    }
    return 0; // ok
}

/* Await and check completion of all IO slots, freeing them for future use. */
static inline int
copyBufferCheckIoResults(COPYBUFFER *cb)
{
    int r = 0;
#ifdef _WIN32
    int i;
    for (i = 0; i < COPYBUFFER_NUM_OVERLAPPING; ++i) {
        DWORD got;
        HANDLE f = cb->files[i];
        if (f != DUBTREE_INVALID_HANDLE) {
            cb->files[i] = DUBTREE_INVALID_HANDLE;
            if (!GetOverlappedResult(f, &cb->ovl[i], &got, 1)) {
                uint32_t err = (uint32_t) GetLastError();
                /* EOF is benign, but we should still flag it to the caller. */
                if (err != ERROR_HANDLE_EOF) {
                    printf("swap: bad IO result, line=%d error=%u\n",
                            __LINE__, err);
                }
                r = -1;
            } else {
                /* Check that the IO completed in full. */
                if (got != cb->sizes[i]) {
                    r = -1;
                }
            }
        }
    }
#endif
    return r;
}

/* Flush buffered-up copies in from or to-sorted order. The sorting is to speed
 * up IO. */

typedef struct BUFFEREDIO {
    uint64_t to;
    uint64_t size;
    uint8_t buf[0];
} BUFFEREDIO;

static int copyBufferBufferedCmp(const void *pa, const void *pb)
{
    BUFFEREDIO **a = (BUFFEREDIO**) pa;
    BUFFEREDIO **b = (BUFFEREDIO**) pb;
    if ((*a)->to < (*b)->to) return -1;
    else if((*b)->to < (*a)->to) return 1;
    else return 0;
}

int copyBufferFlush(COPYBUFFER *cb)
{
    int i;
    int r = 0; // ok
    uint64_t from = 0;
    uint64_t to = 0;
    uint64_t size = 0;
    uint64_t async = 0;
    const uint8_t *s = cb->mem + cb->offset;
    uint8_t *d = cb->dst ? cb->dst : cb->mem + cb->offset;

    BUFFEREDIO **buffered_ios = NULL;
    int n_buffered = 0;

    if (cb->n == 0) goto out;

    if (cb->broken) {
        printf("cannot flush broken copybuffer!\n");
        cb->n = 0;
        assert(0);
        return -1;
    }

    for (;;) {

        /* We loop until heap empty and then once more, to
         * get the last copy flushed as well. */

        COPY *c = cb->heap;

        if (size || cb->n == 0) {

            /* Unless heap empty, try to grow the existing
             * copy by appending topmost heap element. This will
             * coalesce multiple adjacent copies. */

            if (cb->n > 0 && size &&
                    c->from == from + size && c->to == to + size &&
                    (c->from < cb->limit) == (from < cb->limit) &&
                    (c->to < cb->limit) == (to < cb->limit)) {

                size += c->size;

            } else {

                /* We choose a copying strategy based on the where the copy
                 * goes from and to. In-memory we can use straight memcpy,
                 * whereas we have to use file IO to access disk, and in the
                 * disk-to-disk case we use a buffer to optimize bandwidth. */

                int src_in_memory = (from < cb->limit);
                int dst_in_memory = (cb->dst || to < cb->limit);

                /* If non-consecutive, or heap empty, copy. */

                if (src_in_memory && dst_in_memory) {

                    /* Both src and dest in memory. */
                    memcpy(d + to, s + from, size);

                } else if (src_in_memory) {

                    /* Only src in memory. */
                    r = copyBufferMemcpyToFile(cb, to, s + from, size);
                    if (r < 0) {
                        Wwarn("swap: %s fails on line %d with error %d",
                              __FUNCTION__, __LINE__, r);
                        cb->broken = 1;
                        goto out;
                    }
                    async += size;

                } else if (dst_in_memory) {

                    /* Only dst in memory. */
                    r = copyBufferMemcpyFromFile(cb, d + to, from, size);
                    if (r < 0) {
                        Wwarn("swap: %s fails on line %d with error %d",
                              __FUNCTION__, __LINE__, r);
                        cb->broken = 1;
                        goto out;
                    }

                    async += size;

                } else {

                    BUFFEREDIO *bio = (BUFFEREDIO*) malloc(sizeof(BUFFEREDIO) + size);
                    if (!bio) {
                        printf("swap: %s OOM error on line %d\n", __FUNCTION__, __LINE__);
                        cb->broken = 1;
                        goto out;
                    }
                    bio->to = to;
                    bio->size = size;

                    if (!buffered_ios) {
                        buffered_ios = malloc(sizeof(BUFFEREDIO*) * cb->max);
                        if (!buffered_ios) {
                            printf("swap: %s OOM error on line %d\n",
                                    __FUNCTION__, __LINE__);
                            cb->broken = 1;
                            goto out;
                        }
                    }
                    buffered_ios[n_buffered++] = bio;

                    /* Read into buffer. */
                    r = copyBufferMemcpyFromFile(cb, bio->buf, from, size);
                    if (r < 0) {
                        Wwarn("swap: %s fails on line %d with error %d",
                              __FUNCTION__, __LINE__, r);
                        cb->broken = 1;
                        goto out;
                    }

                    async += size;
                }

                size = 0;
            }
        }

        /* Heap empty? */

        if (cb->n == 0) {

            if (async) {
                r = copyBufferCheckIoResults(cb);
                if (r < 0) {
                    Wwarn("swap: %s fails on line %d with error %d",
                          __FUNCTION__, __LINE__, r);
                    cb->broken = 1;
                    goto out;
                }
            }

            /* Anything in buffer? Write it. */

            if (buffered_ios) {
                qsort(buffered_ios, n_buffered, sizeof(buffered_ios[0]),
                        copyBufferBufferedCmp);

                for (i = 0; i < n_buffered; ++i) {
                    BUFFEREDIO *bio = buffered_ios[i];
                    r = copyBufferMemcpyToFile(cb, bio->to, bio->buf, bio->size);
                    if (r < 0) {
                        Wwarn("swap: %s fails on line %d with error %d",
                              __FUNCTION__, __LINE__, r);
                        goto out;
                    }
                }
            }

            break;
        }

        /* If we don't have a read built-up, we must start a new one. */
        if (size == 0) {
            from = c->from;
            to   = c->to;
            size = c->size;
        }

        /* Pop topmost from heap. */

        *c = cb->heap[--(cb->n)];
        copyBufferSiftDown(cb, cb->heap, cb->n);
    }

out:

    if (n_buffered) {
        r = copyBufferCheckIoResults(cb);
        if (r < 0) {
            Wwarn("swap: %s fails on line %d with error %d",
                  __FUNCTION__, __LINE__, r);
            cb->broken = 1;
        }
        for (i = 0; i < n_buffered; ++i) {
            free(buffered_ios[i]);
        }
        free(buffered_ios);
    }

    return r;
}

void copyBufferInsert(COPYBUFFER *cb, uint64_t from, uint64_t to, size_t size)
{
    COPY *c;
    int r;

    /* If buffer is full, flush. */

    if (cb->n == cb->max) {
        r = copyBufferFlush(cb);

        /* See comment above. */
        if (r < 0) {
            printf("swap: copyBufferFlush failed on line %d\n", __LINE__);
            cb->broken = 1;
            return;
        }
    }

    /* Insert copy instruction into heap, and restore heap condition. */

    c = &cb->heap[cb->n];
    c->from = from;
    c->size = size;
    c->to = to;

    copyBufferSiftUp(cb, cb->heap, cb->n++);
}
