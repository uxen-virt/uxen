/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <uuid/uuid.h>

#include "sys.h"
#include "disklib.h"
#include "partition.h"
#include "fs-ntfs.h"
#include "accctrl.h"
#include "aclapi.h"
#include <sddl.h>
#include "winbase-compat.h"
#include "vbox-compat.h"

#include <windows.h>
#include <winioctl.h>
#include <ntdef.h>
#include <psapi.h>


static pNtReadFile NtReadFile;
static pNtQuerySystemInformation NtQuerySystemInformation;
static pNtDuplicateObject NtDuplicateObject;
static pNtQueryObject NtQueryObject;
static pFilterConnectCommunicationPort FilterConnectCommunicationPort;
static pFilterSendMessage FilterSendMessage;
static int shallow_allowed = 1;
static int min_shallow_size = SECTOR_SIZE;
static int follow_links = 1;

extern int ntfs_get_errno(void);

#define MAX_PATH_LEN 2048
DECLARE_PROGNAME;

static int low_priority = 0;

const PWSTR CoWPortName = L"\\CoWPort";
#define COW_VERSION     1
const uint32_t COW_MAGIC_STRING
    = ('B' << 24) + ('C' << 16) + ('o' << 8) + 'W'; /* 'BCoW' in little-endian */

typedef enum {
    StartWatchRequest = 0,
    StopWatchRequest,
} CoWMessageType;

typedef struct {
    uint32_t Version;
    uint32_t Magic; // this serves as a basic level of authentication
    uint32_t Type;
    uint32_t Size;
    char Message[0];
} COW_MESSAGE, *PCOW_MESSAGE;

typedef struct {
    GUID Guid;
    uint32_t FileNameLen;
    uint32_t DirNameLen;
    wchar_t Buffer[0];
} COW_MESSAGE_START_WATCH, *PCOW_MESSAGE_START_WATCH;

static inline double rtc(void)
{
    LARGE_INTEGER time;
    LARGE_INTEGER freq;
    uint64_t t, f;

    QueryPerformanceCounter(&time);
    QueryPerformanceFrequency(&freq);

    t = ((uint64_t)time.HighPart << 32UL) | time.LowPart;
    f = ((uint64_t)freq.HighPart << 32UL) | freq.LowPart;

    return ((double)t) / ((double)f);
}

struct Manifest;
typedef struct Variable {
    wchar_t *name;
    wchar_t *path;
    struct Manifest *man;
    HANDLE volume;
} Variable;

typedef struct VarList {
    int n;
    Variable *entries;
} VarList;

void varlist_init(VarList *ml)
{
    ml->entries = NULL;
    ml->n = 0;
}

Variable *varlist_push(VarList *vl)
{
    int n = vl->n++;
    if (!(n & (n + 1))) {
        vl->entries = realloc(vl->entries, 2 * (n + 1) * sizeof(Variable));
        assert(vl->entries);
    }
    memset(&vl->entries[n], 0, sizeof(Variable));
    return &vl->entries[n];
}

Variable *varlist_find(VarList *vl, const wchar_t *name)
{
    int i;
    for (i = 0; i < vl->n; ++i) {
        Variable *e = &vl->entries[i];
        if (!wcsicmp(e->name, name)) {
            return e;
        }
    }
    return NULL;
}

/* disk handle, code duplicated from img-ntfscp.c */
struct disk {
    disk_handle_t hdd;
    ptbl_t ptbl;
    partition_t p_sysvol;
    partition_t p_bootvol;
    ntfs_fs_t sysvol;
    ntfs_fs_t bootvol;
};

static wchar_t rootdrive = L'c';
static Variable *bootvol_var = NULL;

/* Heap used as priority queue for BFS scan. */
typedef struct HeapElem {
    wchar_t *name;
    uint64_t file_id;
    wchar_t *rerooted_name;
    int top_level;
    int recurse;
} HeapElem;

typedef struct Heap {
    HeapElem *elems;
    int n;
    uint64_t mask;
} Heap;

static inline void heap_init(Heap *hp, uint64_t mask)
{
    hp->elems = NULL;
    hp->n = 0;
    hp->mask = mask;
}

static inline int less_than(Heap *hp, HeapElem *a, HeapElem *b)
{
    uint64_t mask = hp->mask;
    uint64_t va = a->file_id & mask;
    uint64_t vb = b->file_id & mask;
    return (va < vb);
}

static inline void sift_up(Heap *hp, int child)
{
    int parent;
    HeapElem *elems = hp->elems;
    for (; child; child = parent) {
        parent = (child - 1) / 2;
        if (less_than(hp, &elems[child], &elems[parent])) {
            HeapElem tmp = elems[parent];
            elems[parent] = elems[child];
            elems[child] = tmp;
        } else {
            break;
        }
    }
}

static inline void sift_down(Heap* hp, int last)
{
    int parent = 0;
    int child;
    HeapElem *elems = hp->elems;
    for (;; parent = child) {
        child = 2 * parent + 1;
        if (child > last) {
            break;
        }
        /* choose the smaller of the two children */
        if (child + 1 <= last && less_than(hp, &elems[child + 1], &elems[child])) {
            ++child;
        }
        if (less_than(hp, &elems[parent], &elems[child])) {
            break;
        }
        HeapElem tmp = elems[parent];
        elems[parent] = elems[child];
        elems[child] = tmp;
    }
}

static inline
void heap_push(Heap *hp, HeapElem e)
{
    int succ = hp->n + 1;
    if (!(succ & hp->n)) {
        hp->elems = realloc(hp->elems, sizeof(HeapElem) * 2 * succ);
        assert(hp->elems);
    }
    hp->elems[hp->n] = e;
    sift_up(hp, hp->n);
    hp->n = succ;
}

static inline
HeapElem heap_pop(Heap *hp)
{
    HeapElem r = hp->elems[0];
    hp->elems[0] = hp->elems[--(hp->n)];
    sift_down(hp, hp->n);
    return r;
}

static inline
int heap_empty(Heap *hp)
{
    return (hp->n == 0);
}

static inline
void heap_clear(Heap *hp)
{
    free(hp->elems);
    memset(hp, 0, sizeof(Heap));
}

typedef enum { /* actions are ordered from most to least desirable. */
        MAN_CHANGE = 0, /* used internally to degrade something to force copy */
        MAN_EXCLUDE = 1,
        MAN_BOOT = 2, /* file that needs rewiring to /boot. */
        MAN_FORCE_COPY = 3, /* like COPY, but overrides shallow. */
        MAN_SHALLOW_FOLLOW_LINKS = 4, /* shallow but also populate other host-side linked files */
        MAN_SHALLOW = 5, /* normal shallow, e.g. via winsxs name. */
        MAN_COPY_FOLLOW_LINKS = 6, /* deep copy but also populate other host-side linked files. */
        MAN_COPY = 7, /* plain copy from host to vm. */
        MAN_COPY_EMPTY_DIR = 8, /* plain copy from host to vm. */
        MAN_MKDIR = 9, /* used internally to ensure dirs are created before use. */
        MAN_LINK = 10, /* used internally to hardlink files with >1 names. */
        MAN_SYMLINK = 11, /* used internally for symlinks */
    } Action;

typedef struct ManifestEntry {
    ntfs_fs_t vol;
    Variable *var;
    wchar_t *name; /* host name */
    wchar_t *imgname; /* name that goes into the image. Always set. */
    wchar_t* target; /* Used for MAN_LINK */
    size_t name_len;
    uint64_t offset;
    uint64_t file_size;
    uint64_t link_id;
    uint64_t file_id;
    uint32_t securid;
    int cache_index;
    Action action;
    int excludable_single_file_entry;
    uint8_t sha[SHA1_DIGEST_SIZE]; /* only used/populated for file copies */
} ManifestEntry;

typedef struct Manifest {
    int n;
    ManifestEntry *entries;
    /* the _ex vars don't include excludable_single_file_entrys, which is
     * necessary for performance of find_by_prefix()
     */
    int n_ex;
    int (*order_fn)(const void *, const void *);
    ManifestEntry **entries_ex;
} Manifest;

static void man_init(Manifest *man)
{
    man->entries = NULL;
    man->n = 0;
    man->entries_ex = NULL;
    man->n_ex = 0;
}

static inline void man_unsorted(Manifest *man)
{
    man->order_fn = NULL;
}

static ManifestEntry *man_push(Manifest *man)
{
    int n = man->n++;
    man_unsorted(man);
    if (!(n & (n + 1))) {
        man->entries = realloc(man->entries, 2 * (n + 1) * sizeof(ManifestEntry));
        assert(man->entries);

    }
    memset(&man->entries[n], 0, sizeof(ManifestEntry));
    man->entries[n].cache_index = -1;
    return &man->entries[n];
}

static ManifestEntry *man_push_entry(Manifest *man,
                                     const wchar_t *name,
                                     Action action)
{
    ManifestEntry *e = man_push(man);
    e->name = wcsdup(name);
    e->name_len = wcslen(e->name);
    e->action = action;
    e->imgname = e->name;
    return e;
}

ManifestEntry* man_push_file(Manifest *out,
                             ntfs_fs_t vol,
                             Variable *var,
                             const wchar_t *name,
                             uint64_t file_size,
                             uint64_t file_id,
                             const wchar_t *imgname,
                             Action action)
{
    ManifestEntry *e = man_push_entry(out, name, action);
    e->vol = vol;
    e->var = var;
    e->file_size = file_size;
    e->file_id = file_id;
    e->imgname = imgname ? wcsdup(imgname) : e->name;
    if (file_size < min_shallow_size) {
        if (action == MAN_SHALLOW) {
            e->action = MAN_COPY;
        } else if (action == MAN_SHALLOW_FOLLOW_LINKS) {
            e->action = MAN_COPY_FOLLOW_LINKS;
        }
    }
    return e;
}

/* Sorts by imgname first (insensitively), then by name (likewise), then by
 * action, then by case-sensitive name as a tie-break to impose a consistent
 * ordering on entries that differ only by case.
 */
static int cmp_name_action(const void *a, const void *b)
{
    const ManifestEntry *ea = (const ManifestEntry *) a;
    const ManifestEntry *eb = (const ManifestEntry *) b;
    int r = wcsicmp(ea->imgname, eb->imgname);
    if (r != 0) {
        return r;
    }
    r = wcsicmp(ea->name, eb->name);
    if (r != 0) {
        return r;
    }
    r = (int)ea->action - (int)eb->action;
    if (r != 0) {
        return r;
    }
    return wcscmp(ea->name, eb->name);
}

static int cmp_offset_link_action(const void *a, const void *b)
{
    const ManifestEntry *ea = (const ManifestEntry *) a;
    const ManifestEntry *eb = (const ManifestEntry *) b;

    /* Order by disk offset, link_id, and action.
     * Other than the optimizing disk reads, this places
     * multiple names for the same file next to each other
     * in the sorted list, with the more desirable action (e.g.
     * shallow) dominating the less desirable (e.g. copy).
     */

    if (ea->offset < eb->offset) {
        return -1;
    } else if (eb->offset < ea->offset) {
        return 1;
    } else {
        if (ea->link_id < eb->link_id) {
            return -1;
        } else if (eb->link_id < ea->link_id) {
            return 1;
        } else {
            if (ea->action < eb->action) {
                return -1;
            } else if (eb->action < ea->action) {
                return 1;
            } else {
                /* All else being equal, compare by names just to
                 * make sure we get the same sort each time. */
                return wcscmp(ea->imgname, eb->imgname);
            }
        }
    }
}

static int cmp_id_action(const void *a, const void *b)
{
    const ManifestEntry *ea = (const ManifestEntry *) a;
    const ManifestEntry *eb = (const ManifestEntry *) b;

    if (ea->file_id < eb->file_id) {
        return -1;
    } else if (eb->file_id < ea->file_id) {
        return 1;
    } else {
        if (ea->action < eb->action) {
            return -1;
        } else if (eb->action < ea->action) {
            return 1;
        } else {
            /* All else being equal, compare by names just to
             * make sure we get the same sort each time. */
            return wcscmp(ea->name, eb->name);
        }
    }
}

static int cmp_system_handle(const void *a, const void *b)
{
    const PSYSTEM_HANDLE_TABLE_ENTRY_INFO pa = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO) a;
    const PSYSTEM_HANDLE_TABLE_ENTRY_INFO pb = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO) b;

    return (pa->ProcessId - pb->ProcessId);
}

/*
 * Data used by the acl_phase.
*/
static PSID builtin_users = NULL;
static PSID everyone = NULL;

#define MAX_CACHED 512
typedef struct {
    PACL dacl;
    SECURITY_DESCRIPTOR_RELATIVE *sdr;
    uint32_t sdrsz;
    int size;
    volatile int valid;
    int readable;
} CachedAcl;

CachedAcl cached_acls[MAX_CACHED];
volatile int cache_size = 0;

typedef struct {
    Manifest *man;
    int processed_entries;
    int cache_hits;
    int cache_misses;
    volatile int *idx;
} ACLThreadData;

typedef enum {
    ACL_Denied = 0,
    ACL_Allowed = 1,
    ACL_Absent = 2,
} ACLType;

/*
 * End of acl_phase related global data.
*/



#define ENTER_FN() double _t = rtc(); \
    printf("\nenter %s\n", __FUNCTION__)

#define LEAVE_FN() printf("%s took %.2fs\n", __FUNCTION__, rtc() - _t)

static void man_sort(Manifest *man, int (*cmp)(const void *, const void *))
{
    if (man->order_fn != cmp) {
        qsort(man->entries, man->n, sizeof(ManifestEntry), cmp);
        man->order_fn = cmp;
    }
}

static void man_sort_by_name(Manifest *man)
{
    man_sort(man, cmp_name_action);
}

static void man_sort_by_offset_link_action(Manifest *man)
{
    man_sort(man, cmp_offset_link_action);
}

static void man_sort_by_id(Manifest *man)
{
    man_sort(man, cmp_id_action);
}

/* Note the criteria for eliminating duplicates in the man_uniq_xxx() fns has to
 * be compatible with the sort order otherwise the duplicates won't be found
 * because they aren't adjacent to one another.
 */

static void man_uniq_by_name(Manifest *man)
{
    /* Uniques based on imgname only (which in cases where we don't care, will
     * be the same as name). Since cmp_name_action sorts by imgname first, this
     * is still compatible with man_sort_by_name() */
    int i, j;
    if (man->n == 0) {
        return;
    }
    assert(man->order_fn == cmp_name_action);
    for (i = j = 1; i < man->n; ++i) {

        ManifestEntry *a = &man->entries[i];
        const wchar_t *aname = a->imgname;
        const wchar_t* jname = man->entries[j - 1].imgname;
        if (wcsicmp(aname, jname) != 0) {
            man->entries[j++] = *a;
        }
    }
    man->n = j;
}

static void man_uniq_by_name_and_action(Manifest *man)
{
    /* This is called on input manifests therefore an entry is only a duplicate
     * if all of its name, action AND imgname match */
    int i, j;
    if (man->n == 0) {
        return;
    }
    assert(man->order_fn == cmp_name_action);
    for (i = j = 1; i < man->n; ++i) {

        ManifestEntry *a = &man->entries[i];
        ManifestEntry *b = &man->entries[j - 1];
        if (wcsicmp(a->name, b->name) != 0
               || wcsicmp(a->imgname, b->imgname) != 0
               || a->action != b->action) {
            man->entries[j++] = *a;
        }
    }
    man->n = j;
}

static void man_filter_excludables(Manifest *man)
{
    /* Set up the _ex variables. These are pointers to all the entries which
     * don't have excludable_single_file_entry set. This is needed for efficient
     * searching for excludes in the case where you have a huge number of single
     * file entries.
     */
    int n_ex = 0;
    int i, j;
    for (i = 0; i < man->n; i++) {
        ManifestEntry *e = &man->entries[i];
        if (!e->excludable_single_file_entry) {
            n_ex++;
        }
    }
    man->entries_ex = realloc(man->entries_ex, sizeof(ManifestEntry *) * n_ex);
    man->n_ex = n_ex;
    for (i = j = 0; i < man->n; i++) {
        ManifestEntry *e = &man->entries[i];
        if (!e->excludable_single_file_entry) {
            man->entries_ex[j++] = e;
        }
    }
}

/* Replaces backslashes with forward slashes and eliminates duplicate slashes.
 * Note this does not alter the case of s */
static inline void normalize_string(wchar_t *s)
{
    int last = 0;
    wchar_t *d = s;
    while (*s) {
        int c = *s++;
        if (c == '\\') {
            c = '/';
        }
        if (c == '/' && last == '/') {
            continue;
        }
        last = c;
        *d++ = c;
    }
    *d = L'\0';
}

static inline void normalize_string2(wchar_t *s)
{
    while (*s) {
        if (*s == '/') {
            *s = '\\';
        }
        ++s;
    }
}

/* Join input strings and place the result in buf, observing MAX_PATH_LEN, and
 * null-terminating the result. Exit with err() if the result would be longer
 * than MAX_PATH_LEN - 1. */
static inline
wchar_t *path_join_var(wchar_t *buf, ...)
{
    wchar_t *dst = buf;
    wchar_t *end = buf + MAX_PATH_LEN;
    va_list argp;
    wchar_t *src;
    va_start(argp, buf);

    for (src = NULL; dst != end; ) {
        wchar_t c = src ? *src++ : 0;
        if (!c) {
            src = va_arg(argp, wchar_t *);
            if (!src) {
                break;
            } else {
                continue;
            }
        }
        *dst++ = c;
    }

    va_end(argp);

    if (dst == end) {
        errx(1, "path too long");
    } else {
        *dst = 0;
        return buf;
    }
}
#define path_join_var(...) path_join_var(__VA_ARGS__, NULL)

static inline
wchar_t *path_join(wchar_t *buf, const wchar_t *a, const wchar_t *b)
{
    return path_join_var(buf, a, b);
}

static inline wchar_t *prefix(Variable *var, const wchar_t *s)
{
    static wchar_t buf[MAX_PATH_LEN];
    path_join(buf, var->path, s);
    normalize_string2(buf);
    return buf;
}

static inline void strip_filename(wchar_t *path)
{
    wchar_t *last = NULL;
    wchar_t *c = path;
    while (*c) {
        if (*c == '/') {
            last = c;
        }
        ++c;
    }
    if (last) {
        *last = '\0';
    }
}

static inline void strip_trailing_slash(wchar_t *path) {
    int len = wcslen(path);
    if (len > 1 && path[len-1] == L'/') {
        path[len-1] = 0;
    }
}

#define CONST_WCSLEN(literal) ((sizeof(literal) / sizeof(wchar_t)) - 1)
#define LONG_PATH_PREFIX L"\\??\\"
#define LONG_PATH_PREFIX_LEN CONST_WCSLEN(LONG_PATH_PREFIX)
_STATIC_ASSERT(LONG_PATH_PREFIX_LEN == 4);

static inline const wchar_t *strip_long_path_prefix(const wchar_t *path)
{
    /* Remove the \??\ from the start of path, if present */
    if (wcsncmp(path, LONG_PATH_PREFIX, LONG_PATH_PREFIX_LEN) == 0) {
        return path + LONG_PATH_PREFIX_LEN;
    } else {
        return path;
    }
}

int read_manifest(FILE *f, VarList *vars, Manifest *suffix)
{
    char whole_line[MAX_PATH_LEN];
    char *fn;
    int line = 1;

    printf("reading manifest\n");
    for (line = 1; fgets(whole_line, sizeof(whole_line), f); ++line) {
        fn = whole_line;
        ManifestEntry *m;

        size_t l = strlen(fn);
        if (fn[l - 1] == L'\n') {
            fn[l - 1] = L'\0';
        }

        if (!fn[0] || fn[0] == '#' || fn[0] == '[') {
            /* Comments etc we can skip over. */
            continue;
        } else if (fn[0] == '.') {
            /* Add to suffixes manifest. */
            char *c;
            int colon = 0;
            for (c = fn + 1; *c; ++c) {
                if (*c == ':') {
                    *c = '\0';
                    colon = 1;
                    break;
                }
            }
            m = man_push_entry(suffix, wide(fn + 1), MAN_EXCLUDE);
            m->name_len = c - (fn + 1);

            /* Format is .ext:xxMB or .ext:xxKB. If there is no colon
             * we leave the size at default 0 bytes. Note that we never
             * check for the superfluous 'B'. */
            if (colon) {
                ++c;
                while (isdigit(*c)) {
                    m->file_size = 10 * m->file_size + (*c - '0');
                    ++c;
                }
                if (*c == 'K') {
                    m->file_size <<= 10;
                } else if (*c == 'M') {
                    m->file_size <<= 20;
                } else {
                    printf("unable to parse suffix rule '%s'\n", fn);
                    exit(1);
                }
            }


        } else {
            int ok = 0;
            int action;
            int follow_host_links = 0;
            int excludable_single_file_entry = 0;
            if (fn[0] == '^') {
                follow_host_links = 1;
                fn++; /* it is an extra prefix so recommence parsing the char afterwards */
            }
            if (fn[0] == '?') {
                excludable_single_file_entry = 1;
                fn++; /* it is an extra prefix so recommence parsing the char afterwards */
            }
            switch (fn[0]) {
                case '+':
                    action = follow_host_links ? MAN_COPY_FOLLOW_LINKS : MAN_COPY;
                    break;
                case '-':
                    action = MAN_EXCLUDE;
                    if (follow_host_links) {
                        printf("Following links not permitted for - lines\n");
                        return -1;
                    }
                    break;
                case '!':
                    action = MAN_FORCE_COPY;
                    if (follow_host_links) {
                        printf("Following links not permitted for ! lines\n");
                        return -1;
                    }
                    break;
                case '*':
                    action = follow_host_links ? MAN_SHALLOW_FOLLOW_LINKS : MAN_SHALLOW;
                    break;
                case ':': {
                    action = MAN_COPY_EMPTY_DIR;
                    break;
                }
                default:
                    errx(1, "unhandled : %s, line %d\n", whole_line, line);
                    break;
            }

            /* Scan the ${XXX} part of the manifest line. */
            if (fn[1] == '$' && fn[2] == '{') {
                char *v = &fn[3];
                char *c;
                char *right;
                /* make right point to the string after the ':' if any */
                for (right = v; (*right != '\0') && (*right != ':'); ++right) {}
                if (*right == '\0') {
                    right = NULL;
                } else {
                    *right++ = '\0';
                }
                for (c = v; *c; ++c) {
                    if (*c == '}') {
                        *c++ = '\0';
                        ok = 1;
                        break;
                    }
                }
                if (ok) {

                    Variable *var;

                    wchar_t *w = wide(v);
                    var = varlist_find(vars, w);
                    if (!var) {
                        errx(1 ,"undefined variable name '%ls' on line %d.\n", w, line);
                    }
                    free(w);
                    w = wide(c);
                    normalize_string(w);
                    m = man_push_entry(var->man, w, action);
                    free(w);
                    if (right) {
                        m->imgname = wide(right);
                        //printf("in manifest [%S] ==> [%S]\n", m->name, m->imgname);
                    }
                    m->excludable_single_file_entry = excludable_single_file_entry;
                }
            }
            if (!ok) {
                errx(1, "unable to parse prefix entry '%s' on line %d.\n", whole_line, line);
            }
        }
    }

    return 0;
}

static ManifestEntry *find_full_name(const Manifest *man, const wchar_t *fn)
{
    int i;
    for (i = 0; i < man->n; ++i) {
        ManifestEntry *e = &man->entries[i];
        if (!wcsicmp(fn, e->name)) {
            return e;
        }
    }
    return NULL;
}

static ManifestEntry *find_by_prefix(Manifest *man, const wchar_t *fn)
{
    int i;
    ManifestEntry *match = NULL;

    for (i = 0; i < man->n_ex; ++i) {

        ManifestEntry *e = man->entries_ex[i];

        if (!wcsnicmp(fn, e->name, e->name_len) &&
                (!match || e->name_len > match->name_len)) {
            match = e;
        }
    }
    return match;
}

static ManifestEntry *find_by_suffix(Manifest *man, const wchar_t *fn)
{
    int i;
    size_t fn_len = wcslen(fn);
    ManifestEntry *match = NULL;

    for (i = 0; i < man->n; ++i) {

        ManifestEntry *e = &man->entries[i];

        if (fn_len >= e->name_len &&
                (!e->name_len || fn[fn_len - (1 + e->name_len)] == L'.') &&
                !wcsnicmp(fn + fn_len - e->name_len, e->name, e->name_len) &&
                (!match || e->name_len > match->name_len)) {
            match = e;
        }
    }
    return match;
}

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

static inline
NTSTATUS EnablePrivilege(
    IN LPCTSTR szPrivilege
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    TOKEN_PRIVILEGES NewState;
    LUID             luid;
    HANDLE hToken    = NULL;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken )) {
        printf("Failed OpenProcessToken\n");
        status = STATUS_UNSUCCESSFUL;
        goto out;
    }

    if ( !LookupPrivilegeValue( NULL,
                                szPrivilege,
                                &luid )) {
        printf("Failed LookupPrivilegeValue\n");
        status = STATUS_UNSUCCESSFUL;
        goto out;
    }

    NewState.PrivilegeCount = 1;
    NewState.Privileges[0].Luid = luid;
    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken,
                               FALSE,
                               &NewState,
                               0,
                               NULL,
                               NULL)) {
        printf("Failed AdjustTokenPrivileges\n");
        status = STATUS_UNSUCCESSFUL;
        goto out;
    }

out:
    if (hToken) {
        CloseHandle(hToken);
    }

    return status;
}

/* Header compat. for OpenFileById */
typedef enum _FILE_ID_TYPE {
    FileIdType          = 0,
    ObjectIdType        = 1,
    ExtendedFileIdType  = 2,
    MaximumFileIdType
} FILE_ID_TYPE, *PFILE_ID_TYPE;

typedef struct {
    DWORD        dwSize;
    FILE_ID_TYPE Type;
    union {
        LARGE_INTEGER FileId;
        GUID          ObjectId;
#if 0//(_WIN32_WINNT >= _WIN32_WINNT_WIN8)
        ExtendedFileId;
#endif
    } DUMMYUNIONNAME;
} FILE_ID_DESCRIPTOR;

HANDLE WINAPI OpenFileById(
    HANDLE hFile,
    FILE_ID_DESCRIPTOR *lpFileID,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwFlags
    );

static
HANDLE open_file_by_id(HANDLE volume, uint64_t file_id, DWORD access, DWORD extra_flags)
{
    HANDLE h;
    FILE_ID_DESCRIPTOR fid = {sizeof(fid), };
    fid.Type = FileIdType;
    fid.FileId.QuadPart = file_id;

    h = OpenFileById(volume,
            &fid,
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            FILE_FLAG_BACKUP_SEMANTICS | extra_flags
            );
    if (h == INVALID_HANDLE_VALUE) {
        printf("error opening file_id %"PRIx64", err=%u\n",
                (uint64_t) file_id, (uint32_t) GetLastError());
    }
    return h;
}

static HANDLE open_file_by_name(const wchar_t *file_name, DWORD extra_flags)
{
    HANDLE h = CreateFileW(
        file_name,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | extra_flags,
        NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD win32_err = GetLastError();
        printf("failed to open %ls for copying, err=%u\n", file_name, (uint32_t)win32_err);
    }
    return h;
}

int stat_file(HANDLE volume, uint64_t file_id, uint64_t *file_size, uint64_t *offset)
{
    STARTING_VCN_INPUT_BUFFER in;
    BY_HANDLE_FILE_INFORMATION inf;
    RETRIEVAL_POINTERS_BUFFER retr;
    DWORD bytes;

    HANDLE h = open_file_by_id(volume, file_id, FILE_READ_ATTRIBUTES, 0);
    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    if (!GetFileInformationByHandle(h, &inf)) {
        CloseHandle(h);
        return -1;
    }

    *file_size = ((uint64_t)inf.nFileSizeHigh << 32ULL) | inf.nFileSizeLow;

    memset(&in, 0, sizeof(in));
    if (DeviceIoControl(h,
                FSCTL_GET_RETRIEVAL_POINTERS,
                &in, sizeof(in),
                &retr, sizeof(retr),
                &bytes,
                NULL)) {

        *offset = ((uint64_t)retr.Extents[0].Lcn.HighPart << 32ULL)
            | retr.Extents[0].Lcn.LowPart;

    } else {
        /* We don't care. */
    }

    CloseHandle(h);
    return 0;
}

/* From ddk\ntifs.h */
typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR  DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;
#define IO_REPARSE_TAG_SYMLINK                  (0xA000000CL)       // winnt

static wchar_t *get_symlink_path(HANDLE h)
{
    size_t sz = 1024;
    REPARSE_DATA_BUFFER *buf = malloc(sz);
    DWORD bytes_returned = 0;
    BOOL ok = DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, NULL, 0, buf, sz, &bytes_returned, NULL);
    if (ok) {
        if (buf->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
            ULONG n = buf->SymbolicLinkReparseBuffer.SubstituteNameLength;
            ULONG offset = buf->SymbolicLinkReparseBuffer.SubstituteNameOffset;
            wchar_t *result = malloc(n + sizeof(wchar_t));
            memcpy(result, buf->SymbolicLinkReparseBuffer.PathBuffer +
                (offset / sizeof(wchar_t)), n);
            result[n / sizeof(wchar_t)] = 0; /* null terminate */
            free(buf);
            return result;
        } else {
            printf("Skipping unsupported reparse point tag=%08x\n",
                (uint32_t)buf->ReparseTag);
        }
    } else {
        printf("DeviceIoControl(FSCTL_GET_REPARSE_POINT) failed err=%u\n",
            (uint32_t)GetLastError());
    }
    free(buf);
    return NULL;
}

static inline
int path_exists(wchar_t *fn, uint64_t *file_id, uint64_t *file_size,
                int *is_dir, wchar_t **symlink)
{
    HANDLE h;
    BY_HANDLE_FILE_INFORMATION inf;
    int r = 0;
    *is_dir = 0;
    *file_id = 0;
    *file_size = 0;
    *symlink = NULL;
    h = CreateFileW(fn,
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    NULL);
    if (h != INVALID_HANDLE_VALUE) {
        r = 1;
        if (GetFileInformationByHandle(h, &inf)) {
            if (inf.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                /* Both files and directories can be reparse points (and
                 * equally there are both file and directory symlinks) */
                *symlink = get_symlink_path(h);
            }

            if (!(inf.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                *file_size = ((uint64_t)inf.nFileSizeHigh << 32ULL) | inf.nFileSizeLow;
                *is_dir = 0;
            } else {
                *is_dir = 1;
            }
            *file_id = ((uint64_t) inf.nFileIndexHigh << 32ULL) | inf.nFileIndexLow;
        }
        CloseHandle(h);
    }
    return r;
}

/* Breadth-first search directory scan. This is faster than DFS due to better
 * access locality. */

int files, directories;

int bfs(Variable *var,
        Manifest *suffixes,
        Manifest *out,
        Manifest *extra_dirs,
        struct disk *disk,
        ManifestEntry* toplevel_entry,
        int recurse)
{
    assert(disk->bootvol);

    int i;
    uint64_t file_id;
    uint64_t file_size = 0;
    int manifested_action;
    int action;
    const size_t info_sz = 4<<20;
    void *info_buf;
    const wchar_t* dn = toplevel_entry->name;
    assert(min_shallow_size >= SECTOR_SIZE);
    int heap_switch = 0;
    int is_dir;
    wchar_t *symlink = NULL;
    Heap heaps[2];

    manifested_action = toplevel_entry->action;
    action = toplevel_entry->action;

    /* First check if this is a single file that needs to be included
     * in the output manifest by itself. */
    if (path_exists(prefix(var, dn), &file_id, &file_size, &is_dir, &symlink)) {
        if (!is_dir) {
            ManifestEntry *e;
            if (toplevel_entry->excludable_single_file_entry) {
                /* Check if we should exclude it or otherwise ignore this entry */
                ManifestEntry* otherm = find_by_prefix(var->man, dn);
                if (otherm && otherm->action < action) {
                    return 0;
                }
            }
            e = man_push_file(out,
                          disk->bootvol,
                          var,
                          dn,
                          file_size,
                          file_id,
                          toplevel_entry->imgname,
                          toplevel_entry->action);
            if (symlink) {
                e->action = MAN_SYMLINK;
                e->target = symlink;
            }
            //printf("1.Adding entry [%S]=[%d]=>[%S]\n", e->name, e->action, e->imgname);
            return 0;
        } else {
            /* The manifest should use trailing slashes for all dirs, complain if not. */
            if (dn[wcslen(dn) - 1] != L'/') {
                //printf("warning: [%ls] is a directory!\n", dn);
            }
        }
    } else {
        /* We do not like overly broad manifests, so complain about things not found. */
        if (!toplevel_entry->excludable_single_file_entry) {
            /* But don't complain about things marked as excludable single file
             * entries, as well as honouring excludes these are allowed to not
             * exist.
             */
            uint32_t err = (uint32_t)GetLastError();
            printf("warning: file not found! [%ls%ls] err=%u\n", var->path, dn, err);
        }
        return 0;
    }

    info_buf = malloc(info_sz);
    if (!info_buf) {
        printf("%s: out of memory\n", __FUNCTION__);
        return -1;
    }

    /* Initialize heaps for use as file-id ordered priority queues. */
    for (i = 0; i < 2; ++i) {
        /* Only order heaps on the 48 bits of file-id that index into MFT. */
        heap_init(&heaps[i], 0xffffffffffffULL);
    }

    /* Do a modified breadth-first search from the supplied directory name down.  */
    wchar_t *rewrite = toplevel_entry->imgname == toplevel_entry->name ? NULL :
        toplevel_entry->imgname;
    HeapElem he = {wcsdup(dn), 0, rewrite, 1, recurse};
    //printf("1.pushing [%S], [%S]\n", he.name, (he.rerooted_name ? he.rerooted_name : L"NULL"));
    directories++;

    heap_push(&heaps[heap_switch], he);
    for (;;) {

        HANDLE dir;
        HeapElem q;

        /* Use two heaps (priority queues) to implement an elevator-like scan
         * over the logical layout of the MFT. As long as we have a file_id
         * that is larger than one we visited last, use that. If not, start
         * over from the smallest known file_id. */

        if (heap_empty(&heaps[heap_switch])) {
            heap_switch ^= 1;
        }

        if (heap_empty(&heaps[heap_switch])) {
            break;
        }

        q = heap_pop(&heaps[heap_switch]);

        dir = CreateFileW(prefix(var, q.name), GENERIC_READ, FILE_SHARE_READ
                | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS, NULL);

        if (dir != INVALID_HANDLE_VALUE) {

            while (GetFileInformationByHandleEx(dir, FileIdBothDirectoryInfo, info_buf,
                        info_sz)) {
                size_t sum = 0;
                int done = 0;
                do {
                    ManifestEntry *m;
                    FILE_ID_BOTH_DIR_INFO *info = (FILE_ID_BOTH_DIR_INFO*)
                        ((uint8_t*) info_buf + sum);

                    done = (info->NextEntryOffset == 0);
                    sum += info->NextEntryOffset;

                    wchar_t fn[MAX_PATH_LEN] = L"";
                    memcpy(fn, info->FileName, info->FileNameLength);
                    fn[info->FileNameLength / sizeof(wchar_t)] = L'\0';
                    DWORD attr = info->FileAttributes;

                    if (!wcscmp(fn, L".")) {
                        if (q.top_level) {
                            assert(out);
                            m = man_push_entry(out, q.name, MAN_MKDIR);
                            m->vol = disk->bootvol;
                            m->var = var;
                            if (toplevel_entry->imgname) {
                                m->imgname = wcsdup(toplevel_entry->imgname);
                                normalize_string(m->imgname);
                                strip_trailing_slash(m->imgname);
                            }
                            /* These came from user input so require a little more
                             * cleaning up.  disklib_mkdir_simple gets upset if you
                             * don't strip trailing slashes */
                            normalize_string(m->name);
                            strip_trailing_slash(m->name);
                            m->name_len = wcslen(m->name);
                            m->file_id = info->FileId.QuadPart;
                            assert(m->file_id);
                        }
                        continue;
                    } else if (!he.recurse) {
                        continue;
                    }

                    if (!wcscmp(fn, L"..")) {
                        continue;
                    }

                    wchar_t full_name[MAX_PATH_LEN] = L"";
                    wchar_t rerooted_full_name[MAX_PATH_LEN] = L"";
                    swprintf(full_name, L"%s/%s", q.name, fn);
                    normalize_string(full_name);

                    if (q.rerooted_name) {
                        swprintf(rerooted_full_name, L"%s/%s", q.rerooted_name, fn);
                        normalize_string(rerooted_full_name);
                    }

                    m = find_by_prefix(var->man, full_name);
                    assert(full_name[1] != ':');

                    if (m) {
                        /* If we find a file or dir that is covered by another
                         * manifest entry, we will skip processing it here, and
                         * leave that for when bfs() gets called for that entry
                         * later.  This avoids double processing of e.g.
                         * /windows/winsxs that will be both covered by a COPY
                         * action for /windows and a SHALLOW action for
                         * /windows/winsxs. */
                        if (m->action != manifested_action) {
                            continue;
                        }
                    } else {
                        printf("unknown file %ls\n", full_name);
                        exit(1);
                    }

                    file_id = info->FileId.QuadPart;
                    file_size = info->EndOfFile.QuadPart;
                    action = m->action;

                    if ((attr & FILE_ATTRIBUTE_DIRECTORY) ==
                            FILE_ATTRIBUTE_DIRECTORY) {

                        action = MAN_MKDIR;
                        he.name = wcsdup(full_name);
                        he.file_id = file_id;
                        he.rerooted_name = NULL;
                        he.top_level = 0;
                        he.recurse = 1;
                        if (rerooted_full_name[0] != L'\0') {
                            he.rerooted_name = wcsdup(rerooted_full_name);
                        }
                        //printf("2. pushing [%S], [%S]\n", he.name, (he.rerooted_name ? he.rerooted_name : L"NULL"));
                        if (less_than(&heaps[0], &q, &he)) {
                            heap_push(&heaps[heap_switch], he);
                        } else {
                            heap_push(&heaps[heap_switch ^ 1], he);
                        }
                        ++directories;

                    } else {
                        /* Check if we should exclude the file based on extension and size. */
                        ManifestEntry *s = find_by_suffix(suffixes, fn);
                        ++files;
                        if (s && file_size >= s->file_size) {
                            printf("info: excluding file by suffix and size: %ls (%"PRIu64" bytes)\n",
                                    full_name, file_size);
                            continue;
                        }
                    }

                    if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
                        /* Need to open it to see if it's a symlink */
                        BY_HANDLE_FILE_INFORMATION inf;
                        wchar_t *dest = NULL;
                        HANDLE h = open_file_by_name(full_name, FILE_FLAG_OPEN_REPARSE_POINT);
                        if (h == INVALID_HANDLE_VALUE) {
                            printf("Couldn't open path [%ls] to determine if it's a symlink\n", full_name);
                            continue;
                        }
                        /* Get the attributes again. Sometimes we get bad data from
                         * GetFileInformationByHandleEx(dir, FileIdBothDirectoryInfo, ...)
                         */
                        if (GetFileInformationByHandle(h, &inf)) {
                            attr = inf.dwFileAttributes;
                        } else {
                            printf("GetFileInformationByHandle(%ls) failed err=%u\n",
                                full_name, (uint32_t) GetLastError());
                        }

                        if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
                            dest = get_symlink_path(h);
                        } else {
                            printf("[%ls] is not actually a reparse point!\n", full_name);
                        }
                        CloseHandle(h);

                        if (dest) {
                            wchar_t *rewrite = rerooted_full_name[0] ? rerooted_full_name : NULL;
                            ManifestEntry *e = man_push_file(out, disk->bootvol, var, full_name,
                                0, 0, rewrite, MAN_SYMLINK);
                            e->target = dest;
                        }

                        if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
                            continue;
                        }
                    }

                    /* Getting to here we found a file/dir that we want to include in the output manifest. */
                    wchar_t* rewrite = NULL;
                    if (rerooted_full_name[0] != L'\0') {
                        rewrite = rerooted_full_name;
                    }
                    assert(file_id);
                    int follow = 0;
                    if (action == MAN_SHALLOW_FOLLOW_LINKS) {
                        action = MAN_SHALLOW;
                        follow = follow_links;
                    } else if (action == MAN_COPY_FOLLOW_LINKS) {
                        action = MAN_COPY;
                        follow = follow_links;
                    }
                    man_push_file(out, disk->bootvol, var, full_name, file_size, file_id, rewrite, action);
                    //printf("2.Adding entry [%S]=[%d]=>[%S]\n", e->name, e->action, imgname);

                    if (rewrite || !follow) {
                        continue;
                    }

                    DWORD length = 0;
                    wchar_t link_name[MAX_PATH_LEN];
                    HANDLE h = INVALID_HANDLE_VALUE;
                    for (;;) {
                        length = MAX_PATH_LEN;
                        if (h == INVALID_HANDLE_VALUE) {
                            /* First time through loop */
                            h = FindFirstFileNameW(prefix(var, full_name), 0, &length, link_name);
                            if (h == INVALID_HANDLE_VALUE) {
                                printf("FindFirstFileNameW() failed on %ls with err=%u",
                                        full_name, (uint32_t) GetLastError());
                                /* Give up on this entry, move to next */
                                break;
                            }
                        } else {
                            if (!FindNextFileNameW(h, &length, link_name)) {
                                DWORD err = GetLastError();
                                if (err != ERROR_HANDLE_EOF) {
                                    printf("FindNextFileName() failed on %ls with err=%u",
                                            full_name, (uint32_t) err);
                                }
                                /* Give up on this entry, move to next */
                                break;
                            }
                        }
                        normalize_string(link_name);

                        /* Current file or already covered by manifest? */
                        if (!wcsncmp(link_name, full_name, length) ||
                            find_by_prefix(var->man, link_name)) {
                            continue;
                        }

                        /* We don't attempt to support changing the guest name
                         * for followed links, so pass in NULL here (previously
                         * we passed in rewire which would have done the wrong
                         * thing if rewire had actually been non-NULL) */
                        man_push_file(out, disk->bootvol, var, link_name,
                                file_size, file_id, NULL, action);

                        /* Possibly create enclosing dirs. */
                        for (;;) {
                            strip_filename(link_name);
                            if (!*link_name || find_full_name(extra_dirs,
                                        link_name)) {
                                break;
                            }
                            m = man_push_entry(extra_dirs, link_name, MAN_COPY_EMPTY_DIR);
                        }

                    }
                    if (h != INVALID_HANDLE_VALUE) {
                        FindClose(h);
                        h = INVALID_HANDLE_VALUE;
                    }

                } while (!done);
            }
            uint32_t err = (uint32_t)GetLastError();
            if (err && err != ERROR_NO_MORE_FILES) {
                printf("Enumeration of [%ls] finished with err=%u\n", prefix(var, q.name), err);
            }
            CloseHandle(dir);
        } else {
            printf("Failed to open dir [%ls] err=%u\n", prefix(var, q.name), (uint32_t)GetLastError());
        }
        free(q.name);
    }
    free(info_buf);

    for (i = 0; i < 2; ++i) {
        heap_clear(&heaps[i]);
    }

    return 0;
}

static int disk_open(char *fn, int rw, struct disk *disk,
                     int sysvol, int bootvol)
{
    int ret = 0;

    memset(disk, 0, sizeof(*disk));

    printf("open image: %s (sysvol=%d, bootvol=%d)\n", fn, sysvol, bootvol);

    /* If we don't get the sysvol and bootvol args from Krypton, we have to guess
     * them. From a non-raw backend that means reading the BCD. */

    if (!disklib_open_image(fn, rw, &disk->hdd)) {
        printf("could not open image %s\n", fn);
        goto out;
    }

    printf("open partition table: %s\n", fn);
    disk->ptbl = ptbl_open(disk->hdd);
    if ( NULL == disk->ptbl ) {
        printf("ptbl_open: %s: %s\n", fn, disklib_strerror(disklib_errno()));
        goto out_disk;
    }

    disk->p_sysvol = ptbl_get_partition(disk->ptbl, sysvol);
    if ( NULL == disk->p_sysvol ) {
        printf("%s: sysvol not found (%d)\n", fn, sysvol);
        goto out_ptbl;
    }

    disk->sysvol = disklib_ntfs_mount(disk->p_sysvol, rw);
    if ( NULL == disk->sysvol ) {
        printf("Mounting sysvol: %s: %s\n",
                 fn, disklib_strerror(disklib_errno()));
        goto out_ptbl;
    }

    if ( bootvol == sysvol ) {
        disk->bootvol = disk->sysvol;
        disk->p_bootvol = disk->p_sysvol;
    }else{
        disk->p_bootvol = ptbl_get_partition(disk->ptbl, bootvol);
        if ( NULL == disk->p_bootvol ) {
            printf("%s: bootvol not found (%d)\n", fn, bootvol);
            goto out_unmount;
        }

        disk->bootvol = disklib_ntfs_mount(disk->p_bootvol, rw);
        if ( NULL == disk->bootvol ) {
            printf("Mounting bootvol: %s: %s\n",
                     fn, disklib_strerror(disklib_errno()));
            goto out_unmount;
        }
    }

    ret = 1;
    goto done;

out_unmount:
    disklib_ntfs_umount(disk->sysvol);
out_ptbl:
    ptbl_close(disk->ptbl);
out_disk:
    disklib_close_image(disk->hdd);
out:
    memset(disk, 0, sizeof(*disk));
done:
    printf("\n");
    return ret;
}

static void disk_close(struct disk *disk)
{
    disklib_ntfs_umount(disk->sysvol);
    if ( disk->sysvol != disk->bootvol )
        disklib_ntfs_umount(disk->bootvol);
    ptbl_close(disk->ptbl);
    disklib_close_image(disk->hdd);
    memset(disk, 0, sizeof(*disk));
}

#define STATUS_FILE_LOCK_CONFLICT (0xC0000054UL)
#define STATUS_END_OF_FILE (0xC0000011UL)

#define LOCK_WAIT_PERIOD 10000 /* 10s */

#define MAX_IOS 256
typedef struct IO {
    HANDLE file;
    ManifestEntry *m;
    void *buffer; // non-NULL if slot in use
    uint64_t size;
    uint64_t offset;
    uint32_t securid;
    HANDLE event;
    IO_STATUS_BLOCK iosb;
    int last;
    SHA1_CTX *sha_ctx; // non-NULL if we should calculate the SHA
} IO;

static IO ios[MAX_IOS];
static int io_idx = 0;
static int io_nchanged = 0;

static void init_ios()
{
    int i;
    memset(ios, 0, sizeof(ios));
    for (i = 0; i < MAX_IOS; ++i) {
        IO *io = &ios[i];
        io->event = CreateEvent(NULL, TRUE, TRUE, NULL);
        assert(io->event);
    }
}

static void issue_io(IO* io)
{
    LARGE_INTEGER o;
    o.QuadPart = io->offset;
    memset(&io->iosb, 0, sizeof(io->iosb));
    ULONG rc = NtReadFile(io->file, io->event, NULL, NULL, &io->iosb, io->buffer, io->size, &o, NULL);
    if (rc && rc != STATUS_PENDING) {
        err(1, "copy_file read returned %x for path [%ls]\n", (uint32_t)rc, io->m->name);
    }
}

static void complete_io(IO* io)
{
    NTSTATUS status;
    if (WaitForSingleObject(io->event, INFINITE) != WAIT_OBJECT_0) {
        err(1, "io wait failed %u\n", (uint32_t) GetLastError());
    }

    /* Inexplicably, winbase-compat.h names this stat not Status... */
    status = io->iosb.stat;

    if (status == STATUS_FILE_LOCK_CONFLICT) {
        DWORD result;
        OVERLAPPED overlapped = {0};

        /* Don't change this logging without also updating tests */
        printf("Lock conflict error for file [%ls]\n", io->m->imgname);

        /* We are taking a simplistic approach here, and not attempting to share
         * the lock across multiple IOs should the file be split into more than
         * one read. It's unlikely to have been re-locked and we'll handle it ok
         * by re-acquiring the lock in the unlikely event that it has.
         */
        ResetEvent(io->event);
        overlapped.hEvent = io->event; /* reuse this */
        LockFileEx(io->file, 0, 0, MAXDWORD, MAXDWORD, &overlapped);
        result = WaitForSingleObject(overlapped.hEvent, LOCK_WAIT_PERIOD);
        ResetEvent(io->event);
        overlapped.hEvent = 0;
        if (result == WAIT_OBJECT_0) {
            printf("Lock acquired, retrying copy of [%ls]\n", io->m->name);
            issue_io(io);
            /* In this case we wait synchronously for the read to complete */
            if (WaitForSingleObject(io->event, INFINITE) != WAIT_OBJECT_0) {
                err(1, "io wait 2 failed %u\n", (uint32_t) GetLastError());
            }
            UnlockFileEx(io->file, 0, MAXDWORD, MAXDWORD, &overlapped);
            status = io->iosb.stat;
        } else {
            printf("Lock acquire for [%ls] failed with [%x] err=%u\n", io->m->name, (uint32_t)result, (uint32_t)GetLastError());
            goto cleanup;
        }
    }

    if (status == STATUS_END_OF_FILE) {
        /* Not fatal. We don't really have to do anything else here (other than
         * not exit) because the change would get picked up by the usn_phase,
         * but it makes it easier to test if we do.
         * Don't change this logging without also updating tests
         */
        printf("File [%ls] has shrunk!\n", io->m->name);
        goto cleanup;
    } else if (!NT_SUCCESS(status)) {
        err(1, "Read of [%ls] failed with [%x]\n", io->m->name, (uint32_t)status);
    }

    if (disklib_write_simple(io->m->vol, io->m->imgname, io->buffer, io->size,
                io->offset, 0, io->securid) < io->size) {
        err(1, "ntfs write error: %s\n", strerror(ntfs_get_errno()));
    }

    if (io->sha_ctx) {
        SHA1_Update(io->sha_ctx, io->buffer, io->size);
        if (io->last) {
            SHA1_Final(io->sha_ctx, io->m->sha);
            free(io->sha_ctx);
            io->sha_ctx = NULL;
        }
    }

    if (io->last && io->m->action == MAN_CHANGE) {
        /* We successfully copied it, so clear the changed action */
        io->m->action = MAN_FORCE_COPY;
        --io_nchanged;
    }

cleanup:
    if (io->last) {
        CloseHandle(io->file);
        io->file = INVALID_HANDLE_VALUE;
    }
    free(io->buffer);
    io->buffer = NULL;
    ResetEvent(io->event);
    if (!NT_SUCCESS(status) && io->m->action != MAN_CHANGE) {
        io->m->action = MAN_CHANGE;
        ++io_nchanged;
    }
}

static void complete_all_ios(void)
{
    int i;
    for (i = 0; i < MAX_IOS; ++i ) {
        int idx = (io_idx++) % MAX_IOS;
        IO *io = &ios[idx];
        if (io->buffer) {
            complete_io(io);
        }
    }
}

static void copy_file(ManifestEntry *m, HANDLE input, int calculate_shas)
{
    ntfs_fs_t vol = m->vol;
    const wchar_t *path = m->imgname;
    uint64_t size = m->file_size;
    size_t buf_size = (low_priority ? 1 : 4) << 20;
    uint64_t offset;
    uint64_t take;
    SHA1_CTX *sha_ctx = NULL;
    if (calculate_shas) {
        sha_ctx = (SHA1_CTX*)malloc(sizeof(SHA1_CTX));
        SHA1_Init(sha_ctx);
    }

    if (size == 0) {
        /* Special-case empty files. */
        if (calculate_shas) {
            SHA1_Final(sha_ctx, m->sha);
            free(sha_ctx);
        }
        if (disklib_write_simple(vol, path, NULL, 0, 0, 0, m->securid)) {
            err(1, "ntfs write error: %s\n", strerror(ntfs_get_errno()));
        }
        if (m->action == MAN_CHANGE) {
            /* Clearing the MAN_CHANGE is normally done in complete_io() */
            m->action = MAN_FORCE_COPY;
            --io_nchanged;
        }
    }

    for (offset = 0; size; size -= take, offset += take) {
        int idx = (io_idx++) % MAX_IOS;
        IO *io = &ios[idx];

        take = size < buf_size ? size : buf_size;

        if (io->buffer) {
            complete_io(io);
        }

        io->file = input;
        io->m = m;
        io->size = take;
        io->offset = offset;
        io->sha_ctx = sha_ctx;
        io->securid = m->securid;

        assert(!io->buffer);
        io->buffer = malloc(take);
        io->last = (size == take);
        assert(io->buffer);

        issue_io(io);
    }
}

int get_relative_sd_from_sd(SECURITY_DESCRIPTOR *sd,
    PSID owner, PSID group, PACL dacl, PACL sacl,
    SECURITY_DESCRIPTOR_RELATIVE **sdr, uint32_t *sdrsz)
{
    int ret = 0;
    SECURITY_DESCRIPTOR_RELATIVE *out = NULL;

    assert(sd);
    assert(sdr && sdrsz);

    int owner_len = (IsValidSid(owner) ? GetLengthSid(owner) : 0);
    int group_len = (IsValidSid(group) ? GetLengthSid(group) : 0);
    int sacl_len = (sacl ? sacl->AclSize : 0);
    int dacl_len = (dacl ? dacl->AclSize : 0);

    *sdrsz = sizeof(SECURITY_DESCRIPTOR_RELATIVE) + owner_len + group_len
                + sacl_len + dacl_len;

    out = malloc(*sdrsz);
    if (!out) {
        printf("Unable to allocate [%d] bytes\n", *sdrsz);
        ret = -1;
        goto exit;
    }

    char *offset = (char *)out;
    offset += sizeof(SECURITY_DESCRIPTOR_RELATIVE);

    out->Revision = sd->Revision;
    out->Sbz1 = sd->Sbz1;
    out->Control = sd->Control;

    if(owner_len) {
        memcpy(offset, owner, owner_len);
        out->Owner = offset - (char *)out;
        offset += owner_len;
    }

    if(group_len) {
        memcpy(offset, group, group_len);
        out->Group = offset - (char *)out;
        offset += group_len;
    }

    if ((sd->Control & SE_SACL_PRESENT) && sacl) {
        memcpy(offset, sacl, sacl_len);
        out->Sacl = offset - (char *)out;
        offset += sacl_len;
    } else {
        out->Sacl = offset - (char *)out;
    }

    if ((sd->Control & SE_DACL_PRESENT) && dacl) {
        memcpy(offset, dacl, dacl_len);
        out->Dacl = offset - (char *)out;
        offset += dacl_len;
    } else {
        out->Dacl = offset - (char *)out;
    }

exit:
    *sdr = out;
    return ret;
}

int get_relative_sd_from_handle(HANDLE h, SECURITY_DESCRIPTOR_RELATIVE **sdr, uint32_t *sdrsz)
{
    assert(sdr);
    assert(sdrsz);

    int ret = 0;
    PSID owner = NULL;
    PSID group = NULL;
    PACL dacl = NULL;
    PACL sacl = NULL;
    SECURITY_DESCRIPTOR *sd = NULL;

    ret = GetSecurityInfo(h, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
            &owner, &group, &dacl, &sacl, (void **)&sd);
    if (ret != ERROR_SUCCESS) {
        printf("GetSecurityInfo failed: [%u].\n", ret);
        ret = -1;
        goto exit;
    }

    ret = get_relative_sd_from_sd(sd, owner, group, dacl, sacl, sdr, sdrsz);
    if (ret) {
        printf("Unable to convert sd to relative sd : %d\n", ret);
        goto exit;
    }

exit:
    if (sd) {
        LocalFree(sd);
    }
    return ret;
}

int get_securid_from_entry(ManifestEntry *m)
{
    int ret = 0;
    SECURITY_DESCRIPTOR_RELATIVE *sdr = NULL;
    HANDLE h = INVALID_HANDLE_VALUE;

    assert(m);
    assert(m->vol);

    if (m->file_id == 0) {
        printf("%ls has no file-id!\n", m->name);
        ret = -1;
        goto exit;
    }

    if (m->securid) {
        ret = 0;
        goto exit;
    }

    if (m->cache_index != -1) {
        m->securid = disklib_ntfs_setsecurityattr(m->vol,
                        (void*)cached_acls[m->cache_index].sdr,
                        cached_acls[m->cache_index].sdrsz);
        if (!m->securid) {
            printf("disklib_ntfs_setsecurityattr failed\n");
            ret = -1;
        }
        goto exit;
    }

    h = open_file_by_id(m->var->volume, m->file_id, READ_CONTROL |
            ACCESS_SYSTEM_SECURITY, 0);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Unable to open %ls\n", m->name);
        ret = -1;
        goto exit;
    }

    uint32_t sdrsz = 0;
    ret = get_relative_sd_from_handle(h, &sdr, &sdrsz);
    if (ret) {
        printf("Error in get_relative_sd_from_handle : %d\n", ret);
        goto exit;
    }

    m->securid = disklib_ntfs_setsecurityattr(m->vol, (void*)sdr, sdrsz);
    if (!m->securid) {
        printf("error in disklib_ntfs_setsecurityattr: %s\n",
                strerror(ntfs_get_errno()));
        goto exit;
    }

exit:
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
    if (sdr) {
        free(sdr);
    }
    return ret;
}

static int shallow_file(ManifestEntry *m,
        const wchar_t *host_path)
{
    size_t buf_size = 16 << 20;
    static void *buf = NULL;
    uint64_t offset, take;
    int i;

    if (!buf) {
        buf = malloc(buf_size);
        assert(buf);
        char *b = buf;
        for (i = 0; i < buf_size / SECTOR_SIZE; ++i) {
            fill_with_magic_bytes(b);
            b += SECTOR_SIZE;
        }
    }

    if (get_securid_from_entry(m) != 0) {
        printf("unable to get securid for %ls\n", m->name);
    }

    uint64_t size = m->file_size;
    for (offset = 0; ; size -= take, offset += take) {
        take = size < buf_size ? size : buf_size;
        char *u = utf8(host_path);
        set_current_filename(u, offset, m->file_id);

        if (disklib_write_simple(m->vol, m->imgname, buf, take, offset, 1, m->securid) < take) {
            printf("ntfs write error: %s\n", strerror(ntfs_get_errno()));
            exit(1);
        }

        free(u);

        if (!take) {
            break;
        }
    }

    return 0;
}

NTSTATUS init_driver(void)
{
    /* We will deliberately leak handles from LoadLibrary. */
    HINSTANCE hInst = NULL;

    hInst = LoadLibraryW(L"FltLib.dll");
    if (!hInst) {
        printf("Unable to load FltLib.dll\n");
        return STATUS_UNSUCCESSFUL;
    }

    FilterConnectCommunicationPort =
        (pFilterConnectCommunicationPort)GetProcAddress(hInst,
            "FilterConnectCommunicationPort");
    if (!FilterConnectCommunicationPort) {
        printf("Unable to get FilterConnectCommunicationPort\n");
        return STATUS_UNSUCCESSFUL;
    }

    FilterSendMessage =
        (pFilterSendMessage)GetProcAddress(hInst, "FilterSendMessage");
    if (!FilterSendMessage) {
        printf("Unable to get FilterSendMessage\n");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

int init_logiccp(void)
{
    NTSTATUS status = STATUS_SUCCESS;

    NtReadFile = (pNtReadFile)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtReadFile");
    assert(NtReadFile);

    NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    assert(NtQuerySystemInformation);

    NtDuplicateObject = (pNtDuplicateObject)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtDuplicateObject");
    assert(NtDuplicateObject);

    NtQueryObject = (pNtQueryObject)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    assert(NtQueryObject);

    status = init_driver();
    if (!NT_SUCCESS(status)) {
        printf("Unable to init driver functions : [%d]\n", (int)status);
        return -1;
    }

    status = EnablePrivilege(SE_SECURITY_NAME);
    if (!NT_SUCCESS(status)) {
        printf("Unable to acquire SE_SECURITY_NAME privilege : %d\n", (int)status);
        return -1;
    }

    status = EnablePrivilege(SE_BACKUP_NAME);
    if (!NT_SUCCESS(status)) {
        printf("Unable to acquire SE_BACKUP_NAME privilege : %d\n", (int)status);
        return -1;
    }

    status = EnablePrivilege(SE_DEBUG_NAME);
    if (!NT_SUCCESS(status)) {
        printf("Unable to acquire SE_DEBUG_NAME privilege : %d\n", (int)status);
        return -1;
    }

    return 0;
}

#define ENTER_PHASE() ENTER_FN()

#define LEAVE_PHASE() LEAVE_FN()

#define ENTER_PHASEN(n) double _t = rtc(); \
    printf("\nenter %s %d\n", __FUNCTION__, n)

#define LEAVE_PHASEN(n) printf("%s %d took %.2fs\n", __FUNCTION__, n, rtc() - _t)

int scanning_phase(struct disk *disk, VarList *vars,
        Manifest *suffixes, Manifest *man_out)
{
    ENTER_PHASE();
    int i, r;

    for (i = 0; i < vars->n; ++i) {
        int j;
        Manifest extra_dirs;
        man_init(&extra_dirs);
        Variable *var = &vars->entries[i];
        if (!var->path) {
            printf("ignoring manifest entries under ${%ls}\n", var->name);
            continue; /* command-line argument -sPATH= so we ignore this variable */
        }
        Manifest *man = var->man;
        if (var->path[0]) {
            /* Don't try and open a host volume handle for the dummy var which
             * has no host-side equivalent
             */
            var->volume = CreateFileW(prefix(var, L""), GENERIC_READ,
                    FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
            if (var->volume == INVALID_HANDLE_VALUE) {
                printf("Failed while processing [%ls], err=%u\n", var->path,
                        (uint32_t) GetLastError());
                return -1;
            }
        }

        for (j = 0; j < man->n; ++j) {
            ManifestEntry *m = &man->entries[j];
            if (!shallow_allowed && (m->action == MAN_SHALLOW)) {
                m->action = MAN_FORCE_COPY;
            }
            if (!shallow_allowed && (m->action == MAN_SHALLOW_FOLLOW_LINKS)) {
                m->action = MAN_COPY_FOLLOW_LINKS;
            }
            switch (m->action) {
                case MAN_SHALLOW:
                case MAN_COPY:
                case MAN_COPY_EMPTY_DIR:
                case MAN_FORCE_COPY:
                case MAN_SHALLOW_FOLLOW_LINKS:
                case MAN_COPY_FOLLOW_LINKS:
                    r = bfs(var, suffixes, man_out, &extra_dirs, disk, m, m->action != MAN_COPY_EMPTY_DIR);
                    if (r < 0) {
                        printf("Failed while processing [%ls] : [%d]\n", m->name, r);
                        return r;
                    }
                    break;
                default:
                    break;
            }
        }
        man_sort_by_name(&extra_dirs);
        man_uniq_by_name(&extra_dirs);
        for (j = 0; j < extra_dirs.n; ++j) {
            ManifestEntry *m = &extra_dirs.entries[j];
            bfs(var, &extra_dirs, man_out, NULL, disk, m, 0);
        }
    }
    printf("scanned %d files in %d directories\n", files, directories);
    LEAVE_PHASE();
    return 0;
}

static inline
int is_same_file(const ManifestEntry *a, const ManifestEntry *b)
{
    return (a->var == b->var && a->file_id == b->file_id);
}

int stat_files_phase(struct disk *disk, Manifest *man, wchar_t *file_id_list)
{
    ENTER_PHASE();
    assert(man->order_fn == cmp_id_action);

    int i;
    ManifestEntry *last = NULL;
    uint64_t link_id = 0;
    FILE *file_id_file = NULL;
    uint64_t old_file_id = 0;
    int changed_operations = 0;

    if (shallow_allowed) {
        file_id_file = _wfopen(file_id_list, L"wb");
        if (!file_id_file) {
            printf("unable to open %ls for write\n", file_id_list);
            return -1;
        }
        setvbuf(file_id_file, NULL, _IOFBF, 1 << 20);
    }

    for (i = 0; i < man->n; ++i) {
        ManifestEntry *m = &man->entries[i];
        Action action = m->action;

        if (action == MAN_COPY || action == MAN_SHALLOW || action == MAN_FORCE_COPY) {

            ++files;

            /* Check for file with same ids, and link them together under the
             * most desirable action. */
            if (last && is_same_file(last, m)) {
                m->link_id = last->link_id = link_id;
                action = last->action;
            } else {
                m->link_id = 0;
                ++link_id;
            }

            /* Only stat files we want to copy. */
            if (action == MAN_COPY || action == MAN_FORCE_COPY) {
                Action old_action = m->action;
                if (stat_file(m->var->volume, m->file_id, &m->file_size,
                            &m->offset) < 0) {
                    printf("skipping file %ls (err=%u)\n", m->name,
                            (uint32_t) GetLastError());
                    m->action = MAN_EXCLUDE;
                    man_unsorted(man);
                } else if (old_action != m->action) {
                    changed_operations ++;
                }
            }

            /* The file-ids are sorted. Write unique file-ids into the file_id_list file */
            if (action == MAN_SHALLOW) {
                assert(shallow_allowed); /* Shouldn't see any shallowed files here */
                if (old_file_id != m->file_id) {
                    if (fwrite(&m->file_id, sizeof(uint64_t), 1, file_id_file) != 1) {
                        printf("Error in writing to file [%ls]\n", file_id_list);
                        return -1;
                    }
                    old_file_id = m->file_id;
                }
            }
        }

        last = m;
    }

    if (file_id_file) {
        fclose(file_id_file);
    }

    printf("Number of files that have been converted to force-copy = [%d]\n",
        changed_operations);

    LEAVE_PHASE();
    return 0;
}

int mkdir_phase(struct disk *disk, Manifest *man)
{
    ENTER_PHASE();
    assert(man->order_fn == cmp_name_action);

    int i;

    for (i = 0; i < man->n; ++i) {
        ManifestEntry *m = &man->entries[i];

        if (m->action == MAN_MKDIR) {
            //printf("mkdir [%ls]\n", m->name);

            if (get_securid_from_entry(m) != 0) {
                printf("unable to get securid for %ls\n", m->name);
            }

            if (wcsncmp(m->imgname, L"/", MAX_PATH_LEN) == 0) {
                /* Root is not a dir so need to skip this in case a top-level
                 * manifest entry maps a dir in to the root */
                continue;
            }
            if (disklib_mkdir_simple(m->vol, m->imgname, m->securid) < 0) {
                printf("unable to mkdir %ls : %s\n", m->imgname,
                        strerror(ntfs_get_errno()));
                return -1;
            }
        }
    }
    LEAVE_PHASE();
    return 0;
}

#define SHA1FMT "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"

int rewire_phase(struct disk *disk, Manifest *man)
{
    ENTER_PHASE();
    assert(man->order_fn == cmp_name_action);

    int i;
    const wchar_t bootmgr[] = L"bootmgr";
    const wchar_t bootloader_fonts[] = L"/Windows/Boot/Fonts/";
    const wchar_t bios_bootloader_files[] = L"/Windows/Boot/PCAT/";
    wchar_t cookedpath[MAX_PATH_LEN];

    for (i = 0; i < man->n; ++i) {
        ManifestEntry *m = &man->entries[i];

        if (!wcsnicmp(m->name, bios_bootloader_files,
                    wcslen(bios_bootloader_files))) {
            if (!wcsnicmp(m->name + wcslen(m->name) - wcslen(bootmgr),
                        bootmgr, wcslen(bootmgr))) {
                path_join(cookedpath, L"/", bootmgr);
            } else {
                path_join(cookedpath, L"/Boot", m->name + wcslen(bios_bootloader_files));
            }

        } else if (!wcsnicmp(m->name, bootloader_fonts,
                    wcslen(bootloader_fonts))) {
            path_join(cookedpath, L"/Boot/Fonts/", m->name + wcslen(bootloader_fonts));
        } else {
            continue;
        }

        //printf("Rewiring %ls to %ls\n", m->name, cookedpath);
        m->action = (m->action == MAN_MKDIR ? MAN_MKDIR : MAN_BOOT);
        m->vol = disk->sysvol;
        m->imgname = wcsdup(cookedpath);
    }

    man_unsorted(man);
    LEAVE_PHASE();
    return 0;
}

int vm_links_phase_1(struct disk *disk, Manifest *man)
{
    ENTER_PHASE();
    assert(man->order_fn == cmp_offset_link_action);

    int i;
    ManifestEntry *last = NULL;
    int q = 0;
    for (i = 0; i < man->n; ++i) {
        ManifestEntry *m = &man->entries[i];

        if (last && m->link_id && is_same_file(m, last)) {
            /* We cannot link files that we moved to /boot on sysvol. */
            if (last->action != MAN_BOOT && last->action != MAN_EXCLUDE) {
                m->target = last->imgname;
                m->action = MAN_LINK; // Preserves sorting order
                ++q;
            }
        } else {
            last = m;
        }
    }
    printf("prepared %d links\n", q);

    LEAVE_PHASE();
    return 0;
}

int vm_links_phase_2(struct disk *disk, Manifest *man)
{
    ENTER_PHASE();
    assert(man->order_fn == cmp_offset_link_action);

    int i;
    for (i = 0; i < man->n; ++i) {
        ManifestEntry *m = &man->entries[i];
        if (m->action == MAN_LINK) {
            int err = 0;
            if (disklib_mklink_simple(m->vol, m->target, m->imgname) < 0) {
                err = ntfs_get_errno();
                if (err == ENOENT) {
                    /* It is not impossible for the link dir to not exist yet.
                     * The only reason this isn't an issue for all single file
                     * manifest entry lines is that disklib_write_simple will
                     * create the intervening dirs if they don't already exist,
                     * but disklib_mklink_simple explicitly doesn't ask ntfslib
                     * for this behaviour.
                     */
                    printf("creating dir for %ls and retrying mklink\n", m->imgname);
                    wchar_t *dir = wcsdup(m->imgname);
                    strip_filename(dir);
                    if (disklib_mkdir_simple(m->vol, dir, m->securid) >= 0 &&
                        disklib_mklink_simple(m->vol, m->target, m->imgname) >= 0) {
                        err = 0;
                    }
                    free(dir);
                } else if (err == EEXIST) {
                    /* This can happen if the distribution image already
                     * contained a file which we try to reconstruct via WinSxS
                     * links. For now, just ignore it.
                     */
                    printf("ignoring attempt to link from %ls to %ls\n",
                        m->target, m->imgname);
                    err = 0;
                }
            }
            if (err) {
                printf("link failed : linkid=%"PRIx64" err=%d target=%ls link=%ls\n",
                        m->link_id,
                        err,
                        m->target, m->imgname);
                return -1;
            }
        } else if (m->action == MAN_SYMLINK) {
            /* See if target is something we've renamed and if so, fix up */
            static wchar_t target_buf[MAX_PATH_LEN];
            const wchar_t *target = strip_long_path_prefix(m->target);
            if (wcsnicmp(target, &rootdrive, 1) == 0 && target[1] == ':') {
                /* Target is on root drive so worth checking */
                path_join(target_buf, target + 2, NULL); /* skip driveletter */
                normalize_string(target_buf);
                ManifestEntry *e = find_full_name(man, target_buf);
                if (e) {
                    /* The root drive is assumed to always be C: inside the
                     * image. This should be the case regardless of what the
                     * host root drive letter is.
                     */
                    path_join(target_buf, L"C:", e->imgname);
                    normalize_string2(target_buf);
                    printf("Fixing up symlink target %ls => %ls\n",
                           m->target, target_buf);
                    free(m->target);
                    m->target = wcsdup(target_buf);
                }
            }
            if (disklib_symlink_simple(m->vol, m->imgname,
                                       m->target, m->securid) < 0) {
                printf("symlink failed for link=%ls target=%ls\n",
                       m->imgname, m->target);
            }
        }
    }

    LEAVE_PHASE();
    return 0;
}

int flush_phase(struct disk *disk)
{
    ENTER_PHASE();
    disk_close(disk);
    LEAVE_PHASE();
    return 0;
}

#define MAX_THREADS 15
#if MAX_THREADS > MAXIMUM_WAIT_OBJECTS
#error "Maximum number of threads can be at most 64(MAXIMUM_WAIT_OBJECTS)."
#endif

/* Compare two ACLs for equality. Idea of caching ACL results seen on Stack Overflow. */
static int acl_equal(ACL *a, ACL *b)
{
    int i;
    if (a->AceCount != b->AceCount) {
        return 0;
    }

    for (i = 0; i < a->AceCount; ++i) {
        /* Get the ACEs */
        PACE_HEADER ace1;
        PACE_HEADER ace2;
        GetAce(a, i, (LPVOID*)&ace1);
        GetAce(b, i, (LPVOID*)&ace2);

        /* Compare the ACE sizes */
        if (ace1->AceSize != ace2->AceSize) {
            return 0;
        }

        /* Compare ACE contents */
        if (memcmp(ace1, ace2, ace1->AceSize)) {
            return 0;
        }
    }
    return 1;
}

static ACLType invert_acl(ACLType acl_type)
{
    switch (acl_type) {
        case ACL_Denied:
            return ACL_Allowed;
        case ACL_Allowed:
            return ACL_Denied;
        case ACL_Absent:
            return acl_type;
    }

    return acl_type;
}

static int read_allowed(PACL acl, int *readable)
{
    assert(readable);

    int ret = 0;
    if (!acl) {
        /* This means that everyone has complete access. */
        *readable = 1;
        goto cleanup;
    }

    *readable = 0;

    ACL_SIZE_INFORMATION acl_size_info;
    int everyone_read = ACL_Absent;
    int builtin_users_read = ACL_Absent;
    int i;
    if (!GetAclInformation(acl, &acl_size_info,
            sizeof(acl_size_info), AclSizeInformation)) {
        printf("GetAclInformation failed: %d\n", (int)GetLastError());
        ret = -1;
        goto cleanup;
    }

    for (i = 0; i < (int)acl_size_info.AceCount; i++) {
        void *ace;
        if (!GetAce(acl, i, &ace)) {
            printf("GetAce failed: %d\n", (int)GetLastError());
            ret = -1;
            goto cleanup;
        }

        SID *sid = NULL;
        int mask;
        ACLType acl_set = ACL_Absent;

        /* Check type of ACE and whether it's inherited or not */
        if (((ACCESS_ALLOWED_ACE *)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *access = (ACCESS_ALLOWED_ACE *)ace;
            sid = (SID *)&access->SidStart;
            mask = access->Mask;
            acl_set = ACL_Allowed;
        } else if (((ACCESS_DENIED_ACE *)ace)->Header.AceType == ACCESS_DENIED_ACE_TYPE) {
            ACCESS_DENIED_ACE *access = (ACCESS_DENIED_ACE *)ace;
            sid = (SID *)&access->SidStart;
            mask = access->Mask;
            acl_set = ACL_Denied;
        } else {
            ret = -1;
            printf("Unknown ACE type encountered\n");
            break;
        }

        /* Check SID to which this ACE applies */
        if (!IsValidSid(sid)) {
            printf("Invalid SID found\n");
            ret = -1;
            break;
        }

        /* deny trumps everything else */
        if ((builtin_users_read != ACL_Denied) && EqualSid(sid, builtin_users)) {
            if (mask & (GENERIC_ALL | GENERIC_READ | FILE_READ_DATA)) {
                builtin_users_read = acl_set;
            } else {
                builtin_users_read = invert_acl(acl_set);
            }
        } else if ((everyone_read != ACL_Denied) && EqualSid(sid, everyone)) {
            if (mask & (GENERIC_ALL | GENERIC_READ | FILE_READ_DATA)) {
                everyone_read = acl_set;
            } else {
                everyone_read = invert_acl(acl_set);
            }
        }
    }

    if ((everyone_read == ACL_Absent)
        && (builtin_users_read == ACL_Absent)) {
        /* Both uninitialized indicates read access not mentioned for both groups. */
        *readable = 0;
    } else if ((everyone_read == ACL_Denied)
                || (builtin_users_read == ACL_Denied)) {
        *readable = 0;
    } else {
        /* both allowed or one allowed and the other uninitialized */
        *readable = 1;
    }

cleanup:
    return ret;
}

static int acl_file(HANDLE h, ManifestEntry *m, int *acls_broken, int *hit)
{
    int readable = 1;
    int ret = 0;

    assert (hit);
    assert (acls_broken);

    *hit = 0;

    /* If we intend to shallow this file, check that the user will be able to
     * read it when the time comes to do so. */
    if (!*acls_broken) {
        int i;
        DWORD rc;
        PSID owner = NULL;
        PSID group = NULL;
        PACL dacl = NULL;
        PACL sacl = NULL;
        SECURITY_DESCRIPTOR *sd = NULL;
        m->cache_index = -1;

        rc = GetSecurityInfo(h, SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
                &owner, &group, &dacl, &sacl, (void **)&sd);
        if (rc != ERROR_SUCCESS) {
            printf("GetSecurityInfo failed: [%d].\n", (int)rc);
            ret = -1;
            goto sec_error;
        }

        if (!dacl) {
            printf("got NULL dacl for %ls\n", m->name);
            ret = -1;
            goto rights_error;
        }

        for (i = 0; i < cache_size; ++i) {
            if (__sync_bool_compare_and_swap(&cached_acls[i].valid, 1, 1)) {
                if (acl_equal(cached_acls[i].dacl, dacl)){
                    *hit = 1;
                    m->cache_index = i;
                    readable = cached_acls[i].readable;
                    break;
                }
            }
        }

        if (!*hit) { /* ACL not found in cache. */
            int rc = read_allowed(dacl, &readable);
            if (rc < 0) {
                printf("read_allowed failed, disabling ACL check!\n");
                *acls_broken = 1;
                ret = -1;
                goto rights_error;
            }

            int index = __sync_fetch_and_add(&cache_size, 1);
            if (index >= MAX_CACHED) {
                printf("Can't cache element as cache is full\n");
            } else {
                cached_acls[index].dacl = malloc(dacl->AclSize);
                assert(cached_acls[index].dacl); // XXX error handling
                memcpy(cached_acls[index].dacl, dacl, dacl->AclSize);

                rc = get_relative_sd_from_sd(sd, owner, group, dacl, sacl,
                        &cached_acls[index].sdr, &cached_acls[index].sdrsz);
                if (!rc) {
                    m->cache_index = index;
                }
                // TODO: Free all cached_index[index].sdr at exit time

                cached_acls[index].readable = readable;
                if (!__sync_bool_compare_and_swap(&cached_acls[index].valid, 0, 1)) {
                    printf("Cache error: wrongly initialized for [%d]!\n",
                        index);
                    *acls_broken = 1;
                    ret = -1;
                    goto rights_error;
                }
            }
        } else {
            readable = cached_acls[i].readable;
        }

rights_error:
        LocalFree(sd);
sec_error:

        if (!readable) {
            m->action = MAN_CHANGE;
        }
    }

    return ret;
}

/* Note: This function must no longer set anything to be MAN_EXCLUDE because
 * that can corrupt the vm_links state. Any failures or problems in accessing a
 * file must degrade the entry to MAN_CHANGE which will mean we'll handle it in
 * copy_phase, where we can handle errors without peturbing the manifest. */
static DWORD WINAPI acl_files_thread(LPVOID lpParam)
{
    assert(lpParam != NULL);
    ACLThreadData *td = (ACLThreadData*)lpParam;
    int index = 0;
    HANDLE h;
    int acls_broken = 0;
    int hit;

    td->processed_entries = 0;
    for (;;) {
        index = __sync_fetch_and_add(td->idx, 1);
        if (index >= td->man->n) {
            break;
        }

        ManifestEntry *m = &td->man->entries[index];
        if (m->action != MAN_SHALLOW) {
            continue;
        }

        assert(m->file_id != 0);

        h = open_file_by_id(m->var->volume, m->file_id, READ_CONTROL |
                ACCESS_SYSTEM_SECURITY, 0);
        if (h == INVALID_HANDLE_VALUE) {
            printf("Unable to open file %ls (err=%u)\n", m->name,
                    (int)GetLastError());
            /* Worry about it in copy_phase */
            m->action = MAN_CHANGE;
            continue;
        }

        hit = 0;
        if (acl_file(h, m, &acls_broken, &hit) < 0) {
            printf("acl_file failed for [%ls] : [%d]\n", m->name,
                (int)GetLastError());
            m->action = MAN_CHANGE;
        }
        if (m->action == MAN_CHANGE) {
            td->processed_entries ++;
        }

        if (hit) {
            td->cache_hits ++;
        } else {
            td->cache_misses ++;
        }

        CloseHandle(h);
    }
    return 0;
}

int acl_phase(struct disk *disk, Manifest *man)
{
    assert(shallow_allowed);
    ENTER_PHASE();
    assert(man->order_fn == cmp_id_action);

    int ret = 0;
    int i;
    int num_copies = 0;
    int cache_hits = 0;
    int cache_misses = 0;
    ACLThreadData acl_thread_data[MAX_THREADS];
    HANDLE h_acl_threads[MAX_THREADS];
    int acl_thread_count = 0;
    volatile int shared_idx = 0;

    DWORD sz = SECURITY_MAX_SID_SIZE;
    builtin_users = (PSID)malloc(sz);
    if (!builtin_users) {
        printf("Unable to allocate [%d] bytes\n", (int)sz);
        ret = -1;
        goto cleanup;
    }

    everyone = (PSID)malloc(sz);
    if (!everyone) {
        printf("Unable to allocate [%d] bytes\n", (int)sz);
        ret = -1;
        goto cleanup;
    }

    /* There is an 'Anonymous' group that is  WinBuiltinUsersSid - WinWorldSid. Hence using
       both SIDs.*/
    if (!CreateWellKnownSid(WinBuiltinUsersSid, NULL, builtin_users, &sz)) {
        printf("Unable to create WinBuiltinUsersSid, %u\n", (uint32_t) GetLastError());
        ret = -1;
        goto cleanup;
    }

    sz = SECURITY_MAX_SID_SIZE;
    if (!CreateWellKnownSid(WinWorldSid, NULL, everyone, &sz)) {
        printf("Unable to create WinWorldSid, %u\n", (uint32_t) GetLastError());
        ret = -1;
        goto cleanup;
    }

    memset(&acl_thread_data, 0, sizeof(acl_thread_data));
    for (i = 0; i < MAX_THREADS; ++i) {
        acl_thread_data[i].man = man;
        acl_thread_data[i].idx = &shared_idx;

        h_acl_threads[i] = CreateThread(NULL, 0, acl_files_thread,
                            &acl_thread_data[i], 0, NULL);
        if (!h_acl_threads[i]) {
            printf("CreateThread[%d] failed : [%d]\n", i, (int)GetLastError());
            break;
        }
        acl_thread_count = i + 1;
    }

    printf("Created [%d] threads to process files\n", acl_thread_count);

    /* Wait for thread termination */
    if (acl_thread_count > 0) {
        printf("Waiting for [%d] threads to complete\n", acl_thread_count);

        DWORD rc = WaitForMultipleObjects(acl_thread_count, h_acl_threads,
                TRUE, INFINITE);
        switch(rc) {
            case WAIT_OBJECT_0:
                printf("Received termination events from [%d] threads\n",
                        acl_thread_count);
                break;
            default:
                printf("Error in waiting for [%d] threads: [%d]\n",
                        acl_thread_count, (int)GetLastError());
                ret = -1;
                goto cleanup;
                break;
        }
    }

    for (i = 0; i < acl_thread_count; i++) {
        CloseHandle(h_acl_threads[i]);
    }

    /* If we failed to create all threads, return an error. This is done after
     * having waited for the threads, to not end up hanging. */
    if (acl_thread_count < MAX_THREADS) {
        ret = -1;
        goto cleanup;
    }

    for (i = 0; i < acl_thread_count; i++) {
        num_copies += acl_thread_data[i].processed_entries;
        cache_hits += acl_thread_data[i].cache_hits;
        cache_misses += acl_thread_data[i].cache_misses;
    }

    for (i = 0; i < man->n; i++) {
        if (man->entries[i].action == MAN_CHANGE) {
            char *cfilename = utf8(man->entries[i].imgname);
            assert(cfilename);
            printf("Degraded [%s] to force-copy\n", cfilename);
            if (disklib_ntfs_unlink(man->entries[i].vol, cfilename) < 0) {
                //printf("Unable to unlink [%s]\n", cfilename);
            }
            free(cfilename);
            man->entries[i].action = MAN_FORCE_COPY;
        }
    }

    man_unsorted(man);

    printf("Cache hits = [%d], misses = [%d]\n", cache_hits, cache_misses);
    printf("Number of files that will be force-copied due to acls_phase = [%d]\n",
        num_copies);

cleanup:
    LEAVE_PHASE();
    return ret;
}

static void make_unshadowed_host_path(wchar_t* out, ManifestEntry *m)
{
    // First get full hostname including path components from the prefix (if any)
    wchar_t* filename = prefix(m->var, m->name);
    wchar_t* path;
    if (bootvol_var && !wcsnicmp(filename, bootvol_var->path, wcslen(bootvol_var->path))) {
        // Now replace the volume prefix with the rootdrive
        path = filename + wcslen(bootvol_var->path);
    } else {
        // if there's no BOOTVOL then all bets are off as to how we reconstruct
        // the host path from a non-volume prefix, so assume the prefix is not
        // important. Note this does mean we don't support shallowing from any
        // volume other than BOOTVOL - this has always been the case but maybe
        // isn't stated explicitly.
        path = m->name;
    }
    swprintf(out, L"%lc:%ls", rootdrive, path);
    // finally, convert back to backslashes
    normalize_string2(out);
}

int shallow_phase(struct disk *disk, Manifest *man, wchar_t *map_idx)
{
    assert(shallow_allowed);
    ENTER_PHASE();
    assert(man->order_fn == cmp_name_action);

    int i, j;
    FILE *map_file;
    uint64_t total_size_shallowed = 0;

    for (i = j = 0; i < man->n; ++i) {
        ManifestEntry *m = &man->entries[i];

        if (m->action == MAN_SHALLOW || m->action == MAN_BOOT) {
            //printf("%d,%d shallow %ls @ %"PRIx64"\n", i, man->n, m->name, m->offset);
            wchar_t host_name[MAX_PATH_LEN];
            make_unshadowed_host_path(host_name, m);
            shallow_file(m, host_name);
            total_size_shallowed += m->file_size;
            ++j;
        }
    }

    if (j > 0) {
        printf("shallowed %d files, total size %"PRIu64" bytes, writing index"
               " to %ls\n", j, total_size_shallowed, map_idx);
        fflush(stdout);

        map_file = _wfopen(map_idx, L"wb");
        if (!map_file) {
            return -1;
        }
        setvbuf(map_file, NULL, _IOFBF, 16 << 20);

        flush_map_to_file(map_file);
        fclose(map_file);
        set_current_filename(NULL, 0, 0);
    } else {
        printf("nothing to shallow.\n");
    }

    LEAVE_PHASE();
    return 0;
}

inline int should_copy_entry(const ManifestEntry *m, int retry)
{
    /* MAN_CHANGE will appear in the first copy_phase (ie when retry==0) if
     * the usn_phase protecting the shallow_phase detected a modification.
     * MAN_CHANGE will only ever be present in the nth copy_phase if a file
     * failed to copy in (n-1)th copy_phase or if it was flagged from nth usn_phase
     */
    if (retry == 0) {
        return m->action == MAN_COPY || m->action == MAN_FORCE_COPY ||
            m->action == MAN_CHANGE ||
            (!shallow_allowed && m->action == MAN_BOOT);
    } else {
        return m->action == MAN_CHANGE;
    }
}

static void exclude_from_manifest(Manifest *man, ManifestEntry *entry)
{
    ManifestEntry *start = entry;
    ManifestEntry *end = &man->entries[man->n];

    /* We fix up hardlinks so better be sorted how we expect */
    assert(man->order_fn == cmp_offset_link_action);

    /* Have to check for other entries linked to this one, otherwise
     * vm_links_phase_2 will get confused attempting to link to something
     * non-existant
     */
    while (entry < end && is_same_file(start, entry)) {
        printf("Excluding file %ls from manifest\n", entry->name);
        entry->action = MAN_EXCLUDE;
        ++entry;
    }
}

/* Returns zero on success, or positive number of changed files */
int copy_phase(struct disk *disk, Manifest *man, int calculate_shas, int retry)
{
    int i, j;
    int q = 0;
    io_nchanged = 0;
    const int max_opens = 4096; // windows supports 10k open file handles
    HANDLE h;
    HANDLE handles[max_opens];
    int base = 0;
    uint64_t total_size_copied = 0;
    uint64_t total_size_force_copied = 0;

    ENTER_PHASEN(retry);

    for (base = 0; base < man->n; base = i) {

        double t1 = rtc();
        for (i = base, j = 0; i < man->n && j < max_opens; ++i) {
            ManifestEntry *m = &man->entries[i];
            if (should_copy_entry(m, retry)) {
                assert(m->file_id);
                h = open_file_by_id(m->var->volume, m->file_id, GENERIC_READ,
                    FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN);
                if (h == INVALID_HANDLE_VALUE) {
                    printf("failed to open %ls by id for copying, retrying by name\n", m->name);
                    wchar_t *filename = prefix(m->var, m->name);
                    h = open_file_by_name(filename,
                        FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN);
                }
                if (h == INVALID_HANDLE_VALUE) {
                    /* It isn't ideal to just skip things we can't open here,
                     * but we already do just that in stat_files_phase and we
                     * can't easily distinguish between things we know are ok to
                     * ignore (like a file about to be deleted) versus something
                     * bad (like a third-party product interfering with our
                     * access)
                     */
                    printf("failed to open %ls by id or name, skipping\n", m->name);
                    exclude_from_manifest(man, m);
                } else {
                    handles[j++] = h;
                }
            }
        }
        printf("%d opens took %.2fs\n", j, rtc() - t1);

        for (i = base, j = 0; i < man->n && j < max_opens; ++i) {
            ManifestEntry *m = &man->entries[i];
            if (should_copy_entry(m, retry)) {
                if (m->action == MAN_FORCE_COPY) {
                    /* Currently only some files are changed to a MAN_FORCE_COPY. If
                       that behavior changes, remove the log statement.
                    */
                    printf("Force-copying [%ls] of size [%"PRIu64"]\n",
                        man->entries[i].name,
                        man->entries[i].file_size);
                }
                HANDLE h = handles[j++];
                if (h != INVALID_HANDLE_VALUE) {
                    if (m->action == MAN_CHANGE) {
                        ++io_nchanged;
                        /* file size may have changed since we first looked it
                         * up in stat_files_phase, need to recalculate. If it
                         * changes again after this point, the usn_phase
                         * monitoring this copy_phase will pick it up and we'll
                         * retry it again */
                        FILE_STANDARD_INFO info;
                        if (!GetFileInformationByHandleEx(h,
                                                          FileStandardInfo,
                                                          &info,
                                                          sizeof(info))) {
                            printf("Failed to re-get size info for [%ls] err=%d\n",
                                m->name, (int)GetLastError());
                            /* Leave as MAN_CHANGE to be picked up in next retry */
                            continue;
                        }
                        m->file_size = info.EndOfFile.QuadPart;
                    }
                    if (!m->securid) {
                        if (m->cache_index == -1) {
                            if (get_securid_from_entry(m) != 0) {
                                printf("unable to get securid for %ls\n",
                                    man->entries[i].name);
                            }
                        } else {
                            m->securid = disklib_ntfs_setsecurityattr(m->vol,
                                            (void*)cached_acls[m->cache_index].sdr,
                                            cached_acls[m->cache_index].sdrsz);
                        }
                    }
                    copy_file(m, h, calculate_shas);
                    total_size_copied += m->file_size;
                    if (m->action == MAN_FORCE_COPY || m->action == MAN_CHANGE) {
                        total_size_force_copied += m->file_size;
                    }
                    ++q;
                }
            }
        }

    }
    complete_all_ios();
    printf("copied %d files, %"PRIu64" bytes\n", q, total_size_copied);
    printf("force-copied files total size: %"PRIu64" bytes\n", total_size_force_copied);
    printf("number of remaining files needing to be copied: %d\n", io_nchanged);
    LEAVE_PHASEN(retry);
    return io_nchanged;
}

int register_with_cow(
    const GUID Guid,
    const wchar_t* Directory,
    const wchar_t* FileName
    )
{
    HRESULT hr = S_OK;
    HANDLE hPort = INVALID_HANDLE_VALUE;
    PCOW_MESSAGE pMessage = NULL;
    PCOW_MESSAGE_START_WATCH pStartMessage = NULL;
    DWORD outBufferLen = 0;

    assert(Directory);
    assert(FileName);

    hr = FilterConnectCommunicationPort(
            CoWPortName,
            0,
            NULL,
            0,
            NULL,
            &hPort);

    if (FAILED(hr)) {
        printf("Unable to connect to filter : [%d]\n", (int)hr);
        goto cleanup;
    }

    DWORD messageLen =
        sizeof(COW_MESSAGE)
        + sizeof(COW_MESSAGE_START_WATCH)
        + wcslen(Directory) * sizeof(wchar_t)
        + wcslen(FileName) * sizeof(wchar_t)
        + 2 * sizeof(wchar_t);

    pMessage = (PCOW_MESSAGE)malloc(messageLen);
    if (!pMessage) {
        printf("Unable to allocate [%d] bytes\n", (int)messageLen);
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    memset(pMessage, 0, messageLen);

    pMessage->Magic = COW_MAGIC_STRING;
    pMessage->Type = StartWatchRequest;
    pMessage->Version = COW_VERSION;
    pMessage->Size = (ULONG)(messageLen - sizeof(COW_MESSAGE));

    pStartMessage = (COW_MESSAGE_START_WATCH*)pMessage->Message;

    memcpy(&pStartMessage->Guid, &Guid, sizeof(GUID));
    pStartMessage->DirNameLen = (ULONG)(wcslen(Directory));
    pStartMessage->FileNameLen = (ULONG)(wcslen(FileName));

    memcpy(pStartMessage->Buffer, Directory,
        pStartMessage->DirNameLen * sizeof(wchar_t));
    memcpy(pStartMessage->Buffer + pStartMessage->DirNameLen,
            FileName,
            pStartMessage->FileNameLen * sizeof(wchar_t));

    hr = FilterSendMessage(
            hPort,
            pMessage,
            messageLen,
            NULL,
            0,
            &outBufferLen);

    if (FAILED(hr)) {
        printf("Unable to send start message to filter : [%d]\n", (int)hr);
        goto cleanup;
    }

    printf("Successfully sent start message to CoW filter\n");

cleanup:

    if (hPort != INVALID_HANDLE_VALUE) {
        CloseHandle(hPort);
        hPort = INVALID_HANDLE_VALUE;
    }

    if (pMessage) {
        free(pMessage);
        pMessage = NULL;
    }

    if (FAILED(hr)) {
        return -1;
    }

    return 0;
}

void cow_allow_file_access()
{
    // register to be allowed to read exclusively-opened files
    HANDLE cow_port;
    HRESULT hr = FilterConnectCommunicationPort(L"\\CoWAllowReadPort", 0, NULL, 0,
        NULL, &cow_port);
    if (FAILED(hr)) {
        printf("Unable to connect to CoWAllowReadPort : [%d]\n", (int)hr);
    }
}

int get_next_usn(HANDLE drive, USN *usn, uint64_t *journal)
{
    assert(usn);
    assert(drive != INVALID_HANDLE_VALUE);

    USN_JOURNAL_DATA journal_entry = {0};
    DWORD count = 0;
    if (!DeviceIoControl(drive, FSCTL_QUERY_USN_JOURNAL,
            NULL, 0, &journal_entry, sizeof(journal_entry), &count, NULL)) {
        printf("Failed to get journal record: %u\n", (uint32_t) GetLastError());
        return -1;
    }

    *usn = journal_entry.NextUsn;
    if (journal) {
        *journal = journal_entry.UsnJournalID;
    }
    printf("USN = [0x%"PRIx64"]\n", (uint64_t)*usn);

    return 0;
}

int usn_phase(
    HANDLE drive, USN start_usn, USN end_usn,
    uint64_t journal, Manifest *man, int phase)
{
    ENTER_PHASEN(phase);

    /*
     * usn_phase checks for any modification to relevant files, and changes any
     * such manifest entry's action to MAN_CHANGE.
     *
     * USN phase zero is used to protect between launch up to the end of the
     * shallowing phase. Because the later copy_phases also use the file size
     * which was calculated in scanning_phase, USN phase zero checks not only
     * MAN_SHALLOW but also MAN_COPY and MAN_FORCE_COPY.
     *
     * USN phases greater than 0 protect modifications during the copy_phase,
     * and change the action from MAN_COPY or MAN_FORCE_COPY to MAN_CHANGE. The
     * subsequent copy_phase will convert the MAN_CHANGE back to a
     * MAN_FORCE_COPY once it has successfully copied the file (which in the
     * worst case will get converted back to MAN_CHANGE if the subsequent
     * usn_phase detects that the file was *again* modified while being copied).
     *
     * Note that the start_usn for phase N+1 must be the same as the end_usn
     * for phase N, in order to ensure there are no gaps in the USN record
     * during which modifications could occur without us noticing.
     */

    READ_USN_JOURNAL_DATA read_data = {0};
    Heap changed_fileids;
    uint32_t num_changed_fileids = 0;

    heap_init(&changed_fileids, ~0ULL);

    read_data.StartUsn = start_usn;
    read_data.ReturnOnlyOnClose = FALSE;
    read_data.UsnJournalID = journal;
    read_data.BytesToWaitFor = 0;
    read_data.Timeout = 0;

    /* Look at all reasons. */
    read_data.ReasonMask = -1;

    char buffer[4096];
    DWORD dwBytes;
    DWORD dwRetBytes;
    while (read_data.StartUsn < end_usn) {
        memset(buffer, 0, sizeof(buffer));
        if(!DeviceIoControl(drive, FSCTL_READ_USN_JOURNAL, &read_data,
              sizeof(read_data), &buffer, sizeof(buffer), &dwBytes, NULL)) {
            printf("Read journal failed (%u)\n", (uint32_t) GetLastError());
            return -1;
        }

        PUSN_RECORD usn_record = (PUSN_RECORD)(((PUCHAR)buffer) + sizeof(USN));
        dwRetBytes = dwBytes - sizeof(USN);
        while (dwRetBytes > 0) {
            HeapElem he = {NULL, usn_record->FileReferenceNumber, NULL};
            heap_push(&changed_fileids, he);
            num_changed_fileids ++;

            dwRetBytes -= usn_record->RecordLength;
            usn_record =
                (PUSN_RECORD)(((PCHAR)usn_record) + usn_record->RecordLength);
        }
        read_data.StartUsn = *((USN*)buffer);
    }

    printf("Number of changed files as per USN = [%d]\n", num_changed_fileids);

    /* Do a basic inner-join based on file-id.
     * Caller must have already sorted manifest.  */
    int i;
    int num_copies = 0;
    for (i = 0; i < man->n && !heap_empty(&changed_fileids);) {
        HeapElem *he = &changed_fileids.elems[0];
        if (he->file_id < man->entries[i].file_id) {
            heap_pop(&changed_fileids);
        } else if (man->entries[i].file_id < he->file_id) {
            ++i;
        } else {
            ManifestEntry *m = &man->entries[i];
            wchar_t *filename = m->name;
            printf("File [%ls] is changed! Will examine it.\n",
                filename);

            /* We're interested in checking a file if:
             * - It's a shallow or copy in usn_phase zero
             * - It's a copy in the usn_phase protecting the first copy_phase
             *   (ie when phase==1)
             * - It's a MAN_CHANGE in any subsequent copy_phase
             */
            if ((phase == 0 && m->action == MAN_SHALLOW)
                || (phase <= 1 && (m->action == MAN_COPY ||
                                   m->action == MAN_FORCE_COPY))
                || (phase > 1 && m->action == MAN_CHANGE)) {
                char *cfilename = utf8(m->imgname);
                assert(cfilename);

                printf("Deleting [%ls] from target\n", filename);
                if (disklib_ntfs_unlink(m->vol, cfilename) < 0) {
                    if (disklib_errno() != DISKLIB_ERR_NOENT) {
                        /* Not an error for the file to not even have made it
                         * into the image */
                        printf("Unable to unlink [%s] err=%d\n", cfilename, disklib_errno());
                        free(cfilename);
                        return -1;
                    }
                }
                free(cfilename);

                printf("Going to (re-)copy [%ls]\n", filename);
                m->action = MAN_CHANGE;
                ++num_copies;
            }

            heap_pop(&changed_fileids);
            ++i;
        }
    }

    printf("Number of files that will be force-/re-copied = [%d]\n", num_copies);

    LEAVE_PHASEN(phase);

    return num_copies;
}

/* There is not much error logging in this function as most of the errors
   indicate that the handle is not a regular file / is a directory. */
int get_file_name(HANDLE h_file, wchar_t** file_name)
{
    int ret = -1;
    HANDLE h_mem;
    wchar_t mapped_name[MAX_PATH_LEN];
    void *mem = NULL;

    /* Create a file mapping object. */
    h_mem = CreateFileMapping(h_file, NULL, PAGE_READONLY, 0, 1, NULL);
    if (!h_mem) {
        ret = -1;
        goto cleanup;
    }

    /* Create a file mapping to get the file name. */
    mem = MapViewOfFile(h_mem, FILE_MAP_READ, 0, 0, 1);
    if (!mem) {
        ret = -1;
        goto cleanup;
    }

    if (!GetMappedFileNameW(GetCurrentProcess(), mem, mapped_name, MAX_PATH_LEN)) {
        ret = -1;
        goto cleanup;
    }

    /* Translate path with device name to drive letters. */
    wchar_t *device_paths;
    DWORD device_paths_size = 0;

    device_paths_size = GetLogicalDriveStringsW(0, NULL);
    if (!device_paths_size) {
        printf("GetLogicalDriveStringsW failed : [%d]\n", (int)GetLastError());
        ret = -1;
        goto cleanup;
    }

    device_paths = (wchar_t*)malloc((device_paths_size + 1) * sizeof(wchar_t));
    if (!device_paths) {
        printf("Error allocating [%d] bytes\n",
            (int)((device_paths_size + 1) * sizeof(wchar_t)));
        ret = -1;
        goto cleanup;
    }

    if (!GetLogicalDriveStringsW(device_paths_size, device_paths)) {
        ret = -1;
        goto cleanup;
    }

    wchar_t device_name[MAX_PATH_LEN];
    wchar_t drive[3] = L" :";
    int found = 0;
    wchar_t* p = device_paths;

    do {
        *drive = *p;
        if (QueryDosDeviceW(drive, device_name, MAX_PATH_LEN)) {
            size_t name_len = wcslen(device_name);

            if (name_len < MAX_PATH_LEN) {
                found = (_wcsnicmp(mapped_name, device_name, name_len) == 0)
                        && (*(mapped_name + name_len) == L'\\');

                if (found) {
                    wchar_t temp_name[MAX_PATH_LEN];
                    path_join(temp_name, drive, mapped_name + name_len);
                    *file_name = wcsdup(temp_name);
                    if (!*file_name) {
                        ret = -1;
                        goto cleanup;
                    }
                }
            }
        }

        for (; *p != L'\0'; ++p) { /* Go to the next L'\0'.*/ }
        p++; /* Skip over the L'\0'. The last entry has an extra L'\0' */
    } while (!found && (*p != L'\0'));

    ret = 0;

cleanup:
    if (mem) {
        UnmapViewOfFile(mem);
    }
    if (h_mem) {
        CloseHandle(h_mem);
    }
    return ret;
}

int open_handles_phase(
    Manifest *man)
{
    ENTER_PHASE();

    NTSTATUS status = STATUS_SUCCESS;
    PSYSTEM_HANDLE_INFORMATION handle_info = NULL;
    ULONG handle_info_size = 0x10000;
    HANDLE h_process;
    ULONG index;
    ULONG current_process_id = GetCurrentProcessId();
    Heap open_fileids;
    uint32_t num_open_fileids = 0;
    int ret = 0;

    heap_init(&open_fileids, ~0ULL);

    do {
        handle_info = (PSYSTEM_HANDLE_INFORMATION)realloc(handle_info, handle_info_size);
        if (!handle_info) {
            printf("Error in allocating [%d] bytes\n", (int)handle_info_size);
            ret = -1;
            goto cleanup;
        }
        status = NtQuerySystemInformation(SystemHandleInformation, handle_info,
                    handle_info_size, NULL);
        handle_info_size *= 2;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        printf("NtQuerySystemInformation failed!\n");
        ret = -1;
        goto cleanup;
    }

    qsort(handle_info->Handles, handle_info->HandleCount,
        sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO), cmp_system_handle);

    index = 0;
    while (index < handle_info->HandleCount) {
        ULONG pid = 0;

        /* Exclude the current process. */
        if (handle_info->Handles[index].ProcessId == current_process_id) {
            for(++index;
                (index < handle_info->HandleCount)
                    && (handle_info->Handles[index].ProcessId == current_process_id);
                ++index) {}
            continue;
        }

        h_process = OpenProcess(PROCESS_DUP_HANDLE, FALSE,
                            handle_info->Handles[index].ProcessId);
        if (!h_process) {
            /* Skip over all handles whose process cannot be opened. This will happen for
            * some protected processes and PIDs 0 and 4. */
            pid = handle_info->Handles[index].ProcessId;
            for(++index;
                (index < handle_info->HandleCount)
                    && (handle_info->Handles[index].ProcessId == pid);
                ++index) {}
            continue;
        }

        pid = handle_info->Handles[index].ProcessId;
        while (handle_info->Handles[index].ProcessId == pid) {
            HANDLE h_dup = NULL;
            HANDLE h_file = INVALID_HANDLE_VALUE;
            BYTE buffer[0x1000];
            POBJECT_TYPE_INFORMATION obj_type_info =
                (POBJECT_TYPE_INFORMATION)buffer;
            BY_HANDLE_FILE_INFORMATION file_handle_info = {0};
            wchar_t *file_name = NULL;
            uint64_t file_id;
            int copy_file;

            status = NtDuplicateObject(h_process,
                        (HANDLE)(intptr_t)handle_info->Handles[index].Handle,
                        GetCurrentProcess(),
                        &h_dup,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status)) {
                goto next;
            }

            // Filter only 'File' type.
            status = NtQueryObject(h_dup,
                ObjectTypeInformation,
                obj_type_info,
                sizeof(buffer),
                NULL);

            if (!NT_SUCCESS(status)) {
                goto next;
            }

            if (_wcsnicmp(obj_type_info->Name.Buffer, L"File",
                    obj_type_info->Name.Length / sizeof(wchar_t)) != 0) {
                goto next;
            }

            if (get_file_name(h_dup, &file_name) < 0) {
                goto next;
            }

            if (!GetFileInformationByHandle(h_dup, &file_handle_info)) {
                printf("GetFileInformationByHandle failed for [%ls]: [%d]\n",
                    file_name, (int)GetLastError());
                goto next;
            }

            CloseHandle(h_dup);
            h_dup = NULL;

            copy_file = 0;
            if (handle_info->Handles[index].GrantedAccess
                & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE)) {
                copy_file = 1;
            }

            if (!copy_file) {
                h_file = CreateFileW(file_name,
                            FILE_READ_DATA,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN
                            | FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_BACKUP_SEMANTICS,
                            NULL);
                if ((h_file == INVALID_HANDLE_VALUE)
                    && (GetLastError() == ERROR_SHARING_VIOLATION)) {
                    copy_file = 1;
                }
            }

            /* If there is write access taken by another file, or if there is no sharing enabled, copy. */
            if (copy_file) {
                file_id = ((uint64_t)file_handle_info.nFileIndexHigh << 32ULL)
                            | file_handle_info.nFileIndexLow;
                HeapElem he = {NULL, file_id, NULL};
                heap_push(&open_fileids, he);
                num_open_fileids++;
                goto next;
            }

next:
            free(file_name);
            file_name = NULL;

            if (h_file != INVALID_HANDLE_VALUE) {
                CloseHandle(h_file);
                h_file = INVALID_HANDLE_VALUE;
            }
            if (h_dup) {
                CloseHandle(h_dup);
                h_dup = NULL;
            }
            index ++;
            continue;
        }

        if (h_process) {
            CloseHandle(h_process);
        }
    }

    printf("Number of files opened for write = [%d]\n", num_open_fileids);

    /* Do a basic inner-join based on file-id.  */
    int i;
    int num_copies = 0;
    for (i = 0; i < man->n && !heap_empty(&open_fileids);) {
        HeapElem *he = &open_fileids.elems[0];
        if (he->file_id < man->entries[i].file_id) {
            heap_pop(&open_fileids);
        } else if (man->entries[i].file_id < he->file_id) {
            ++i;
        } else {
            wchar_t *filename = man->entries[i].name;
            printf("File [%ls] is open! Will examine it.\n",
                filename);

            if (man->entries[i].action == MAN_SHALLOW) {
                char *cfilename = utf8(man->entries[i].imgname);
                assert(cfilename);

                printf("Deleting [%ls] from target disk\n", filename);
                if (disklib_ntfs_unlink(man->entries[i].vol, cfilename) < 0) {
                    printf("Unable to unlink [%s]\n", cfilename);
                    free(cfilename);
                    goto cleanup;
                }
                free(cfilename);

                printf("Going to force-copy [%ls]\n", filename);
                man->entries[i].action = MAN_FORCE_COPY;
                num_copies ++;
            }

            heap_pop(&open_fileids);
            ++i;
        }
    }
    printf("Number of files that will be force-copied = [%d]\n", num_copies);

cleanup:
    free(handle_info);

    LEAVE_PHASE();

    return ret;
}

#define UUID_FMT "{%08X-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X}"
int local_uuid_parse(const char *str, GUID *guid)
{
    // Slightly convoluted way since the compiler doesn't support %hhX of C99.
    unsigned int bytes[8];
    int i = 0;

    int ret = sscanf(str, UUID_FMT, (uint32_t*)&guid->Data1,
        (uint16_t*)&guid->Data2, (uint16_t*)&guid->Data3,
        &bytes[0], &bytes[1], &bytes[2], &bytes[3],
        &bytes[4], &bytes[5], &bytes[6], &bytes[7]);

    if (ret != 11) {
        return -1;
    }

    for (i = 0; i < 8; i++) {
        guid->Data4[i] = bytes[i];
    }

    return 0;
}

void json_escape_string(const wchar_t* wide_source, char* dest)
{
    char* src_buf = utf8(wide_source);
    char* src = src_buf;
    int ch;
    do {
        ch = *src++;
        switch(ch) {
        case '"': /* Drop thru */
        case '\\':
            *dest++ = '\\';
            *dest++ = ch;
            break;
        case '\r':
            *dest++ = '\\';
            *dest++ = 'r';
            break;
        case '\n':
            *dest++ = '\\';
            *dest++ = 'n';
            break;
        default:
            *dest++ = ch;
            break;
        }
    } while (ch != 0);
    *dest = 0; // Make sure to zero-terminate
    free(src_buf);
}

// returns zero on success
int calculate_sha1_for_file(const wchar_t *filename, uint8_t *out_sha)
{
    int err = 0;
    const size_t buf_size = 1 << 20;
    char *buf = NULL;
    HANDLE h = INVALID_HANDLE_VALUE;
    SHA1_CTX sha_ctx;
    SHA1_Init(&sha_ctx);
    buf = malloc(buf_size);
    if (!buf) {
        err = 1;
        goto out;
    }
    h = open_file_by_name(filename, FILE_FLAG_SEQUENTIAL_SCAN);
    if (h == INVALID_HANDLE_VALUE) {
        err = 1;
        goto out;
    }

    for(;;) {
        DWORD bytes_read;
        BOOL ok;
        ok = ReadFile(h, buf, buf_size, &bytes_read, NULL);
        if (!ok) {
            err = 1; /* assume some error */
        }
        if (!ok || bytes_read == 0) {
            break;
        }
        SHA1_Update(&sha_ctx, (uint8_t *)buf, bytes_read);
    }
    SHA1_Final(&sha_ctx, out_sha);
out:
    free(buf);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
    return err;
}

int hash_shallowed_files_phase(struct disk *disk, Manifest *man)
{
    ENTER_PHASE();
    /* Deep-copied files will have their SHA1s calculated in
     * copy_file. Here we will calculate the SHA1s for those we're shallowing.
     * This will only be done when a certain config option is enabled so this is
     * not performance-critical, hence why it is a simple loop rather than using
     * parallel IOs */
    int i;
    for (i = 0; i < man->n; i++) {
        ManifestEntry* entry = &man->entries[i];
        if (entry->action == MAN_SHALLOW || entry->action == MAN_BOOT) {
            wchar_t *host_name = prefix(entry->var, entry->name);
            int err = calculate_sha1_for_file(host_name, entry->sha);
            if (err) {
                printf("Failed to get SHA1 for %ls\n", host_name);
            }
        }
    }

    LEAVE_PHASE();
    return 0;
}

void append_ver_string(wchar_t **output, WORD *lang, void *buf,
                       const wchar_t *variable)
{
    wchar_t *value;
    UINT len;
    BOOL ok;
    wchar_t subblock[64];
    snwprintf(subblock, 64, L"\\StringFileInfo\\%04x%04x\\%ls",
              lang[0], lang[1], variable);
    ok = VerQueryValueW(buf, subblock, (void **)&value, &len);
    if (ok) {
        size_t oldlen = *output ? wcslen(*output) : 0;
        /* +1 for \n, +2 for ": ", +1 for zero term */
        size_t newlen = oldlen + 1 + wcslen(variable) + 2 + len + 1;
        wchar_t *newstr = realloc(*output, newlen * sizeof(wchar_t));
        if (newstr) {
            *output = newstr;
            snwprintf(*output + oldlen, newlen - oldlen, L"%ls: %ls\n",
                      variable, value);
        }
    }
}

/* Returns a string containing various pieces of useful metadata as returned by
 * the Windows GetFileVersionInfoSize() API, or NULL if the file doesn't have
 * any version information.
 */
wchar_t* get_file_metadata(const wchar_t *filename)
{
    void *infobuf = NULL;
    BOOL ok;
    UINT len;
    WORD *langptr;
    wchar_t *result = NULL;
    DWORD bufsize = GetFileVersionInfoSizeW(filename, NULL);
    if (bufsize == 0) {
        /* Probably means no version info - not an error */
        goto out;
    }
    infobuf = malloc(bufsize);
    ok = GetFileVersionInfoW(filename, 0, bufsize, infobuf);
    if (ok) {
        ok = VerQueryValueW(infobuf, L"\\VarFileInfo\\Translation",
                            (void **)&langptr, &len);
    }
    if (!ok) {
        /* Shouldn't happen unless the file has version info but no strings */
        printf("Failed to GetFileVersionInfo for %ls\n", filename);
        goto out;
    }
    append_ver_string(&result, langptr, infobuf, L"CompanyName");
    append_ver_string(&result, langptr, infobuf, L"FileDescription");
    append_ver_string(&result, langptr, infobuf, L"FileVersion");
    append_ver_string(&result, langptr, infobuf, L"ProductName");
    append_ver_string(&result, langptr, infobuf, L"ProductVersion");

out:
    free(infobuf);
    return result;
}

/* If requested to by a -m option on the command line, this outputs a JSON
 * formatted file containing information about all the files added to the image.
 * Note this is not a list of all the files on disk, only the ones added by this
 * logiccp invocation. The format of the output is derived from that used by
 * tinydisk. The only major differences being: it doesn't list all files (as
 * already mentioned); it is not pretty-printed; entries are not sorted by path;
 * the output is UTF-8 rather than ASCII with JSON \u escapes; SHA-1 hashes are
 * only calculated and output for files which are copied, rather than for all
 * files (unless calculate_all_hashes is true).
 *
 * If collect_file_metadata is true, then also add a "description" attribute to
 * any file which has Windows versioning information embedded (which broadly
 * means DLLs and EXEs) containing Company, Product and Version information.
 * This is to aid diagnosing when binaries of unknown provenence end up in the
 * guest.
 *
 * calculate_all_hashes and collect_file_metadata (command line options
 * ALL_HASHES and FILE_METADATA) are off by default thus no effort has been made
 * to performance optimise them. They are only intended to be used when
 * debugging.
*/
int output_manifest_phase(Manifest *man, struct disk* disk,
                          int sysvol, int bootvol, const char* out_path,
                          int calculate_all_hashes, int collect_file_metadata)
{
    ENTER_PHASE();
    FILE* f;
    int i;
    /* Max length of a MAX_PATH_LEN string after JSON escaping */
    static char temp_buf[(MAX_PATH_LEN + 1) * 4];
    static wchar_t wide_buf[MAX_PATH_LEN];

    f = fopen(out_path, "wt");
    if (!f) {
        printf("unable to create output manifest: %s errno=%d\n", out_path, errno);
        return 1;
    }

    fputs("[", f);
    for (i = 0; i < man->n; i++) {
        ManifestEntry* entry = &man->entries[i];
        int has_sha = 0;
        if (entry->action == MAN_EXCLUDE || entry->action == MAN_CHANGE) {
            /* MAN_CHANGE could occur for a file that changed then was deleted */
            continue;
        }

        fprintf(f, "\n{\"partition\": %d",
            entry->vol == disk->sysvol ? sysvol : bootvol);

        json_escape_string(entry->imgname, temp_buf);
        fprintf(f, ", \"path\": \"%s\"", temp_buf);

        switch (entry->action) {
        case MAN_SHALLOW_FOLLOW_LINKS:
        case MAN_COPY_FOLLOW_LINKS:
            /* Don't appear in output manifests */
            fprintf(f, ", \"comment\": \"FOLLOW_LINKS??\"");
            break;

        case MAN_CHANGE:
        case MAN_EXCLUDE:
            /* Already handled */
            break;

        /* These both call shallow_file() */
        case MAN_BOOT:
        case MAN_SHALLOW:
            fprintf(f, ", \"shallow_id\": \"%016"PRIx64"\"", entry->file_id);
            /* Drop thru */
        case MAN_FORCE_COPY: /* Drop thru */
        case MAN_COPY:
            fprintf(f, ", \"size\": %"PRIu64"", entry->file_size);
            make_unshadowed_host_path(wide_buf, entry);
            json_escape_string(wide_buf, temp_buf);
            fprintf(f, ", \"source\": \"host\", \"source_path\": \"%s\"", temp_buf);
            has_sha = calculate_all_hashes
                        || (entry->action == MAN_COPY)
                        || (entry->action == MAN_FORCE_COPY);
            if (has_sha) {
                fprintf(f, ", \"sha1\": \"" SHA1FMT "\"",
                    entry->sha[0], entry->sha[1], entry->sha[2], entry->sha[3],
                    entry->sha[4], entry->sha[5], entry->sha[6], entry->sha[7],
                    entry->sha[8], entry->sha[9], entry->sha[10], entry->sha[11],
                    entry->sha[12], entry->sha[13], entry->sha[14], entry->sha[15],
                    entry->sha[16], entry->sha[17], entry->sha[18], entry->sha[19]);
            }
            if (collect_file_metadata) {
                wchar_t* md = get_file_metadata(wide_buf);
                /* md could be arbitrarily big so do a quick length check
                 * before using temp_buf. Don't expect this to ever happen so
                 * haven't bothered making it truncate, or use a variable sized
                 * buffer etc, but if it does we should definitely not crash. */
                if (md && wcslen(md) < MAX_PATH_LEN) {
                    json_escape_string(md, temp_buf);
                    fprintf(f, ", \"description\": \"%s\"", temp_buf);
                }
                free(md);
            }
            break;

        case MAN_MKDIR:
        case MAN_COPY_EMPTY_DIR:
            fprintf(f, ", \"type\": \"dir\"");
            break;

        case MAN_LINK:
            json_escape_string(entry->target, temp_buf);
            fprintf(f, ", \"type\": \"hardlink\", \"target\": \"%s\"", temp_buf);
            break;

        case MAN_SYMLINK:
            json_escape_string(entry->target, temp_buf);
            fprintf(f, ", \"type\": \"symlink\", \"target\": \"%s\"", temp_buf);
            break;
        }

        if (i+1 == man->n) {
            fputs("}", f);
        } else {
            fputs("},", f);
        }
    }
    fputs("\n]", f);
    fclose(f);
    LEAVE_PHASE();
    return 0;
}

void print_usage(void)
{
    printf("usage: %s [-sBOOTVOL=<path>] [-m<outmanifest>] manifest image.swap " \
        "[USN=<USN record-id in hex>] [GUID=<CoW driver GUID>] " \
        "[PARTITION=<partition number in decimal>] " \
        "[MINSHALLOW=<minimum shallowing size in decimal bytes>]" \
        "[SKIP_USN_PHASE] [SKIP_ACL_PHASE] [SKIP_OPEN_HANDLES_PHASE]" \
        "[SKIP_COW_REGISTRATION] [NOSHALLOW] [ALL_HASHES] [FILE_METADATA]" \
        "[SKIP_FOLLOW_LINKS]\n",
            getprogname());
}

#define NUMBER_OF(x)                     (sizeof((x))/sizeof((x)[0]) - 1)
#define ARG_SUBSTITUTION                 "-s"
#define ARG_OUT_MANIFEST                 "-m"
#define ARG_USN                          "USN="
#define ARG_GUID                         "GUID="
#define ARG_PARTITION                    "PARTITION="
#define ARG_MINSHALLOW                   "MINSHALLOW="
#define ARG_SKIP_USN_PHASE               "SKIP_USN_PHASE"
#define ARG_SKIP_ACL_PHASE               "SKIP_ACL_PHASE"
#define ARG_SKIP_OPEN_HANDLES_PHASE      "SKIP_OPEN_HANDLES_PHASE"
#define ARG_SKIP_COW_REGISTRATION        "SKIP_COW_REGISTRATION"
#define ARG_SKIP_FOLLOW_LINKS            "SKIP_FOLLOW_LINKS"
#define ARG_NOSHALLOW                    "NOSHALLOW"
#define ARG_ALL_HASHES                   "ALL_HASHES"
#define ARG_FILE_METADATA                "FILE_METADATA"
#define ARG_NUM_RETRIES                  "NUM_RETRIES="
#define ARG_ABSENT_FILES_FATAL           "ABSENT_FILES_FATAL"
#define ARG_PAUSE_BEFORE_COPY            "PAUSE_BEFORE_COPY"
#define ARG_SUBSTITUTION_SIZE            NUMBER_OF(ARG_SUBSTITUTION)
#define ARG_OUT_MANIFEST_SIZE            NUMBER_OF(ARG_OUT_MANIFEST)
#define ARG_USN_SIZE                     NUMBER_OF(ARG_USN)
#define ARG_GUID_SIZE                    NUMBER_OF(ARG_GUID)
#define ARG_PARTITION_SIZE               NUMBER_OF(ARG_PARTITION)
#define ARG_MINSHALLOW_SIZE              NUMBER_OF(ARG_MINSHALLOW)
#define ARG_SKIP_USN_PHASE_SIZE          NUMBER_OF(ARG_SKIP_USN_PHASE)
#define ARG_SKIP_ACL_PHASE_SIZE          NUMBER_OF(ARG_SKIP_ACL_PHASE)
#define ARG_SKIP_OPEN_HANDLES_PHASE_SIZE NUMBER_OF(ARG_SKIP_OPEN_HANDLES_PHASE)
#define ARG_SKIP_COW_REGISTRATION_SIZE   NUMBER_OF(ARG_SKIP_COW_REGISTRATION)
#define ARG_SKIP_FOLLOW_LINKS_SIZE       NUMBER_OF(ARG_SKIP_FOLLOW_LINKS)
#define ARG_NOSHALLOW_SIZE               NUMBER_OF(ARG_NOSHALLOW)
#define ARG_ALL_HASHES_SIZE              NUMBER_OF(ARG_ALL_HASHES)
#define ARG_FILE_METADATA_SIZE           NUMBER_OF(ARG_FILE_METADATA)
#define ARG_PAUSE_BEFORE_COPY_SIZE       NUMBER_OF(ARG_PAUSE_BEFORE_COPY)
#define ARG_NUM_RETRIES_SIZE             NUMBER_OF(ARG_NUM_RETRIES)
#define ARG_ABSENT_FILES_FATAL_SIZE      NUMBER_OF(ARG_ABSENT_FILES_FATAL)

int main(int argc, char **argv)
{
    int i, nchanged;
    int r = 0;
    struct disk disk;
    FILE *manifest_file;
    Manifest suffixes, man_out;
    VarList vars;

    if (init_logiccp() < 0) {
        printf("Unable to initialize\n");
        exit(1);
    }

    low_priority = reduce_io_priority();
    setprogname(argv[0]);
    if (argc < 3) {
        print_usage();
        exit(1);
    }
    convert_args(argc, argv);

    varlist_init(&vars);
    man_init(&man_out);
    man_init(&suffixes);

    char *arg_out_manifest = NULL;
    char *arg_manifest_file = NULL;
    char *arg_swap_file = NULL;
    char *arg_usn = NULL;
    char *arg_guid = NULL;
    char *arg_partition = NULL;
    char *arg_minshallow = NULL;

    int skip_acl_phase = 0;
    int skip_open_handles_phase = 0;
    int skip_cow_registration = 0;
    int skip_usn_phase = 0;
    int calculate_all_hashes = 0;
    int collect_file_metadata = 0;
    int pause_before_copy = 0; /* Only used for unit tests! */
    int num_retries = 5;

    while (argc >= 2) {
        if (strncmp(argv[1], ARG_SUBSTITUTION, ARG_SUBSTITUTION_SIZE) == 0) {
            /* Handle -s switches for setting for defining variables. */
            char *v = argv[1] + ARG_SUBSTITUTION_SIZE;
            char *c = v;
            size_t l;
            while (*c != '=' && *c) {
                ++c;
            }
            /* Krypton may have quoted the actual path, so clean that up. */
            *c++ = '\0';
            l = strlen(c);
            if (*c == '"' && c[l - 1] == '"') {
                c[l - 1] = '\0';
                ++c;
            }

            Variable *e = varlist_push(&vars);
            e->man = (Manifest*) malloc(sizeof(Manifest));
            man_init(e->man);
            e->name = wide(v);
            /* path can be NULL, which means skip manifest lines under this var. */
            e->path = *c ? wide(c) : NULL;
        } else if (strncmp(argv[1], ARG_OUT_MANIFEST, ARG_OUT_MANIFEST_SIZE) == 0) {
            arg_out_manifest = argv[1];
            arg_out_manifest += ARG_OUT_MANIFEST_SIZE;
        } else if (strncmp(argv[1], ARG_USN, ARG_USN_SIZE) == 0) {
            arg_usn = argv[1];
            arg_usn += ARG_USN_SIZE;
        } else if (strncmp(argv[1], ARG_GUID, ARG_GUID_SIZE) == 0) {
            arg_guid = argv[1];
            arg_guid += ARG_GUID_SIZE;
        } else if (strncmp(argv[1], ARG_PARTITION, ARG_PARTITION_SIZE) == 0) {
            arg_partition = argv[1];
            arg_partition += ARG_PARTITION_SIZE;
        } else if (strncmp(argv[1], ARG_MINSHALLOW, ARG_MINSHALLOW_SIZE) == 0) {
            arg_minshallow = argv[1];
            arg_minshallow += ARG_MINSHALLOW_SIZE;
        } else if (strncmp(argv[1], ARG_SKIP_USN_PHASE, ARG_SKIP_USN_PHASE_SIZE) == 0) {
            skip_usn_phase = 1;
            printf("Will skip USN phase\n");
        } else if (strncmp(argv[1], ARG_SKIP_OPEN_HANDLES_PHASE, ARG_SKIP_OPEN_HANDLES_PHASE_SIZE) == 0) {
            skip_open_handles_phase = 1;
            printf("Will skip open handles phase\n");
        } else if (strncmp(argv[1], ARG_SKIP_ACL_PHASE, ARG_SKIP_ACL_PHASE_SIZE) == 0) {
            skip_acl_phase = 1;
            printf("Will skip ACL phase\n");
        } else if (strncmp(argv[1], ARG_SKIP_COW_REGISTRATION, ARG_SKIP_COW_REGISTRATION_SIZE) == 0) {
            skip_cow_registration = 1;
            printf("Will skip COW registration\n");
        } else if (strncmp(argv[1], ARG_SKIP_FOLLOW_LINKS, ARG_SKIP_FOLLOW_LINKS_SIZE) == 0) {
            follow_links = 0;
            printf("Will skip following hardlinks\n");
        } else if (strncmp(argv[1], ARG_NOSHALLOW, ARG_NOSHALLOW_SIZE) == 0) {
            shallow_allowed = 0;
            printf("Not allowing shallowing\n");
        } else if (strncmp(argv[1], ARG_ALL_HASHES, ARG_ALL_HASHES_SIZE) == 0) {
            printf("Will collect hashes for all files\n");
            calculate_all_hashes = 1;
        } else if (strncmp(argv[1], ARG_FILE_METADATA, ARG_FILE_METADATA_SIZE) == 0) {
            printf("Will collect metadata for all files\n");
            collect_file_metadata = 1;
        } else if (strncmp(argv[1], ARG_PAUSE_BEFORE_COPY, ARG_PAUSE_BEFORE_COPY_SIZE) == 0) {
            pause_before_copy = 1;
            printf("Will pause before copy_phase\n");
        } else if (strncmp(argv[1], ARG_NUM_RETRIES, ARG_NUM_RETRIES_SIZE) == 0) {
            num_retries = atoi(argv[1] + ARG_NUM_RETRIES_SIZE);
            printf("Using %d retries\n", num_retries);
        } else if (strncmp(argv[1], ARG_ABSENT_FILES_FATAL, ARG_ABSENT_FILES_FATAL_SIZE) == 0) {
            /* No longer has any effect, but for compatibility we silently ignore it */
        } else if (arg_manifest_file == NULL) {
            arg_manifest_file = argv[1];
        } else if (arg_swap_file == NULL) {
            arg_swap_file = argv[1];
        } else {
            print_usage();
            exit(1);
        }
        ++argv;
        --argc;
    }

    bootvol_var = varlist_find(&vars, L"BOOTVOL");
    manifest_file = fopen(arg_manifest_file, "r");
    if (!manifest_file) {
        err(1, "unable to open manifest: %s", arg_manifest_file);
    }

    if (arg_minshallow) {
        min_shallow_size = ((atoi(arg_minshallow) + (SECTOR_SIZE-1)) / SECTOR_SIZE) * SECTOR_SIZE;
        if (min_shallow_size < SECTOR_SIZE) {
            /* We cannot shallow files shorter than 512 bytes, because that is the
             * size of our memcmp check in util.c. */
            min_shallow_size = SECTOR_SIZE;
        }
    }

    int partition = 1;
    if (arg_partition) {
        partition = atoi(arg_partition);
    }
    if (partition != 1) {
        shallow_allowed = 0;
        skip_usn_phase = 1; /* Implied by not shallowing */
    }
    if (!disk_open(arg_swap_file, 1, &disk, 0, partition)) {
        printf("Unable to open disk:partition [%s:%d]\n",
            arg_swap_file, partition);
        exit(1);
    }

    /* Find out drive letter of system drive, for use in shallow map. */
    wchar_t *systemroot;
    systemroot = _wgetenv(L"SystemDrive");
    if (systemroot && systemroot[1] == L':') {
        rootdrive = systemroot[0];
    }

    USN start_usn = 0ULL;
    HANDLE drive = INVALID_HANDLE_VALUE;
    if (shallow_allowed && !skip_usn_phase) {
        wchar_t unc_systemroot[MAX_PATH_LEN];
        path_join(unc_systemroot, L"\\\\?\\", systemroot);
        drive = CreateFileW(
                        unc_systemroot,
                        GENERIC_READ,
                        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_ALWAYS,
                        FILE_FLAG_NO_BUFFERING,
                        NULL);
        if (drive == INVALID_HANDLE_VALUE) {
            err(1, "Unable to open volume [%ls]: %d\n",
                unc_systemroot, (int)GetLastError());
        }

        if (arg_usn) {
            start_usn = strtoull(arg_usn, NULL, 0);
            if (start_usn == ULLONG_MAX) {
                printf("Invalid value for USN record: %s\n", arg_usn);
                print_usage();
                exit(1);
            }
        } else {
            if (get_next_usn(drive, &start_usn, NULL) < 0) {
                err(1, "Unable to record starting USN entry\n");
            }
        }
        printf("START USN = [0x%"PRIx64"]\n", (uint64_t)start_usn);
    }

    wchar_t *location = _wfullpath(NULL, wide(arg_swap_file), 0);
    normalize_string(location);
    strip_filename(location);

    wchar_t map_idx[MAX_PATH_LEN] = L"";
    wchar_t file_id_list[MAX_PATH_LEN] = L"";
    wchar_t cow_dir[MAX_PATH_LEN] = L"";

    if (shallow_allowed) {
        unsigned char uuid[16];
        char uuid_str[37];
        r = vd_get_uuid(disk.hdd.vboxhandle, uuid);
        if (r == sizeof(uuid_t)) {
            uuid_unparse_lower(uuid, uuid_str);
            printf("uuid is %s\n", uuid_str);
        } else {
            err(1, "unable to get uuid from disk backend r=%d", r);
        }

        wchar_t *wuuid = wide(uuid_str);

        path_join_var(map_idx, location, L"/swapdata-", wuuid, L"/map.idx");
        path_join_var(file_id_list, location, L"/swapdata-", wuuid,L"/fileidlist.idx");
        path_join_var(cow_dir, location, L"/swapdata-", wuuid, L"/cow");
    }

    /* Read and parse user-supplied manifest. */
    read_manifest(manifest_file, &vars, &suffixes);

    for (i = 0; i < vars.n; ++i) {
        Manifest *man = vars.entries[i].man;
        man_sort_by_name(man);
        man_uniq_by_name_and_action(man);
        man_filter_excludables(man);
    }

    man_sort_by_name(&suffixes);
    man_uniq_by_name_and_action(&suffixes);

    /* Needed to scan exclusively-opened files when not using VSS, because of
     * how path_exists() is implemented.
     */
    cow_allow_file_access();

    /* Scan directories on host. */
    if (scanning_phase(&disk, &vars, &suffixes, &man_out) < 0) {
        err(1, "scanning_phase failed");
    }

    /* There should be no further MAN_COPY_FOLLOW_LINKS or
       MAN_SHALLOW_FOLLOW_LINKS from here on. */

    /* Stat all files individually. */
    man_sort_by_id(&man_out);
    if (stat_files_phase(&disk, &man_out, file_id_list) < 0) {
        err(1, "stat_files_phase failed");
    }

    GUID guid = {0};
    if (shallow_allowed) {
        if (arg_guid && !skip_cow_registration) {
            if (local_uuid_parse(arg_guid, &guid) < 0) {
                err(1, "Error in parsing guid [%s]", arg_guid);
            }

            if (!CreateDirectoryW(cow_dir, NULL)
                && (GetLastError() != ERROR_ALREADY_EXISTS)) {
                printf("unable to create CoW directory %ls!\n", cow_dir);
                exit(1);
            }

            wchar_t cow_drvpath[MAX_PATH_LEN];
            path_join(cow_drvpath, L"\\??\\", cow_dir);
            normalize_string2(cow_drvpath);

            wchar_t fileidlist_drvpath[MAX_PATH_LEN];
            path_join(fileidlist_drvpath, L"\\??\\", file_id_list);
            normalize_string2(fileidlist_drvpath);

            if (register_with_cow(guid, cow_drvpath, fileidlist_drvpath) < 0) {
                err(1, "Registration with filter failed: (%s, %ls, %ls)\n",
                    arg_guid, cow_drvpath, fileidlist_drvpath);
            }
        }
    }

    man_sort_by_name(&man_out);
    man_uniq_by_name(&man_out);

    if (rewire_phase(&disk, &man_out) < 0) {
        err(1, "rewiring_phase failed");
    }

    /* Unlikely that rewire_phase meant there's anything additional to uniq,
     * but just in case rerun */
    man_sort_by_name(&man_out);
    man_uniq_by_name(&man_out);

    if (mkdir_phase(&disk, &man_out) < 0) {
        err(1, "mkdir_phase failed");
    }

    /* Copy/shallow phase. */
    printf("copy + shallow %d files\n", man_out.n);

    man_sort_by_offset_link_action(&man_out);
    if (vm_links_phase_1(&disk, &man_out) < 0) {
        err(1, "vm_links_phase_1 failed");
    }

    if (shallow_allowed) {

        if (!skip_acl_phase) {
            man_sort_by_id(&man_out);
            if (acl_phase(&disk, &man_out) < 0) {
                err(1, "acl_phase failed");
            }
        }

        man_sort_by_name(&man_out);
        if (shallow_phase(&disk, &man_out, map_idx) < 0) {
            err(1, "shallow_phase failed");
        }

        if (calculate_all_hashes) {
            if (hash_shallowed_files_phase(&disk, &man_out) < 0) {
                err(1, "hash_shallowed_files_phase failed");
            }
        }

        if (!skip_usn_phase) {
            /* Read the USN journal again and consume the set. */
            USN end_usn;
            uint64_t journal;
            if (get_next_usn(drive, &end_usn, &journal) < 0) {
                err(1, "Unable to record ending USN entry\n");
            }

            man_sort_by_id(&man_out);
            if (usn_phase(drive, start_usn, end_usn, journal, &man_out, 0) < 0) {
                err(1, "usn_phase failed\n");
            }
            start_usn = end_usn;
        }

        if (!skip_open_handles_phase) {
            if (open_handles_phase(&man_out) < 0) {
                err(1, "open_handles_phase failed\n");
            }
        }
    }


    init_ios();

    /* This option only exists so we can unit-test making changes between
       stat_files_phase and copy_phase */
    if (pause_before_copy) {
        char ch;
        /* Don't change this logging without also updating test code */
        printf("Press a key to continue to copy_phase\n");
        fread(&ch, 1, 1, stdin);
    }

    for (i = nchanged = 0; !skip_usn_phase && i < num_retries; ++i) {
        USN end_usn;
        uint64_t journal;

        man_sort_by_offset_link_action(&man_out);
        nchanged = copy_phase(&disk, &man_out, arg_out_manifest != NULL, i);
        r = get_next_usn(drive, &end_usn, &journal);
        if (r < 0) {
            err(1, "Unable to record ending USN entry\n");
        }
        man_sort_by_id(&man_out);
        r = usn_phase(drive, start_usn, end_usn, journal, &man_out, i + 1);
        if (r < 0) {
            err(1, "usn_phase %d failed\n", i + 1);
        }
        nchanged += r;
        start_usn = end_usn;

        if (nchanged == 0) {
            break;
        }
    }
    if (nchanged > 0) {
        /* Note this is not considered fatal - if a file is still churning after
         * repeated retries we give up and just copy it as-is below */
        printf("Failed to successfully copy %d files after %d attempts\n", nchanged, i);
    }
    if (nchanged > 0 || num_retries == 0 || skip_usn_phase) {
        /* Since the usn_phase will have deleted any changed file from the image
         * we need to do another "best-effort" copy just to put something in
         * there. Also need a copy if we were told not to do any retries at all
         * or if we skipped the retry logic entirely due to SKIP_USN_PHASE.
         */
        man_sort_by_offset_link_action(&man_out);
        r = copy_phase(&disk, &man_out, arg_out_manifest != NULL, i);
        if (r != 0) {
            /* Here we treat any remaining changed files as fatal
             * because there isn't really any remedial action we can take short
             * of excluding the file, which will potentially cause much worse
             * problems down the line. */
            err(1, "copy_phase %d failed", i);
        }
    }

    man_sort_by_offset_link_action(&man_out);

    if (vm_links_phase_2(&disk, &man_out) < 0) {
        err(1, "vm_links_phase_2 failed");
    }

    if (arg_out_manifest != NULL) {
        r = output_manifest_phase(&man_out, &disk, 0, partition,
                                  arg_out_manifest, calculate_all_hashes,
                                  collect_file_metadata);
        if (r < 0) {
            err(1, "output_manifest_phase failed");
        }
    } else {
        printf("Skipping output_manifest_phase.\n");
    }

    if (flush_phase(&disk) < 0) {
        err(1, "flush_phase failed");
    }

    if (drive != INVALID_HANDLE_VALUE) {
        CloseHandle(drive);
        drive = INVALID_HANDLE_VALUE;
    }

    printf("done. exit.\n");
    fflush(stderr);
    fflush(logfile);

    return r;
}
