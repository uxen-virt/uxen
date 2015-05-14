/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

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


static pNtCreateFile NtCreateFile;
static pNtClose NtClose;
static pNtReadFile NtReadFile;
static pNtQuerySystemInformation NtQuerySystemInformation;
static pNtDuplicateObject NtDuplicateObject;
static pNtQueryObject NtQueryObject;
static pFilterConnectCommunicationPort FilterConnectCommunicationPort;
static pFilterSendMessage FilterSendMessage;
static int shallow_allowed = 1;
static int min_shallow_size = SECTOR_SIZE;

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

/* Heap used as priority queue for BFS scan. */
typedef struct HeapElem {
    wchar_t *name;
    uint64_t file_id;
    wchar_t *rerooted_name;
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
        MAN_CHANGE = 0,
        MAN_EXCLUDE = 1,
        MAN_BOOT = 2, /* file that needs rewiring to /boot. */
        MAN_FORCE_COPY = 3, /* like COPY, but overrides shallow. */
        MAN_SHALLOW = 4, /* normal shallow, e.g. via winsxs name. */
        MAN_HARDLINK_SHALLOW = 5, /* shallow the file via a host-side hardlink. */
        MAN_COPY = 6, /* plain copy from host to vm. */
        MAN_MKDIR = 7, /* used internally to ensure dirs are created before use. */
        MAN_LINK = 8, /* used internally to hardlink files with >1 names. */
    } Action;

typedef struct ManifestEntry {
    ntfs_fs_t vol;
    Variable *var;
    wchar_t *name;
    wchar_t *host_name; /* set if different from guest name. */
    wchar_t *rewrite;
    size_t name_len;
    uint64_t offset;
    uint64_t file_size;
    uint64_t link_id;
    uint64_t file_id;
    Action action;
} ManifestEntry;

typedef struct Manifest {
    int n;
    ManifestEntry *entries;
} Manifest;

ManifestEntry *find_by_prefix(Manifest *man, const wchar_t *fn);
ManifestEntry *find_by_name(Manifest *man, const wchar_t *fn);

void man_init(Manifest *man)
{
    man->entries = NULL;
    man->n = 0;
}

ManifestEntry *man_push(Manifest *man)
{
    int n = man->n++;
    if (!(n & (n + 1))) {
        man->entries = realloc(man->entries, 2 * (n + 1) * sizeof(ManifestEntry));
        assert(man->entries);

    }
    memset(&man->entries[n], 0, sizeof(ManifestEntry));
    return &man->entries[n];
}

int cmp(const void *a, const void *b)
{
    const ManifestEntry *ea = (const ManifestEntry *) a;
    const ManifestEntry *eb = (const ManifestEntry *) b;
    int r = wcscmp(ea->name, eb->name);
    if (r != 0) {
        return r;
    } else {
        if (ea->action < eb->action) {
            return -1;
        } else if (eb->action < ea->action) {
            return 1;
        } else {
            return 0;
        }
    }
}

int cmp2(const void *a, const void *b)
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
                return wcscmp(ea->name, eb->name);
            }
        }
    }
}

int cmp3(const void *a, const void *b)
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

int cmp_system_handle(const void *a, const void *b)
{
    const PSYSTEM_HANDLE_TABLE_ENTRY_INFO pa = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO) a;
    const PSYSTEM_HANDLE_TABLE_ENTRY_INFO pb = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO) b;

    return (pa->ProcessId - pb->ProcessId);
}

void man_sort_by_name(Manifest *man)
{
    qsort(man->entries, man->n, sizeof(ManifestEntry), cmp);
}

void man_sort_by_offset(Manifest *man)
{
    qsort(man->entries, man->n, sizeof(ManifestEntry), cmp2);
}

void man_sort_by_id(Manifest *man)
{
    qsort(man->entries, man->n, sizeof(ManifestEntry), cmp3);
}

void man_uniq_by_id(Manifest *man)
{
    /* uniq'ify manifest. */
    int i, j;
    for (i = j = 0; i < man->n; ++i) {

        ManifestEntry *a = &man->entries[i];
        if (i == 0 || a->file_id != man->entries[j - 1].file_id) {
            man->entries[j++] = *a;
        }
    }
    man->n = j;
}

void man_uniq_by_name(Manifest *man)
{
    /* uniq'ify manifest. */
    int i, j;
    for (i = j = 0; i < man->n; ++i) {

        ManifestEntry *a = &man->entries[i];
        if (i == 0 || wcscmp(a->name, man->entries[j - 1].name) != 0) {
            man->entries[j++] = *a;
        }
    }
    man->n = j;
}

void man_uniq_by_name_and_action(Manifest *man)
{
    /* uniq'ify manifest. */
    int i, j;
    for (i = j = 0; i < man->n; ++i) {

        ManifestEntry *a = &man->entries[i];
        if (i == 0 || wcscmp(a->name, man->entries[j - 1].name) != 0
                   || a->action != man->entries[j - 1].action) {
            man->entries[j++] = *a;
        }
    }
    man->n = j;
}

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
        *d++ = towlower(c);
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

/* Join two strings and place the result in buf, observing MAX_PATH_LEN, and
 * null-terminating the result. Exit with err() if the result would be longer
 * than MAX_PATH_LEN - 1. */
static inline
wchar_t *path_join(wchar_t *buf, const wchar_t *a, const wchar_t *b)
{
    const wchar_t *srcs[] = {a, b, NULL};
    const wchar_t **src = srcs;
    wchar_t *dst = buf;
    wchar_t *end = buf + MAX_PATH_LEN;

    while (*src && dst != end) {
        wchar_t c = *src[0]++;
        if (c) {
            *dst++ = c;
        } else {
            ++src;
        }
    }

    if (dst == end) {
        errx(1, "path too long: '%ls' + '%ls'", a, b);
    } else {
        *dst = 0;
        return buf;
    }
}

/* path_join is only supposed to get called with MAX_PATH_LEN output buffers. */
#define path_join(__a, __b, __c) \
    do {assert(sizeof((__a))/sizeof(wchar_t) == MAX_PATH_LEN); \
        path_join((__a), (__b), (__c)); } \
    while(0);

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

int read_manifest(FILE *f, VarList *vars, Manifest *suffix)
{
    char fn[MAX_PATH_LEN];
    int line = 1;

    printf("reading manifest\n");
    for (line = 1; fgets(fn, sizeof(fn), f); ++line) {
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
            m = man_push(suffix);
            m->action = MAN_EXCLUDE;
            for (c = fn + 1; *c; ++c) {
                if (*c == ':') {
                    *c = '\0';
                    colon = 1;
                    break;
                }
            }
            m->name = wide(fn + 1);
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
            switch (fn[0]) {
                case '+':
                    action = MAN_COPY;
                    break;
                case '-':
                    action = MAN_EXCLUDE;
                    break;
                case '!':
                    action = MAN_FORCE_COPY;
                    break;
                case '*':
                    action = MAN_SHALLOW;
                    break;
                case '&':
                    action = MAN_HARDLINK_SHALLOW;
                    break;
                default:
                    errx(1, "unhandled : %s, line %d\n", fn, line);
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
                    m = man_push(var->man);
                    m->name = wide(c);
                    normalize_string(m->name);
                    m->name_len = wcslen(m->name);
                    m->action = action;
                    if (right) {
                        m->rewrite = wide(right);
                        //printf("in manifest [%S] ==> [%S]\n", m->name, m->rewrite);
                    }
                }
            }
            if (!ok) {
                errx(1, "unable to parse prefix entry '%s' on line %d.\n", fn, line);
            }
        }
    }

    return 0;
}

ManifestEntry *find_by_name(Manifest *man, const wchar_t *fn)
{
    int half;
    ManifestEntry *middle;
    ManifestEntry *first = man->entries;
    int len = man->n;
    while (len > 0) {
        half = len >> 1;
        middle = first + half;
        if (wcscmp(middle->name, fn) < 0) {
            first = middle + 1;
            len = len - half - 1;
        } else
            len = half;
    }
    if (first == &man->entries[man->n] || wcscmp(first->name, fn)) {
        return NULL;
    } else {
        return first;
    }
}

ManifestEntry *find_by_prefix(Manifest *man, const wchar_t *fn)
{
    int i;
    ManifestEntry *match = NULL;

    for (i = 0; i < man->n; ++i) {

        ManifestEntry *e = &man->entries[i];

        if (!wcsncmp(fn, e->name, e->name_len) &&
                (!match || e->name_len > match->name_len)) {
            match = e;
        }
    }
    return match;
}

ManifestEntry *find_by_suffix(Manifest *man, const wchar_t *fn)
{
    int i;
    size_t fn_len = wcslen(fn);
    ManifestEntry *match = NULL;

    for (i = 0; i < man->n; ++i) {

        ManifestEntry *e = &man->entries[i];

        if (fn_len >= e->name_len &&
                (!e->name_len || fn[fn_len - (1 + e->name_len)] == L'.') &&
                !wcsncmp(fn + fn_len - e->name_len, e->name, e->name_len) &&
                (!match || e->name_len > match->name_len)) {
            match = e;
        }
    }
    return match;
}

int disklib_mkdir_simple(ntfs_fs_t fs, const wchar_t *path);

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

HANDLE open_file_from_id(HANDLE volume, uint64_t file_id, DWORD flags)
{
    HANDLE h;
    IO_STATUS_BLOCK iosb = {{0}};
    OBJECT_ATTRIBUTES oa = {sizeof(oa), 0};
    UNICODE_STRING name;
    name.Buffer = (PWSTR)&file_id;
    name.Length = name.MaximumLength = sizeof(file_id);
    oa.ObjectName = &name;
    oa.RootDirectory = volume;

    NTSTATUS rc = NtCreateFile(
            &h,
            flags,
            &oa,
            &iosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL
            | FILE_ATTRIBUTE_HIDDEN
            | FILE_ATTRIBUTE_SYSTEM
            | FILE_SEQUENTIAL_ONLY,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_OPEN_BY_FILE_ID | FILE_OPEN_FOR_BACKUP_INTENT | FILE_NON_DIRECTORY_FILE,
            NULL,
            0
            );
    if (rc) {
        printf("rc %x for file_id %"PRIx64"\n", (uint32_t) rc, (uint64_t) file_id);
        h = INVALID_HANDLE_VALUE;
    }
    return h;
}

int stat_file(HANDLE volume, uint64_t file_id, uint64_t *file_size, uint64_t *offset,
        Action *action)
{
    STARTING_VCN_INPUT_BUFFER in;
    BY_HANDLE_FILE_INFORMATION inf;
    RETRIEVAL_POINTERS_BUFFER retr;
    DWORD bytes;

    HANDLE h = open_file_from_id(volume, file_id, FILE_READ_ATTRIBUTES);
    if (h == INVALID_HANDLE_VALUE || h == 0) {
        return -1;
    }

    if (!GetFileInformationByHandle(h, &inf)) {
        NtClose(h);
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

    NtClose(h);
    return 0;
}

/* Breadth-first search directory scan. This is faster than DFS due to better
 * access locality. */

int files, directories;

static inline
int path_exists(wchar_t *fn, uint64_t *file_id, uint64_t *file_size, int *is_dir)
{
    HANDLE h;
    BY_HANDLE_FILE_INFORMATION inf;
    int r = 0;
    *is_dir = 0;
    *file_id = 0;
    *file_size = 0;
    h = CreateFileW(fn, GENERIC_READ, FILE_SHARE_READ
                | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        r = 1;
        if (GetFileInformationByHandle(h, &inf)) {
            if (!(inf.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                *file_id = ((uint64_t) inf.nFileIndexHigh << 32ULL) | inf.nFileIndexLow;
                *file_size = ((uint64_t)inf.nFileSizeHigh << 32ULL) | inf.nFileSizeLow;
                *is_dir = 0;
            } else {
                *is_dir = 1;
            }
        }
        CloseHandle(h);
    }
    return r;
}

int bfs(Variable *var, Manifest *suffixes,
        Manifest *out, struct disk *disk,
        const wchar_t *dn)
{
    assert(disk->bootvol);

    int i;
    uint64_t file_id;
    uint64_t file_size = 0;
    int manifested_action;
    int action;
    const size_t info_sz = 4<<20;
    ManifestEntry *m;
    void *info_buf;
    assert(min_shallow_size >= SECTOR_SIZE);
    int heap_switch = 0;
    int is_dir;
    Heap heaps[2];

    m = find_by_prefix(var->man, dn);
    if (!m) {
        printf("unknown file [%ls:%ls]\n", var->path, dn);
        exit(1);
    }
    manifested_action = m->action;
    action = m->action;

    /* First check if this is a single file that needs to be included
     * in the output manifest by itself. */
    if (path_exists(prefix(var, dn), &file_id, &file_size, &is_dir)) {
        if (!is_dir) {
            ManifestEntry *e = man_push(out);
            e->vol = disk->bootvol;
            e->var = var;
            e->name = wcsdup(dn);
            e->name_len = wcslen(e->name);
            e->file_size = file_size;
            e->file_id = file_id;
            e->rewrite = m->rewrite;
            e->action = m->action;
            if ((action == MAN_SHALLOW || action == MAN_HARDLINK_SHALLOW)
                && file_size < min_shallow_size) {
                e->action = MAN_COPY;
            }
            //printf("1.Adding entry [%S]=[%d]=>[%S]\n", e->name, e->action, (e->rewrite ? e->rewrite : L"NULL"));
            return 0;
        } else {
            /* The manifest should use trailing slashes for all dirs, complain if not. */
            if (dn[wcslen(dn) - 1] != L'/') {
                //printf("warning: [%ls] is a directory!\n", dn);
            }
        }
    } else {
        /* We do not like overly broad manifests, so complain about things not found. */
        printf("warning: file not found! [%ls:%ls]\n", var->path, dn);
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
    HeapElem he = {wcsdup(dn), 0, m->rewrite};
    //printf("1.pushing [%S], [%S]\n", he.name, (he.rerooted_name ? he.rerooted_name : L"NULL"));

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
                    FILE_ID_BOTH_DIR_INFO *info = (FILE_ID_BOTH_DIR_INFO*)
                        ((uint8_t*) info_buf + sum);

                    done = (info->NextEntryOffset == 0);
                    sum += info->NextEntryOffset;

                    wchar_t full_name[MAX_PATH_LEN] = L"";
                    wchar_t rerooted_full_name[MAX_PATH_LEN] = L"";
                    wchar_t fn[MAX_PATH_LEN] = L"";
                    memcpy(fn, info->FileName, info->FileNameLength);
                    fn[info->FileNameLength / sizeof(wchar_t)] = L'\0';
                    DWORD attr = info->FileAttributes;

                    if (!wcscmp(fn, L".") || !wcscmp(fn, L"..")) {
                        continue;
                    }

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

                    } else if ((attr & FILE_ATTRIBUTE_REPARSE_POINT) ==
                            FILE_ATTRIBUTE_REPARSE_POINT) {
                        printf("warning: %ls: unsupported reparse point!\n", full_name);
                        continue;
                    } else {
                        /* Check if we should exclude the file based on extension and size. */
                        ManifestEntry *s = find_by_suffix(suffixes, fn);
                        if (s && file_size >= s->file_size) {
                            printf("info: excluding file by suffix and size: %ls (%"PRIu64" bytes)\n",
                                    full_name, file_size);
                            continue;
                        }
                        if ((action == MAN_SHALLOW || action == MAN_HARDLINK_SHALLOW)
                                && file_size < min_shallow_size) {
                            action = MAN_COPY;
                        }
                    }

                    /* Getting to here we found a file that we want to include in the output manifest. */
                    ManifestEntry *e = man_push(out);
                    e->vol = disk->bootvol;
                    e->action = action;
                    e->var = var;
                    e->rewrite = NULL;
                    if (rerooted_full_name[0] != L'\0') {
                        e->rewrite = wcsdup(rerooted_full_name);
                    }
                    e->name = wcsdup(full_name);
                    e->name_len = wcslen(e->name);
                    e->file_size = file_size;
                    e->file_id = file_id;
                    //printf("2.Adding entry [%S]=[%d]=>[%S]\n", e->name, e->action, (e->rewrite ? e->rewrite : L"NULL"));

                } while (!done);
            }
            CloseHandle(dir);
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

#define MAX_IOS 256
typedef struct IO {
    HANDLE file;
    ntfs_fs_t vol;
    const wchar_t *name;
    void *buffer; // non-NULL if slot in use
    uint64_t size;
    uint64_t offset;
    HANDLE event;
    IO_STATUS_BLOCK iosb;
    int last;
} IO;

IO ios[MAX_IOS];
int io_idx = 0;

void complete_io(IO* io)
{
    if (WaitForSingleObject(io->event, INFINITE) != WAIT_OBJECT_0) {
        printf("io wait failed %u\n", (uint32_t) GetLastError());
        exit(1);
    }

    if (disklib_write_simple(io->vol, io->name, io->buffer, io->size,
                io->offset, 0) < io->size) {
        printf("ntfs write error: %s\n", strerror(ntfs_get_errno()));
        exit(1);
    }

    if (io->last) {
        NtClose(io->file);
        io->file = INVALID_HANDLE_VALUE;
    }

    free(io->buffer);
    io->buffer = NULL;
    ResetEvent(io->event);
}

void complete_all_ios(void)
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

static int copy_file(ntfs_fs_t vol, const wchar_t *path, HANDLE input, uint64_t size)
{
    size_t buf_size = (low_priority ? 1 : 4) << 20;
    uint64_t offset;
    uint64_t take;

    if (size == 0) {
        /* Special-case empty files. */
        return disklib_write_simple(vol, path, NULL, 0, 0, 0);
    }

    for (offset = 0; size; size -= take, offset += take) {
        int idx = (io_idx++) % MAX_IOS;
        IO *io = &ios[idx];

        take = size < buf_size ? size : buf_size;

        if (io->buffer) {
            complete_io(io);
        }

        io->file = input;
        io->vol = vol;
        io->name = path;
        io->size = take;
        io->offset = offset;

        assert(!io->buffer);
        io->buffer = malloc(take);
        io->last = (size == take);
        assert(io->buffer);

        LARGE_INTEGER o;
        o.QuadPart = offset;
        memset(&io->iosb, 0, sizeof(io->iosb));

        ULONG rc = NtReadFile(input, io->event, NULL, NULL, &io->iosb, io->buffer, take, &o, NULL);
        if (rc && rc != 0x103) {
            printf("rc %x for handle %p\n", (uint32_t) rc, input);
            exit(1);
        }
    }

    return 0;
}

static int shallow_file(ntfs_fs_t fs,
        const wchar_t *vm_path,
        const wchar_t *host_path,
        uint64_t size,
        uint64_t file_id)
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

    for (offset = 0; ; size -= take, offset += take) {
        take = size < buf_size ? size : buf_size;
        char *u = utf8(host_path);
        set_current_filename(u, offset, file_id);

        if (disklib_write_simple(fs, vm_path, buf, take, offset, 1) < take) {
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

    NtCreateFile = (pNtCreateFile)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtCreateFile");
    assert(NtCreateFile);
    NtClose = (pNtClose)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtClose");
    assert(NtClose);
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

static double t0;
#define ENTER_PHASE() do { t0 = rtc(); \
    printf("\nenter %s\n", __FUNCTION__); \
} while (0);

#define LEAVE_PHASE() do { printf("%s took %.2fs\n", __FUNCTION__, rtc() - t0); } while (0);

int scanning_phase(struct disk *disk, VarList *vars,
        Manifest *suffixes, Manifest *man_out)
{
    ENTER_PHASE();
    int i, r;
    for (i = 0; i < vars->n; ++i) {
        int j;
        Variable *var = &vars->entries[i];
        if (!var->path) {
            printf("ignoring manifest entries under ${%ls}\n", var->name);
            continue; /* command-line argument -sPATH= so we ignore this variable */
        }
        Manifest *man = var->man;
        var->volume = CreateFileW(prefix(var, L""), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (var->volume == INVALID_HANDLE_VALUE) {
            printf("Failed while processing [%ls], err=%u\n", var->path,
                    (uint32_t) GetLastError());
            return -1;
        }

        for (j = 0; j < man->n; ++j) {
            ManifestEntry *m = &man->entries[j];
            if (!shallow_allowed && (m->action == MAN_SHALLOW)) {
                m->action = MAN_FORCE_COPY;
            }
            switch (m->action) {
                case MAN_SHALLOW:
                case MAN_HARDLINK_SHALLOW:
                case MAN_COPY:
                case MAN_FORCE_COPY:
                    r = bfs(var, suffixes, man_out, disk, m->name);
                    if (r < 0) {
                        printf("Failed while processing [%ls] : [%d]\n", m->name, r);
                        return r;
                    }
                    break;
                default:
                    break;
            }
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

int stat_files_phase(struct disk *disk, Manifest *suffixes, Manifest *man, wchar_t *file_id_list)
{
    ENTER_PHASE();
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

        if (action == MAN_COPY || action == MAN_SHALLOW
                || action == MAN_HARDLINK_SHALLOW) {

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

            /* Only stat files we want to copy (leave out ACL checking for now, this
             * will be a command line option. */
            if (action == MAN_COPY || action == MAN_FORCE_COPY) {
                Action old_action = m->action;
                if (stat_file(m->var->volume, m->file_id, &m->file_size, &m->offset,
                            &m->action) < 0) {
                    printf("skipping file %ls (err=%u)\n", m->name,
                            (uint32_t) GetLastError());
                    m->action = MAN_EXCLUDE;
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
    int i;

    for (i = 0; i < man->n; ++i) {
        ManifestEntry *m = &man->entries[i];

        if (m->action == MAN_MKDIR) {
            //printf("mkdir [%ls]\n", m->name);
            if (disklib_mkdir_simple(m->vol, m->name) < 0) {
                printf("unable to mkdir %ls : %s\n", m->name,
                        strerror(ntfs_get_errno()));
                return -1;
            }
        }
    }
    LEAVE_PHASE();
    return 0;
}

#define SHA1FMT "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"

int hardlinks_phase(struct disk *disk, Manifest *man, wchar_t *hardlinks)
{
    ENTER_PHASE();

    SHA1_CTX ctx;
    uint8_t md[SHA1_DIGEST_SIZE];
    wchar_t source[MAX_PATH_LEN];
    wchar_t bromiumlink[MAX_PATH_LEN];
    int i;

    if (!CreateDirectoryW(hardlinks, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        printf("unable to create hardlinks directory %ls!\n", hardlinks);
        exit(1);
    }

    for (i = 0; i < man->n; ++i) {
        ManifestEntry *m = &man->entries[i];

        if (m->action == MAN_HARDLINK_SHALLOW) {

            /* Take sha1() on UTF-8 converted name, to be compatible
             * with img-ntfscp. */
            char *u = utf8(m->name);
            SHA1_Init(&ctx);
            SHA1_Update(&ctx, (uint8_t*)u, strlen(u));
            SHA1_Final(&ctx, md);
            free(u);

            swprintf(bromiumlink, L"%lc:%ls/"SHA1FMT"", rootdrive, hardlinks + 2,
                    md[0], md[1], md[2], md[3], md[4],
                    md[5], md[6], md[7], md[8], md[9],
                    md[10], md[11], md[12], md[13], md[14],
                    md[15], md[16], md[17], md[18], md[19]);
            swprintf(source, L"%c:%s", rootdrive, m->name);

            if (CreateHardLinkW(bromiumlink, source, NULL)
                    || GetLastError() == ERROR_ALREADY_EXISTS) {
                m->host_name = wcsdup(bromiumlink + 2); // will add rootdrive later
                assert(m->host_name);

            } else {
                /* If we cannot hardlink we'll just have to copy instead. */
                //printf("unable to hardlink %ls -> %ls : %u\n", bromiumlink, source,
                        //(uint32_t) GetLastError());
                m->action = MAN_COPY;
            }
        }
    }

    LEAVE_PHASE();
    return 0;
}

int rewire_phase(struct disk *disk, Manifest *man)
{
    ENTER_PHASE();

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
        m->host_name = m->name;
        m->name = wcsdup(cookedpath);
        m->name_len = wcslen(cookedpath);
    }

    for (i = 0; i < man->n; ++i) {
        ManifestEntry *m = &man->entries[i];
        if (m->rewrite) {
            wchar_t fn[MAX_PATH_LEN];
            m->host_name = m->name;
            path_join(fn, m->rewrite, L"");
            m->name = wcsdup(fn);
            printf("mapping [%S] =[%d]=>[%S]\n", m->host_name, m->action, m->name);
        }
    }
    LEAVE_PHASE();
    return 0;
}

int vm_links_phase_1(struct disk *disk, Manifest *man)
{
    ENTER_PHASE();

    int i;
    ManifestEntry *last = NULL;
    int q = 0;
    for (i = 0; i < man->n; ++i) {
        ManifestEntry *m = &man->entries[i];

        if (last && m->link_id && is_same_file(m, last)) {
            /* We cannot link files that we moved to /boot on sysvol. */
            if (last->action != MAN_BOOT) {
                m->host_name = last->name;
                m->action = MAN_LINK;
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

    int i;
    for (i = 0; i < man->n; ++i) {
        ManifestEntry *m = &man->entries[i];
        if (m->action == MAN_LINK) {
            if (disklib_mklink_simple(m->vol, m->host_name, m->name) < 0) {
                printf("link failed : linkid=%"PRIx64" target=%ls link=%ls\n",
                        m->link_id,
                        m->host_name, m->name);
                return -1;
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

/*
 * Data used by the acl_phase.
*/
static PSID builtin_users = NULL;
static PSID everyone = NULL;

#define MAX_CACHED 512
typedef struct {
    ACL *acl;
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

static int acl_file(HANDLE h, Action *action, int *acls_broken, int *hit)
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
        PACL acl = NULL;
        PSECURITY_DESCRIPTOR sec = NULL;
        DWORD rc;

        rc = GetSecurityInfo(h, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                    NULL, NULL, &acl, NULL, &sec);
        if (rc != ERROR_SUCCESS || !acl) {
            printf("GetSecurityInfo failed: [%u]. Handle = [%p]\n",
                (uint32_t)rc, h);
            ret = -1;
            goto sec_error;
        }

        for (i = 0; i < cache_size; ++i) {
            if (__sync_bool_compare_and_swap(&cached_acls[i].valid, 1, 1)) {
                if (cached_acls[i].acl && acl_equal(cached_acls[i].acl, acl)) {
                    *hit = 1;
                    readable = cached_acls[i].readable;
                    break;
                }
            }
        }

        if (!*hit) { /* ACL not found in cache. */
            int rc = read_allowed(acl, &readable);
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
                cached_acls[index].acl = malloc(acl->AclSize);
                assert(cached_acls[index].acl); // XXX error handling
                memcpy(cached_acls[index].acl, acl, acl->AclSize);
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
        LocalFree(sec);
sec_error:

        if (!readable) {
            *action = MAN_CHANGE;
        }
    }

    return ret;
}

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

        h = open_file_from_id(m->var->volume, m->file_id, READ_CONTROL);
        if (h == INVALID_HANDLE_VALUE || h == 0) {
            printf("Unable to open file %ls (err=%u)\n", m->name,
                    (int)GetLastError());
            m->action = MAN_EXCLUDE;
            continue;
        }

        hit = 0;
        if (acl_file(h, &m->action, &acls_broken, &hit) < 0) {
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

        NtClose(h);
    }
    return 0;
}

int acl_phase(struct disk *disk, Manifest *man)
{
    assert(shallow_allowed);
    ENTER_PHASE();

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
            char *cfilename = utf8(man->entries[i].name);
            assert(cfilename);
            printf("Degraded [%s] to force-copy\n", cfilename);
            if (disklib_ntfs_unlink(man->entries[i].vol, cfilename) < 0) {
                //printf("Unable to unlink [%s]\n", cfilename);
            }
            free(cfilename);
            man->entries[i].action = MAN_FORCE_COPY;
        }
    }

    printf("Cache hits = [%d], misses = [%d]\n", cache_hits, cache_misses);
    printf("Number of files that will be force-copied due to acls_phase = [%d]\n",
        num_copies);

cleanup:
    LEAVE_PHASE();
    return ret;
}

int shallow_phase(struct disk *disk, Manifest *man, wchar_t *map_idx)
{
    assert(shallow_allowed);
    ENTER_PHASE();

    int i, j;
    FILE *map_file;
    uint64_t total_size_shallowed = 0;

    for (i = j = 0; i < man->n; ++i) {
        ManifestEntry *m = &man->entries[i];

        if (m->action == MAN_SHALLOW || m->action == MAN_HARDLINK_SHALLOW || m->action == MAN_BOOT) {
            //printf("%d,%d shallow %ls @ %"PRIx64"\n", i, man->n, m->name, m->offset);
            wchar_t host_name[MAX_PATH_LEN];
            swprintf(host_name, L"%lc:%ls", rootdrive,
                    m->host_name ? m->host_name : m->name);
            shallow_file(m->vol, m->name, host_name, m->file_size, m->file_id);
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

int copy_phase(struct disk *disk, Manifest *man)
{
    ENTER_PHASE();

    int i, j;
    memset(ios, 0, sizeof(ios));
    int q = 0;
    const int max_opens = 4096; // windows supports 10k open file handles
    HANDLE h;
    HANDLE handles[max_opens];
    int base = 0;
    uint64_t total_size_copied = 0;
    uint64_t total_size_force_copied = 0;

    for (i = 0; i < MAX_IOS; ++i) {
        IO *io = &ios[i];
        io->event = CreateEvent(NULL, TRUE, TRUE, NULL);
        assert(io->event);
    }

    for (base = 0; base < man->n; base = i) {

        double t1 = rtc();
        for (i = base, j = 0; i < man->n && j < max_opens; ++i) {
            ManifestEntry *m = &man->entries[i];
            if (m->action == MAN_COPY || m->action == MAN_FORCE_COPY) {
                assert(m->file_id);
                h = open_file_from_id(m->var->volume, m->file_id, GENERIC_READ);
                if (h == INVALID_HANDLE_VALUE) {
                    printf("failed to open %ls for copying!\n", m->name);
                }
                handles[j++] = h;
            }
        }
        printf("%d opens took %.2fs\n", j, rtc() - t1);

        for (i = base, j = 0; i < man->n && j < max_opens; ++i) {
            ManifestEntry *m = &man->entries[i];
            if (m->action == MAN_COPY || m->action == MAN_FORCE_COPY) {
                if (m->action == MAN_FORCE_COPY) {
                    /* Currently only some files are changed to a MAN_FORCE_COPY. If
                       that behavior changes, remove the log statement.
                    */
                    printf("Force-copying [%ls] of size [%"PRIu64"]\n",
                        man->entries[i].host_name ?
                            man->entries[i].host_name : man->entries[i].name,
                        man->entries[i].file_size);
                }
                HANDLE h = handles[j++];
                if (h != INVALID_HANDLE_VALUE) {
                    copy_file(m->vol, m->name, h, m->file_size);
                    total_size_copied += m->file_size;
                    if (m->action == MAN_FORCE_COPY) {
                        total_size_force_copied += m->file_size;
                    }
                    ++q;
                } else {
                    err(1, "could not open %ls\n", m->name);
                }
            }
        }

    }
    complete_all_ios();
    printf("copied %d files, %"PRIu64" bytes\n", q, total_size_copied);
    printf("force-copied files total size: %"PRIu64" bytes\n", total_size_force_copied);
    LEAVE_PHASE();
    return 0;
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

    printf("Successfully sent start message to CoW filter");

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

int get_next_usn(HANDLE drive, USN *usn, uint64_t *journal)
{
    int win32_error = ERROR_SUCCESS;
    assert(usn);
    assert(drive != INVALID_HANDLE_VALUE);

    USN_JOURNAL_DATA journal_entry = {0};
    DWORD count = 0;
    if (!DeviceIoControl(drive, FSCTL_QUERY_USN_JOURNAL,
            NULL, 0, &journal_entry, sizeof(journal_entry), &count, NULL)) {
        win32_error = GetLastError();
        printf("Failed to get journal record: %d\n", win32_error);
        return -1;
    }

    *usn = journal_entry.NextUsn;
    if (journal) {
        *journal = journal_entry.UsnJournalID;
    }
    printf("USN = [0x%"PRIx64"]\n", (uint64_t)*usn);

    if (win32_error != ERROR_SUCCESS) {
        return -1;
    }

    return 0;
}

int usn_phase(
    HANDLE drive, USN start_usn, USN end_usn,
    uint64_t journal, Manifest *man)
{
    ENTER_PHASE();

    int win32_error = ERROR_SUCCESS;
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
            win32_error = GetLastError();
            printf( "Read journal failed (%d)\n", win32_error);
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

    /* Do a basic inner-join based on file-id.  */
    int i;
    int num_copies = 0;
    for (i = 0; i < man->n && !heap_empty(&changed_fileids);) {
        HeapElem *he = &changed_fileids.elems[0];
        if (he->file_id < man->entries[i].file_id) {
            heap_pop(&changed_fileids);
        } else if (man->entries[i].file_id < he->file_id) {
            ++i;
        } else {
            wchar_t *filename = man->entries[i].host_name ?
                man->entries[i].host_name : man->entries[i].name;
            printf("File [%ls] is changed! Will examine it.\n",
                filename);

            if (man->entries[i].action == MAN_SHALLOW) {
                char *cfilename = utf8(man->entries[i].name);
                assert(cfilename);

                printf("Deleting [%ls] from target\n", filename);
                if (disklib_ntfs_unlink(man->entries[i].vol, cfilename) < 0) {
                    printf("Unable to unlink [%s]\n", cfilename);
                    free(cfilename);
                    return -1;
                }
                free(cfilename);

                printf("Going to force-copy [%ls]\n", filename);
                man->entries[i].action = MAN_FORCE_COPY;
                num_copies ++;
            }

            heap_pop(&changed_fileids);
            ++i;
        }
    }

    printf("Number of files that will be force-copied = [%d]\n", num_copies);

    LEAVE_PHASE();

    if (win32_error != ERROR_SUCCESS) {
        return -1;
    }

    return 0;
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
            wchar_t *filename = man->entries[i].host_name ?
                man->entries[i].host_name : man->entries[i].name;
            printf("File [%ls] is open! Will examine it.\n",
                filename);

            if (man->entries[i].action == MAN_SHALLOW) {
                char *cfilename = utf8(man->entries[i].name);
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

void print_usage(void)
{
    printf("usage: %s [-sbootvol=shadow-path] manifest image.swap " \
        "[USN=<USN record-id in hex>] [GUID=<CoW driver GUID>] " \
        "[PARTITION=<partition number in decimal>] " \
        "[MINSHALLOW=<minimum shallowing size in decimal bytes>]\n",
            getprogname());
}

#define NUMBER_OF(x)        (sizeof((x))/sizeof((x)[0]) - 1)
#define ARG_USN             "USN="
#define ARG_GUID            "GUID="
#define ARG_PARTITION       "PARTITION="
#define ARG_MINSHALLOW      "MINSHALLOW="
#define ARG_USN_SIZE        NUMBER_OF(ARG_USN)
#define ARG_GUID_SIZE       NUMBER_OF(ARG_GUID)
#define ARG_PARTITION_SIZE  NUMBER_OF(ARG_PARTITION)
#define ARG_MINSHALLOW_SIZE NUMBER_OF(ARG_MINSHALLOW)

int main(int argc, char **argv)
{
    int i;
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

    /* Handle -s switches for setting for defining variables. */
    while (strncmp(argv[1], "-s", 2) == 0) {
        char *v = argv[1] + 2;
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

        ++argv;
        --argc;
    }

    char *arg_manifest_file = argv[1];
    char *arg_swap_file = argv[2];

    char *arg_usn = NULL;
    char *arg_guid = NULL;
    char *arg_partition = NULL;
    char *arg_minshallow = NULL;

    while (argc >= 4) {
        if (strncmp(argv[3], ARG_USN, ARG_USN_SIZE) == 0) {
            arg_usn = argv[3];
            arg_usn += ARG_USN_SIZE;
        } else if (strncmp(argv[3], ARG_GUID, ARG_GUID_SIZE) == 0) {
            arg_guid = argv[3];
            arg_guid += ARG_GUID_SIZE;
        } else if (strncmp(argv[3], ARG_PARTITION, ARG_PARTITION_SIZE) == 0) {
            arg_partition = argv[3];
            arg_partition += ARG_PARTITION_SIZE;
        } else if (strncmp(argv[3], ARG_MINSHALLOW, ARG_MINSHALLOW_SIZE) == 0) {
            arg_minshallow = argv[3];
            arg_minshallow += ARG_MINSHALLOW_SIZE;
        } else {
            print_usage();
            exit(1);
        }
        ++argv;
        --argc;
    }

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
    }
    if (!disk_open(arg_swap_file, 1, &disk, 0, partition)) {
        printf("Unable to open disk:partition [%s:%d]\n",
            arg_swap_file, partition);
        exit(1);
    }

    USN start_usn = 0ULL;
    if (shallow_allowed) {
        if (arg_usn) {
            start_usn = strtoull(arg_usn, NULL, 0);
            if (start_usn == ULLONG_MAX) {
                printf("Invalid value for USN record: %s\n", arg_usn);
                print_usage();
                exit(1);
            }
        }
    }

    /* Find out drive letter of system drive, for use in shallow map. */
    wchar_t *systemroot;
    systemroot = _wgetenv(L"SystemDrive");
    if (systemroot && systemroot[1] == L':') {
        rootdrive = systemroot[0];
    }

    /* Find out where to place hardlinks folder, relative to output (.swap)
     * image. */
    wchar_t hardlinks[MAX_PATH_LEN];
    wchar_t *location = _wfullpath(NULL, wide(arg_swap_file), 0);
    normalize_string(location);
    strip_filename(location);
    path_join(hardlinks, location, L"/swapdata/hardlinks");
    printf("placing hardlinks under %ls\n", hardlinks);

    wchar_t map_idx[MAX_PATH_LEN] = L"";
    wchar_t file_id_list[MAX_PATH_LEN] = L"";
    wchar_t cow_dir[MAX_PATH_LEN] = L"";

    if (shallow_allowed) {
        path_join(map_idx, location, L"/swapdata/map.idx");
        path_join(file_id_list, location, L"/swapdata/fileidlist.idx");
        path_join(cow_dir, location, L"/swapdata/cow");

        if (!CreateDirectoryW(cow_dir, NULL)
            && (GetLastError() != ERROR_ALREADY_EXISTS)) {
            printf("unable to create CoW directory %ls!\n", cow_dir);
            exit(1);
        }
    }

    /* Read and parse user-supplied manifest. */
    read_manifest(manifest_file, &vars, &suffixes);

    for (i = 0; i < vars.n; ++i) {
        Manifest *man = vars.entries[i].man;
        man_sort_by_name(man);
        man_uniq_by_name_and_action(man);
    }

    man_sort_by_name(&suffixes);
    man_uniq_by_name_and_action(&suffixes);

    HANDLE drive = INVALID_HANDLE_VALUE;
    if (shallow_allowed) {
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

        if (!arg_usn) {
            if (get_next_usn(drive, &start_usn, NULL) < 0) {
                err(1, "Unable to record starting USN entry\n");
            }
        }
    }

    /* Scan directories on host. */
    if (scanning_phase(&disk, &vars, &suffixes, &man_out) < 0) {
        err(1, "scanning_phase failed");
    }

    /* Stat all files individually. */
    man_sort_by_id(&man_out);
    if (stat_files_phase(&disk, &suffixes, &man_out, file_id_list) < 0) {
        err(1, "stat_files_phase failed");
    }

    GUID guid = {0};
    if (shallow_allowed) {
        if (arg_guid) {
            if (local_uuid_parse(arg_guid, &guid) < 0) {
                err(1, "Error in parsing guid [%s]", arg_guid);
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

    if (mkdir_phase(&disk, &man_out) < 0) {
        err(1, "mkdir_phase failed");
    }

    if (hardlinks_phase(&disk, &man_out, hardlinks) < 0) {
        err(1, "hardlinks_phase failed");
    }

    /* Copy/shallow phase. */
    printf("copy + shallow %d files\n", man_out.n);

    man_sort_by_offset(&man_out);

    if (vm_links_phase_1(&disk, &man_out) < 0) {
        err(1, "vm_links_phase_1 failed");
    }

    if (shallow_allowed) {
        man_sort_by_id(&man_out);

        if (acl_phase(&disk, &man_out) < 0) {
            err(1, "acl_phase failed");
        }

        if (shallow_phase(&disk, &man_out, map_idx) < 0) {
            err(1, "shallow_phase failed");
        }

        /* Read the USN journal again and consume the set. */
        USN end_usn;
        uint64_t journal;
        if (get_next_usn(drive, &end_usn, &journal) < 0) {
            err(1, "Unable to record ending USN entry\n");
        }

        if (usn_phase(drive, start_usn, end_usn, journal, &man_out) < 0) {
            err(1, "usn_phase failed\n");
        }

        if (drive != INVALID_HANDLE_VALUE) {
            CloseHandle(drive);
            drive = INVALID_HANDLE_VALUE;
        }

        if (open_handles_phase(&man_out) < 0) {
            err(1, "open_handles_phase failed\n");
        }
    }

    man_sort_by_offset(&man_out);
    if (copy_phase(&disk, &man_out) < 0) {
        err(1, "copy_phase failed");
    }

    if (vm_links_phase_2(&disk, &man_out) < 0) {
        err(1, "vm_links_phase_2 failed");
    }

    if (flush_phase(&disk) < 0) {
        err(1, "flush_phase failed");
    }

    printf("done. exit.\n");

    return r;
}
