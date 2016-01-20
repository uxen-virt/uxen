/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "disklib.h"
#include "partition.h"
#include "disklib-internal.h"

#include <windows.h>
#include <assert.h>

#define STACK_SEP ';'

#ifdef _WIN32
char *utf8(const wchar_t* ws)
{
    /* First figure out buffer size needed and malloc it. */
    int sz;
    char *s;
    
    sz = WideCharToMultiByte( CP_UTF8, 0, ws, -1, NULL, 0, NULL, 0);
    s = (char*) malloc(sz + sizeof(char));
    if (s == NULL) return NULL;

    s[sz] = 0;
    /* Now perform the actual conversion. */
    sz = WideCharToMultiByte( CP_UTF8, 0, ws, -1, s, sz, NULL, 0);
    return s;
}

wchar_t *wide(const char *s)
{
    /* First figure out buffer size needed and malloc it. */
    int sz;
    wchar_t *ws;
    
    sz = MultiByteToWideChar( CP_UTF8, 0, s, -1, NULL, 0);
    ws = (wchar_t*) malloc(sizeof(wchar_t) * (sz + 1));

    if (s == NULL) return NULL;

    ws[sz] = 0;
    /* Now perform the actual conversion. */
    MultiByteToWideChar( CP_UTF8, 0, s, -1, ws, sz);
    return ws;
}
#else
#error "need to implement utc-16 -> utf8 conversion for this platform!"
#endif

int disklib_parse_vdpath(char *path, char ***files, size_t *count)
{
    char **f, *ptr;
    size_t cnt, i;

    if ( NULL == path || *path == '\0' ) {
        *files = NULL;
        *count = 0;
        return 1;
    }

    for(cnt = 1, ptr = path; *ptr != '\0'; ptr++) {
        if ( *ptr == STACK_SEP )
            cnt++;
    }

    f = RTMemAlloc(sizeof(*f) * cnt);
    if ( NULL == f )
        return 0;

    for(i = 1, f[0] = ptr = path; *ptr != '\0'; ptr++) {
        if ( *ptr == STACK_SEP ) {
            *ptr = '\0';
            f[i++] = ptr + 1;
        }
    }

    *files = f;
    *count = cnt;
    return 1;
}

PVBOXHDD disklib_open_vbox_image(char *path, int rw)
{
    PVBOXHDD hdd = NULL;
    size_t nfiles, i;
    char **files;
    int rc;

    if ( !disklib_parse_vdpath(path, &files, &nfiles) )
        goto err_out;

    rc = VDCreate(NULL, VDTYPE_HDD, &hdd);
    if (!RT_SUCCESS(rc))
        goto err_free;

    for(i = 0; i < nfiles; i++) {
        char *fmt;
        VDTYPE tp;

        rc = VDGetFormat(NULL, NULL, files[i], &fmt, &tp);
        if ( RT_FAILURE(rc) ) {
            RTPrintf("VDGetFormat: %s: %d\n", files[i], rc);
            goto err;
        }

        rc = VDOpen(hdd, fmt, files[i],
                    rw ? VD_OPEN_FLAGS_NORMAL : VD_OPEN_FLAGS_READ_ONLY, NULL);
        RTStrFree(fmt);
        if ( RT_FAILURE(rc) ) {
            LogAlways(("VDOpen error: %s: %d\n", files[i], rc));
            RTPrintf("VDOpen: %s: %d\n", files[i], rc);
            goto err;
        }
    }

    RTMemFree(files);
    return hdd;

err:
    VDDestroy(hdd);
err_free:
    RTMemFree(files);
err_out:
    return NULL;
}

DECLINLINE(uint64_t) parse_number(const char *c)
{
    const char *in = c;
    uint64_t n = 0;

    while (*in && *in >= '0' && *in <= '9')
    {
        n = 10 * n + (*in++ - '0');
    }
    return n;
}


/* Open a handle wrapping either a VBox disk object or our own raw version of a
 * VMDK. If not VMDK, or if write access is requested, use VBox as fallback. */

int disklib_open_image(char *path, int rw, disk_handle_t *dh)
{
    dh->vboxhandle = disklib_open_vbox_image(path, rw);
    return (dh->vboxhandle != NULL) ? 1 : 0;
}

void disklib_set_slow_flush(disk_handle_t dh)
{
    VDSetOpenFlags(dh.vboxhandle, 0, VD_OPEN_FLAGS_SEQUENTIAL);
}

/* Close a disk handle. */

void disklib_close_image(disk_handle_t dh)
{
    VDDestroy(dh.vboxhandle);
}

/* If we failed at a larger read, we will try to read individual sectors in the
 * hope of getting enough useful data to be able to continue. This is best-effort,
 * so we don't care to return any errors. */

void disk_repair_read(HANDLE handle, uint8_t *buf, uint64_t offset, size_t size)
{
    memset(buf, 0, size);

    while (size) {
        DWORD got;
        /* ok to have OVERLAPPED on stack because we wait for the result. */
        OVERLAPPED o = {0,};
        o.OffsetHigh = offset >>32ULL;
        o.Offset = offset & 0xffffffff;

        if (!ReadFile(handle, buf, SECTOR_SIZE, NULL, &o) && GetLastError() != ERROR_IO_PENDING) {
            LogAlways(("repair-reading at offset %"PRIx64" failed with error %u\n",
                        offset, (uint32_t)GetLastError()));
            return;
        }
        if (!GetOverlappedResult(handle, &o, &got, TRUE)) {
            LogAlways(("repair-read GetOverlappedResult error offset %"PRIx64" failed with error %u\n",
                        offset, (uint32_t)GetLastError()));
        }
        offset += SECTOR_SIZE;
        buf += SECTOR_SIZE;
        size -= SECTOR_SIZE;
    }
}

/* Read from an abstracted disk handle. When doing overlapped IO an OVERLAPPED
 * handle can be passed in the context parameter. We make it a void pointer to
 * prepare for the day when this code runs under a non- Windows host OS. */

int disk_read_sectors(disk_handle_t dh, void *buf,
            uint64_t sec, unsigned int num_sec, void *context)
{
    int rc = VDRead(dh.vboxhandle, SECTOR_SIZE * sec, buf, SECTOR_SIZE * num_sec);
    if (!RT_SUCCESS(rc)) {
        LogAlways(("%s: unable to read from VBox backend on line %d\n",
                    __FUNCTION__, __LINE__));
        disklib__set_errno(DISKLIB_ERR_IO);
        return 0;
    } else {
        disklib__set_errno(DISKLIB_ERR_SUCCESS);
        return 1;
    }
}

int disk_read_check_result(disk_handle_t dh, void *_o)
{
    return 1;
}

/* We wrap this here to not have to pass the vss_path around,
 * and because fs-ntfs.c has trouble including <windows.h>. */

wchar_t *g_vss_path = NULL;
int use_vss_logical_reads(void)
{
    return g_vss_path ? 1 : 0;
}

/* Call this to set the global path prefix for resolving files inside
 * a VSS snapshot. Krypton already does all the heavy lifting to resolve
 * this, so we take this as a cmdline argument, rather than try to figure
 * it out in vss.cpp. */
void set_vss_path(const wchar_t *vss_path)
{
    g_vss_path = wcsdup(vss_path);
}

/* Open a file from its normal path, but inside a VSS snapshot.
 * The \\?\GLOBALROOT prefix gets added here if configured. */
void *open_vss_logical_file(const char *path, int overlapped)
{
    /* Read logical file. */
    HANDLE h;
    wchar_t *c;
    wchar_t *wide_path = wide(path);
    wchar_t *fullpath = calloc((wcslen(g_vss_path) + wcslen(wide_path) + 1),
            sizeof(wchar_t));

    if (!fullpath) {
        free(wide_path);
        return NULL;
    }

    wcscpy(fullpath, g_vss_path);
    wcscat(fullpath, wide_path);
    for (c = fullpath; *c; ++c) {
        if (*c == L'/') {
            *c = L'\\';
        }
    }

    h = CreateFileW(fullpath, GENERIC_READ,
            FILE_SHARE_READ| FILE_SHARE_WRITE, NULL,
            OPEN_EXISTING,
            overlapped ? FILE_FLAG_OVERLAPPED : FILE_ATTRIBUTE_NORMAL,
            NULL);

    free(fullpath);
    free(wide_path);

    if (h != INVALID_HANDLE_VALUE) {
        return (void*) h;
    } else {
        return NULL;
    }
    
}

/* Read a file previously opened by open_vss_logical_file(). The caller is
 * expected to have filled out an OVERLAPPED context with the intra-file offset
 * etc. if needed. The call needs to be abstracted, like CreateFile() above,
 * because fs-ntfsc.c seems unable to include windows.h without everything else
 * falling apart. This is related to the hackery Gianni needed to perform to
 * get ntfslib linked into VBox back at the dawn of time, and may not be
 * necessary under uXen. */
int read_vss_logical_file(void *handle, void *buffer, size_t size, void *o)
{
    int r;
    DWORD got = 0;

    memset(buffer, 0, size);
    r = ReadFile((HANDLE)handle, buffer, size, o ? NULL : &got,
            (OVERLAPPED*)o);
    if (r) {
        return (int) got;
    } else if (GetLastError() != ERROR_IO_PENDING) {
        LogAlways(("%s: ReadFile fails with error %u\n", __FUNCTION__,
                    (uint32_t) GetLastError()));
    }
    return -1;
}

/* Check that an overlapped VSS logical file read completed OK. Note
 * that the VSS functions return negative for error, and 0 for success.
 * The error codes across the ntfs tools are a an inconsistent mess. */
int vss_check_result(void *file, void *_o)
{
    OVERLAPPED *o = (OVERLAPPED*) _o;
    HANDLE handle = (HANDLE) file;
    DWORD got;

    if (!GetOverlappedResult(handle, o, &got, FALSE) &&
            GetLastError() != ERROR_HANDLE_EOF) {
        LogAlways(("%s: failed getting overlapped result %u\n", __FUNCTION__,
                    (uint32_t) GetLastError()));
        disk_flag_io_error();
        return -1;
    }
    return 0;
}

void close_vss_logical_file(void *handle)
{
    CloseHandle((HANDLE) handle);
}

static const char *context_function = "";
static int context_line;
static char context_string[256] = "";

void disk_error_context0(const char *function, int line, const char *string)
{
    context_function = function;
    context_line = line;
    strncpy(context_string, string, sizeof(context_string));
}

void disk_flag_io_error0(const char *function, int line)
{
    const char *var = "NTFSCP_ERROR_LIMIT";
    static int error_count = 0;
    int tolerance = 10;

    /* You can change the error tolerance by setting an env var. */
    if (getenv(var)) {
        tolerance = atoi(getenv(var));
    }

    LogAlways(("IO error %u logged in %s:%d, context was %s:%d '%s'\n",
                (uint32_t)GetLastError(), function, line,
                context_function, context_line, context_string));

    if (error_count++ > tolerance) {
        LogAlways(("ERROR! Too many IO errors, giving up!\n"));
        exit(2);
    }

}

/* Write to an abstracted disk handle. Overlapped/async IO is currently not
 * supported, but we are hoping the backend does a decent job of buffering
 * stuff for us. */

static const char *current_filename = NULL;
static uint64_t current_file_offset = 0;
static uint64_t current_file_id = 0;

typedef struct MAPENTRY {
    uint64_t start;
    uint32_t size;
    uint32_t file_offset;
    uint64_t file_id;
    char name[0];
} MAPENTRY;

static MAPENTRY **map_entries = NULL;
static size_t num_map_entries = 0;

void set_current_filename(const char *fn, uint64_t file_offset, uint64_t file_id)
{
    current_filename = fn;
    current_file_offset = file_offset;
    current_file_id = file_id;
}

static int map_cmp(const void *a, const void *b)
{
    MAPENTRY *pa = *((MAPENTRY**) a);
    MAPENTRY *pb = *((MAPENTRY**) b);

    if (pa->start < pb->start) {
        return -1;
    } else if (pb->start < pa->start) {
        return 1;
    } else return 0;
}

/* If we have gathered a list of shallow file mappings we need to write it now.
 * To facilitate lookups in the Swap backend, we sort it by start block first.
 * */

void flush_map_to_file(void *f)
{
    if (map_entries != NULL) {

        size_t i;
        uint32_t string_offset = 0;
        qsort(map_entries, num_map_entries, sizeof(map_entries[0]), map_cmp);

        fwrite(&num_map_entries, sizeof(uint32_t), 1, f);

        for (i = 0; i < num_map_entries; ++i) {

            MAPENTRY *m = map_entries[i];
            uint32_t tuple[6];
            // the line below is buggy and needs to be fixed! m->start is 64-bits while tuples are 32 bits
            tuple[0] = m->start + m->size; /* index by END not start. */
            tuple[1] = m->size;
            tuple[2] = m->file_offset;
            tuple[3] = string_offset;

            LARGE_INTEGER file_id = *((LARGE_INTEGER*)&m->file_id);
            tuple[4] = file_id.HighPart;
            tuple[5] = file_id.LowPart;

            fwrite(tuple, sizeof(tuple), 1, f);

            string_offset += strlen(m->name) + 1;
        }

        for (i = 0; i < num_map_entries; ++i) {
            MAPENTRY *m = map_entries[i];
            fwrite(m->name, strlen(m->name) + 1, 1, f);
            RTMemFree((void*) m);
        }


        RTMemFree((void*) map_entries);
        map_entries = NULL;
        num_map_entries = 0;
    }
}

static const char magic_sector_bytes[SECTOR_SIZE] = 
    "thisIsTheSecretShallow#Stringj082q457q3846y8qnuo!!86gnbdsufgy83623q89t77sdfkjghskdhvnkjyeah.";

void fill_with_magic_bytes(char *sector)
{
    memcpy(sector, magic_sector_bytes, SECTOR_SIZE);
}

int disk_write_sectors(disk_handle_t dh, const void *buf,
            uint64_t sec, unsigned int num_sec)
{
    if (current_filename &&
        memcmp(buf, magic_sector_bytes, SECTOR_SIZE) == 0) {

        /* We keep the list of mapped files in memory, so that we can sort it
         * before writing it to the map.txt file on disk. */

        MAPENTRY *m = (MAPENTRY*) RTMemAlloc(sizeof(MAPENTRY) +
                strlen(current_filename) + 1);

        if (m == NULL) {
            LogAlways(("Out of memory for map entries!\n"));
            disklib__set_errno(DISKLIB_ERR_NOMEM);
            return 0;
        }

        uint64_t start = sec / 8;
        uint64_t end = (sec + num_sec + 7) / 8;

        m->start = start;
        m->size = end - start;
        m->file_offset  = current_file_offset / 4096;
        m->file_id = current_file_id;
        strcpy(m->name, current_filename);

        /* Is num_map_entries value a power of two? If so we must double the array. */
        if ((num_map_entries & (num_map_entries - 1)) == 0) {

            size_t n = num_map_entries ? 2 * num_map_entries : 1;
            map_entries = (MAPENTRY**) realloc(map_entries, sizeof(MAPENTRY*) * n);

            /* Check for failure of realloc, or overflow of "2 * num_map_entries" entries
             * causing n to become 0. */
            if (map_entries == NULL || n == 0) {
                errx(1, "Out of memory for map entries pointers!\n");
            }
        }

        map_entries[num_map_entries++] = m;

        current_file_offset += SECTOR_SIZE * num_sec;

        disklib__set_errno(DISKLIB_ERR_SUCCESS);
        return 1;
    }

    int rc = VDWrite(dh.vboxhandle, SECTOR_SIZE * sec, buf, SECTOR_SIZE * num_sec);
    if (!RT_SUCCESS(rc)) {
        disklib__set_errno(DISKLIB_ERR_IO);
        return 0;
    }

    disklib__set_errno(DISKLIB_ERR_SUCCESS);
    return 1;
}

/* Get disk size, either by asking VBox or by doing the math from our stored
 * CHS info. */

uint64_t disk_get_size(disk_handle_t dh)
{
    return VDGetSize(dh.vboxhandle, 0);
}
