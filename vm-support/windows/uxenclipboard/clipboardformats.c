/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <tlhelp32.h>
#include "clipboardformats.h"
#include "uxen_bmp_convert.h"
#include "hdrop.h"
#include "openclipboardretry.h"

CRITICAL_SECTION formats_critical_section; 
int uxenclipboard_init_formats_critical_section()
{
    InitializeCriticalSection(&formats_critical_section);
    return 0;
}
static void lock_formats_table()
{
    EnterCriticalSection(&formats_critical_section);
}
static void unlock_formats_table()
{
    LeaveCriticalSection(&formats_critical_section);
}

#define MAX_CLIPBOARD_FORMATS 100
#define MAX_FORMAT_NAME_LENGTH 255
#define FIRST_DYNAMIC_FORMAT 0xc000

static struct fmt_conv {
    unsigned int local;
    unsigned int remote;
    int written;
} current_available_formats[MAX_CLIPBOARD_FORMATS];
int n_formats;

#if 0
static int get_clipboard_process_name(char *name, int name_ch_sz)
{
    DWORD pid = 0;
    HWND h = GetClipboardOwner();
    HANDLE hs;
    PROCESSENTRY32 pe;

    if (!h)
        return -1;
    GetWindowThreadProcessId(h, &pid);
    if (!pid)
        return -1;
    hs = CreateToolhelp32Snapshot(TH32CS_SNAPALL, pid);
    if (!hs)
        return -1;
    pe.dwSize = sizeof(pe);
    if (!Process32First(hs, &pe)) {
        CloseHandle(hs);
        return -1;
    }
    for (;;) {
        if (pe.th32ProcessID == pid) {
            int i,l;
            CloseHandle(hs);
            strncpy(name, pe.szExeFile, name_ch_sz);
            l = strlen(name);
            for (i = 0; i < l; ++i)
                name[i] = tolower(name[i]);
            return 0;
        }
        if (!Process32Next(hs, &pe)) {
            CloseHandle(hs);
            return -1;
        }
    }
}
#endif

static void conv_from_virtual_fmt_name(wchar_t *name_buf, int buf_sz_ch)
{
}

static void conv_to_virtual_fmt_name(wchar_t* name_buf, int buf_sz_ch)
{
#if 0
    if (!wcscmp(name_buf, L"HTML Format")) {
        char process[MAX_PATH];
        if (!get_clipboard_process_name(process, MAX_PATH)) {
            /* rename HTML format if coming from word */
            if (!strcmp(process, "winword.exe"))
                wcsncpy(name_buf, L"Private HTML Format", buf_sz_ch);
        }
    }
#endif
}

/* The below tables stores all custom format names received from the guest.
We have to limit their number - if not, the guest can exhaust all the
registered formats with multiple messages. */
static wchar_t *all_received_custom_formats[MAX_CLIPBOARD_FORMATS];
int insert_all_received_custom_formats(wchar_t *name)
{
    int i = 0;
    while (all_received_custom_formats[i]) {
        if (!wcscmp(name, all_received_custom_formats[i]))
            return 1;
        i++;
    }
    if (i >= MAX_CLIPBOARD_FORMATS - 1)
        return 0;
    all_received_custom_formats[i] = wcsdup(name);
    return all_received_custom_formats[i] ? 1:0;
}

static int fetch_data(char **inbuf, char *outbuf, unsigned int len, char *src, 
unsigned int srcsize)
{
    if (len > srcsize)
        return -1;
    if (*inbuf + len > src + srcsize)
        return -1;
    memcpy(outbuf, *inbuf, len);
    *inbuf += len;
    return 0;
}
#define fetch_type(inbuf, var, data, count) \
    fetch_data(inbuf, (char*)(&var), sizeof(var), data, count)
static int store_data(char **outptr, char * inbuf, unsigned int len, char *dst,
unsigned int dstsize)
{
    if (len > dstsize)
        return -1;
    if (*outptr + len > dst + dstsize)
        return -1;
    memcpy(*outptr, inbuf, len);
    *outptr += len;
    return 0;
}
#define store_type(outptr, var, src, srcsize) \
    store_data(outptr, (char*)(&var), sizeof(var), src, srcsize)

int uxenclipboard_parse_remote_format_announce(char *data, int count)
{
    int rc = 0;
    wchar_t fmt_name[MAX_FORMAT_NAME_LENGTH + 1];
    char *current = data;
    if (count > 65536)
        return -1;
    lock_formats_table();
    n_formats = 0;

    while (current != data + count && n_formats < MAX_CLIPBOARD_FORMATS) {
        unsigned int fmt, local_fmt;
        unsigned int namelen;

        if (fetch_type(&current, fmt, data, count)) {
            rc = -2;
            break;
        }
        if (fmt < FIRST_DYNAMIC_FORMAT) {
            if (uxenclipboard_is_allowed_format(UXENCLIPBOARD_DIRECTION_IN,
                    fmt, NULL)) {
                current_available_formats[n_formats].remote = fmt;
                current_available_formats[n_formats].local = fmt;
                current_available_formats[n_formats].written = 0;
                n_formats++;
            }
            continue;
        }
        if (fetch_type(&current, namelen, data, count)) {
            rc = -3;
            break;
        }
        if (namelen > MAX_FORMAT_NAME_LENGTH) {
            rc = -4;
            break;
        }
        if (fetch_data(&current, (char*)fmt_name, sizeof(wchar_t) * namelen,
                data, count)) {
            rc = -5;
            break;
        }
        fmt_name[namelen] = 0;
        if (!uxenclipboard_is_allowed_format(UXENCLIPBOARD_DIRECTION_IN,
                fmt, fmt_name))
            continue;
        conv_from_virtual_fmt_name(fmt_name, sizeof(fmt_name)/sizeof(wchar_t));
        if (!insert_all_received_custom_formats(fmt_name)) {
            rc = -7;
            break;
        }
        local_fmt = RegisterClipboardFormatW(fmt_name);
        if (!local_fmt) {
            rc = -6;
            break;
        }
        current_available_formats[n_formats].local = local_fmt;
        current_available_formats[n_formats].remote = fmt;
        current_available_formats[n_formats].written = 0;
        n_formats++;
    }
    if (rc < 0)
        n_formats = 0;
    unlock_formats_table();

    return rc;
}

typedef BOOL (WINAPI *GetUpdatedClipboardFormats_t)(
    PUINT lpuiFormats,
    UINT cFormats,
    PUINT pcFormatsOut
);

/* mingw libuser32 lacks GetUpdatedClipboardFormats */
static int mingw_GetUpdatedClipboardFormats(PUINT lpuiFormats, UINT cFormats,
    PUINT pcFormatsOut)
{
    static GetUpdatedClipboardFormats_t real_thing;

    if (!real_thing) {
        HMODULE h = GetModuleHandle("user32.dll");
        if (!h)
            return 0;
        real_thing = (GetUpdatedClipboardFormats_t)
            GetProcAddress(h, "GetUpdatedClipboardFormats");
        if (!real_thing)
            return 0;
    }

    return real_thing(lpuiFormats, cFormats, pcFormatsOut);
}

/* mingw libuser32 lacks AddClipboardFormatListener, too */
typedef BOOL (WINAPI *AddClipboardFormatListener_t)(HWND hwnd);
BOOL WINAPI mingw_AddClipboardFormatListener(HWND hwnd)
{
    static AddClipboardFormatListener_t real_thing;

    if (!real_thing) {
        HMODULE h = GetModuleHandle("user32.dll");
        if (!h)
            return 0;
        real_thing = (AddClipboardFormatListener_t)
            GetProcAddress(h, "AddClipboardFormatListener");
        if (!real_thing)
            return 0;
    }

    return real_thing(hwnd);
}
static struct _guess_fmtname_table {
    wchar_t *ext;
    wchar_t *fmt;
} guess_fmtname_table[] = {
    {L"jpg",    L"JFIF"},
    {L"jpeg",   L"JFIF"},
    {L"jfif",   L"JFIF"},
    {L"gif",    L"GIF"},
    {L"tiff",   L"TIFF"},
    {L"png",    L"PNG"},
    {L"bmp",    L"BMP"},
    {NULL,      NULL},
};

static wchar_t *guess_fmtname_from_filename(wchar_t *filename)
{
    int i;
    wchar_t *ext = NULL;

    for (i = wcslen(filename) - 1; i >= 0; i--)
        if (filename[i] == '.') {
            ext = filename + i + 1;
            break;
        }
    if (!ext)
        return NULL;
    for (i = 0; guess_fmtname_table[i].ext; i++)
        if (!_wcsicmp(guess_fmtname_table[i].ext, ext))
            return guess_fmtname_table[i].fmt;
    return NULL;
}

static wchar_t *get_hdrop_filename(int open_done)
{
    HDROP hdrop;
    wchar_t *filename;
    unsigned int len;

    if (!open_done && !OpenClipboardWithRetry(NULL))
        return NULL;
    if (!(hdrop = GetClipboardData(CF_HDROP))) {
        if (!open_done)
            CloseClipboard();
        return NULL;
    }
    if (DragQueryFileW(hdrop, 0xFFFFFFFF, NULL, 0) != 1) {
        /* multiple files not supported */
        if (!open_done)
            CloseClipboard();
        return NULL;
    }
    len = DragQueryFileW(hdrop, 0, NULL, 0);
    filename = malloc(2 * len + 2);
    if (!filename) {
        if (!open_done)
                CloseClipboard();
        return NULL;
    }
    DragQueryFileW(hdrop, 0, filename, len + 1);
    if (!open_done)
        CloseClipboard();
    return filename;
}

/* If CF_HDROP clipboard format is available, and has only one filename,
   then try to guess by filename extension which (graphics-related) clipboard
   format we
   can present the contents of the file as. On success returns
   non-NULL format name, and the actual filename found in CF_HDROP
   in *filename parameter. */
wchar_t *uxenclipboard_get_format_from_hdrop(int clipboard_open_done,
    wchar_t **filename)
{
    wchar_t *ret;

    *filename = get_hdrop_filename(clipboard_open_done);
    if (!*filename)
        return NULL;
    ret = guess_fmtname_from_filename(*filename);
    if (!ret)
        free(*filename);
    return ret;
}

static int check_for_graphics_in_hdrop(wchar_t *fmt_name,
    unsigned int len, unsigned int *fmt)
{
    wchar_t *guessed_fmtname;
    wchar_t *filename;

    guessed_fmtname = uxenclipboard_get_format_from_hdrop(FALSE,
        &filename);
    if (!guessed_fmtname)
        return 0;
    free(filename);
    if (wcslen(guessed_fmtname) + 1 >= len)
        return 0;
    wcscpy(fmt_name, guessed_fmtname);
    *fmt = RegisterClipboardFormatW(guessed_fmtname);
    if (!fmt)
        return 0;
    return 1;
}

static int do_store_format(char **currbuf, unsigned int fmt,
    wchar_t *fmt_name, char *outbuf, unsigned int len)
{
    unsigned int fmtlen = wcslen(fmt_name);
    if (!uxenclipboard_is_allowed_format(UXENCLIPBOARD_DIRECTION_OUT,
            fmt, fmt_name))
        return 0;
    if (store_type(currbuf, fmt, outbuf, len))
        return -2;
    if (store_type(currbuf, fmtlen, outbuf, len))
        return -4;
    if (store_data(currbuf, (char*)fmt_name, 2 * fmtlen, outbuf, len))
        return -5;
    return 0;
}

int uxenclipboard_prepare_format_announce(char *outbuf, int len)
{
    wchar_t fmt_name[MAX_FORMAT_NAME_LENGTH + 1];
    unsigned int fmts[MAX_CLIPBOARD_FORMATS] = {0,};
    unsigned int synth_fmt;
    int i, fmtlen;
    unsigned int n_fmts;
    char *currbuf = outbuf;
    int ret;

    int have_cf_dib = 0;
    int have_graphics = 0;
    int have_cf_hdrop = 0;

    if (!mingw_GetUpdatedClipboardFormats((PUINT)fmts, MAX_CLIPBOARD_FORMATS,
        (PUINT)&n_fmts))
        return -1;
    for (i = 0; i < n_fmts; i++) {
        if (fmts[i] < FIRST_DYNAMIC_FORMAT) {
            if (fmts[i] == CF_HDROP)
                have_cf_hdrop = 1;
            if (!uxenclipboard_is_allowed_format(UXENCLIPBOARD_DIRECTION_OUT,
                    fmts[i], NULL))
                continue;
            if (store_type(&currbuf, fmts[i], outbuf, len))
                return -2;
            if (fmts[i] == CF_DIB)
                have_cf_dib = 1;
            continue;
        }
        /* registered formats processing */
        fmtlen = GetClipboardFormatNameW(fmts[i], fmt_name, MAX_FORMAT_NAME_LENGTH);
        if (!fmtlen)
            return -3;
        fmt_name[fmtlen] = 0;
        if (uxenclipboard_is_supported_graphics_format(fmt_name))
            have_graphics = 1;
        conv_to_virtual_fmt_name(fmt_name, sizeof(fmt_name)/sizeof(wchar_t));
        ret = do_store_format(&currbuf, fmts[i], fmt_name, outbuf, len);
        if (ret)
            return ret;
    }
    if (!have_graphics && !have_cf_dib && have_cf_hdrop &&
        check_for_graphics_in_hdrop(fmt_name, MAX_FORMAT_NAME_LENGTH, &synth_fmt)) {
        have_graphics = 1;
        ret = do_store_format(&currbuf, synth_fmt, fmt_name, outbuf, len);
        if (ret)
             return ret;
    }

    if (have_graphics && !have_cf_dib &&
        uxenclipboard_is_allowed_format(UXENCLIPBOARD_DIRECTION_OUT, CF_DIB,
            NULL)) {
        unsigned int cf_dib = CF_DIB;
        if (store_type(&currbuf, cf_dib, outbuf, len))
            return -2;
    }
    return currbuf - outbuf;
}

int uxenclipboard_get_announced_format(unsigned int idx, unsigned int *local,
    unsigned int *remote)
{
    if (idx >= n_formats)
        return -1;
    lock_formats_table();
    *local = current_available_formats[idx].local;
    *remote = current_available_formats[idx].remote;
    unlock_formats_table();
    return 0;
}

unsigned int uxenclipboard_translate_announced_format(unsigned int fmt)
{
    unsigned int ret = 0;
    int i;
    if (fmt < FIRST_DYNAMIC_FORMAT) 
        return fmt;
    lock_formats_table();
    for (i = 0; i < n_formats; i++) {
        if (current_available_formats[i].local == fmt) {
            ret = current_available_formats[i].remote;
            break;
        }
    }
    unlock_formats_table();
    return ret;
}

int uxenclipboard_test_format_written(unsigned int remotefmt, int *written)
{
    unsigned int ret = -1;
    int i;

    lock_formats_table();
    for (i = 0; i < n_formats; i++) {
        if (current_available_formats[i].remote == remotefmt) {
            *written = current_available_formats[i].written;
            ret = 0;
            break;
        }
    }
    unlock_formats_table();
    return ret;
}

int uxenclipboard_mark_format_written(unsigned int remotefmt, int written)
{
    unsigned int ret = -1;
    int i;

    lock_formats_table();
    for (i = 0; i < n_formats; i++) {
        if (current_available_formats[i].remote == remotefmt) {
            current_available_formats[i].written = written;
            ret = 0;
            break;
        }
    }
    unlock_formats_table();
    return ret;
}
