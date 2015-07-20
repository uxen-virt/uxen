/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <iprt/log.h>
#undef _WIN32_WINNT /* any cleaner way to include both log.h and config.h ? */
#include "config.h"
#include "dm.h"
#include <clipboardformats.h>
#include <dm/vbox-drivers/heap.h>

#define FIRST_DYNAMIC_FORMAT 0xc000

#define _CF(x) {x, #x}
static struct {
    unsigned int fmt;
    char* name;
} predefined_format_names[] = {
    _CF(CF_BITMAP),
    _CF(CF_DIB),
    _CF(CF_DIBV5),
    _CF(CF_DIF),
    _CF(CF_DSPBITMAP),
    _CF(CF_DSPENHMETAFILE),
    _CF(CF_DSPMETAFILEPICT),
    _CF(CF_DSPTEXT),
    _CF(CF_ENHMETAFILE),
    _CF(CF_HDROP),
    _CF(CF_LOCALE),
    _CF(CF_METAFILEPICT),
    _CF(CF_OEMTEXT),
    _CF(CF_OWNERDISPLAY),
    _CF(CF_PALETTE),
    _CF(CF_PENDATA),
    _CF(CF_RIFF),
    _CF(CF_SYLK),
    _CF(CF_TEXT),
    _CF(CF_TIFF),
    _CF(CF_UNICODETEXT),
    _CF(CF_WAVE),
    {0, NULL}};

static char* get_predefined_format_name(unsigned int fmt)
{
    int i = 0;
    while (predefined_format_names[i].name &&
        predefined_format_names[i].fmt != fmt)
        i++;
    return predefined_format_names[i].name;
}

static int strstr_with_coma(char * haystack, char * needle)
{
    int s = 0, i = 0,
        l = strlen(needle);

    for (;;) {
        if (!haystack[i] || haystack[i] == ',') {
            if (l == i-s && !strncmp(needle, haystack+s, l))
                return 1;
            s = i+1;
        }
        if (!haystack[i])
            return 0;
        ++i;
    }
}

static int uxenclipboard_is_allowed_format_internal(int dir, char * name)
{
    int ret;
    const char *whitelist, *blacklist;
    char *loname, *p;

    switch (dir) {
        case UXENCLIPBOARD_DIRECTION_IN:
            whitelist = clipboard_formats_whitelist_vm2host;
            blacklist = clipboard_formats_blacklist_vm2host;
            break;
        case UXENCLIPBOARD_DIRECTION_OUT:
            whitelist = clipboard_formats_whitelist_host2vm;
            blacklist = clipboard_formats_blacklist_host2vm;
            break;
        default:
            LogRel(("uxenclipboard_is_allowed_format_internal dir %d???\n",
                dir));
            return 0;
    }

    loname = hgcm_strdup(name);
    if (!loname)
        return 0;
    p = loname;
    while (*p) { *p = tolower(*p); ++p; }
    if (strstr(loname, "ole")) {
        LogRel(("format %s direction %s deny via OLE rule\n",
            name, dir==UXENCLIPBOARD_DIRECTION_IN?"in":"out"));
        hgcm_free(loname);
        return 0;
    }
    hgcm_free(loname);

    if (whitelist && whitelist[0]) {
        ret = strstr_with_coma((char*)whitelist, name);
        LogRel(("format %s direction %s %s via whitelist\n",
            name, dir==UXENCLIPBOARD_DIRECTION_IN?"in":"out", ret?"ok":"deny"));
        return ret;
    }
    
    if (blacklist && blacklist[0]) {
        ret = strstr_with_coma((char*)blacklist, name);
        LogRel(("format %s direction %s %s via blacklist\n",
            name, dir==UXENCLIPBOARD_DIRECTION_IN?"in":"out", !ret?"ok":"deny"));
        return !ret;
    }
    return 1;
}

char *buff_ascii_encode(wchar_t *wstr); /*shouldn't it be in some reusable header?*/
int uxenclipboard_is_allowed_format(int direction, unsigned int fmt,
    wchar_t* name)
{
    char * name_ascii;
    int ret;
    if (!name) {
        name_ascii = get_predefined_format_name(fmt);
        if (!name_ascii) {
            Log(("Denying unknown predefined format %d\n", fmt));
            return 0;
        }
        return uxenclipboard_is_allowed_format_internal(direction, name_ascii);
    }
    name_ascii = buff_ascii_encode(name);
    if (!name_ascii)
        return 0;
    if (!strlen(name_ascii)) {
        Log(("Empty format name?"));
        ret = 0;
    } else
        ret = uxenclipboard_is_allowed_format_internal(direction, name_ascii);
    free(name_ascii);
    return ret;
}

int uxenclipboard_get_format_name(unsigned int fmt, char *name, int sz)
{
    int rv;

    if (fmt < FIRST_DYNAMIC_FORMAT) {
        char *ascii = get_predefined_format_name(fmt);
        if (!ascii)
            return -1;
        strncpy(name, ascii, sz);
        return 0;
    }
    rv = GetClipboardFormatNameA(fmt, name, sz);
    return rv ? 0 : -1;
}

