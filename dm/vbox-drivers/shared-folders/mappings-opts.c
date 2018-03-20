/*
 * Copyright 2015-2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/os.h>
#include "mappings.h"
#include "shflhandle.h"
#include "util.h"
#include <dm/config.h>
#include <dm/qemu_glue.h>
#include <dm/debug.h>
#include <dm/queue.h>
#include <dm/shared-folders.h>
#include <err.h>

#define SUBFOLDER_PATHMAX 512
#define PATH_SEP '\\'
#define PATH_SEP_ALT '/'

typedef struct folder_opt_entry {
    TAILQ_ENTRY(folder_opt_entry) entry;

    wchar_t  mapname[SUBFOLDER_PATHMAX];
    wchar_t  subfolder[SUBFOLDER_PATHMAX];
    int      dynamic;
    uint64_t opts;
} folder_opt_entry_t;

static critical_section folder_opt_lock;
static TAILQ_HEAD(, folder_opt_entry) folder_opt_entries;

static wchar_t *
eat_leading_sep(wchar_t *path)
{
    while (*path && *path == PATH_SEP)
        path++;
    return path;
}

static wchar_t *
get_path_suffix(wchar_t *prefix, wchar_t *path)
{
    if (!wcsncmp(L"\\\\?\\", prefix, 4))
        prefix += 4;
    if (!wcsncmp(L"\\\\?\\", path, 4))
        path += 4;
    while (sf_is_sep(*prefix)) ++prefix;
    while (sf_is_sep(*path)) ++path;

    while (*path && *prefix) {
        wchar_t a = towlower(*path);
        wchar_t b = towlower(*prefix);
        if (a != b)
            return NULL;
        ++path;
        ++prefix;
    }

    if (*prefix)
        return NULL;
    while (sf_is_sep(*path))
        ++path;
    return path;
}

int
is_path_prefixof(wchar_t *prefix, wchar_t *path)
{
    return get_path_suffix(prefix, path) ? 1 : 0;
}

#if 0
static void
catpath(wchar_t *buf, wchar_t *path)
{
    int buflen = wcslen(buf);
    wchar_t *p = buf + buflen;

    if (buflen && buf[buflen-1] != PATH_SEP)
        *p++ = PATH_SEP;
    while (*path == PATH_SEP)
        ++path;
    while (*path)
        *p++ = *path++;
}
#endif

static wchar_t *
get_mapname(SHFLROOT root)
{
    MAPPING *m = vbsfMappingGetByRoot(root);

    if (!m || !m->pMapName)
        return NULL;
    return m->pMapName->String.ucs2;
}

static folder_opt_entry_t *
find_exact_entry(wchar_t *mapname, wchar_t *subfolder, int dyn)
{
    folder_opt_entry_t *e;

    TAILQ_FOREACH(e, &folder_opt_entries, entry) {
        if ((dyn < 0 || e->dynamic == dyn) &&
            !wcsnicmp(mapname, e->mapname, SUBFOLDER_PATHMAX) &&
            !wcsnicmp(subfolder, e->subfolder, SUBFOLDER_PATHMAX))
            return e;
    }
    return NULL;
}

/* longest path match, dynamic opts first */
static folder_opt_entry_t *
find_entry_for_path(SHFLROOT root, wchar_t *path)
{
    wchar_t *mapname = get_mapname(root);
    folder_opt_entry_t *e, *found = NULL;
    int maxlen = 0, len;
    int dyn;

    if (!mapname)
        return NULL;

    path = eat_leading_sep(path);
    for (dyn = 1; dyn >= 0; dyn--) {
        TAILQ_FOREACH(e, &folder_opt_entries, entry) {
            if (e->dynamic != dyn)
                continue;

            if (!wcsncmp(mapname, e->mapname, SUBFOLDER_PATHMAX) &&
                is_path_prefixof(e->subfolder, path))
            {
                len = wcslen(e->subfolder);
                if (len >= maxlen) {
                    maxlen = len;
                    found = e;
                }
            }
        }
        if (found)
            break;
    }

    return found;
}

static void
del_opt(SHFLROOT root, wchar_t *subfolder, int dyn_only)
{
    folder_opt_entry_t *e, *next;
    wchar_t *mapname = get_mapname(root);

    if (!mapname)
        return;

    TAILQ_FOREACH_SAFE(e, &folder_opt_entries, entry, next) {
        if (!wcsncmp(mapname, e->mapname, SUBFOLDER_PATHMAX) &&
            !wcsncmp(subfolder, e->subfolder, SUBFOLDER_PATHMAX))
        {
            if (!dyn_only || e->dynamic) {
                debug_printf("shared-folders: delete option entry "
                             "(%ls, %ls, %"PRIx64", dyn=%d)\n",
                             e->mapname, e->subfolder, e->opts, e->dynamic);
                TAILQ_REMOVE(&folder_opt_entries, e, entry);
                free(e);
            }
        }
    }
}

uint64_t
_sf_get_opt(SHFLROOT root, wchar_t *path)
{
    folder_opt_entry_t *e;
    MAPPING *mapping = vbsfMappingGetByRoot(root);

    if (!mapping)
        return 0;

    critical_section_enter(&folder_opt_lock);
    e = find_entry_for_path(root, path);
    critical_section_leave(&folder_opt_lock);

    return e ? e->opts : mapping->opts;
}

int
_sf_has_opt(SHFLROOT root, wchar_t *path, uint64_t opt)
{
    uint64_t cur_opt = _sf_get_opt(root, path);

    return (cur_opt & opt) == opt;
}

int
_sf_hidden_path(SHFLROOT root, wchar_t *path)
{
    folder_opt_entry_t *e;
    MAPPING *mapping = vbsfMappingGetByRoot(root);
    wchar_t *mapname = get_mapname(root);
    int dyn;

    if (!mapping || !mapname)
        return 0;

    critical_section_enter(&folder_opt_lock);
    path = eat_leading_sep(path);
    for (dyn = 1; dyn >= 0; dyn--) {
        e = find_exact_entry(mapname, path, dyn);
        if (e) break;
    }
    critical_section_leave(&folder_opt_lock);

    return e ? (e->opts & SF_OPT_HIDE) : 0;
}

void
_sf_set_opt(SHFLROOT root, wchar_t *subfolder, uint64_t opt, int dyn)
{
    folder_opt_entry_t *e;
    MAPPING *mapping = vbsfMappingGetByRoot(root);
    wchar_t *mapname = get_mapname(root);
    uint64_t prev;

    if (!mapname || !mapping)
        return;

    prev = _sf_get_opt(root, subfolder);

    critical_section_enter(&folder_opt_lock);
    e = find_exact_entry(mapname, subfolder, dyn);
    if (!e) {
        e = calloc(1, sizeof(*e));
        if (!e)
            errx(1, "out of memory");
        wcsncpy(e->mapname, mapname, SUBFOLDER_PATHMAX);
        wcsncpy(e->subfolder, subfolder, SUBFOLDER_PATHMAX);
        TAILQ_INSERT_TAIL(&folder_opt_entries, e, entry);
    }
    e->dynamic = dyn;
    e->opts = opt;
    critical_section_leave(&folder_opt_lock);

    if ((prev & SF_OPT_SCRAMBLE) != (opt & SF_OPT_SCRAMBLE))
        vbsfNotifyCryptChanged();
    debug_printf(
        "shared-folders: set subfolder option (folder %ls subfolder %ls opt 0x%08"PRIx64" dyn %d)\n",
        mapname, subfolder, opt, dyn);
}

void
_sf_mod_opt(SHFLROOT root, wchar_t *subfolder, uint64_t opt, int add, int dyn)
{
    uint64_t o = _sf_get_opt(root, subfolder);

    _sf_set_opt(root, subfolder, add ? (o | opt) : (o & ~opt), dyn);
}

void
_sf_restore_opt(SHFLROOT root, wchar_t *subfolder, uint64_t opt)
{
    del_opt(root, subfolder, 1);
}

void
sf_opts_init(void)
{
    TAILQ_INIT(&folder_opt_entries);
    critical_section_init(&folder_opt_lock);
}
