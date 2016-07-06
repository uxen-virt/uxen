/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/os.h>
#include "mappings.h"
#include "shflhandle.h"
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

static void
clear_dyn_entries(void)
{
    folder_opt_entry_t *e, *next;

    TAILQ_FOREACH_SAFE(e, &folder_opt_entries, entry, next) {
        if (e->dynamic) {
            TAILQ_REMOVE(&folder_opt_entries, e, entry);
            free(e);
        }
    }
}

static void
put_wstr(QEMUFile *f, wchar_t *s)
{
    int len = wcslen(s);

    qemu_put_be32(f, len);
    qemu_put_buffer(f, (uint8_t*)s, len*2);
}

static void
get_wstr(QEMUFile *f, wchar_t *s)
{
    int len = qemu_get_be32(f);

    if (len < SUBFOLDER_PATHMAX) {
        memset(s, 0, SUBFOLDER_PATHMAX * 2);
        qemu_get_buffer(f, (uint8_t*)s, len*2);
    }
}

static void
state_save(QEMUFile *f, void *opaque)
{
    folder_opt_entry_t *e;
    uint32_t count = 0;

    /* only store dynamicaly added options in the savefile */
    critical_section_enter(&folder_opt_lock);
    TAILQ_FOREACH(e, &folder_opt_entries, entry)
        if (e->dynamic)
            ++count;
    qemu_put_be32(f, count);
    TAILQ_FOREACH(e, &folder_opt_entries, entry) {
        if (e->dynamic) {
            put_wstr(f, e->mapname);
            put_wstr(f, e->subfolder);
            qemu_put_be64(f, e->opts);
            qemu_put_byte(f, e->dynamic);
        }
    }
    critical_section_leave(&folder_opt_lock);
}

static void
dump_opt_table(void)
{
    folder_opt_entry_t *e;
    int i = 0;

    TAILQ_FOREACH(e, &folder_opt_entries, entry) {
        debug_printf("shared-folders: option entry %d (%ls, %ls, %"PRIx64", dyn=%d)\n",
                     i, e->mapname, e->subfolder, e->opts, e->dynamic);
        ++i;
    }
}

static int
state_load(QEMUFile *f, void *opaque, int version_id)
{
    uint32_t count;

    critical_section_enter(&folder_opt_lock);
    clear_dyn_entries();
    count = qemu_get_be32(f);
    while (count--) {
        folder_opt_entry_t *e = calloc(1, sizeof(*e));

        get_wstr(f, e->mapname);
        get_wstr(f, e->subfolder);
        e->opts = qemu_get_be64(f);
        e->dynamic = qemu_get_byte(f);

        TAILQ_INSERT_TAIL(&folder_opt_entries, e, entry);

        debug_printf("shared-folders: loaded folder option entry (%ls, %ls, %"PRIx64", dyn=%d)\n",
                     e->mapname, e->subfolder, e->opts, e->dynamic);
    }
    dump_opt_table();
    critical_section_leave(&folder_opt_lock);
    return 0;
}

static int
is_sep(wchar_t c)
{
    return (c == PATH_SEP || c == PATH_SEP_ALT);
}

static wchar_t *
get_path_suffix(wchar_t *prefix, wchar_t *path)
{
    if (!wcsncmp(L"\\\\?\\", prefix, 4))
        prefix += 4;
    if (!wcsncmp(L"\\\\?\\", path, 4))
        path += 4;
    while (is_sep(*prefix)) ++prefix;
    while (is_sep(*path)) ++path;

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
    while (is_sep(*path))
        ++path;
    return path;
}

int
is_path_prefixof(wchar_t *prefix, wchar_t *path)
{
    return get_path_suffix(prefix, path) ? 1 : 0;
}

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
    wchar_t *rootpath = (wchar_t*)vbsfMappingsQueryHostRoot(root);
    wchar_t *mapname = get_mapname(root);
    folder_opt_entry_t *e, *found = NULL;
    int maxlen = 0, len;
    int dyn;

    if (!rootpath || !mapname)
        return NULL;

    for (dyn = 1; dyn >= 0; dyn--) {
        TAILQ_FOREACH(e, &folder_opt_entries, entry) {
            wchar_t subfolder_fullpath[SUBFOLDER_PATHMAX] = { 0 };

            if (e->dynamic != dyn)
                continue;
            if (wcslen(rootpath) + wcslen(e->subfolder) >= SUBFOLDER_PATHMAX) {
                warnx("shared-folders: path too long");
                continue;
            }

            wcsncpy(subfolder_fullpath, rootpath, SUBFOLDER_PATHMAX);
            catpath(subfolder_fullpath, e->subfolder);

            if (!wcsncmp(mapname, e->mapname, SUBFOLDER_PATHMAX) &&
                is_path_prefixof(subfolder_fullpath, path))
            {
                len = wcslen(e->subfolder);
                if (len >= maxlen) {
                    len = maxlen;
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
    wchar_t *rootpath = (wchar_t*)vbsfMappingsQueryHostRoot(root);

    if (!mapping || !mapname || !rootpath)
        return 0;
    path = get_path_suffix(rootpath, path);
    if (!path)
        return 0;
    critical_section_enter(&folder_opt_lock);
    e = find_exact_entry(mapname, path, -1);
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
    register_savevm(NULL, "shared-folders-opts", 0, 0,
                    state_save, state_load, NULL);
}
