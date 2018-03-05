/*
 * Copyright 2017-2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/debug.h>
#include <dm/queue.h>
#include <dm/dm.h>
#include <wchar.h>
#include <iprt/alloc.h>
#include <iprt/err.h>
#include "shfl.h"
#include "mappings.h"
#include "util.h"
#include "redir.h"

typedef struct redir_entry {
    TAILQ_ENTRY(redir_entry) entry;

    wchar_t *sfname;
    wchar_t *src;
    wchar_t *dst;
} redir_entry_t;

static TAILQ_HEAD(, redir_entry) redir_entries;
static critical_section redir_lock;

static int
sf_path_equal(wchar_t *a, wchar_t *b)
{
    while (sf_is_sep(*a)) a++;
    while (sf_is_sep(*b)) b++;
    while (*a && *b) {
        if (towlower(*a) != towlower(*b))
            return 0;
        a++;
        b++;
    }

    return (!*a && !*b) ? 1 : 0;
}

static redir_entry_t *
sf_redirect_find(wchar_t *sfname, wchar_t *src)
{
    redir_entry_t *e;

    critical_section_enter(&redir_lock);
    TAILQ_FOREACH(e, &redir_entries, entry) {
        if (sf_path_equal(e->src, src) && wcscmp(e->sfname, sfname) == 0) {
            critical_section_leave(&redir_lock);
            return e;
        }
    }
    critical_section_leave(&redir_lock);

    return NULL;
}

static void
sf_redirect_update_dst(redir_entry_t *e, wchar_t *dst)
{
    critical_section_enter(&redir_lock);
    if (e->dst) {
        RTMemFree(e->dst);
    }
    e->dst = sf_wstrdup(dst);
    critical_section_leave(&redir_lock);
}

wchar_t *
sf_redirect_path(SHFLROOT root, wchar_t *path)
{
    PMAPPING mapping = vbsfMappingGetByRoot(root);

    if (mapping) {
        redir_entry_t *e = sf_redirect_find(mapping->pMapName->String.ucs2, path);

        return e ? sf_wstrdup(e->dst) : NULL;
    }

    return NULL;
}

int
sf_redirect_add(wchar_t *sfname, wchar_t *src, wchar_t *dst)
{
    redir_entry_t *e;

    e = sf_redirect_find(sfname, src);
    if (e) {
        sf_redirect_update_dst(e, dst);
        if (!hide_log_sensitive_data)
            debug_printf("shared-folders: updated redirect %ls -> %ls\n", src, dst);
        return 0;
    }

    e = RTMemAlloc(sizeof(*e));
    if (!e)
        return VERR_NO_MEMORY;

    e->sfname = sf_wstrdup(sfname);
    e->src = sf_wstrdup(src);
    e->dst = sf_wstrdup(dst);
    critical_section_enter(&redir_lock);
    TAILQ_INSERT_TAIL(&redir_entries, e, entry);
    critical_section_leave(&redir_lock);
    if (!hide_log_sensitive_data)
        debug_printf("shared-folders: added redirect %ls -> %ls\n", src, dst);

    return 0;
}

int
sf_redirect_del(wchar_t *sfname, wchar_t *src)
{
    redir_entry_t *e;

    e = sf_redirect_find(sfname, src);
    if (e) {
        critical_section_enter(&redir_lock);
        TAILQ_REMOVE(&redir_entries, e, entry);
        critical_section_leave(&redir_lock);
        if (!hide_log_sensitive_data)
            debug_printf("shared-folders: removed redirect %ls -> %ls\n", e->src, e->dst);
        RTMemFree(e->sfname);
        RTMemFree(e->src);
        RTMemFree(e->dst);
        RTMemFree(e);
    }

    return 0;
}

void
sf_redirect_init(void)
{
    TAILQ_INIT(&redir_entries);
    critical_section_init(&redir_lock);
}

