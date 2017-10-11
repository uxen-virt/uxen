/*
 * Copyright 2017, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/debug.h>
#include <dm/queue.h>
#include <wchar.h>
#include <iprt/alloc.h>
#include <iprt/err.h>
#include "vbsf.h"
#include "mappings.h"
#include "util.h"

#define PATH_SEP '\\'
#define PATH_SEP_ALT '/'

wchar_t *
sf_wstrdup(wchar_t *str)
{
    size_t sz = wcslen(str) * 2 + 2;
    wchar_t *dup = RTMemAlloc(sz);

    if (!dup)
        return NULL;

    wcscpy(dup, str);

    return dup;
}

int
sf_is_sep(wchar_t c)
{
    return (c == PATH_SEP || c == PATH_SEP_ALT);
}

SHFLROOT
sf_root_by_name(wchar_t *name)
{
    SHFLROOT root = SHFL_ROOT_NIL;
    vbsfMappingGetByName(name, &root);

    return root;
}


