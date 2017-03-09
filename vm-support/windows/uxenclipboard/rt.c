/*
 * Copyright 2013-2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <malloc.h>
#include <stdio.h>
#include <windows.h>

void * RTMemAllocTag(size_t cb, const char *pszTag)
{
    return malloc(cb);
}

void * RTMemAllocZTag(size_t cb, const char *pszTag)
{
    return calloc(1, cb);
}

