/*
 * Copyright 2017-2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _SF_UTIL_H_
#define _SF_UTIL_H_

wchar_t *sf_wstrdup(wchar_t*);
int sf_is_sep(wchar_t);
SHFLROOT sf_root_by_name(wchar_t *name);
bool sf_is_redirected_path(SHFLROOT root, wchar_t *guest_path);
wchar_t *sf_redirect_path(SHFLROOT root, wchar_t *guest_path);

#endif
