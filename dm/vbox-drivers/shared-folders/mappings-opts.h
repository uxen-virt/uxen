/*
 * Copyright 2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _SF_MAPPINGS_OPTS_H_
#define _SF_MAPPINGS_OPTS_H_

void sf_opts_init(void);
uint64_t _sf_get_opt(SHFLROOT root, wchar_t *subfolder);
int _sf_has_opt(SHFLROOT root, wchar_t *subfolder, uint64_t opt);
void _sf_set_opt(SHFLROOT root, wchar_t *subfolder, uint64_t opt, int dyn);
void _sf_mod_opt(SHFLROOT root, wchar_t *subfolder, uint64_t opt, int add, int dyn);
/* restores default */
void _sf_restore_opt(SHFLROOT root, wchar_t *subfolder, uint64_t opt);
#endif
