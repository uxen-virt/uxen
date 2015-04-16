/*
 * Copyright 2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _MAPPINGS_CRYPT_H_
#define _MAPPINGS_CRYPT_H_

void sf_crypt_mapping_init(void);
void sf_override_crypt_mode(wchar_t *mapname, wchar_t *rootpath, wchar_t *path, int *mode);

#endif
