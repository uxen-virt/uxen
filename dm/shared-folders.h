/*
 * Copyright 2015-2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __SHARED_FOLDERS_H_
#define __SHARED_FOLDERS_H_

#define SF_OPT_SCRAMBLE 0x1
#define SF_OPT_HIDE 0x2
#define SF_OPT_NO_FLUSH 0x4
#define SF_OPT_NO_QUOTA 0x8
#define SF_OPT_NO_REDIRECTED_SCRAMBLE 0x10
#define SF_OPT_SCRAMBLE_FILENAMES 0x20

int sf_service_start(void);
void sf_service_stop(void);
int sf_server_process_request(char *req, int reqsize, char* respbuf, int* respsize);
int sf_add_mapping(const char * path, const char *name, const char *file_suffix, int writable,
                   uint64_t opts, uint64_t quota);
int sf_init();
int sf_quit();
void sf_vm_pause(void);
void sf_vm_unpause(void);

int sf_set_opt(wchar_t *name, wchar_t *subfolder, uint64_t opt);
int sf_mod_opt(wchar_t *name, wchar_t *subfolder, uint64_t opt, int add);
int sf_mod_opt_dynamic(wchar_t *name, wchar_t *subfolder, uint64_t opt, int add);
int sf_restore_opt(wchar_t *name, wchar_t *subfolder, uint64_t opt);

void *makeSHFLString(wchar_t *str);
void *makeSHFLStringUTF8(char *str);

#endif
