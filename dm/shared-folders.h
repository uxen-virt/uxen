/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __SHARED_FOLDERS_H_
#define __SHARED_FOLDERS_H_

int sf_parse_config(yajl_val config);
int sf_service_start(void);
void sf_service_stop(void);
int sf_server_process_request(char *req, int reqsize, char* respbuf, int* respsize);
int sf_add_mapping(const char * path, const char *name, int writable, int crypt_mode);
int sf_add_subfolder_crypt(char *name, char *subfolder, int crypt_mode);
int sf_del_subfolder_crypt(char *name, char *subfolder);
int sf_init();
int sf_quit();

#endif
