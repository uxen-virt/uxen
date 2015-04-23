/*
 * Copyright 2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef FILECRYPT_HELPER_H_
#define FILECRYPT_HELPER_H_

#include "mappings.h"
#include "shflhandle.h"
#include "filecrypt.h"

/* test whether particular handle/path needs crypting */
int fch_query_crypt_by_handle(SHFLCLIENTDATA *client, SHFLROOT root, SHFLHANDLE handle, int *crypt_mode);
int fch_query_crypt_by_path(SHFLCLIENTDATA *client, SHFLROOT root, wchar_t *path, int *crypt_mode);

/* associate empty crypt context with handle */
int fch_create_crypt_hdr(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE handle);
/* read crypt context from disk */
int fch_read_crypt_hdr(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE handle, filecrypt_hdr_t **hdr);
/* convert file offset to host */
uint64_t fch_host_fileoffset(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE handle, uint64_t guest_off);
/* convert fs info struct to guest */
void fch_guest_fsinfo(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE handle, RTFSOBJINFO *info);
/* convert fs info struct to guest */
void fch_guest_fsinfo_path(SHFLCLIENTDATA *pClient, SHFLROOT root, wchar_t *path, RTFSOBJINFO *info);
/* test for file/handle writablity */
int fch_writable_file(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE handle,
                      const wchar_t *path, bool *fWritable);
/* read crypt context for dir entry */
int fch_read_dir_entry_crypthdr(SHFLCLIENTDATA *pClient, SHFLROOT root,
                                wchar_t *dir, wchar_t *entry, filecrypt_hdr_t **crypt);
/* encrypt buffer inplace. off = offset in file, not in buffer */
void fch_crypt(SHFLCLIENTDATA *pClient, SHFLHANDLE handle, uint8_t *buf, uint64_t off, uint64_t len);
/* decrypt buffer inplace, off = offset in file, not in buffer */
void fch_decrypt(SHFLCLIENTDATA *pClient, SHFLHANDLE handle, uint8_t *buf, uint64_t off, uint64_t len);
/* rewrite whole file, possibly with new encryption settings */
int fch_re_write_file(SHFLCLIENTDATA *client, SHFLROOT root, SHFLHANDLE src);

#endif
