/*
 * Copyright 2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _FILECRYPT_H_
#define _FILECRYPT_H_

#include <stdint.h>
#include <windows.h>

#define FILECRYPT_API

#define FILECRYPT_MAGIC 0x454C49464653C55F
#define FILECRYPT_HDR_PAD 4096
#define FILECRYPT_KEYBITS 256
#define FILECRYPT_KEYBYTES (FILECRYPT_KEYBITS / 8)
#define CRYPT_NONE 0
#define CRYPT_TRIVIAL 1

typedef struct filecrypt_hdr {
    uint64_t magic;
    uint32_t hdrversion;
    uint32_t hdrlen;
    uint32_t crypttype;
    uint32_t keylen;
    uint8_t key[FILECRYPT_KEYBYTES*2];
} filecrypt_hdr_t;

int FILECRYPT_API fc_init(void);
/* allocate header */
filecrypt_hdr_t* FILECRYPT_API fc_init_hdr(void);
/* free header */
void FILECRYPT_API fc_free_hdr(filecrypt_hdr_t *h);
/* allocate & read header. caller responsible for free */
int  FILECRYPT_API fc_read_hdr(HANDLE file, int *iscrypt, filecrypt_hdr_t **hdr);
/* allocate & read header. caller responsible for free */
int  FILECRYPT_API fc_path_read_hdr(wchar_t *path, int *iscrypt, filecrypt_hdr_t **hdr);
/* write header */
int  FILECRYPT_API fc_write_hdr(HANDLE file, filecrypt_hdr_t *hdr);
/* encrypt buffer in-place. off = offset in file (not in the buffer) */
void FILECRYPT_API fc_crypt(filecrypt_hdr_t *h, void *buf, uint64_t off, uint32_t len);
/* decrypt buffer in-place. off = offset in file (not in the buffer) */
void FILECRYPT_API fc_decrypt(filecrypt_hdr_t *h, void *buf, uint64_t off, uint32_t len);
/* read/write and decrypt/crypt bytes from file */
BOOL FILECRYPT_API fc_read(filecrypt_hdr_t *h, HANDLE f, void *buffer, DWORD sz, DWORD *num_read);
BOOL FILECRYPT_API fc_write(filecrypt_hdr_t *h, HANDLE f, void *buffer, DWORD sz, DWORD *num_written);

#endif
