/*
 * Copyright 2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "filecrypt.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static uint8_t buffer[32768];

static int _write(filecrypt_hdr_t *crypt, HANDLE file, void *buf, int cnt)
{
    DWORD part = 0;
    uint8_t *p = (uint8_t*)buf;

    while (cnt>0) {
        if (!(crypt ? fc_write(crypt, file, p, cnt, &part)
                    : WriteFile(file, p, cnt, &part, NULL)))
            return GetLastError();
        if (part == 0)
            return ERROR_WRITE_FAULT;
        p += part;
        cnt -= part;
    }
    return 0;
}

void do_decode(const wchar_t *src, const wchar_t *dst, int inplace)
{
    HANDLE h, hd;
    int iscrypt;
    filecrypt_hdr_t *crypt;
    DWORD nread;
    uint64_t off;
    int rc;

    h = CreateFileW(src, GENERIC_READ,
                    inplace ? 0 : FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "source file open error\n");
        exit(1);
    }

    fc_read_hdr(h, &iscrypt, &crypt);
    if (!iscrypt) {
        fprintf(stderr, "source file not encoded\n");
        exit(1);
    }
    if (!crypt) {
        fprintf(stderr, "crypt header read error\n");
        exit(1);
    }
    hd = CreateFileW(dst, GENERIC_WRITE,
                     0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                     NULL);
    if (hd == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "destination file open error\n");
        exit(1);
    }

    off = 0;
    for (;;) {
        if (!fc_read(crypt, h, buffer, sizeof(buffer), &nread)) {
            fprintf(stderr, "read error %d\n", (int)GetLastError());
            exit(1);
        }
        if (!nread)
            break; //EOF
        off += nread;
        if ((rc = _write(NULL, hd, buffer, nread))) {
            fprintf(stderr, "write error %d\n", rc);
            exit(1);
        }
    }

    free(crypt);
    CloseHandle(h);
    CloseHandle(hd);

    if (inplace && !ReplaceFileW(src, dst, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "replace file error %d\n", (int)GetLastError());
        exit(1);
    }
}

void do_encode(const wchar_t *src, const wchar_t *dst, int inplace)
{
    HANDLE h, hd;
    int iscrypt;
    filecrypt_hdr_t *crypt = NULL;
    filecrypt_hdr_t *cr = NULL;
    DWORD nread;
    uint64_t off;
    int rc;

    h = CreateFileW(src, GENERIC_READ,
                    inplace ? 0 : FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "source file open error\n");
        exit(1);
    }

    fc_read_hdr(h, &iscrypt, &crypt);
    if (iscrypt) {
        fprintf(stderr, "source file already encoded\n");
        exit(1);
    }
    SetFilePointer(h, 0, NULL, FILE_BEGIN);

    hd = CreateFileW(dst, GENERIC_WRITE,
                     0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                     NULL);
    if (hd == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "destination file open error\n");
        exit(1);
    }

    cr = fc_init_hdr();
    if (!cr) {
        fprintf(stderr, "no memory\n");
        exit(1);
    }
    rc = fc_write_hdr(hd, cr);
    if (rc) {
        fprintf(stderr, "header write error %d\n", rc);
        exit(1);
    }

    off = 0;
    for (;;) {
        if (!ReadFile(h, buffer, sizeof(buffer), &nread, NULL)) {
            fprintf(stderr, "read error %d\n", (int)GetLastError());
            exit(1);
        }
        if (!nread)
            break; //EOF
        off += nread;
        if ((rc = _write(cr, hd, buffer, nread))) {
            fprintf(stderr, "write error %d\n", rc);
            exit(1);
        }
    }
    CloseHandle(h);
    CloseHandle(hd);

    if (inplace && !ReplaceFileW(src, dst, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "replace file error %d\n", (int)GetLastError());
        exit(1);
    }
}

void usage()
{
    fprintf(stderr, "usage:\n filecrypt [-e|-E|-d|-D] <source> <destination>\n");
    fprintf(stderr, "   -e -d      encode/decode\n");
    fprintf(stderr, "   -E -D      encode/decode inplace (overwrites source file)\n");
    exit(1);
}

int main(void)
{
    int argc;
    LPWSTR *argv;
    LPWSTR cmdline;
    int inplace = 0;
    int encode = 0;
    int decode = 0;

    cmdline = GetCommandLineW();
    argv = CommandLineToArgvW(cmdline, &argc);
    if (argc != 4)
        usage();
    fc_init();
    encode = !wcscmp(argv[1], L"-e") || !wcscmp(argv[1], L"-E");
    decode = !wcscmp(argv[1], L"-d") || !wcscmp(argv[1], L"-D");
    inplace = !wcscmp(argv[1], L"-E") || !wcscmp(argv[1], L"-D");
    if (encode)
        do_encode(argv[2], argv[3], inplace);
    else if (decode)
        do_decode(argv[2], argv[3], inplace);
    else
        usage();
    return 0;
}
