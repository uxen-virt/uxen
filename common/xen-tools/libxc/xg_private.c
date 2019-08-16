/******************************************************************************
 * xg_private.c
 *
 * Helper functions for the rest of the library.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
/*
 * uXen changes:
 *
 * Copyright 2012-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef _WIN32
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <winbase.h>
#include <winnt.h>
#include <winioctl.h>
#undef ERROR
#endif

#include <stdlib.h>
#include <unistd.h>
#ifndef _WIN32
#include <zlib.h>
#endif

#include "xg_private.h"


#ifdef _WIN32
static inline wchar_t *_utf8_to_wide(const char *s)
{
    int sz;
    wchar_t *ws;

    /* First figure out buffer size needed and malloc it. */
    sz = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (!sz)
        return NULL;

    ws = (wchar_t *)malloc(sizeof(wchar_t) * (sz + 1));
    if (!ws)
        return NULL;
    ws[sz] = 0;

    /* Now perform the actual conversion. */
    sz = MultiByteToWideChar(CP_UTF8, 0, s, -1, ws, sz);
    if (!sz) {
        free(ws);
        ws = NULL;
    }

    return ws;
}
#endif

char *xc_read_image(xc_interface *xch,
                    const char *filename, unsigned long *size)
{
#ifndef _WIN32
    int kernel_fd = -1;
    gzFile kernel_gfd = NULL;
    char *image = NULL, *tmp;
    unsigned int bytes;

    if ( (filename == NULL) || (size == NULL) )
        return NULL;

    if ( (kernel_fd = open(filename, O_RDONLY)) < 0 )
    {
        PERROR("Could not open kernel image");
        goto out;
    }

    if ( (kernel_gfd = gzdopen(kernel_fd, "rb")) == NULL )
    {
        PERROR("Could not allocate decompression state for state file");
        goto out;
    }

    *size = 0;

#define CHUNK 1*1024*1024
    while(1)
    {
        if ( (tmp = realloc(image, *size + CHUNK)) == NULL )
        {
            PERROR("Could not allocate memory for kernel image");
            free(image);
            image = NULL;
            goto out;
        }
        image = tmp;

        bytes = gzread(kernel_gfd, image + *size, CHUNK);
        switch (bytes)
        {
        case -1:
            PERROR("Error reading kernel image");
            free(image);
            image = NULL;
            goto out;
        case 0: /* EOF */
            goto out;
        default:
            *size += bytes;
            break;
        }
    }
#undef CHUNK

 out:
    if ( *size == 0 )
    {
        PERROR("Could not read kernel image");
        free(image);
        image = NULL;
    }
    else if ( image )
    {
        /* Shrink allocation to fit image. */
        tmp = realloc(image, *size);
        if ( tmp )
            image = tmp;
    }

    if ( kernel_gfd != NULL )
        gzclose(kernel_gfd);
    else if ( kernel_fd >= 0 )
        close(kernel_fd);
    return image;
#else
    char *image = NULL;
    HANDLE ih;
    LARGE_INTEGER s;
    ULONG bytesRead;
    wchar_t *filename_w;

    filename_w = _utf8_to_wide(filename);
    if (!filename) {
        ERROR("Failed to convert utf8 to wide (%ld)", GetLastError());
        return NULL;
    }

    ih = CreateFileW(filename_w, GENERIC_READ, FILE_SHARE_READ, NULL,
                     OPEN_EXISTING, 0, NULL);

    free(filename_w);

    if (ih == INVALID_HANDLE_VALUE) {
        ERROR("CreateFileW failed (%ld)", GetLastError());
        return NULL;
    }

    if (!GetFileSizeEx(ih, &s)) {
        ERROR("GetFileSizeEx failed (%ld)", GetLastError());
        return NULL;
    }

    image = malloc((SIZE_T)s.u.LowPart);
    if (!image) {
        PERROR("malloc failed");
        return NULL;
    }

    if (!ReadFile(ih, image, s.u.LowPart, &bytesRead, NULL)) {
        ERROR("ReadFile failed (%ld)", GetLastError());
        return NULL;
    }

    if (bytesRead != s.u.LowPart) {
        ERROR("Size mismatch, read %ld bytes, expected %ld",
              bytesRead, s.u.LowPart);
        return NULL;
    }
    CloseHandle(ih);
    *size = s.u.LowPart;
    return image;
#endif
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
