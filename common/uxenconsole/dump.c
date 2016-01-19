/*
 * Copyright 2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/mman.h>
#include <poll.h>
#include <stdlib.h>
#endif
#include <stdio.h>
#include <stdint.h>

#include "uxenconsolelib.h"
#include "uxenhid-common.h"

struct bmp_fileheader {
    uint16_t signature;
    uint32_t filesize;
    uint32_t reserved;
    uint32_t fileoffset_to_pixelarray;
} __attribute__((packed));

struct bmp_infoheader {
    uint32_t dibheadersize;
    uint32_t width;
    uint32_t height;
    uint16_t planes;
    uint16_t bitsperpixel;
    uint32_t compression;
    uint32_t imagesize;
    uint32_t ypixelpermeter;
    uint32_t xpixelpermeter;
    uint32_t numcolorspallette;
    uint32_t mostimpcolor;
} __attribute__((packed));

struct dump_context
{
    int stop;
    char *filename;
};

static void
console_resize_surface(void *priv,
                       unsigned int width,
                       unsigned int height,
                       unsigned int linesize,
                       unsigned int length,
                       unsigned int bpp,
                       unsigned int offset,
                       file_handle_t shm_handle)
{
    struct dump_context *d = priv;
    FILE *bmpfile;
    struct bmp_fileheader fh;
    struct bmp_infoheader ih;
    size_t pix_len;
    uint8_t *view;
    uint8_t *s;
    int i;

#ifdef _WIN32
    view = MapViewOfFile(shm_handle, FILE_MAP_READ, 0, 0, length);
    if (!view) {
#else
    view = mmap(NULL, length, PROT_READ, MAP_FILE | MAP_SHARED,
                shm_handle, 0);
    if (view == MAP_FAILED) {
#endif
        fprintf(stderr, "failed to map shared memory\n");
        goto closehandle;
    }

    bmpfile = fopen(d->filename, "wb");
    if (!bmpfile) {
        fprintf(stderr, "fopen failed\n");
        goto unmap;
    }

    pix_len = width * ((bpp + 7) / 8) * height;
    fh.signature = 0x4D42;
    fh.filesize = sizeof(fh) + sizeof(ih) + pix_len;
    fh.reserved = 0x0;
    fh.fileoffset_to_pixelarray = sizeof(fh) + sizeof(ih);
    ih.dibheadersize = sizeof(ih);
    ih.width = width;
    ih.height = -height;
    ih.planes = 1;
    ih.bitsperpixel = bpp;
    ih.compression = 0;
    ih.imagesize = pix_len;
    ih.ypixelpermeter = 0x130B;
    ih.xpixelpermeter = 0x130B;
    ih.numcolorspallette = 0;
    ih.mostimpcolor = 0;

    fwrite(&fh, 1, sizeof(fh), bmpfile);
    fwrite(&ih, 1, sizeof(ih), bmpfile);

    for (i = 0, s = view + offset; i < height; i++, s += linesize)
        fwrite(s, width, ((bpp + 7) / 8), bmpfile);

    fclose(bmpfile);
unmap:
#ifdef _WIN32
    UnmapViewOfFile(view);
#else
    munmap(view, length);
#endif
closehandle:
#ifdef _WIN32
    CloseHandle(shm_handle);
#else
    close(shm_handle);
#endif
    d->stop = 1;
}

static void
console_disconnected(void *priv)
{
    struct dump_context *d = priv;

    d->stop = 1;
}

static ConsoleOps console_ops = {
    .resize_surface = console_resize_surface,
    .disconnected = console_disconnected,
};

static int
dump(char *consolename, char *filename)
{
    file_handle_t hdl;
    uxenconsole_context_t ctx;
    struct dump_context d;
#ifndef _WIN32
    struct pollfd pfd = { 0 };
#endif

    ctx = uxenconsole_init(&console_ops, &d, consolename);
    if (!ctx) {
        fprintf(stderr, "uxenconsole_init failed\n");
        return -1;
    }

    hdl = uxenconsole_connect(ctx);
#ifdef _WIN32
    if (!hdl) {
#else
    if (hdl < 0) {
#endif
        fprintf(stderr, "uxenconsole_connect failed\n");
        return -1;
    }

    d.stop = 0;
    d.filename = filename;

#ifndef _WIN32
    pfd.fd = hdl;
    pfd.events = POLLIN | POLLHUP | POLLERR;
    while (!d.stop && poll(&pfd, 1, -1) == 1 &&
           (pfd.revents & (POLLHUP | POLLERR)) == 0)
#else
    while (!d.stop && WaitForSingleObject(hdl, INFINITE) == WAIT_OBJECT_0)
#endif
        uxenconsole_channel_event(ctx, hdl, 0);

    uxenconsole_cleanup(ctx);

    return 0;
}

static void
usage(char *progname)
{
    fprintf(stderr, "Usage: %s <consolename> <filename>\n\n", progname);
    exit(-1);
}

int main(int argc, char **argv)
{
    if (argc != 3)
        usage(argv[0]);

    return dump(argv[1], argv[2]);
}
