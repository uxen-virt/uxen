/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "attoimg.h"

#define PAGE_SIZE 4096

enum opt {
    OPT_KERNEL,
    OPT_INITRAMFS,
    OPT_TRAMPOLINE,
    OPT_MEMSIZE,
    OPT_VCPUS,
    OPT_OUTPUT,
    OPT_INPUT,
    OPT_PKEY,
    OPT_ROOTHASH,
    OPT_MAX,
};

static const char *opt[OPT_MAX];

static size_t
read_bytes(FILE *f, void *buffer, size_t count)
{
    size_t rd_total = 0;
    while (rd_total != count) {
        size_t rd = fread(buffer, 1, count - rd_total, f);
        if (!rd)
            return 0;
        rd_total += rd;
    }

    return rd_total;
}

void usage(void)
{
    printf("usage:\n");
    printf("create initial attovm image:\n");
    printf("  attoimg     -k <kernel> -r <initramfs> -t <trampoline> -s <suspend image> -m <memsize in mb> -v <vcpus> -p <privatekey>\n");
    printf("              -h <root disk hash file>\n");
    printf("              create <imagefile>\n");
    printf("sign existing attovm image:\n");
    printf("  attoimg     -p <privatekey>\n");
    printf("              sign <input image> <signed image>\n");
    exit(1);
}

int open_and_read_bytes(const char *filename, uint8_t *buf, int count)
{
    FILE *f;

    f = fopen(filename, "rb");
    if (!f)
        return -1;
    if (read_bytes(f, buf, count) != count) {
        fclose(f);
        return -1;
    }
    fclose(f);

    return 0;
}

int read_key(const char *filename, uint8_t *pkey)
{
    return open_and_read_bytes(filename, pkey, ATTOIMG_SIGNKEY_BYTES);
}

int read_rhash(const char *filename, uint8_t *rhash)
{
    return open_and_read_bytes(filename, rhash, ATTOIMG_ROOTHASH_BYTES);
}

int create_image(void)
{
    struct attoimg_initial_image_info info;
    struct attoimg_image_sign_data sign;
    int rc;

    memset(&info, 0, sizeof(info));
    memset(&sign, 0, sizeof(sign));

    if (!opt[OPT_KERNEL]) {
      printf("missing kernel\n");
      usage();
    }
    if (!opt[OPT_INITRAMFS]) {
      printf("missing initramfs\n");
      usage();
    }
    if (!opt[OPT_TRAMPOLINE]) {
      printf("missing trampoline\n");
      usage();
    }
    if (!opt[OPT_MEMSIZE]) {
      printf("missing memory size\n");
      usage();
    }
    if (!opt[OPT_VCPUS]) {
      printf("missing number of vcpus\n");
      usage();
    }
    if (!opt[OPT_ROOTHASH]) {
      printf("missing root disk hash file\n");
      usage();
    }

    if (!opt[OPT_OUTPUT]) {
        printf("missing output imagefile\n");
        usage();
    }

    info.kernel = opt[OPT_KERNEL];
    info.initramfs = opt[OPT_INITRAMFS];
    info.trampoline = opt[OPT_TRAMPOLINE];
    info.memsize_mb = atoi(opt[OPT_MEMSIZE]);
    info.nr_vcpus = atoi(opt[OPT_VCPUS]);

    if (opt[OPT_PKEY]) {
        if (read_key(opt[OPT_PKEY], sign.private_key)) {
            printf("failed to read key file %s\n", opt[OPT_PKEY]);
            exit(1);
        }
    }

    if (opt[OPT_ROOTHASH]) {
        if (read_rhash(opt[OPT_ROOTHASH], info.roothash)) {
            printf("failed to read root hash file %s\n", opt[OPT_ROOTHASH]);
            exit(1);
        }
    }

    rc = attoimg_image_create_from_kernel_image(opt[OPT_PKEY] ? &sign : NULL, &info, opt[OPT_OUTPUT]);
    if (!rc) {
        printf("succesfully created attovm image %s\n", opt[OPT_OUTPUT]);
    } else {
        printf("error %d\n", rc);
    }
    return rc;
}

int sign_image(void)
{
    struct attoimg_image_sign_data sign;
    int rc;

    memset(&sign, 0, sizeof(sign));

    if (!opt[OPT_INPUT]) {
        printf("missing input imagefile\n");
        usage();
    }
    if (!opt[OPT_OUTPUT]) {
        printf("missing output imagefile\n");
        usage();
    }
    if (!opt[OPT_PKEY]) {
        printf("missing key file\n");
        usage();
    }

    if (read_key(opt[OPT_PKEY], sign.private_key)) {
        printf("failed to read key file %s\n", opt[OPT_PKEY]);
        exit(1);
    }

    rc = attoimg_image_sign_existing(&sign, opt[OPT_INPUT], opt[OPT_OUTPUT]);
    if (rc) {
        printf("error %d\n", rc);
        exit(1);
    }

    printf("signed: %s\n", opt[OPT_OUTPUT]);
    return 0;
}

int main(int argc, char **argv)
{
    int i = 0;
    int getopt = 0;
    int create = 0;
    int sign = 0;
    enum opt current_opt;

    for (i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (!getopt) {
            if (!strcmp(arg, "-k")) {
                getopt = 1;
                current_opt = OPT_KERNEL;
            } else if (!strcmp(arg, "-r")) {
                getopt = 1;
                current_opt = OPT_INITRAMFS;
            } else if (!strcmp(arg, "-t")) {
                getopt = 1;
                current_opt = OPT_TRAMPOLINE;
            } else if (!strcmp(arg, "-m")) {
                getopt = 1;
                current_opt = OPT_MEMSIZE;
            } else if (!strcmp(arg, "-v")) {
                getopt = 1;
                current_opt = OPT_VCPUS;
            } else if (!strcmp(arg, "-p")) {
                getopt = 1;
                current_opt = OPT_PKEY;
            } else if (!strcmp(arg, "-h")) {
                getopt = 1;
                current_opt = OPT_ROOTHASH;
            } else if (!strcmp(arg, "create")) {
                create = 1;
                getopt = 1;
                current_opt = OPT_OUTPUT;
            } else if (!strcmp(arg, "sign")) {
              sign = 1;
              getopt = 1;
              current_opt = OPT_INPUT;
            } else {
                printf("bad option: %s\n", arg);
                usage();
            }
        } else {
            opt[current_opt] = arg;
            getopt = 0;

            if (sign && current_opt == OPT_INPUT) {
              getopt = 1;
              current_opt = OPT_OUTPUT;
            }
        }
    }

    if (create)
        return create_image();
    else if (sign)
        return sign_image();
    else
        usage();
    return 0;
}
