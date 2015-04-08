/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Johannes Weiss <weiss@tux4u.de>
 * SPDX-License-Identifier: ISC
 */

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libimg.h"

volatile bool running = true;

static void usage(const char **argv)
{
    printf("%s: [-k] SWAP-FILE\n", argv[0]);
    printf("  -k: Keep alive (don't exit)\n");
}

static void sighandler(int signo, siginfo_t *siginfo, __unused void *context)
{
    running = false;
}

int main(int argc, const char **argv)
{
    struct sigaction sig_act;
    bool keep_alive = false;
    int argc_swapfile = 1;
    int r;
    BlockDriverState *bs;

    if (argc < 2) {
        usage(argv);
        exit(1);
    }

    if (0 == strcmp("-k", argv[1])) {
        argc_swapfile++;
        keep_alive = true;
    }
    char *src = malloc(strlen(argv[argc_swapfile])+6);
    strcpy(src, "swap:");
    strcat(src, argv[argc_swapfile]);

    ioh_init();
    bh_init();
    aio_init();
    bdrv_init();
    bs = bdrv_new(src);

    if (!bs) {
        printf("no bs\n");
        return -1;
    }

    r = bdrv_open(bs, src, BDRV_O_RDWR);
    if (r < 0) {
        fprintf(stderr, "brdv_open('%s') failed: %s.\n", src, strerror(errno));
        exit(1);
    }
    free(src);

    memset(&sig_act, 0, sizeof(struct sigaction));
    sig_act.sa_sigaction = &sighandler;
    sig_act.sa_flags = SA_SIGINFO;
    sigaction(SIGINT, &sig_act, NULL);
    sigaction(SIGTERM, &sig_act, NULL);

    while (keep_alive && running) {
        sleep(10000);
    }

    bdrv_delete(bs);

    printf("Exiting\n");

    return 0;
}
