/*
 * Copyright 2016-2019, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>

#include "../include/uxen-v4vlib.h"

#define PORT 10000
#define PACKET_SIZE 16384

struct foo {
    uint64_t bytes;
    uint64_t start;
    uint64_t last;
};

static char buf[PACKET_SIZE];

static uint64_t get_tick_count_64(void)
{
    struct timeval tv;

    memset(&tv, 0, sizeof(tv));
    gettimeofday(&tv, NULL);

    return ((uint64_t) tv.tv_sec) * 1000 + ((uint64_t) tv.tv_usec) / 1000;
}

static inline void
start_foo(struct foo *foo)
{
    foo->last = foo->start = get_tick_count_64();
}

static inline void
do_foo (struct foo *foo)
{
    uint64_t now = get_tick_count_64();
    char unit = 'k';
    float f;

    if ((now - foo->last) < 5000)
        return;
    foo->last = now;

    now -= foo->start;

    if (!now)
        return;

    f = (float) foo->bytes;
    f *= 8000.;
    f = f / (float) now;


    if (f > 1E9) {
        f = f / 1.E9;
        unit = 'G';
    }


    if (f > 1E6) {
        f = f / 1.E9;
        unit = 'M';
    }

    if (f > 1E3) {
        f = f / 1.E3;
        unit = 'k';
    }

    printf("%.3f %cbits/s\n", f, unit);

}


static void read_thread(int fd)
{
    ssize_t len;
    struct foo foo = { 0 };
    int red = 0;

    printf("listening for data\n");

    for (;;) {
        len = recv(fd, buf, PACKET_SIZE, 0);
        if (len < 0) {
            warn("recv error");
            break;
        }

        if (!foo.start)
            start_foo(&foo);

        foo.bytes += len;
        do_foo(&foo);

        red++;
    }
}

static void write_thread(int fd)
{
    struct foo foo = { 0 };
    ssize_t writ;
    struct pollfd pl;

    pl.fd = fd;
    pl.events = POLLOUT;

    start_foo(&foo);

    for (;;) {

        pl.revents = 0;
        poll(&pl, 1, -1);
        writ = send(fd, buf, PACKET_SIZE, 0);
        if (writ < 0)
            warn("send error %d", errno);
        if (writ > 0) {
            foo.bytes += writ;
            do_foo(&foo);
        }
    }
}

int main(int argc, char **argv)
{
    int fd;
    struct sockaddr_vm addr;
    int tx = 1;

    if (argc > 1 && !strcmp (argv[1], "rx"))
        tx = 0;

    fd = socket(AF_VSOCK, SOCK_DGRAM, 0);
    if (fd < 0)
        err(1, "socket");

    memset(&addr, 0, sizeof(addr));
    addr.family = AF_VSOCK;
    addr.partner = 0;
    addr.v4v.port = PORT;

    if (bind(fd, (const struct sockaddr *) &addr, sizeof(addr)) < 0)
        err(1, "bind %d", (int) errno);

    addr.v4v.domain = V4V_DOMID_DM;
    addr.v4v.port = PORT;
    if (connect(fd, (const struct sockaddr *) &addr, sizeof(addr)) < 0)
        err(1, "connect %d", (int) errno);
    if (tx)
        write_thread(fd);
    else
        read_thread(fd);

    close(fd);

    return 0;
}
