/*
 * Copyright 2016, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
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

#define V4V_PORT 44449

#define ATTO_MSG_GETURL 0
#define ATTO_MSG_GETURL_RET 1

struct atto_agent_msg {
    uint8_t type;
    union {
        char string[4096];
    };
} __attribute__((packed));

void
talk(int fd)
{
    struct atto_agent_msg msg;
    ssize_t len;

    msg.type = ATTO_MSG_GETURL;

    len = send(fd, &msg, sizeof(msg), 0);
    if (len < 0)
        err(1, "send error %d\n", errno);
    len = recv(fd, &msg, sizeof(msg), 0);
    if (len < 0)
        err(1, "recv error %d\n", errno);
    if (len != sizeof(msg))
        err(1, "short recv, %d != %d\n", len, sizeof(msg));
    if (msg.type != ATTO_MSG_GETURL_RET)
        err(1, "bad msg type %d\n", msg.type);
    printf("URL: %s\n", msg.string);
}

int main(int argc, char **argv)
{
    int fd;
    struct sockaddr_vm addr;
    int tx = 1;

    fd = socket(AF_VSOCK, SOCK_DGRAM, 0);
    if (fd < 0)
        err(1, "socket");

    memset(&addr, 0, sizeof(addr));
    addr.family = AF_VSOCK;
    addr.partner = V4V_DOMID_DM;
    addr.v4v.domain = V4V_DOMID_DM;
    addr.v4v.port = V4V_PORT;

    if (bind(fd, (const struct sockaddr *) &addr, sizeof(addr)) < 0)
        err(1, "bind %d", (int) errno);

    if (connect(fd, (const struct sockaddr *) &addr, sizeof(addr)) < 0)
        err(1, "connect %d", (int) errno);
    talk(fd);

    close(fd);

    return 0;
}
