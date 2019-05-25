/*
 * Copyright 2016-2019, Bromium, Inc.
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
#include <stdlib.h>
#include <string.h>
#include <poll.h>

#include <uxen-v4vlib.h>

#include "winlayouts.h"

#include "prototypes.h"

#define RING_SIZE 262144
#define V4V_PORT 44449

#define ATTO_MSG_GETURL 0
#define ATTO_MSG_GETURL_RET 1
#define ATTO_MSG_GETBOOT 2
#define ATTO_MSG_GETBOOT_RET 3
#define ATTO_MSG_RESIZE 4
#define ATTO_MSG_RESIZE_RET 5
#define ATTO_MSG_CURSOR_TYPE        6
#define ATTO_MSG_CURSOR_TYPE_RET    7
#define ATTO_MSG_CURSOR_CHANGE      8
#define ATTO_MSG_CURSOR_CHANGE_RET  9
#define ATTO_MSG_CURSOR_GET_SM      10
#define ATTO_MSG_CURSOR_GET_SM_RET  11
#define ATTO_MSG_KBD_LAYOUT         12
#define ATTO_MSG_KBD_LAYOUT_RET     13
#define ATTO_MSG_KBD_FOCUS          14
#define ATTO_MSG_KBD_FOCUS_RET      15

#define RESIZE_SCRIPT   "/usr/bin/x-resize.sh"

#undef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

struct atto_agent_msg {
    uint8_t type;
    union {
        char string[512];
        struct {
            uint32_t xres;
            uint32_t yres;
        };
        unsigned win_kbd_layout;
        unsigned offer_kbd_focus;
    };
} __attribute__((packed));

/* See struct atto_agent_varlen_packet in C:\dev\uxen\xen\dm\atto-agent.c */
struct long_msg_t {
    struct atto_agent_msg msg;
    char extra[RING_SIZE - 4096 - sizeof(struct atto_agent_msg) - 1];
    char null;
} __attribute__((packed));

#define MAX_NUMBER_FDS  256

static struct long_msg_t long_msg;
static struct pollfd poll_fds[MAX_NUMBER_FDS];
static int npollfds = 0;

int pollfd_add (int fd)
{
    int i;

    for (i = 0; i < ARRAY_SIZE (poll_fds); i++) {
        if (poll_fds[i].fd == -1) {
            poll_fds[i].fd = fd;
            poll_fds[i].events = POLLIN;
            poll_fds[i].revents = 0;
            npollfds++;
            return 0;
        }
    }

    return -1;
}

int pollfd_remove (int fd)
{
    int i, j;

    for (i = 0; i < ARRAY_SIZE (poll_fds); i++) {
        if (poll_fds[i].fd == -1)
            break;
        if (poll_fds[i].fd == fd) {
            poll_fds[i].fd = -1;
            poll_fds[i].events = 0;
            poll_fds[i].revents = 0;
            for (j = i + 1; j < ARRAY_SIZE (poll_fds); j++) {
                if (poll_fds[j].fd == -1)
                    break;
                poll_fds[j-1] = poll_fds[j];
                poll_fds[j].fd = -1;
            }
            npollfds--;
            return 0;
        }
    }

    return -1;
}

void
talk(int fd, int request)
{
    struct atto_agent_msg *msg = &long_msg.msg;
    ssize_t len;

    msg->type = request;

    len = send(fd, msg, sizeof(*msg), 0);
    if (len < 0)
        err(1, "send error %d\n", errno);
    for (;;) {
        len = recv(fd, &long_msg, sizeof(long_msg), 0);
        if (len < 0)
            err(1, "recv error %d\n", errno);
        if (len < sizeof(*msg))
            err(1, "short recv, %d < %d\n", (int) len, (int) sizeof(*msg));
        if (msg->type != request + 1)
            continue;
        break;
    }

    if (msg->type == ATTO_MSG_RESIZE)
        return;

    long_msg.null = 0; /* Null terminate just in case */
    printf("%s\n", msg->string);
}

void
event_loop(int fd)
{
    struct atto_agent_msg msg;
    ssize_t len;
    static int32_t lastx = 0, lasty = 0;
    int32_t w, h;
    char command[1024];
    int i, event_fds[MAX_NUMBER_FDS], nevent_fds;

    msg.type = ATTO_MSG_RESIZE;
    len = send(fd, &msg, sizeof(msg), 0);
    if (len < 0)
        err(1, "send error %d\n", errno);

    memset (&poll_fds, 0, sizeof (poll_fds));
    for (i = 0; i < ARRAY_SIZE(poll_fds); i++)
        poll_fds[i].fd = -1;

    pollfd_add (fd);
    prot_kbd_init ();

    for (;;) {
        if (poll(poll_fds, npollfds, -1) < 0) {
            if (errno != EINTR)
                err(1, "poll %d", (int) errno);
            continue;
        }

        nevent_fds = 0;
        for (i = 1; i < npollfds; i++) {
            if ((poll_fds[i].revents & POLLIN)) {
                event_fds[nevent_fds++] = poll_fds[i].fd;
                poll_fds[i].revents = 0;
            }
        }

        for (i = 0; i < nevent_fds; i++)
            prot_kbd_event(event_fds[i]);

        if (!(poll_fds[0].revents & POLLIN))
            continue;
        poll_fds[0].revents = 0;

        len = recv(fd, &msg, sizeof(msg), 0);
        if (len < 0)
            err(1, "recv error %d\n", errno);
        if (len != sizeof(msg))
            err(1, "short recv, %d != %d\n", (int) len, (int) sizeof(msg));

        switch(msg.type) {
        case ATTO_MSG_RESIZE_RET:
            w = (int32_t) msg.xres;
            h = (int32_t) msg.yres;

            if (w == 0 || h == 0)
                continue;

            if (lastx && abs(w-lastx) < 3 && lasty && abs(h-lasty) < 3)
                continue;
            lastx = w;
            lasty = h;
            memset(command, 0, sizeof(command));
            snprintf(command, sizeof(command) - 1,
                     "%s %d %d", RESIZE_SCRIPT,
                     (int) w, (int) h);
            system(command);
            break;
        case ATTO_MSG_KBD_LAYOUT_RET:
        {
            int i;

            for (i = 0;; i++) {
                WinKBLayoutRec *lrec;

                lrec = &winKBLayouts[i];
                if (lrec->winlayout == (unsigned int) (-1) ||
                    lrec->xkbmodel == NULL) {

                    break;
                }

                if (lrec->winlayout == msg.win_kbd_layout) {
                    memset(command, 0, sizeof(command));
                    if (lrec->xkblayout && lrec->xkbvariant) {
                        snprintf(command, sizeof(command) - 1,
                                 "DISPLAY=:0.0 /usr/bin/setxkbmap -model %s -layout %s -variant %s",
                                 lrec->xkbmodel, lrec->xkblayout, lrec->xkbvariant);
                    } else if (lrec->xkblayout) {
                        snprintf(command, sizeof(command) - 1,
                                 "DISPLAY=:0.0 /usr/bin/setxkbmap -model %s -layout %s",
                                 lrec->xkbmodel, lrec->xkblayout);
                    } else {
                        snprintf(command, sizeof(command) - 1,
                                 "DISPLAY=:0.0 /usr/bin/setxkbmap -model %s", lrec->xkbmodel);
                    }
                    system(command);
                    break;
                }
            }
        }
        break;
        case ATTO_MSG_KBD_FOCUS_RET:
            prot_kbd_focus_request (msg.offer_kbd_focus);
            break;
        default:
            warnx("unknown message type %d", (int) msg.type);
            break;
        }
    }
}

int main(int argc, char **argv)
{
    int fd;
    struct sockaddr_vm addr;
    int daemon = 0;
    int request = 0;

    if (argc < 2)
        err(1, "bad args");
    if (!strcmp(argv[1], "get-url")) {
        request = ATTO_MSG_GETURL;
    } else if (!strcmp(argv[1], "get-boot")) {
        request = ATTO_MSG_GETBOOT;
    } else if (!strcmp(argv[1], "resize")) {
        request = ATTO_MSG_RESIZE;
    } else if (!strcmp(argv[1], "daemon")) {
        daemon = 1;
    } else
        err(1, "bad args");

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

    if (!daemon)
        talk(fd, request);
    else
        event_loop(fd);

    close(fd);

    return 0;
}
