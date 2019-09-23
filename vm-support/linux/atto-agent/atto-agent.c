/*
 * Copyright 2016-2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#define _GNU_SOURCE /* for fallocate */

#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <fcntl.h>

#include <uxen-v4vlib.h>

#include "../../../common/include/atto-agent-protocol.h"
#include "atto-agent.h"

#define RING_SIZE 262144

#define RESIZE_SCRIPT   "/usr/bin/x-resize.sh"

#undef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* See struct atto_agent_varlen_packet in C:\dev\uxen\xen\dm\atto-agent.c */
struct long_msg_t {
    struct atto_agent_msg msg;
    char extra[RING_SIZE - 4096 - sizeof(struct atto_agent_msg) - 1];
    char null;
} __attribute__((packed));

#define MAX_NUMBER_FDS  256

volatile shared_state_t *shared_state;
static int shared_state_fd;

static struct pollfd poll_fds[MAX_NUMBER_FDS];
static int npollfds = 0;
static int polltimeout = -1;


static void run_head_cmd(head_id_t head, void *opaque)
{
    const char *cmd = opaque;

    headctl_system_cmd(head, cmd);
}

static int update_x_kbd_layout(void)
{
    kbd_layout_t win_kbd_layout = get_active_kbd_layout();
    char command[256];
    int ret;

    ret = get_x_update_kbd_layout_command(win_kbd_layout, command, sizeof(command));
    if (ret)
        return ret;

    headctl_for_each_head(run_head_cmd, command);

    return 0;
}


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

void atto_agent_reset_kbd_layout(void)
{
    update_x_kbd_layout();
}

int sync_shared_state(void)
{
    return msync((void*)shared_state, sizeof(*shared_state), MS_SYNC | MS_INVALIDATE);
}

int lock_shared_state(void)
{
    return flock(shared_state_fd, LOCK_EX);
}

void unlock_shared_state(void)
{
    flock(shared_state_fd, LOCK_UN);
}

static void init_shared_state(void)
{
    int fd = open(SHARED_STATE_FILE, O_RDWR | O_CLOEXEC);
    int existed = 1;

    if (fd < 0) {
        fd = open(SHARED_STATE_FILE, O_RDWR | O_CREAT | O_CLOEXEC, 00644);
        if (fd < 0)
            err(1, "open shared state %d", (int) errno);

        if (fallocate(fd, 0, 0, sizeof(*shared_state)))
            err(1, "fallocated %d", (int) errno);

        existed = 0;
    }

    shared_state = mmap(NULL, sizeof(*shared_state), PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, 0);
    if (!shared_state)
        err(1, "map shared state %d", (int) errno);

    shared_state_fd = fd;

    if (!existed) {
        lock_shared_state();
        memset((void*)shared_state, 0, sizeof(*shared_state));
        shared_state->active_layout = KBD_LAYOUT_INVALID;
        sync_shared_state();
        unlock_shared_state();
    }
}

void
talk(int fd, int request)
{
    struct long_msg_t long_msg;
    struct atto_agent_msg *msg = &long_msg.msg;
    ssize_t len;

    memset(&long_msg, 0, sizeof(long_msg));
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
event_loop(int fd, int protkbd)
{
    struct atto_agent_msg msg;
    ssize_t len;
    int32_t w, h, head;
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
    kbd_init (protkbd);
    headctl_init ();

    for (;;) {
        polltimeout = -1;
        kbd_wakeup(&polltimeout);
        headctl_wakeup(&polltimeout);
        if (poll(poll_fds, npollfds, polltimeout) < 0) {
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
            kbd_event(event_fds[i]);

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
            head = (int32_t) msg.head_id;

            if (w == 0 || h == 0)
                continue;

            memset(command, 0, sizeof(command));
            snprintf(command, sizeof(command) - 1,
                     "%s %d %d %d", RESIZE_SCRIPT,
                     (int) w, (int) h, (int)head);
            system(command);
            break;
        case ATTO_MSG_KBD_LAYOUT_RET:
            set_active_kbd_layout((kbd_layout_t)msg.win_kbd_layout);
            update_x_kbd_layout();
            break;
        case ATTO_MSG_KBD_FOCUS_RET:
            kbd_focus_request (msg.offer_kbd_focus);
            if (msg.offer_kbd_focus)
                headctl_activate (msg.head_id);
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
    int protkbd = 0;
    int do_headctl = 0;

    init_shared_state();

    if (argc < 2)
        err(1, "bad args");
    if (!strcmp(argv[1], "headctl")) {
        do_headctl = 1;
    } else if (!strcmp(argv[1], "get-url")) {
        request = ATTO_MSG_GETURL;
    } else if (!strcmp(argv[1], "get-boot")) {
        request = ATTO_MSG_GETBOOT;
    } else if (!strcmp(argv[1], "resize")) {
        request = ATTO_MSG_RESIZE;
    } else if (!strcmp(argv[1], "daemon")) {
        daemon = 1;
        if (argc > 2 && !strcmp(argv[2], "--protkbd")) {
            protkbd = 1;
        }
    } else
        err(1, "bad args");

    if (do_headctl) {
        headctl(argc, argv);
        return 0;
    }

    fd = socket(AF_VSOCK, SOCK_DGRAM, 0);
    if (fd < 0)
        err(1, "socket");

    memset(&addr, 0, sizeof(addr));
    addr.family = AF_VSOCK;
    addr.partner = V4V_DOMID_DM;
    addr.v4v.domain = V4V_DOMID_DM;
    addr.v4v.port = ATTO_AGENT_V4V_PORT;

    if (bind(fd, (const struct sockaddr *) &addr, sizeof(addr)) < 0)
        err(1, "bind %d", (int) errno);

    if (connect(fd, (const struct sockaddr *) &addr, sizeof(addr)) < 0)
        err(1, "connect %d", (int) errno);

    if (!daemon)
        talk(fd, request);
    else
        event_loop(fd, protkbd);

    close(fd);

    return 0;
}
