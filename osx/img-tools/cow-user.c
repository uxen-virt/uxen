/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

//
//  cow-user.c
//  copy-on-write
//
//  Created by Phillip Jordan on 25/02/2013.
//  Copyright (c) 2013 Bromium UK Ltd. All rights reserved.
//

#include "cow-user.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/errno.h>

static uint32_t kern_ctl_id_for_name(int sys_socket_fd,
                                     const char *kctl_name)
{
    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    strncpy(info.ctl_name, kctl_name, sizeof(info.ctl_name));
    if (ioctl(sys_socket_fd, CTLIOCGINFO, &info)) {
        perror("Could not get ID for kernel control.\n");
        exit(-1);
    }
    return info.ctl_id;
}

static int connect_kern_ctl_socket(const char *kctl_name, int type)
{
    int fd = socket(PF_SYSTEM, type, SYSPROTO_CONTROL);

    if (fd == -1)
        return fd;

    struct sockaddr_ctl addr;
    bzero(&addr, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = 0;

    addr.sc_id = kern_ctl_id_for_name(fd, kctl_name);

    int err = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
    if (err) {
        fprintf(stderr,
                "Failed to connect to kernel control socket: %d (%s)\n",
                errno, strerror(errno));
        close(fd);
        fd = -1;
    }
    return fd;
}

int cow_connect_socket(void)
{
    return connect_kern_ctl_socket(BR_COPY_ON_WRITE_KCONTROL_SOCKET_NAME,
                                   SOCK_DGRAM);
}

int cow_set_target_path(int fd, const char *path)
{
    size_t path_len = strlen(path);
    if (path_len > UINT32_MAX)
        return EOVERFLOW;
    return setsockopt(fd, SYSPROTO_CONTROL, COW_CTL_CopyTargetPath, path,
                      (socklen_t) path_len);
}

static inline int cmp_file_id(const void *a, const void *b)
{
    const copy_on_write_file_id_t *ia = a;
    const copy_on_write_file_id_t *ib = b;
    if (ia->cnid < ib->cnid)
        return -1;
    else if (ia->cnid == ib->cnid)
        return 0;
    else
        return 1;
}

int cow_set_watchlist(int fd, const uint64_t * file_ids,
                      uint32_t num_file_ids)
{
    int r;
    uint32_t i, j;
    copy_on_write_file_id_t *ids = malloc(sizeof(copy_on_write_file_id_t) *
            num_file_ids);
    if (!ids) {
        return -1;
    }

    for (i = 0; i < num_file_ids; ++i) {
        ids[i].cnid = (uint32_t) file_ids[i];
        ids[i].id = i;
        ids[i].state = 0;
    }

    /* sort | uniq on file id list. */
    qsort(ids, num_file_ids, sizeof(copy_on_write_file_id_t), cmp_file_id);
    for (i = j = 0; i < num_file_ids; ++i) {
        if (i == 0 || ids[i - 1].cnid != ids[i].cnid) {
            ids[j++] = ids[i];
        }
    }
    r = setsockopt(fd, SYSPROTO_CONTROL, COW_CTL_CNIDWatchList,
                      ids, sizeof(copy_on_write_file_id_t) * j);
    free(ids);
    return r;
}

int cow_start_receiving_file_events(int fd)
{
    return setsockopt(fd, SYSPROTO_CONTROL,
                      COW_CTL_StartReceivingFileEvents, NULL, 0);
}

int cow_stop_receiving_file_events(int fd)
{
    return setsockopt(fd, SYSPROTO_CONTROL,
                      COW_CTL_StopReceivingFileEvents, NULL, 0);
}

// Returns 0 for valid link request, ESHUTDOWN if kext is shutting down, or other error
int cow_wait_for_link_request(int fd, copy_on_write_link_request_t * rq)
{
    socklen_t len = sizeof(*rq);
    return getsockopt(fd, SYSPROTO_CONTROL, COW_CTL_WatchedLinkRequest, rq,
                      &len);
}

// Returns 0 for valid link response, ESHUTDOWN if kext is shutting down, or other error
int cow_send_link_response(int fd,
                           const copy_on_write_link_response_t * res)
{
    socklen_t len = sizeof(*res);

    return setsockopt(fd, SYSPROTO_CONTROL, COW_CTL_WatchedLinkRequest,
                      res, len);

}
