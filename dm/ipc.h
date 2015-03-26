/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _IPC_H_
#define _IPC_H_

struct ipc_service;

struct ipc_client {
    struct ipc_service *owner;
    int disconnected;
#if defined(_WIN32)
    uint8_t buffer[2048];
    DWORD buf_pos, buf_len;
    OVERLAPPED read_evt, write_evt;
    HANDLE pipe;
    ULONG pid;
#elif defined(__APPLE__)
    int out_fd, in_fd;
    int sock;
#endif
    TAILQ_ENTRY(ipc_client) link;
};

struct ipc_service_ops {
    int (*connect)(struct ipc_client *, void *);
    void (*disconnect)(struct ipc_client *, void *);
    void (*data_pending)(struct ipc_client *, void *);
};

struct ipc_service {
    struct ipc_service_ops *ops;
    size_t client_size;
    char *path;
    void *opaque;
#if defined(_WIN32)
    OVERLAPPED conn_evt;
    HANDLE pipe;
#elif defined(__APPLE__)
    int sock;
#endif
    TAILQ_HEAD(, ipc_client) clients;
};

int ipc_service_init(struct ipc_service *s, const char *path,
                     struct ipc_service_ops *ops, size_t client_size,
                     void *opaque);
void ipc_service_cleanup(struct ipc_service *s);

void ipc_client_close(struct ipc_client *c);
uintptr_t ipc_client_share(struct ipc_client *c, uintptr_t handle);
int ipc_client_recv(struct ipc_client *c, void *buf, size_t len);
int ipc_client_send(struct ipc_client *c, void *buf, size_t len);

#endif /* _IPC_H_ */
