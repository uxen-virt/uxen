/*
 * Copyright 2014-2017, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <termios.h>
#include <util.h>
#include <sys/ioctl.h>
#endif

#include "qemu_glue.h"

#include "ioh.h"
#include "timer.h"

#include "ipc.h"

#if defined(__APPLE__)
static void unix_socket_read_handler(void *opaque)
{
    struct ipc_client *c = opaque;
    struct ipc_service *s = c->owner;

    s->ops->data_pending(c, s->opaque);
    if (c->disconnected)
        s->ops->disconnect(c, s->opaque);
}

static void unix_socket_connect_handler(void *opaque)
{
    struct ipc_service *s = opaque;
    int sock;
    int ret, sockopt;
    struct sockaddr_un sun;
    socklen_t len;
    struct ipc_client *c;

    len = sizeof(sun);
    sock = accept(s->sock, (void *)&sun, &len);
    if (sock <  0) {
        warn("accept");
        return;
    }

    sockopt = 1;
    ret = setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE,  &sockopt,
                     sizeof (sockopt));
    if (ret) {
        warn("setsockopt");
        close(sock);
        return;
    }

    c = calloc(1, s->client_size);
    if (!c) {
        close(sock);
        return;
    }

    c->disconnected = 0;
    c->out_fd = c->in_fd = -1;
    ioh_set_read_handler(sock, NULL, unix_socket_read_handler, c);
    c->sock = sock;
    c->owner = s;
    TAILQ_INSERT_TAIL(&s->clients, c, link);

    s->ops->connect(c, s->opaque);
}

static int unix_socket_create(struct ipc_service *s)
{
    int rc;
    struct sockaddr_un sun;

    s->sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s->sock == -1) {
        warn("socket");
        return -1;
    }

    sun.sun_family = AF_UNIX;
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", s->path);
    unlink(s->path);
    rc = bind(s->sock, (void *)&sun, sizeof(sun));
    if (rc < 0) {
        warn("bind");
        close(s->sock);
        s->sock = -1;
        return -1;
    }

    rc = listen(s->sock, 1);
    if (rc < 0) {
        warn("listen");
        close(s->sock);
        s->sock = -1;
        return -1;
    }

    ioh_set_read_handler(s->sock, NULL, unix_socket_connect_handler, s);

    return 0;
}

static void unix_socket_share_fd(struct ipc_client *c, int fd)
{
    c->out_fd = fd;
}

static int unix_socket_send(struct ipc_client *c, void *buf, size_t len)
{
    struct msghdr msg;
    struct iovec iov;
    struct {
        struct cmsghdr hdr;
        int fd;
    } cmsgbuf;
    int rc;

    if (c->disconnected)
        return 0;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;

    msg.msg_control = NULL;
    msg.msg_controllen = 0;

    if (c->out_fd != -1) {
        cmsgbuf.hdr.cmsg_len = sizeof(cmsgbuf);
        cmsgbuf.hdr.cmsg_level = SOL_SOCKET;
        cmsgbuf.hdr.cmsg_type = SCM_RIGHTS;
        cmsgbuf.fd = c->out_fd;

        msg.msg_control = &cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);
        c->out_fd = -1;
    }

    iov.iov_base = (void *)buf;
    iov.iov_len = len;

    while (iov.iov_len) {
        rc = sendmsg(c->sock, &msg, 0);
        switch (rc) {
        case -1:
            if (errno != EPIPE) {
                warn("sendmsg");
                return -1;
            }
            /* Fall-through */
        case 0:
            c->disconnected = 1;
            break;
        default:
            iov.iov_base += rc;
            iov.iov_len -= rc;
        }

        msg.msg_control = NULL;
        msg.msg_controllen = 0;

        if (c->disconnected)
            break;
    }

    return len - iov.iov_len;
}

static int unix_socket_recv(struct ipc_client *c, void *buf, size_t len)
{
    struct msghdr msg;
    struct iovec iov;
    struct {
        struct cmsghdr hdr;
        int fd;
    } cmsgbuf;
    int rc;

    if (c->disconnected)
        return 0;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = &cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    iov.iov_base = buf;
    iov.iov_len = len;

    memset(&cmsgbuf, 0, sizeof(cmsgbuf));

    rc = recvmsg(c->sock, &msg, 0);
    if (rc == -1)
        warn("recvmsg");
    else if (!rc)
        c->disconnected = 1;

    if (cmsgbuf.hdr.cmsg_len &&
        cmsgbuf.hdr.cmsg_level == SOL_SOCKET &&
        cmsgbuf.hdr.cmsg_type == SCM_RIGHTS) {
        if (c->in_fd != -1)
            close(c->in_fd);
        c->in_fd = cmsgbuf.fd;
    }

    return rc;
}

static void unix_socket_close(struct ipc_client *c)
{
    if (c->in_fd != -1) {
        close(c->in_fd);
        c->in_fd = -1;
    }
    close(c->sock);
    ioh_set_read_handler(c->sock, NULL, NULL, c);
    c->sock = -1;
}

static void unix_socket_destroy(struct ipc_service *s)
{
    close(s->sock);
    ioh_set_read_handler(s->sock, NULL, NULL, s);
    s->sock = -1;
}
#elif defined(_WIN32)
static void win32_pipe_read_handler(void *opaque)
{
    struct ipc_client *c = opaque;
    struct ipc_service *s = c->owner;
    DWORD l;
    BOOL rc;

    rc = GetOverlappedResult(c->pipe, &c->read_evt, &l, FALSE);
    while (rc == TRUE) {
        c->buf_len = l;
        while (c->buf_pos < c->buf_len)
            s->ops->data_pending(c, s->opaque);
        c->buf_pos = c->buf_len = 0;
        rc = ReadFile(c->pipe, c->buffer, sizeof(c->buffer), &l, &c->read_evt);
    }
    if (GetLastError() != ERROR_IO_PENDING)
        c->disconnected = 1;

    if (c->disconnected)
        s->ops->disconnect(c, s->opaque);
}

static HANDLE win32_pipe_create_helper(const char *path,
                                       OVERLAPPED *overlapped)
{
    HANDLE pipe;
    DWORD err;
    BOOL res;

    pipe = CreateNamedPipe(path,
                           PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                           PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
                           PIPE_WAIT,
                           PIPE_UNLIMITED_INSTANCES,
                           2048, 2048, 5000,
                           NULL);
    if (!pipe) {
        Wwarn("CreateNamedPipe");
        return NULL;
    }
    debug_printf("connecting named pipe: %s\n", path);
    res = ConnectNamedPipe(pipe, overlapped);
    err = GetLastError();
    if (!res && (err != ERROR_IO_PENDING) && (err != ERROR_PIPE_CONNECTED)) {
        Wwarn("ConnectNamedPipe");
        CloseHandle(pipe);
        return NULL;
    }
    debug_printf("pipe connected\n");

    return pipe;
}

static void win32_pipe_connect_handler(void *opaque)
{
    struct ipc_service *s = opaque;
    struct ipc_client *c;
    DWORD l;
    BOOL rc;
    HANDLE client_pipe;

    if (!GetOverlappedResult(s->pipe, &s->conn_evt, &l, TRUE)) {
        Wwarn("GetOverlappedResult");
        return;
    }

    client_pipe = s->pipe;
    s->pipe = win32_pipe_create_helper(s->path, &s->conn_evt);
    if (!s->pipe) {
        DisconnectNamedPipe(client_pipe);
        CloseHandle(client_pipe);
        return;
    }

    c = calloc(1, s->client_size);
    if (!c)
        return;

    c->disconnected = 0;
    c->owner = s;
    c->pipe = client_pipe;
    if (!GetNamedPipeClientProcessId(client_pipe, &c->pid)) {
        Wwarn("GetNamedPipeClientProcessId");
        free(c);
        DisconnectNamedPipe(client_pipe);
        CloseHandle(client_pipe);
        return;
    }

    c->read_evt.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    c->write_evt.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    ioh_add_wait_object(&c->read_evt.hEvent, win32_pipe_read_handler, c,
                        NULL);

    TAILQ_INSERT_TAIL(&s->clients, c, link);

    s->ops->connect(c, s->opaque);

    c->buf_pos = c->buf_len = 0;
    rc = ReadFile(c->pipe, c->buffer, sizeof(c->buffer), &l, &c->read_evt);
    while (rc == TRUE) {
        c->buf_len = l;
        while (c->buf_pos < c->buf_len)
            s->ops->data_pending(c, s->opaque);
        c->buf_pos = c->buf_len = 0;
        rc = ReadFile(c->pipe, c->buffer, sizeof(c->buffer), &l, &c->read_evt);
    }
    if (GetLastError() != ERROR_IO_PENDING)
        c->disconnected = 1;

    if (c->disconnected)
        s->ops->disconnect(c, s->opaque);
}

static int win32_pipe_create(struct ipc_service *s)
{
    s->conn_evt.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    ioh_add_wait_object(&s->conn_evt.hEvent, win32_pipe_connect_handler, s,
                        NULL);

    s->pipe = win32_pipe_create_helper(s->path, &s->conn_evt);
    if (!s->pipe) {
        CloseHandle(s->conn_evt.hEvent);
        ioh_del_wait_object(&s->conn_evt.hEvent, NULL);
        s->conn_evt.hEvent = NULL;
        return -1;
    }

    return 0;
}

static HANDLE win32_pipe_share_handle(struct ipc_client *c, HANDLE handle)
{
    HANDLE proc, dup;
    BOOL rc;

    if (c->disconnected)
        return NULL;

    proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, c->pid);
    if (!proc)
        return NULL;
    rc = DuplicateHandle(GetCurrentProcess(), handle, proc,
                         &dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
    CloseHandle(proc);
    if (!rc)
        dup = NULL;

    return dup;
}

static int win32_pipe_recv(struct ipc_client *c, void *buf, size_t len)
{
    size_t l;

    l = c->buf_len - c->buf_pos;
    if (l > len)
        l = len;

    memcpy(buf, c->buffer + c->buf_pos, l);
    c->buf_pos += l;

    return l;
}

static int win32_pipe_send(struct ipc_client *c, void *buf, size_t len)
{
    BOOL rc;
    DWORD count;
    DWORD l = 0;

    if (c->disconnected)
        return 0;

    while (l < len) {
        rc = WriteFile(c->pipe, buf + l, len - l, NULL, &c->write_evt);
        if (rc)
            return len;

        if (GetLastError() != ERROR_IO_PENDING ||
            !GetOverlappedResult(c->pipe, &c->write_evt, &count, TRUE)) {
            c->disconnected = 1;
            break;
        }
        l += count;
    }

    return l;
}

static void win32_pipe_close(struct ipc_client *c)
{
    ioh_del_wait_object(&c->read_evt.hEvent, NULL);
    CloseHandle(c->read_evt.hEvent);
    CloseHandle(c->write_evt.hEvent);
    DisconnectNamedPipe(c->pipe);
    CloseHandle(c->pipe);
    c->pipe = NULL;
}

static void win32_pipe_destroy(struct ipc_service *s)
{
    ioh_del_wait_object(&s->conn_evt.hEvent, NULL);
    CloseHandle(s->conn_evt.hEvent);
    CloseHandle(s->pipe);
    s->pipe = NULL;
}
#endif

uintptr_t ipc_client_share(struct ipc_client *c, uintptr_t handle)
{
#if defined(__APPLE__)
    unix_socket_share_fd(c, (int)handle);
    return handle;
#elif defined(_WIN32)
    return (uintptr_t)win32_pipe_share_handle(c, (HANDLE)handle);
#endif
}

int ipc_client_recv(struct ipc_client *c, void *buf, size_t len)
{
#if defined(__APPLE__)
    return unix_socket_recv(c, buf, len);
#elif defined(_WIN32)
    return win32_pipe_recv(c, buf, len);
#endif
}

int ipc_client_send(struct ipc_client *c, void *buf, size_t len)
{
#if defined(__APPLE__)
    return unix_socket_send(c, buf, len);
#elif defined(_WIN32)
    return win32_pipe_send(c, buf, len);
#endif
}

void ipc_client_close(struct ipc_client *c)
{
    struct ipc_service *s = c->owner;

#if defined(__APPLE__)
    unix_socket_close(c);
#elif defined(_WIN32)
    win32_pipe_close(c);
#endif

    TAILQ_REMOVE(&s->clients, c, link);
    free(c);
}

int ipc_service_init(struct ipc_service *s, const char *path,
                     struct ipc_service_ops *ops, size_t client_size,
                     void *opaque)
{
    if (client_size < sizeof(struct ipc_client))
        return -1;

    memset(s, 0, sizeof(*s));
    s->ops = ops;
    s->client_size = client_size;
    s->opaque = opaque;
    TAILQ_INIT(&s->clients);

    debug_printf("initializing ipc service, path=%s\n", path);
#if defined(__APPLE__)
    s->path = strdup(path);
    if (unix_socket_create(s)) {
        free(s->path);
        return -1;
    }
#elif defined(_WIN32)
    asprintf(&s->path, "\\\\.\\pipe\\%s", path);
    if (win32_pipe_create(s)) {
        free(s->path);
        return -1;
    }
#endif

    return 0;
}

void ipc_service_cleanup(struct ipc_service *s)
{
    struct ipc_client *c, *cn;

    TAILQ_FOREACH_SAFE(c, &s->clients, link, cn)
        s->ops->disconnect(c, s->opaque); /* Must call client_close() */
    assert(TAILQ_EMPTY(&s->clients));

#if defined(__APPLE__)
    unix_socket_destroy(s);
#elif defined(_WIN32)
    win32_pipe_destroy(s);
#endif
    free(s->path);
    s->path = NULL;
}

