/*
 * Copyright 2014-2019, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <errno.h>
#endif

#include "uxenconsolelib.h"
#include "console-rpc.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>


#define BUF_SZ 1024

struct ctx {
    struct uxenconsole_ops *ops;
    void *priv;

    char *buf;
    size_t buf_len;
    size_t msg_len;

    char *filename;

#if defined(_WIN32)
    HANDLE pipe;
    OVERLAPPED oread;
    char read_buf[BUF_SZ];
    struct sndbuf {
        struct sndbuf *next;
        struct sndbuf **pprev;
        OVERLAPPED ovlp;
        size_t len;
    } *sndlist_first, **sndlist_last;
    CRITICAL_SECTION sndlock;
#elif defined(__APPLE__)
    int socket;
    int recvd_fd;
#endif
};

uxenconsole_context_t
uxenconsole_init(ConsoleOps *console_ops, void *console_priv, char *filename)
{
    struct ctx *c;

    c = calloc(1, sizeof (*c));
    if (!c)
        return NULL;

    c->ops = console_ops;
    c->priv = console_priv;
    c->filename = filename;
#if defined(_WIN32)
    c->sndlist_first = NULL;
    c->sndlist_last = &c->sndlist_first;
    InitializeCriticalSection(&c->sndlock);
#elif defined(__APPLE__)
    c->socket = -1;
    c->recvd_fd = -1;
#endif

    return c;
}

static void
handle_message(struct ctx *c, struct uxenconsole_msg_header *hdr)
{
    switch (hdr->type) {
    case UXENCONSOLE_MSG_TYPE_RESIZE_SURFACE:
        {
            struct uxenconsole_msg_resize_surface *msg = (void *)hdr;

            if (c->ops->resize_surface) {
                c->ops->resize_surface(c->priv,
                                       msg->width,
                                       msg->height,
                                       msg->linesize,
                                       msg->length,
                                       msg->bpp,
                                       msg->offset,
#if !defined(__APPLE__)
                                       (file_handle_t)msg->shm_handle);
            } else
                CloseHandle((file_handle_t)msg->shm_handle);
#else
                                       c->recvd_fd);
            } else
                close(c->recvd_fd);
            c->recvd_fd = -1;
#endif
        }
        break;
    case UXENCONSOLE_MSG_TYPE_INVALIDATE_RECT:
        {
            struct uxenconsole_msg_invalidate_rect *msg = (void *)hdr;

            if (c->ops->invalidate_rect)
                c->ops->invalidate_rect(c->priv,
                                        msg->x,
                                        msg->y,
                                        msg->w,
                                        msg->h);
        }
        break;
    case UXENCONSOLE_MSG_TYPE_UPDATE_CURSOR:
        {
            struct uxenconsole_msg_update_cursor *msg = (void *)hdr;

            if (c->ops->update_cursor) {
                c->ops->update_cursor(c->priv,
                                      msg->w,
                                      msg->h,
                                      msg->hot_x,
                                      msg->hot_y,
                                      msg->mask_offset,
                                      msg->flags,
#if !defined(__APPLE__)
                                      (file_handle_t)msg->shm_handle);
            } else
                CloseHandle((file_handle_t)msg->shm_handle);
#else
                                       c->recvd_fd);
            } else
                close(c->recvd_fd);
            c->recvd_fd = -1;
#endif
        }
        break;
    case UXENCONSOLE_MSG_TYPE_KEYBOARD_LEDSTATE:
        {
            struct uxenconsole_msg_keyboard_ledstate *msg = (void *)hdr;

            if (c->ops->keyboard_ledstate)
                c->ops->keyboard_ledstate(c->priv, msg->state);
        }
        break;
    case UXENCONSOLE_MSG_TYPE_SET_SHARED_SURFACE:
        {
            struct uxenconsole_msg_set_shared_surface *msg = (void *)hdr;

            if (c->ops->set_shared_surface)
                c->ops->set_shared_surface(c->priv, (file_handle_t)msg->surface);
        }
        break;
    default:
        break;
    }
}

static size_t
channel_read(struct ctx *c, void *data, size_t len)
{
    struct uxenconsole_msg_header *hdr;
    size_t hdrlen = sizeof (*hdr);
    size_t r = 0;

    if (c->buf_len < hdrlen) {
        c->buf = realloc(c->buf, hdrlen);
        if (!c->buf)
            return -1;
        c->buf_len = hdrlen;
    }

    while (r < len) {
        size_t l;

        hdr = (void *)c->buf;

        if (c->msg_len < hdrlen) {
            l = hdrlen - c->msg_len;
            if (l > (len - r))
                l = len - r;

            memcpy(c->buf + c->msg_len, data + r, l);
            r += l;
            c->msg_len += l;
        } else {
            if (c->buf_len < hdr->len) {
                c->buf = realloc(c->buf, hdr->len);
                if (!c->buf)
                    return -1;
                hdr = (void *)c->buf;
                c->buf_len = hdr->len;
            }

            l = hdr->len - c->msg_len;
            if (l > (len - r))
                l = len - r;
            memcpy(c->buf + c->msg_len, data + r, l);
            r += l;
            c->msg_len += l;
        }

        if (c->msg_len >= hdrlen && c->msg_len == hdr->len) {
            handle_message(c, hdr);
            c->msg_len = 0;
        }
    }

    return r;
}

static int
channel_write(struct ctx *c, void *data, unsigned int len)
{
#if defined(_WIN32)
    BOOL rc;
    DWORD bytes;
    struct sndbuf *b;

    b = malloc(sizeof(*b) + len);
    if (!b)
        return -1;
    RtlZeroMemory(&b->ovlp, sizeof(OVERLAPPED));
    RtlCopyMemory(b + 1, data, len);
    b->len = len;

    rc = WriteFile(c->pipe, b + 1, b->len, &bytes, &b->ovlp);
    if (!rc) {
        if (GetLastError() == ERROR_IO_PENDING) {
            EnterCriticalSection(&c->sndlock);
            b->next = NULL;
            b->pprev = c->sndlist_last;
            *c->sndlist_last = b;
            c->sndlist_last = &b->next;
            LeaveCriticalSection(&c->sndlock);
            return b->len;
        }
        free(b);
        return -1;
    } else if (bytes != b->len) {
        free(b);
        return -1;
    }

    free(b);

    return (int)bytes;
#elif defined(__APPLE__)
    unsigned int l = 0;
    ssize_t rc;

    while (l < len) {
        rc = send(c->socket, data + l, len - l, 0);
        switch (rc) {
        case -1:
            return -1;
        case 0:
            if (c->ops->disconnected)
                c->ops->disconnected(c->priv);
            uxenconsole_disconnect(c);
            return 0;
        default:
            l += rc;
        }
    }

    return l;
#endif
}

#if defined(_WIN32)
BOOL WINAPI CancelIoEx(HANDLE hFile, LPOVERLAPPED lpOverlapped);

static void
snd_complete(struct ctx *c)
{
    struct sndbuf *b, *bn;
    DWORD bytes;
    BOOL rc;

    EnterCriticalSection(&c->sndlock);
    b = c->sndlist_first;
    while (b) {
        bn = b->next;
        rc = GetOverlappedResult(c->pipe, &b->ovlp, &bytes, FALSE);

        if (!rc && GetLastError() == ERROR_IO_INCOMPLETE) {
            b = bn;
            continue;
        }

        if (!rc || bytes != b->len) {
            LeaveCriticalSection(&c->sndlock);
            if (c->ops->disconnected)
                c->ops->disconnected(c->priv);
            uxenconsole_disconnect(c);
            return;
        }

        if (bn)
            bn->pprev = b->pprev;
        else
            c->sndlist_last = b->pprev;
        *b->pprev = bn;
        free(b);
        b = bn;
    }
    LeaveCriticalSection(&c->sndlock);
}
#else
#define snd_complete(c)
#endif

file_handle_t
uxenconsole_connect(uxenconsole_context_t ctx)
{
    struct ctx *c = ctx;
#if defined(_WIN32)
    BOOL rc;
    DWORD count;
    DWORD err;

    c->oread.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    while (1) {
        c->pipe = CreateFile(c->filename,
                             GENERIC_READ | GENERIC_WRITE,
                             0, NULL, OPEN_EXISTING,
                             FILE_FLAG_OVERLAPPED, NULL);
        if (c->pipe != INVALID_HANDLE_VALUE)
            break;
        err = GetLastError();
        if (err == ERROR_PIPE_BUSY)
            WaitNamedPipe(c->filename, 1000);
        else {
            CloseHandle(c->oread.hEvent);
            c->oread.hEvent = NULL;
            SetLastError(err);
            return NULL;
        }
    }

    rc = ReadFile(c->pipe, c->read_buf, BUF_SZ, &count, &c->oread);
    while (rc == TRUE) {
        channel_read(c, c->read_buf, count);
        rc = ReadFile(c->pipe, c->read_buf, BUF_SZ, &count, &c->oread);
    }
    err = GetLastError();
    if (err != ERROR_IO_PENDING) {
        CloseHandle(c->pipe);
        CloseHandle(c->oread.hEvent);
        c->pipe = NULL;
        c->oread.hEvent = NULL;
        SetLastError(err);
        return NULL;
    }

    return c->oread.hEvent;
#elif defined(__APPLE__)
    int rc;
    struct sockaddr_un sa;
    int len;
    int err;

    len = snprintf(sa.sun_path, sizeof (sa.sun_path), "%s", c->filename);
    sa.sun_family = AF_UNIX;
    sa.sun_len = sizeof (sa) - sizeof (sa.sun_path) + len + 1;

    c->socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (c->socket < 0)
        return -1;

    while (1) {
        rc = connect(c->socket, (void *)&sa, sizeof (sa));
        if (rc == 0)
            break;
        err = errno;
        close(c->socket);
        errno = err;
        return -1;
    }

    return c->socket;
#endif
}

void
uxenconsole_channel_event(uxenconsole_context_t ctx, file_handle_t event,
                          int is_write)
{
    struct ctx *c = ctx;
#if defined(_WIN32)
    BOOL rc;
    DWORD count;

    if (is_write)
        return; /* Not implemented */

    rc = GetOverlappedResult(c->pipe, &c->oread, &count, FALSE);
    while (rc == TRUE) {
        channel_read(c, c->read_buf, count);
        rc = ReadFile(c->pipe, c->read_buf, BUF_SZ, &count, &c->oread);
    }
    if (GetLastError() != ERROR_IO_PENDING) {
        if (c->ops->disconnected)
            c->ops->disconnected(c->priv);
        uxenconsole_disconnect(c);
    }
#elif defined(__APPLE__)
    char buf[BUF_SZ];
    ssize_t rc;
    struct msghdr msg;
    struct iovec iov;
    struct {
        struct cmsghdr hdr;
        int fd;
    } cmsgbuf;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsgbuf;
    msg.msg_controllen = sizeof (cmsgbuf);

    iov.iov_base = buf;
    iov.iov_len = BUF_SZ;

    rc = recvmsg(c->socket, &msg, 0);
    switch (rc) {
    case -1:
        return;
    case 0:
        if (c->ops->disconnected)
            c->ops->disconnected(c->priv);
        uxenconsole_disconnect(c);
        return;
    default:
        if (cmsgbuf.hdr.cmsg_len &&
            cmsgbuf.hdr.cmsg_level == SOL_SOCKET &&
            cmsgbuf.hdr.cmsg_type == SCM_RIGHTS)
            c->recvd_fd = cmsgbuf.fd;
        channel_read(c, buf, (size_t)rc);
    }
#endif
}

void
uxenconsole_disconnect(uxenconsole_context_t ctx)
{
    struct ctx *c = ctx;

#if defined(_WIN32)
    if (c->pipe) {
        struct sndbuf *b, *bn;

        EnterCriticalSection(&c->sndlock);
        b = c->sndlist_first;
        while (b) {
            DWORD bytes;

            bn = b->next;
            if (CancelIoEx(c->pipe, &b->ovlp) ||
                GetLastError() != ERROR_NOT_FOUND)
                GetOverlappedResult(c->pipe, &b->ovlp, &bytes, TRUE);

            free(b);
            b = bn;
        }
        LeaveCriticalSection(&c->sndlock);
        if (c->pipe) {
            CancelIo(c->pipe);
            CloseHandle(c->pipe);
        }
        if (c->oread.hEvent) {
            CloseHandle(c->oread.hEvent);
        }
        c->oread.hEvent = NULL;
        c->pipe = NULL;
    }
#elif defined(__APPLE__)
    if (c->socket != -1) {
        close(c->socket);
        c->socket = -1;
    }
#endif
}

void
uxenconsole_cleanup(uxenconsole_context_t ctx)
{
    struct ctx *c = ctx;

#if defined(_WIN32)
    if (c->pipe)
        uxenconsole_disconnect(ctx);
    DeleteCriticalSection(&c->sndlock);
#elif defined(__APPLE__)
    if (c->socket >= 0)
        uxenconsole_disconnect(ctx);
#endif

    free(c);
}

int
uxenconsole_mouse_event(uxenconsole_context_t ctx,
                        unsigned int x,
                        unsigned int y,
                        int dv,
                        int dh,
                        unsigned int flags)
{
    struct ctx *c = ctx;
    struct uxenconsole_msg_mouse_event msg;
    int rc;

    snd_complete(c);

    msg.header.type = UXENCONSOLE_MSG_TYPE_MOUSE_EVENT;
    msg.header.len = sizeof (msg);
    msg.x = x;
    msg.y = y;
    msg.dv = dv;
    msg.dh = dh;
    msg.flags = flags;

    rc = channel_write(c, &msg, sizeof (msg));
    if (rc != sizeof (msg))
        return -1;

    return 0;
}

int
uxenconsole_keyboard_event(uxenconsole_context_t ctx,
                           unsigned int keycode,
                           unsigned int repeat,
                           unsigned int scancode,
                           unsigned int flags,
                           void *chars,
                           unsigned int nchars,
                           void *chars_bare,
                           unsigned int nchars_bare)
{
    struct ctx *c = ctx;
    struct uxenconsole_msg_keyboard_event msg;
    int rc;
    unsigned int charlen;
    unsigned int char_bare_len;

    snd_complete(c);

    charlen = (flags & KEYBOARD_EVENT_FLAG_UCS2) ? nchars * 2 : nchars;
    char_bare_len = (flags & KEYBOARD_EVENT_FLAG_UCS2) ? nchars_bare * 2 : nchars_bare;

    if (charlen > UXENCONSOLE_MSG_KEYBOARD_MAX_LEN)
        return -1;

    if (char_bare_len > UXENCONSOLE_MSG_KEYBOARD_MAX_LEN)
        return -2;

    msg.header.type = UXENCONSOLE_MSG_TYPE_KEYBOARD_EVENT;
    msg.header.len = sizeof msg;
    msg.keycode = keycode;
    msg.repeat = repeat;
    msg.scancode = scancode;
    msg.flags = flags;
    msg.charslen = charlen;
    msg.chars_bare_len = char_bare_len;
    memcpy(msg.chars, chars, charlen);
    memcpy(msg.chars_bare, chars_bare, char_bare_len);

    rc = channel_write(c, &msg, sizeof msg);
    if (rc != sizeof msg)
        return -1;

    return 0;
}

int
uxenconsole_request_resize(uxenconsole_context_t ctx,
                           unsigned int width,
                           unsigned int height,
                           unsigned int flags)
{
    struct ctx *c = ctx;
    struct uxenconsole_msg_request_resize msg;
    int rc;

    snd_complete(c);

    msg.header.type = UXENCONSOLE_MSG_TYPE_REQUEST_RESIZE;
    msg.header.len = sizeof (msg);
    msg.width = width;
    msg.height = height;
    msg.flags = flags;

    rc = channel_write(c, &msg, sizeof (msg));
    if (rc != sizeof (msg))
        return -1;

    return 0;
}

int
uxenconsole_clipboard_permit(uxenconsole_context_t ctx,
                             int permit_type)
{
    struct ctx *c = ctx;
    struct uxenconsole_msg_clipboard_permit msg;
    int rc;

    snd_complete(c);

    msg.header.type = UXENCONSOLE_MSG_TYPE_CLIPBOARD_PERMIT;
    msg.header.len = sizeof (msg);
    msg.permit_type = permit_type;

    rc = channel_write(c, &msg, sizeof (msg));
    if (rc != sizeof (msg))
        return -1;

    return 0;
}

int
uxenconsole_set_shared_surface(uxenconsole_context_t ctx,
                               file_handle_t surface)
{
    struct ctx *c = ctx;
    struct uxenconsole_msg_set_shared_surface msg;
    int rc;

    snd_complete(c);

    msg.header.type = UXENCONSOLE_MSG_TYPE_SET_SHARED_SURFACE;
    msg.header.len = sizeof (msg);
    msg.surface = (uintptr_t)surface;

    rc = channel_write(c, &msg, sizeof (msg));
    if (rc != sizeof (msg))
        return -1;

    return 0;
}

int
uxenconsole_touch_device_hotplug(uxenconsole_context_t ctx,
                                 int plug)
{
    struct ctx *c = ctx;
    struct uxenconsole_msg_touch_device_hotplug msg;
    int rc;

    snd_complete(c);

    msg.header.type = UXENCONSOLE_MSG_TYPE_TOUCH_DEVICE_HOTPLUG;
    msg.header.len = sizeof (msg);
    msg.plug = plug;

    rc = channel_write(c, &msg, sizeof (msg));
    if (rc != sizeof (msg))
        return -1;

    return 0;
}

int
uxenconsole_focus_changed(uxenconsole_context_t ctx,
                          int focus)
{
    struct ctx *c = ctx;
    struct uxenconsole_msg_focus_changed msg;
    int rc;

    snd_complete(c);

    msg.header.type = UXENCONSOLE_MSG_TYPE_FOCUS_CHANGED;
    msg.header.len = sizeof (msg);
    msg.focus = focus;

    rc = channel_write(c, &msg, sizeof (msg));
    if (rc != sizeof (msg))
        return -1;

    return 0;
}

int
uxenconsole_keyboard_layout_changed(uxenconsole_context_t ctx,
                                    uint32_t layout)
{
    struct ctx *c = ctx;
    struct uxenconsole_msg_keyboard_layout_changed msg;
    int rc;

    snd_complete(c);

    msg.header.type = UXENCONSOLE_MSG_TYPE_KEYBOARD_LAYOUT_CHANGED;
    msg.header.len = sizeof (msg);
    msg.layout = layout;

    rc = channel_write(c, &msg, sizeof (msg));
    if (rc != sizeof (msg))
        return -1;

    return 0;
}

