/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include "net-user.h"

size_t netuser_can_recv(struct net_user *nu, void *opaque)
{
    return nu->can_recv ? nu->can_recv(opaque) : 0;
}

void netuser_recv(struct net_user *nu, void *opaque, const uint8_t *buf, int size)
{
    if (nu->recv)
        nu->recv(opaque, buf, size);
}

void netuser_send(struct net_user *nu, void *opaque)
{
    if (nu->send)
        nu->send(opaque);
}

void netuser_close(struct net_user *nu, void *opaque)
{
    if (nu->close)
        nu->close(opaque);
}

int netuser_add_wait_object(struct net_user *nu, ioh_event *ev,
                    WaitObjectFunc *cb, void *cb_opaque)
{
    return nu->add_wait_object ? nu->add_wait_object(nu->opaque, ev, cb, cb_opaque) : -1;
}

void netuser_del_wait_object(struct net_user *nu, ioh_event *ev)
{
    if (nu->del_wait_object)
        nu->del_wait_object(nu->opaque, ev);
}

#ifndef _WIN32
int netuser_add_wait_fd(struct net_user *nu, int fd, int events, WaitObjectFunc2 *func2, void *opaque)
{
    return nu->add_wait_fd ? nu->add_wait_fd(nu->opaque, fd, events, func2, opaque) : -1;
}

void netuser_del_wait_fd(struct net_user *nu, int fd)
{
    if (nu->del_wait_fd)
        nu->del_wait_fd(nu->opaque, fd);
}
#endif

int netuser_schedule_bh(struct net_user *nu, void (*cb1) (void*), void (*cb2)(void *), void *cb_opaque)
{
    return nu->schedule_bh ? nu->schedule_bh(nu->opaque, cb1, cb2, cb_opaque) : -1;
}

uint32_t netuser_get_hostaddr(struct net_user *nu)
{
    return nu->get_hostaddr ? nu->get_hostaddr(nu->opaque) : (uint32_t) (-1);
}

#ifdef _WIN32
#define SANE_STR_SIZE ((uint32_t) (((uint32_t)(-1)) >> 2))
#define IS_SANE_LENGTH(a)   (((size_t)(a)) < SANE_STR_SIZE)
#include <wchar.h>

/* Convert a wide Unicode string to an UTF8 string */
char * buff_ascii_encode(wchar_t *wstr)
{
    int cbResult = 0;
    int iLastErr = 0;
    char *ascii_string = NULL;

    if (!wstr)
        goto err;

    cbResult = WideCharToMultiByte(CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (cbResult <= 0 || !IS_SANE_LENGTH(cbResult)) {
        warnx("%s: wrong cbResult = %d", __FUNCTION__, cbResult);
        goto err;
    }
    ascii_string = calloc(1, (size_t) cbResult + 1);
    if (!ascii_string) {
        warnx("%s: malloc", __FUNCTION__);
        goto err;
    }

    if (WideCharToMultiByte(CP_ACP, 0, wstr, -1, ascii_string, cbResult, NULL, NULL) <= 0) {
        iLastErr = GetLastError();
        warnx("%s: Unicode to ACP translation failed. lasterr=%d", __FUNCTION__, iLastErr);
        goto err;
    }

out:
    return ascii_string;

err:
    if (ascii_string)
        free(ascii_string);
    ascii_string = NULL;
    goto out;
}
#endif
