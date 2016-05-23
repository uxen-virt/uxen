/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifdef _WIN32
#include <winsock2.h>
#endif

#include <assert.h>
#define ERR_WINDOWS
#define ERR_AUTO_CONSOLE
#include <err.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../common/defroute.h"

#include "uxenevent.h"

static int sock = -1;

int
logging_vprintf(const char *fmt, va_list ap)
{
    struct sockaddr_in sa;
    int len;
    int ret;
    char buf[1400];

    if (sock < 0)
        return 0;

    len = vsnprintf(buf, sizeof(buf), fmt, ap);

    memset(&sa,0,sizeof(sa));

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = get_default_route();
    sa.sin_port = htons(LOGGING_DEFAULT_PORT);

    ret = sendto(sock, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa));

    if (ret < len)  {
	char ebuf[256];
	int elen;
	int err;

	err = WSAGetLastError();

        debug_log("sendto(%d, %p, %d, 0, { .sin_family=%d, .sin_addr.s_addr=%x, .sin_port=%d }, %d) == %d [WSAGetLastError=%d]\n", 
		sock, buf, len, (int) sa.sin_family, (unsigned) sa.sin_addr.s_addr,(int) htons(sa.sin_port),(int) sizeof(sa),ret,err);

        elen = snprintf(ebuf,sizeof(ebuf),"uxenevent mythical bug: sendto(%d, %p, %d, 0, { .sin_family=%d, .sin_addr.s_addr=%x, .sin_port=%d }, %d) == %d [WSAGetLastError=%d]\n", sock,buf,len,(int) sa.sin_family, (unsigned) sa.sin_addr.s_addr,(int) htons(sa.sin_port),(int) sizeof(sa),ret,err);

    	(void) sendto(sock, ebuf, elen, 0, (struct sockaddr *)&sa, sizeof(sa));
    }
	

    return len;
}

int
logging_printf(const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = logging_vprintf(fmt, ap);
    va_end(ap);

    return ret;
}

int
logging_init(void)
{
    int ret;
    struct sockaddr_in sa;
    BOOLEAN one=TRUE;

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        debug_log("socket");
        goto fail;
    }


    ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one));
    if (ret < 0) {
        debug_log("setsockopt %x", WSAGetLastError());
        goto fail;
    }

    memset(&sa,0,sizeof(sa));

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(LOGGING_SOURCE_PORT);

    ret = bind(sock, (struct sockaddr *)&sa, sizeof(sa));
    if (ret < 0) {
        debug_log("bind %x", WSAGetLastError());
        goto fail;
    }

    return 0;

fail:
    if (sock >= 0)
        close(sock);
    sock = -1;
    return -1;

}

