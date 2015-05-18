/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include "nickel.h"

#include <dm/qemu_glue.h>
#include <dm/async-op.h>
#ifdef _WIN32
#include <inttypes.h>

#include <windows.h>
#include <ws2tcpip.h>
#include <sys/timeb.h>
#include <iphlpapi.h>

#define EWOULDBLOCK WSAEWOULDBLOCK
#define EINPROGRESS WSAEINPROGRESS
#undef errno
#define errno ((int) WSAGetLastError())
#else
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#define ioctlsocket ioctl
#undef TCP_NODELAY
#define	TCP_NODELAY 0x01
#endif

#include <err.h>
#include <stdbool.h>
#include <stdint.h>

#include "nickel.h"
#include "dns/dns.h"
#include "dns/dns-fake.h"
#include "buff.h"
#include "socket.h"
#include "log.h"

#ifndef VERBSTATS
#define VERBSTATS 1
#endif

#ifndef _WIN32
#define FD_readfds POLLIN
#define FD_writefds POLLOUT
#define FD_acceptfds 0
#define FD_connectfds 0
#define FD_closefds 0 /* XXXPM */
#define FD_closefds 0
#define GET_NETWORK_EVENTS(so) do { } while(0)
#define SO_ISSET(so, set) ( so->revents & FD_ ## set )
#define SO_ISERR(so, set) 0
#define SO_ERR(so, set) 0

#define update_fdevents(so, _events) do {                       \
        if (so->events != (_events)) {                          \
            if (so->events)                                     \
                ni_del_wait_fd(so->ni, so->s);                  \
            so->events = _events;                               \
            if (so->events)                                     \
                ni_add_wait_fd(so->ni, so->s, so->events,       \
                                fd_events_poll, so);            \
        }                                                       \
    } while (0)

#else
#define ERROR_LOG(fmt, ...) error_printf(fmt, ## __VA_ARGS__)

#define POLLIN  0x1
#define POLLOUT 0x4
#define POLLERR 0x8
#define update_fdevents(so, events) do {                                        \
        if (!(events))                                                          \
           break;                                                               \
        int rc = WSAEventSelect((so)->s, (so)->ni->so_event, FD_ALL_EVENTS);    \
        if (rc == SOCKET_ERROR) {                                               \
            ERROR_LOG("nsp: WSAEventSelect(%d) failed at %d: error %d\n",       \
                      (so)->s, __LINE__, WSAGetLastError());                    \
        }                                                                       \
    } while(0)

#define GET_NETWORK_EVENTS(so) do {					\
	int rc = WSAEnumNetworkEvents((so)->s, (so)->ni->so_event, &NetworkEvents); \
	if (rc == SOCKET_ERROR) {					\
	    ERROR_LOG("nsp: WSAEnumNetworkEvents(%d) failed at %d: error %d\n", \
		      ((so)->s), __LINE__, WSAGetLastError());		\
	}								\
    } while(0)
#define FD_acceptfds FD_ACCEPT
#define FD_acceptfds_BIT FD_ACCEPT_BIT
#define FD_closefds FD_CLOSE
#define FD_closefds_BIT FD_CLOSE_BIT
#define FD_connectfds FD_CONNECT
#define FD_connectfds_BIT FD_CONNECT_BIT
#define FD_readfds FD_READ
#define FD_readfds_BIT FD_READ_BIT
#define FD_writefds FD_WRITE
#define FD_writefds_BIT FD_WRITE_BIT
#define SO_ISSET(so, set) (					\
	(NetworkEvents.lNetworkEvents & FD_ ## set) &&		\
	(NetworkEvents.iErrorCode[FD_ ## set ## _BIT] == 0)	\
	)
#define SO_ISERR(so, set) (					\
	(NetworkEvents.lNetworkEvents & FD_ ## set) &&		\
	(NetworkEvents.iErrorCode[FD_ ## set ## _BIT])		\
	)
#define SO_ERR(so, set) (NetworkEvents.iErrorCode[FD_ ## set ## _BIT])
#endif

#define NSO_SS_CLOSED        0
#define NSO_SS_CREATED       1
#define NSO_SS_CONNECTING    2
#define NSO_SS_CONNECTED     3
#define NSO_SS_NEEDS_CLOSE   4
#define NSO_SS_CLOSING       5
#define NSO_SS_RECONNECTING  6
#define NSO_SS_LISTENING     7

#define SDEL_OFF             0
#define SDEL_CLOSING         1
#define SDEL_CLOSED          2

#define SF_FLUSH_CLOSE       0x1
#define SF_A_CONNECTING      0x2
#define SF_SOCK_READ         0x4
#define SF_SOCK_WRITE        0x8

struct socket {
    LIST_ENTRY(socket) entry;
    struct nickel *ni;
    int is_udp;
    int s;
    int state;
    uint32_t flags;
    int del;
    int last_err;

    so_event_t evt_cb;
    void *evt_opaque;
    so_accept_t accept_cb;
    void *accept_opaque;

    struct socket *parent;
    int events;
    int revents;

    struct net_addr *a_list;
    size_t a_idx;
    Timer *a_timer;
    struct net_addr addr;

    uint16_t port;
    uint16_t clt_port;

    uint32_t refcnt;
};

static void events_poll(void *opaque);
static void list_connect_free(struct socket *so);
static int list_connect_next(struct socket *so);
static void _so_close(struct socket *so, bool reconnect);
static void _so_connect(struct socket *so);
static void so_connected(struct socket *so);

#if VERBSTATS

#define LOG_STATS_SEC   60
#define HYB_NEXT_CONNECT_MS 300

static void so_stats(struct nickel *ni)
{
    static int64_t last_ts = -1;
    int64_t ts;

    ts = get_clock_ms(rt_clock);
    if (last_ts >= 0 && last_ts + LOG_STATS_SEC * 1000 > ts)
        return;

    last_ts = ts;
    NETLOG4("%s: %u max %u", __FUNCTION__,
            (unsigned int) ni->number_remote_sockets,
            (unsigned int) ni->number_total_remote_sockets);
}
#endif


#ifndef _WIN32
static void fd_events_poll(void *opaque, int revents)
{
   struct socket *so = (struct socket *) opaque;
   if (!so)
       return;
   so->revents = revents;
   events_poll(opaque);
}
#endif

static void so_get(struct socket *so)
{
    if (!so)
        return;

    atomic_inc(&so->refcnt);
}

static void so_put(struct socket *so)
{

    if (!so)
        return;

    if (atomic_dec_and_test(&so->refcnt)) {
        assert(so->del);
        ni_wakeup_loop(so->ni);
    }
}

void so_fd_nonblock(int fd)
{
#ifdef FIONBIO
#ifdef _WIN32
    unsigned long opt = 1;
#else
    int opt = 1;
#endif

    ioctlsocket(fd, FIONBIO, &opt);
#else
    int opt;

    opt = fcntl(fd, F_GETFL, 0);
    opt |= O_NONBLOCK;
    fcntl(fd, F_SETFL, opt);
#endif
}

void so_free(struct socket *so)
{
    if (so->parent) {
        so_put(so->parent);
        so->parent = NULL;
        ni_wakeup_loop(so->ni);
    }
    list_connect_free(so);
    _so_close(so, false);
    if (so->entry.le_prev)
        LIST_REMOVE(so, entry);

#if VERBSTATS
    atomic_dec(&so->ni->number_remote_sockets);
    so_stats(so->ni);
#endif

    free(so);
}

int so_dbg(struct buff *bf, struct socket *so)
{
    if (!so)
        return buff_appendf(bf, " s:*");
    else
        return buff_appendf(bf, " s:%d p:%hu st:%d", so->s, ntohs(so->clt_port),
                so->state);
}

static void so_closing(struct socket *so)
{
    bool event = true;

    if (so->state == NSO_SS_CLOSING)
        event = false;

    if (so->state != NSO_SS_RECONNECTING)
        so->state = NSO_SS_CLOSING;
    if (event && so->evt_cb)
        so->evt_cb(so->evt_opaque, SO_EVT_CLOSING, so->last_err);

    so->flags &= ~SF_FLUSH_CLOSE;

    if (so->parent) {
        struct socket *pso = so->parent;

        so_close(so);
        if (pso && !pso->del) {
            struct socket *cso, *ns_next;

            LIST_FOREACH_SAFE(cso, &so->ni->sock_list, entry, ns_next) {
                if (cso->parent == pso && !cso->del)
                    break;
            }
            if (!cso)
                so_closing(pso);
        }
    }
}

static void _so_close(struct socket *so, bool reconnect)
{
    if (so->s >= 0) {
        update_fdevents(so, 0);
        if (closesocket(so->s))
            NETLOG("%s: closesocket failed, err %d", __FUNCTION__, errno);
        so->s = -1;
        so->clt_port = 0;
    }

    list_connect_free(so);
    so->state = NSO_SS_CLOSED;
    if (reconnect)
        _so_connect(so);
}


static void list_connect_free(struct socket *so)
{
    struct socket *cso, *ns_next;

    if (!so->a_list)
        return;

    LIST_FOREACH_SAFE(cso, &so->ni->sock_list, entry, ns_next) {
        if (cso->parent != so && !cso->del)
            continue;
        so_close(cso);
    }

    LIST_FOREACH_SAFE(cso, &so->ni->defered_list, entry, ns_next) {
        if (cso->parent != so && !cso->del)
            continue;
        so_close(cso);
    }

    free(so->a_list);
    so->a_list = NULL;
    so->a_idx = 0;
    so->flags &= ~(SF_A_CONNECTING);
}

static void list_connect_connecting(struct socket *so)
{
    if (so->del || (so->flags & SF_A_CONNECTING))
        return;

    if (so->evt_cb)
        so->evt_cb(so->evt_opaque, SO_EVT_CONNECTING, so->last_err);

    so->state = NSO_SS_CREATED;
    so->flags |= SF_A_CONNECTING;
}

static void list_connect_connected(struct socket *cso)
{
    struct socket *so = cso->parent;

    if (cso->del || !so || so->del)
        return;

    so->addr = cso->addr;
    so->s = cso->s;
    so->events = so->revents = 0;
    update_fdevents(cso, 0);
    cso->s = -1;
    cso->events = cso->revents = 0;
    list_connect_free(so);
    so_connected(so);
    ni_wakeup_loop(so->ni);
}

static void list_connect_timeout_cb(void *opaque)
{
    struct socket *so = opaque;

    so_put(so);
    if (so->del)
        return;

    if (so->a_timer) {
        free_timer(so->a_timer);
        so->a_timer = NULL;
    }

    if (so->a_list)
        list_connect_next(so);
}

static int list_connect_next(struct socket *so)
{
    int ret = -1;
    struct socket *cso = NULL;

    if (!so->a_list || !so->a_list[so->a_idx].family)
        goto cleanup;

    cso = so_create(so->ni, false, NULL, NULL);
    if (!cso)
        goto cleanup;

    so_get(so);
    cso->parent = so;
    ret = so_connect(cso, so->a_list + so->a_idx, so->port);
    so->a_idx++;
    if (ret < 0)
        goto cleanup;
    if (!so->a_timer) {
        so_get(so);
        so->a_timer = ni_new_vm_timer(so->ni, HYB_NEXT_CONNECT_MS,
                list_connect_timeout_cb, so);
        if (!so->a_timer) {
            so_put(so);
            goto cleanup;
        }
    }

    ret = 0;
out:
    return ret;
cleanup:
    if (cso)
        so_close(cso);
    ret = -1;
    goto out;
}

struct socket * so_create(struct nickel *ni, bool udp, so_event_t cb, void *opaque)
{
    struct socket *so = NULL;

    so = calloc(1, sizeof(*so));
    if (!so)
        goto out;
    so->refcnt = 1;
    so->ni = ni;
    so->s = -1;
    so->evt_cb = cb;
    so->evt_opaque = opaque;
    if (udp)
        so->is_udp = 1;
    LIST_INSERT_HEAD(&ni->defered_list, so, entry);
#if VERBSTATS
    atomic_inc(&so->ni->number_remote_sockets);
    if (so->ni->number_remote_sockets > so->ni->number_total_remote_sockets)
        so->ni->number_total_remote_sockets = so->ni->number_remote_sockets;
    so_stats(so->ni);
#endif
out:
    return so;
}

int so_connect(struct socket *so, const struct net_addr *addr, uint16_t port)
{
    if (so->state != NSO_SS_CLOSED)
        return 0;

    so->addr = *addr;
    so->port = port;

    return so_reconnect(so);
}

int so_connect_list(struct socket *so, const struct net_addr *a, uint16_t port)
{
    int ret = -1;
    size_t len = 0;

    while (a && a[len].family)
        len++;

    if (!len)
        goto out;

    if (len == 1) {
        ret = so_connect(so, a, port);
        goto out;
    }

    /* we have more then one IP address and could be a mixture IPv4 IPv6 */
    /* try to connect to them in that order */
    list_connect_free(so);
    so->a_list = dns_ips_dup(a);
    if (!so->a_list)
        goto out;
    so->port = port;

    /* start with first ip and so on ... */
    ret = list_connect_next(so);
out:
    return ret;
}

int so_reconnect(struct socket *so)
{
    list_connect_free(so);
    so->state = NSO_SS_RECONNECTING;
    if (so->s < 0)
        _so_close(so, true);
    return 0;
}

int so_listen(struct socket *so, const struct net_addr *addr, uint16_t port, so_accept_t accept_cb,
        void *accept_opaque)
{
    int ret = -1, r, opt, err = 0;
    bool ipv4 = true;

    if (so->s != -1) {
        NETLOG("%s: socket already created", __FUNCTION__);
        goto out;
    }

    so->addr = *addr;
    so->port = port;

    if (so->addr.family == AF_INET) {
        ipv4 = true;
    } else if (so->addr.family == AF_INET6) {
        ipv4 = false;
    } else {
        NETLOG("%s: invalid inet family %hu", __FUNCTION__, so->addr.family);
        goto out;
    }

    r = qemu_socket(so->addr.family, SOCK_STREAM, 0);
    err = errno;
    if (r < 0) {
        so->state = NSO_SS_NEEDS_CLOSE;
        goto out;
    }
    so->s = r;
    opt = 1;
    setsockopt(so->s, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
    r = 0;
    if (ipv4) {
        struct sockaddr_in saddr;

        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr = so->addr.ipv4;
        saddr.sin_port = so->port;
        r = bind(so->s, (const struct sockaddr *) &saddr, sizeof(saddr));
    } else {
        struct sockaddr_in6 saddr;

        memset(&saddr, 0, sizeof(saddr));
        saddr.sin6_family = AF_INET6;
        saddr.sin6_addr = so->addr.ipv6;
        saddr.sin6_port = so->port;
        r = bind(so->s, (const struct sockaddr *) &saddr, sizeof(saddr));
    }
    err = errno;
    if (r < 0) {
        NETLOG("%s: bind error %d", __FUNCTION__, err);
        goto out;
    }
    r = listen(so->s, 1);
    err = errno;
    if (r < 0) {
        NETLOG("%s: listen error %d", __FUNCTION__, err);
        goto out;
    }

    so->accept_cb = accept_cb;
    so->accept_opaque = accept_opaque;
    so->state = NSO_SS_LISTENING;
    ni_wakeup_loop(so->ni);

    ret = 0;
out:
    if (ret)
        so->last_err = err;
    return ret;
}

size_t so_read(struct socket *so, const uint8_t *buf, size_t len)
{
    ssize_t ret = 0;
    int err = 0;
    bool wakeup = false;

    if (so->state != NSO_SS_CONNECTED)
        goto out;

    if ((so->flags & SF_SOCK_READ))
        wakeup = true;
    so->flags &= ~(SF_SOCK_READ);
    ret = recv(so->s, (void *) buf, len, 0);
    NETLOG5("%s: so %lx recv %d / %d", __FUNCTION__, so, (int) ret, (int) len);
    err = errno;
    so->last_err = err;
    if (ret < 0 && (err == EINTR || err == EAGAIN || err == EWOULDBLOCK)) {
        ret = 0;
        goto out;
    }

    if (ret == 0 && len == 0)
        goto out;

#if defined(_WIN32)
    if (ret == 0) {
        unsigned long available;

        ret = ioctlsocket(so->s, FIONREAD, &available);
        if (ret >= 0 && available) {
            ret = 0;
            goto out;
        }
        ret = 0;
    }
#endif

    if (ret <= 0) {
        ret = 0;
        so->state = NSO_SS_NEEDS_CLOSE;
        wakeup = true;
        goto out;
    }

    if ((so->flags & SF_FLUSH_CLOSE))
        wakeup = true;
out:
    if (wakeup)
        ni_wakeup_loop(so->ni);

    assert(ret >= 0);
    if (ret < 0)
        ret = 0;
    return ret;
}

unsigned long so_read_available(struct socket *so)
{
    unsigned long ret = 0;

    if (so->state != NSO_SS_CONNECTED)
        goto out;

#if defined(_WIN32)
    if (ioctlsocket(so->s, FIONREAD, &ret) < 0)
#else
    if (ioctl(so->s, FIONREAD, &ret) < 0)
#endif
        ret = 0;
out:
    return ret;
}

size_t so_write(struct socket *so, const uint8_t *buf, size_t len)
{
    ssize_t ret = 0;
    int err = 0;
    bool wakeup = false;

    if (!so || so->del || so->s < 0)
        goto out;

    if ((so->flags & SF_SOCK_WRITE))
        wakeup = true;
    so->flags &= ~(SF_SOCK_WRITE);
    if (so->state != NSO_SS_CONNECTED) {
        ret = 0;
        goto out;
    }
    ret = send(so->s, (void *) buf, len, 0);
    err = errno;
    NETLOG5("so %lx ret %d err %d", so, (int) ret, err);
    so->last_err = err;
    if (ret < 0 && (err != EINTR && err != EAGAIN && err != EWOULDBLOCK)) {
        ret = 0;
        so->state = NSO_SS_NEEDS_CLOSE;
        wakeup = true;
        goto out;
    }
    if (ret < 0 || (ret == 0 && len == 0)) {
        ret = 0;
        goto out;
    }

    if (ret <= 0) {
        ret = 0;
        so->state = NSO_SS_NEEDS_CLOSE;
        wakeup = true;
        goto out;
    }

out:
    if (wakeup)
        ni_wakeup_loop(so->ni);

    assert(ret >= 0);
    if (ret < 0)
        ret = 0;
    return ret;
}

void so_buf_ready(struct socket *so)
{

    so->flags &= ~(SF_SOCK_READ);
#if defined(_WIN32)
    if (so->s != -1) {
        ssize_t l;

        l = recv(so->s, (void *) &l, 0, 0);
    }
#endif

    NETLOG5("SO %lx so_buf_ready", so);
    ni_wakeup_loop(so->ni);
}

int so_close(struct socket *so)
{
    if (so->del)
        return 0;

    ni_wakeup_loop(so->ni);
    so->del = SDEL_CLOSING;
    so->evt_cb = NULL;
    so->evt_opaque = NULL;
    so_put(so);
    return 0;
}

int so_shutdown(struct socket *so)
{
    if (so->del || so->s < 0)
        return -1;

    return shutdown(so->s, 1);
}

int so_closesocket(struct socket *so)
{
    if (so->del || so->s < 0)
        return -1;

    so->state = NSO_SS_CLOSING;
    ni_wakeup_loop(so->ni);
    return 0;
}

static void _so_connect(struct socket *so)
{
    int opt, r, err = 0;
    bool ipv4 = true;

    assert(so->s == -1);
    if (so->s >= 0)
        goto out;

    if (so->addr.family == AF_INET) {
        ipv4 = true;
    } else if (so->addr.family == AF_INET6) {
        ipv4 = false;
    } else {
        NETLOG("%s: invalid inet family %hu", __FUNCTION__, so->addr.family);
        goto out;
    }

    if (so->evt_cb)
        so->evt_cb(so->evt_opaque, SO_EVT_CONNECTING, so->last_err);
    else if (so->parent)
        list_connect_connecting(so->parent);

    r = qemu_socket(so->addr.family, so->is_udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    err = errno;
    so->last_err = err;
    if (r < 0) {
        so->state = NSO_SS_NEEDS_CLOSE;
        goto out;
    }
    so->s = r;
    so_fd_nonblock(so->s);
    opt = 1;
    setsockopt(so->s, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
    if (!so->is_udp) {
        opt = 1;
        setsockopt(so->s, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));
    }

    if (ipv4) {
        struct sockaddr_in saddr;

        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr = so->addr.ipv4;
        saddr.sin_port = so->port;
        r = connect(so->s, (const struct sockaddr *) &saddr, sizeof(saddr));
    } else {
        struct sockaddr_in6 saddr;

        memset(&saddr, 0, sizeof(saddr));
        saddr.sin6_family = AF_INET6;
        saddr.sin6_addr = so->addr.ipv6;
        saddr.sin6_port = so->port;
        r = connect(so->s, (const struct sockaddr *) &saddr, sizeof(saddr));
    }
    err = errno;
    so->last_err = err;
    if (r < 0 && (err != EINPROGRESS) && (err != EWOULDBLOCK)) {
        so->state = NSO_SS_NEEDS_CLOSE;
        goto out;
    }
    so->state = NSO_SS_CREATED;
    if (so->is_udp)
        ni_wakeup_loop(so->ni);
out:
    return;
}

static void so_connected(struct socket *so)
{
    struct sockaddr_storage laddr;
    socklen_t laddrlen = sizeof(laddr);

    if ((so->state > NSO_SS_CONNECTING))
        return;

#ifndef _WIN32
    {
        int r, val;

        do {
            socklen_t valsize = sizeof(val);

            errno = 0;
            val = 0;
            r = getsockopt(so->s, SOL_SOCKET, SO_ERROR, (void *) &val, &valsize);
        } while (r == -1 && errno == EINTR);

        if (val) {
            NETLOG4("%s: so:%" PRIxPTR " SO_ERROR %d", __FUNCTION__, (uintptr_t) so, val);
            so->last_err = val;
            if (so->evt_cb)
                so->evt_cb(so->evt_opaque, SO_EVT_CLOSING, so->last_err);

            return;
        }
    }
#endif

    so->state = NSO_SS_CONNECTED;

    if (so->addr.family == AF_INET)
        laddrlen = sizeof(struct sockaddr_in);
    else
        laddrlen = sizeof(struct sockaddr_in6);

    if (getsockname(so->s, (struct sockaddr *)&laddr, &laddrlen) == 0)
        so->clt_port = so->addr.family == AF_INET6 ?
            ((struct sockaddr_in6 *)&laddr)->sin6_port :
            ((struct sockaddr_in  *)&laddr)->sin_port;

    if (so->parent)
        list_connect_connected(so);
    else if (so->evt_cb)
        so->evt_cb(so->evt_opaque, SO_EVT_CONNECTED, so->last_err);
}

static int so_accept(struct socket *so)
{
    int  ret = -1, r = -1, opt, err = 0;
    struct socket *aso = NULL;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    r = accept(so->s, (struct sockaddr *)&addr, &addrlen);
    err = errno;

    if (r < 0) {
        NETLOG("%s: accept error %d", __FUNCTION__, err);
        goto err;
    }

    aso = so_create(so->ni, false, so->evt_cb, so->evt_opaque);
    if (!aso) {
        warnx("%s: malloc failure", __FUNCTION__);
        goto err;
    }

    aso->s = r;
    so_fd_nonblock(aso->s);
    opt = 1;
    setsockopt(aso->s, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
    opt = 1;
    setsockopt(aso->s, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));

    if (addr.ss_family == AF_INET) {
        aso->addr.family = AF_INET;
        aso->addr.ipv4 = ((struct sockaddr_in *) (&addr))->sin_addr;
        aso->port = ((struct sockaddr_in *) (&addr))->sin_port;
    } else if (addr.ss_family == AF_INET6) {
        aso->addr.family = AF_INET6;
        aso->addr.ipv6 = ((struct sockaddr_in6 *) (&addr))->sin6_addr;
        aso->port = ((struct sockaddr_in6 *) (&addr))->sin6_port;
    } else {
        NETLOG("%s: invalid inet family %hu", __FUNCTION__, addr.ss_family);
        goto err;
    }

    aso->state = NSO_SS_CONNECTED;
    if (so->accept_cb)
        so->accept_cb(so->accept_opaque, aso);
    ni_wakeup_loop(so->ni);
    ret = 0;
out:
    return ret;
err:
    if (r != -1)
        closesocket(r);
    if (aso) {
        aso->s = -1;
        so_close(aso);
    }
    ret = -1;
    goto out;
}

static void so_reading(struct socket *so)
{
    so->flags |= SF_SOCK_READ;
    if (so->evt_cb)
        so->evt_cb(so->evt_opaque, SO_EVT_READ, so->last_err);
}

static void so_writing(struct socket *so)
{
    so->flags |= SF_SOCK_WRITE;
    if (so->evt_cb)
        so->evt_cb(so->evt_opaque, SO_EVT_WRITE, so->last_err);
}

static void events_poll(void *opaque)
{
    struct socket *so = NULL;
    struct nickel *ni = NULL;
#ifdef _WIN32
    struct socket *ns_next;
    WSANETWORKEVENTS NetworkEvents;
#endif

#ifdef _WIN32
    ni = (struct nickel *) opaque;
#else
    so = (struct socket *) opaque;
    ni = so->ni;
#endif

#ifdef _WIN32
    LIST_FOREACH_SAFE(so, &ni->sock_list, entry, ns_next) {
#else
    do {
#endif
        bool closing = false;

        if (so->del || so->s == -1)
            continue;

        GET_NETWORK_EVENTS(so);

        if (SO_ISSET(so, writefds) || SO_ISSET(so, connectfds)) {
            so_connected(so);
            so_writing(so);
        }

        if (so->del)
            continue;

        if (SO_ISSET(so, readfds) || SO_ISSET(so, acceptfds)) {
            if (so->state == NSO_SS_LISTENING) {
                so_accept(so);
            } else {
                so_reading(so);
            }
        }

        if (so->del)
            continue;

        if (SO_ISSET(so, closefds))
            closing = true;
        if (SO_ISERR(so, closefds)) {
            closing = true;
            so->last_err = SO_ERR(so, closefds);
        }
        if (SO_ISERR(so, connectfds)) {
            closing = true;
            so->last_err = SO_ERR(so, connectfds);
        }
        if (SO_ISERR(so, readfds)) {
            closing = true;
            so->last_err = SO_ERR(so, readfds);
        }
        if (SO_ISERR(so, writefds)) {
            closing = true;
            so->last_err = SO_ERR(so, writefds);
        }
        if (closing) {
            if (so->state != NSO_SS_CONNECTED) {
                so_closing(so);
                continue;
            }
#if defined(_WIN32)
            {
                unsigned long available = 0;
                int err;

                err = ioctlsocket(so->s, FIONREAD, &available);
                if (err < 0  || !available) {
                    so_closing(so);
                    continue;
                }
            }
#endif
            so->flags |= SF_FLUSH_CLOSE;
            so_reading(so);
            continue;
        }

    }
#ifndef _WIN32
    while(1 == 0);
#endif
}

int16_t so_getclport(struct socket *so)
{
    if (!so)
        return 0;

    return so->clt_port;
}

struct net_addr so_get_remote_addr(struct socket *so)
{
    return so->addr;
}

uint16_t so_get_remote_port(struct socket *so)
{
    return so->port;
}

void so_update_event(struct socket *so, so_event_t cb, void *opaque)
{
    so->evt_cb = cb;
    so->evt_opaque = opaque;
}

void so_prepare(struct nickel *ni, int *timeout)
{
    struct socket *so, *ns_next;

    LIST_FOREACH_SAFE(so, &ni->defered_list, entry, ns_next) {
        LIST_REMOVE(so, entry);
        LIST_INSERT_HEAD(&ni->sock_list, so, entry);
    }

    LIST_FOREACH_SAFE(so, &ni->sock_list, entry, ns_next) {
        if (so->del)
            goto check_closing;

        if (so->state == NSO_SS_NEEDS_CLOSE)
            so_closing(so);
        if (so->del)
            goto check_closing;
        if (so->state == NSO_SS_RECONNECTING)
            _so_close(so, true);
        if (so->del)
            goto check_closing;

        if (so->state == NSO_SS_CONNECTED && (so->flags & SF_FLUSH_CLOSE))
            so_reading(so);
        if (so->del)
            goto check_closing;

        if (so->state == NSO_SS_CLOSING)
            _so_close(so, false);
        if (so->del || so->s == -1)
            goto check_closing;

        if (so->state == NSO_SS_CREATED) {
            update_fdevents(so, POLLIN | POLLOUT);
            so->state = NSO_SS_CONNECTING;
            if (so->is_udp) {
                so->state = NSO_SS_CONNECTED;
                if (so->evt_cb)
                    so->evt_cb(so->evt_opaque, SO_EVT_CONNECTED, so->last_err);
            }
            continue;
        }

        if (so->state == NSO_SS_CONNECTING)
            update_fdevents(so, POLLIN | POLLOUT);

        if (so->state == NSO_SS_CONNECTED) {
            int events = 0;

            if (!(so->flags & SF_SOCK_READ))
                events |= POLLIN;
            if (!(so->flags & SF_SOCK_WRITE))
                events |= POLLOUT;

            update_fdevents(so, events);
        }

        if (so->state == NSO_SS_LISTENING)
            update_fdevents(so, POLLIN);

/* needs to be the last line in the loop */
check_closing:
        if (so->del == SDEL_CLOSING) {
            _so_close(so, false);
            so->del = SDEL_CLOSED;
        }
        if (!so->refcnt)
            so_free(so);
    }

}

int so_init(struct nickel *ni)
{
#ifdef _WIN32
    ni->so_event = WSACreateEvent();
    if (ni->so_event == WSA_INVALID_EVENT) {
        warnx("%s: WSACreateEvent failed, %d", __FUNCTION__, WSAGetLastError());
        return -1;
    }
    ni_add_wait_object(ni, &ni->so_event, events_poll, ni);
#endif
    return 0;
}
