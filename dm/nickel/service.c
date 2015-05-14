/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/char.h>
#include <dm/vm.h>
#include <dm/libnickel.h>
#include <dm/net-user.h>
#include "nickel.h"
#include "log.h"
#include "socket.h"
#include "service.h"
#include "tcpip.h"
#include "dns/dns.h"

struct tcp_vmfwd {
    LIST_ENTRY(tcp_vmfwd) entry;

    /* only main host addr supported */
    /* struct in_addr host_addr; */
    int host_port;

    struct in_addr vm_addr;
    int vm_port;

    yajl_val service_config;

    CharDriverState *chr;
    CharDriverState *(*service_open)(void *, struct net_user *, CharDriverState **,
            struct sockaddr_in, struct sockaddr_in, yajl_val);
};

struct udp_vmfwd {
    LIST_ENTRY(udp_vmfwd) entry;

    /* only main host addr supported */
    /* struct in_addr host_addr; */
    int host_port;

    struct in_addr vm_addr;
    int vm_port;

    CharDriverState *chr;

    void *svc_opaque;
    void (*svc_cb) (void *);

    yajl_val service_config;
    CharDriverState *(*service_open)(void *, struct net_user *, CharDriverState **,
            struct sockaddr_in, struct sockaddr_in, yajl_val);

    uint64_t total_byte_limit;
};

static LIST_HEAD(, prx_fwd) ni_prx_list = LIST_HEAD_INITIALIZER(&ni_prx_list);

void *
ni_vmfwd_add_service(struct nickel *ni, int is_udp,
                      CharDriverState *(*service_open)(void *,
                                                       struct net_user *,
                                                       CharDriverState **,
                                                       struct sockaddr_in,
                                                       struct sockaddr_in,
                                                       yajl_val),
                      yajl_val service_config,
                      struct in_addr host_addr, int host_port,
                      struct in_addr vm_addr, int vm_port, uint64_t byte_limit)
{
    void *opaque;
    dict config_dict;

    config_dict = dict_new();
    if (!config_dict) {
        warnx("%s: malloc", __FUNCTION__);
        return NULL;
    }
    if (service_config && dict_merge(service_config, config_dict)) {
        warnx("%s: dict_merge failed", __FUNCTION__);
        return NULL;
    }

    if (is_udp) {
        struct udp_vmfwd *vmfwd;

        if (service_open == NULL) {
            warnx("%s: no service_open fn", __FUNCTION__);
            return NULL;
        }

        vmfwd = (struct udp_vmfwd *)calloc(1, sizeof(struct udp_vmfwd));
        if (vmfwd == NULL) {
            warnx("%s: malloc", __FUNCTION__);
            return NULL;
        }

        vmfwd->service_open = service_open;
        vmfwd->service_config = config_dict;

        vmfwd->host_port = htons(host_port);
        vmfwd->vm_addr = vm_addr;
        vmfwd->vm_port = htons(vm_port);

        if (byte_limit)
            vmfwd->total_byte_limit = byte_limit + 1;

        LIST_INSERT_HEAD(&ni->udp_vmfwd, vmfwd, entry);
        opaque = vmfwd;
    } else {
        struct tcp_vmfwd *vmfwd;

        if (service_open == NULL) {
            warnx("%s: no service_open fn", __FUNCTION__);
            return NULL;
        }

        vmfwd = (struct tcp_vmfwd *)calloc(1, sizeof(struct tcp_vmfwd));
        if (vmfwd == NULL) {
            warnx("%s: malloc", __FUNCTION__);
            return NULL;
        }

        vmfwd->service_open = service_open;
        vmfwd->service_config = config_dict;

        vmfwd->host_port = htons(host_port);
        vmfwd->vm_addr = vm_addr;
        vmfwd->vm_port = htons(vm_port);

        LIST_INSERT_HEAD(&ni->tcp_vmfwd, vmfwd, entry);
        opaque = vmfwd;
    }

    return opaque;
}

void *
ni_vmfwd_add(struct nickel *ni, int is_udp, void *chr,
                struct in_addr host_addr, int host_port,
                struct in_addr vm_addr, int vm_port, uint64_t byte_limit)
{
    void *opaque = NULL;

    if (!vm_addr.s_addr)
        vm_addr = ni->dhcp_startaddr;
    if (is_udp) {
        struct udp_vmfwd *vmfwd;

        vmfwd = (struct udp_vmfwd *)calloc(1, sizeof(struct udp_vmfwd));
        if (vmfwd == NULL) {
            warnx("%s: malloc", __FUNCTION__);
            return NULL;
        }

        vmfwd->chr = chr;
        vmfwd->svc_cb = NULL;

        vmfwd->host_port = htons(host_port);
        vmfwd->vm_addr = vm_addr;
        vmfwd->vm_port = htons(vm_port);

        if (byte_limit)
            vmfwd->total_byte_limit = byte_limit + 1;

        LIST_INSERT_HEAD(&ni->udp_vmfwd, vmfwd, entry);
        opaque = vmfwd;
    } else {
        warnx("tcp vmfwd not supported");
    }

    return opaque;
}

bool ni_is_udp_vmfwd(struct nickel *ni, const struct in_addr dst_ip,
        const uint16_t dst_port)
{
    struct udp_vmfwd *vmfwd;

    if ((dst_ip.s_addr & ni->network_mask.s_addr) != ni->network_addr.s_addr)
        return false;

    LIST_FOREACH(vmfwd, &ni->udp_vmfwd, entry)
        if (dst_port == vmfwd->host_port)
            return true;

    return false;
}

bool ni_is_tcp_vmfwd(struct nickel *ni, const struct in_addr dst_ip,
        const uint16_t dst_port)
{
    struct tcp_vmfwd *vmfwd;

    if ((dst_ip.s_addr & ni->network_mask.s_addr) != ni->network_addr.s_addr)
        return false;

    LIST_FOREACH(vmfwd, &ni->tcp_vmfwd, entry)
        if (dst_port == vmfwd->host_port)
            return true;

    return false;
}

yajl_val ni_get_service_config(struct nickel *ni, const char *service_name)
{
    yajl_val ret = NULL;
    struct tcp_vmfwd *vmfwd;

    LIST_FOREACH(vmfwd, &ni->tcp_vmfwd, entry) {
        const char *name;

        if (!vmfwd->service_config)
            continue;
        name = yajl_object_get_string(vmfwd->service_config, "service");
        if (!name)
            continue;
        if (strcmp(service_name, name) != 0)
            continue;

        ret = vmfwd->service_config;
        break;
    }

    return ret;
}

CharDriverState *
ni_udp_vmfwd_open(struct nickel *ni, struct sockaddr_in saddr,
        struct sockaddr_in daddr, void *opaque)
{
    struct udp_vmfwd *vmfwd;
    CharDriverState *chr;

    LIST_FOREACH(vmfwd, &ni->udp_vmfwd, entry)
        if (daddr.sin_port == vmfwd->host_port && (vmfwd->vm_port == 0 ||
                    saddr.sin_port == vmfwd->vm_port))
            break;

    if (!vmfwd)
        return NULL;

#if NEXT_STAGE
    if (!(vmfwd->total_byte_limit + 1))
        goto out;
    if (vmfwd->total_byte_limit) {
        if (vmfwd->total_byte_limit < len) {
            vmfwd->total_byte_limit = (uint64_t)(-1);
            LOGSLIRP("%s: byte count limit reached for udp vmfwd :%d -> :%d,"
                " subsequent packets from guest will be dropped.", __FUNCTION__,
                ntohs(vmfwd->vm_port), ntohs(vmfwd->host_port));

            goto out;
        }
        vmfwd->total_byte_limit -= len;
    }
#endif

    if (vmfwd->chr)
        return vmfwd->chr;

    chr = vmfwd->service_open(opaque, &ni->nu, &vmfwd->chr, saddr, daddr,
            vmfwd->service_config);
    return chr;
}

static struct prx_fwd *
ni_prx_find_service(const char *name, bool udp)
{
    int is_udp = udp ? 1 : 0;
    struct prx_fwd *prx = NULL;

    LIST_FOREACH(prx, &ni_prx_list, entry)
        if (prx->is_udp == is_udp && !strcmp(prx->name, name))
            break;

    return prx;
}

CharDriverState *
ni_tcp_vmfwd_open(struct nickel *ni, struct sockaddr_in saddr, struct sockaddr_in daddr, void *opaque)
{
    struct tcp_vmfwd *vmfwd;
    CharDriverState *chr = NULL;

    LIST_FOREACH(vmfwd, &ni->tcp_vmfwd, entry)
        if (daddr.sin_port == vmfwd->host_port &&
            (vmfwd->vm_addr.s_addr == INADDR_ANY ||
             saddr.sin_addr.s_addr == vmfwd->vm_addr.s_addr) &&
            (vmfwd->vm_port == 0 || saddr.sin_port == vmfwd->vm_port))
            break;

    if (!vmfwd)
        goto out;

    if (vmfwd->chr)
        chr = vmfwd->chr;
    else
        chr = vmfwd->service_open(opaque, &ni->nu, &vmfwd->chr, saddr, daddr,
                vmfwd->service_config);
out:
    return chr;
}

CharDriverState *
ni_prx_open(struct nickel *ni, bool udp, struct sockaddr_in saddr,
            struct sockaddr_in daddr, void *opaque)
{
    struct prx_fwd *prx;
    int is_udp = udp ? 1 : 0;
    CharDriverState *chr = NULL;

    if (daddr.sin_addr.s_addr == ni->host_addr.s_addr) {
        if (!ni->ac_enabled)
            daddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        else
            return NULL;
    }
    LIST_FOREACH(prx, &ni->prx_fwd, entry) {
        if (is_udp != prx->is_udp)
            continue;
        chr = prx->open(opaque, ni, saddr, daddr);
        if (chr)
            break;
    }

    return chr;
}

CharDriverState *
ni_prx_accept(void *opaque, struct nickel *ni, struct socket *so)
{
    struct prx_fwd *prx;
    CharDriverState *chr = NULL;

    LIST_FOREACH(prx, &ni->prx_fwd, entry) {
        if (!prx->accept)
            continue;
        chr = prx->accept(opaque, ni, so);
        if (chr)
            break;
    }

    return chr;
}
static struct prx_fwd *
ni_add_proxy(struct nickel *ni, struct prx_fwd *prx)
{
    struct prx_fwd *prx0 = NULL;

    prx0 = calloc(1, sizeof(*prx0));
    if (!prx0)
        return NULL;
    memcpy(prx0, prx, sizeof(*prx0));
    LIST_INSERT_HEAD(&ni->prx_fwd, prx0, entry);

    return prx0;
}

int ni_proxyfwd_add(struct nickel *ni, const char *name, bool udp)
{
    struct prx_fwd *prx = NULL;
    int is_udp = udp ? 1 : 0;
    dict d;

    LIST_FOREACH(prx, &ni->prx_fwd, entry) {
        if (prx->is_udp == is_udp && strcmp(prx->name, name) == 0)
            break;
    }

    if (prx)
        return 0;

    prx = ni_prx_find_service(name, udp);
    if (prx == NULL) {
        error_report("unknown service %s for vm proxy forwarding", name);
        return -1;
    }
    prx = ni_add_proxy(ni, prx);
    if (!prx)
        return -1;

    d = dict_new();
    if (!d)
        return -1;
    if (prx->init)
        prx->init(ni, d);

    NETLOG("%s: adding %s service", __FUNCTION__, name);
    return 0;
}


int ni_proxyfwd(struct nickel *ni, const yajl_val object)
{
    struct prx_fwd *prx;
    const char *name;
    int is_udp = 0;

    name = yajl_object_get_string(object, "name");
    if (!name) {
        error_report("'name' key missing in vm proxy fwd dict");
        return -1;
    }
    is_udp = yajl_object_get_bool_default(object, "udp", 0);
    prx = ni_prx_find_service(name, is_udp != 0);
    if (prx == NULL) {
        error_report("unknown service %s for vm proxy forwarding", name);
        return -1;
    }
    prx = ni_add_proxy(ni, prx);
    if (!prx)
        return -1;
    if (prx->init)
        prx->init(ni, object);

    if (!is_udp)
        ni->tcp_service_ok = 1;

    return 0;
}


void _ni_prx_add_service(struct prx_fwd *prx)
{
    prx->is_udp = !!prx->is_udp;
    LIST_INSERT_HEAD(&ni_prx_list, prx, entry);
}


/* pipe to TCP */
struct host_pipe_s {
    CharDriverState *chr;
    int ni_closed;
    int closing;
    int close_on_retry;
    int close_reconnect;
    void *ni_opaque;
    struct nickel *ni;
};

static int
pipe_can_receive(void *opaque)
{
    struct host_pipe_s *pipe = opaque;

    if (pipe->ni_closed)
        return 0;

    return ni_can_recv(pipe->ni_opaque);
}

static void
pipe_receive(void *opaque, const uint8_t *buf, int size)
{
    struct host_pipe_s *pipe = opaque;

    if (pipe->ni_closed)
        return;

    ni_recv(pipe->ni_opaque, buf, size);
}

static int pipe_can_write(void *opaque)
{
    return (64 * 1024 - 2);
}

static void pipe_close_cb(void *opaque)
{
    struct host_pipe_s *pipe = opaque;

    if (!pipe->ni_closed) {
        pipe->ni_closed = 1;
        ni_close(pipe->ni_opaque);
        pipe->ni_opaque = NULL;
    }
    NETLOG("%s: closing hostfwd pipe", __FUNCTION__);
    qemu_chr_close(pipe->chr);
    pipe->chr = NULL;
    pipe->ni_opaque = NULL;
    free(pipe);
}

static void pipe_reconect_cb(void *opaque)
{
    struct host_pipe_s *pipe = opaque;

    if (pipe->chr && pipe->chr->chr_reconnect)
        pipe->chr->chr_reconnect(pipe->chr);
    if (pipe->chr->chr_update_read_handler)
        pipe->chr->chr_update_read_handler(pipe->chr);

}

static struct host_pipe_s *
pipe_open(struct nickel *ni, const char *pipe_name)
{
    struct host_pipe_s *pipe;
    CharDriverState *chr;

    pipe = calloc(1, sizeof(*pipe));
    if (!pipe) {
        warnx("%s: malloc", __FUNCTION__);
        return NULL;
    }

    chr = qemu_chr_open("nickel-pipe", pipe_name, NULL, &ni->io_handlers);
    if (!chr) {
        free(pipe);
        return NULL;
    }

    pipe->chr = chr;
    return pipe;
}

static void
pipe_event(void *opaque, int event)
{
    struct host_pipe_s *pipe = opaque;

    if (event == CHR_EVENT_RESET || event == CHR_EVENT_EOF) {

        if (!pipe->ni_closed)
            ni_event(pipe->ni_opaque, CHR_EVENT_EOF);
        return;
    }
}

static void
pipe_send_event(CharDriverState *chr, int event)
{
    struct host_pipe_s *pipe = chr->handler_opaque;

    if (event == CHR_EVENT_NI_REFUSED) {
        if (pipe->close_on_retry && ni_schedule_bh(pipe->ni, NULL, pipe_reconect_cb, pipe) < 0)
            NETLOG("%s: ni_schedule_bh failed", __FUNCTION__);

        return;
    }

    if (event == CHR_EVENT_NI_RST || event == CHR_EVENT_NI_CLOSE) {
        if (pipe->close_reconnect) {
            if (ni_schedule_bh(pipe->ni, NULL, pipe_reconect_cb, pipe) < 0)
                NETLOG("%s: ni_schedule_bh failed", __FUNCTION__);

            return;
        }
        if (pipe->closing)
            return;
        NETLOG("guest connection close request with %s", event == CHR_EVENT_NI_RST ?
                "RST" : "FIN");
        pipe->closing = 1;
        if (!pipe->ni_closed) {
            ni_close(pipe->ni_opaque);
            pipe->ni_opaque = NULL;
            pipe->ni_closed = 1;
        }

        if (event == CHR_EVENT_NI_RST && pipe->ni->crash_dump_on_ipc_rst)
            vm_inject_nmi();

        // schedule closing the pipe
        if (ni_schedule_bh(pipe->ni, NULL, pipe_close_cb, pipe) < 0) {
            warnx("%s: ni_schedule_bh failed!", __FUNCTION__);
            return;
        }
    }
}

int
ni_add_hostfwd_pipe(struct nickel *ni, int is_udp, const char *host_pipe, struct in_addr host_addr,
        int host_port, struct in_addr guest_addr, int guest_port, int close_reconnect, int close_on_retry)
{
    struct host_pipe_s *pipe = NULL;
    int ret = -1;
    void *opaque = NULL;

    if (is_udp) {
	warnx("udp hostfwd not supported");
        goto out;
    }

    pipe = pipe_open(ni, host_pipe);
    if (!pipe) {
        error_report("could not open pipe %s", host_pipe);
        return -1;
    }
    pipe->ni = ni;
    pipe->chr->reconnect_on_close = close_reconnect;
    pipe->close_reconnect = close_reconnect;
    pipe->close_on_retry = close_on_retry;
    if (!guest_addr.s_addr)
        guest_addr = ni->dhcp_startaddr;
    if (!host_addr.s_addr)
        host_addr = ni->host_addr;
    /* SS_FWDCLOSE set so that the pipe is closed when guest (tcp part) closes the connection */
    /* SS_CLOSERETRY set so that the pipe is closed even while retrying to connect to guest */
    opaque = tcp_listen_create(ni, pipe->chr, host_addr.s_addr, htons(host_port), guest_addr.s_addr,
            htons(guest_port), SS_HOSTFWD | (close_reconnect ? 0 : SS_FWDCLOSE) |
           (close_on_retry ? SS_CLOSERETRY : 0));
    if (!opaque)
        goto out;

    pipe->ni_opaque = opaque;
    qemu_chr_add_handlers(pipe->chr, pipe_can_receive, pipe_receive, pipe_event,
                          (void*)pipe);
    pipe->chr->chr_can_write = pipe_can_write;
    pipe->chr->chr_send_event = pipe_send_event;
    ret = 0;
out:
    return ret;
}

struct hostfwd_listen_t {
    struct nickel *ni;
    struct socket *so;
    uint16_t guest_port;
};

static void hostfwd_listen_event(void *opaque, uint32_t evt, int err)
{
}

static void hostfwd_accept(void *opaque, struct socket *so)
{
    struct hostfwd_listen_t *hfwd = opaque;
    void *tcp_opaque;
    CharDriverState *chr;

    tcp_opaque = tcp_listen_create(hfwd->ni, NULL, 0, 0, 0, htons(hfwd->guest_port), SS_HOSTFWD);
    if (!tcp_opaque) {
        NETLOG("%s: tcp_listen_create failed", __FUNCTION__);
        so_close(so);
        return;
    }

    chr = ni_prx_accept(tcp_opaque, hfwd->ni, so);
    if (!chr) {
        NETLOG("%s: ni_prx_accept failed", __FUNCTION__);
        so_close(so);
        ni_close(tcp_opaque);
        return;
    }

    tcpip_set_chr(tcp_opaque, chr);
    ni_can_recv(tcp_opaque); /* triggers fwd timer */
}

int ni_add_hostfwd(struct nickel *ni, int is_udp, struct in_addr host_addr,
                      int host_port, struct in_addr guest_addr, int guest_port)
{
    struct net_addr addr;
    struct hostfwd_listen_t *hfwd = NULL;
    struct socket *lso = NULL;

    if (is_udp) {
#if NEXT_STAGE
        if (!udp_listen(ni, host_addr.s_addr, htons(host_port),
                        guest_addr.s_addr, htons(guest_port), SS_HOSTFWD))
            return -1;
#endif
        NETLOG("%s: udp not yet supported", __FUNCTION__);
        return -1;
    }

    hfwd = calloc(1, sizeof(*hfwd));
    if (!hfwd) {
        warnx("%s: malloc", __FUNCTION__);
        return -1;
    }
    hfwd->ni = ni;

    lso = so_create(ni, false, hostfwd_listen_event, (void*) hfwd);
    if (!lso) {
        NETLOG("%s: so_create error", __FUNCTION__);
        return -1;
    }
    hfwd->so = lso;
    hfwd->guest_port = guest_port;
    addr.family = AF_INET;
    addr.ipv4 = host_addr;
    if (so_listen(lso, &addr, htons(host_port), hostfwd_accept, hfwd) < 0) {
        NETLOG("%s: so_listen error", __FUNCTION__);
        return -1;
    }
    return 0;
}
