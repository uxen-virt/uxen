/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "config.h"

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "char.h"
#include "monitor.h"
#include "ns.h"
#include "opts.h"
#include "slirp.h"

#include "qemu/net.h"

#if defined(__APPLE__)
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#endif

#include <libslirp.h>
#if defined(SLIRP_DUMP_PCAP)
#include "control.h"
#include <sys/time.h>
#if defined(__APPLE__)
#include <unistd.h>
#endif
#endif


static int get_str_sep(char *buf, int buf_size, const char **pp, int sep)
{
    const char *p, *p1;
    int len;
    p = *pp;
    p1 = strchr(p, sep);
    if (!p1)
        return -1;
    len = p1 - p;
    p1++;
    if (buf_size > 0) {
        if (len > buf_size - 1)
            len = buf_size - 1;
        memcpy(buf, p, len);
        buf[len] = '\0';
    }
    *pp = p1;
    return 0;
}

/* slirp network adapter */

typedef struct SlirpState {
    VLANClientState nc;
    QTAILQ_ENTRY(SlirpState) entry;
    Slirp *slirp;
#if defined(SLIRP_DUMP_PCAP)
    FILE *pcapf;
    char *pcap_fpath;
    int debug_dns_udp_icmp;
#endif
} SlirpState;

const char *legacy_tftp_prefix;
const char *legacy_bootp_filename;
static QTAILQ_HEAD(slirp_stacks, SlirpState) slirp_stacks =
    QTAILQ_HEAD_INITIALIZER(slirp_stacks);

static int slirp_hostfwd(SlirpState *s, const yajl_val object);
#if 0
static int slirp_guestfwd(SlirpState *s, const char *config_str,
                          int legacy_format);
#endif

int slirp_can_output(void *opaque)
{
    SlirpState *s = opaque;

    return qemu_can_send_packet(&s->nc);
}

#if defined(SLIRP_DUMP_PCAP)
typedef struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        uint32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

static int64_t epoch_ts = 0LL;

static int64_t
get_epoch_ts(void)
{
    int64_t ret, diff = 0LL;
    int i;

    for (i = 0; i < 10; i++) {
        int64_t t1, t2;
        struct timeval tv;

        t1 = get_clock_ns(rt_clock);
        gettimeofday(&tv, NULL);
        t2 = get_clock_ns(rt_clock);
        if (!diff || diff > t2 - t1) {
            diff = t2 - t1;
            ret = CLOCK_BASE * tv.tv_sec + tv.tv_usec * 1000
                - ((t2 + t1) >> 1);
            if (diff < 10000LL)
                break;
        }
    }

    return ret;
}

static int
slirp_pcap_fileinit(SlirpState *s)
{
    bool appending = false;
    pcap_hdr_t pcap_gh = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1
    };

    if (s->pcapf)
        return 0;

    if (!s->pcap_fpath)
        return -1;

    appending = (access(s->pcap_fpath, F_OK) != -1);
    s->pcapf = fopen(s->pcap_fpath, appending ? "ab" : "wb");
    if (!s->pcapf) {
        warnx("%s: cannot create pcap file", __FUNCTION__);
        return -1;
    }

    if (appending) {
        fseek(s->pcapf, 0L, SEEK_END);
        appending = ftell(s->pcapf) != 0L;
    }

    setvbuf(s->pcapf, (char *)NULL, _IOFBF, BUFSIZ);
    if (!appending)
        fwrite((void*)&pcap_gh, sizeof(pcap_gh), 1, s->pcapf);

    return 0;
}

static int slirp_pcap_config(SlirpState *s, const yajl_val arg)
{
    int ret = -1;
    const char *fpath = NULL;

    if (YAJL_IS_OBJECT(arg)) {
        fpath = yajl_object_get_string(arg, "file");
        if (!fpath) {
            warnx("tcpdump map: \"file\" key needs to exist and be a string");
            goto out;
        }
    } else {
        fpath = YAJL_GET_STRING(arg);
    }

    if (!fpath) {
        warnx("tcpdump arg wrong type: expect string (or map)");
        goto out;
    }

    s->pcap_fpath = strdup(fpath);
    if (!s->pcap_fpath) {
        warnx("malloc failure");
        goto out;
    }

    epoch_ts = get_epoch_ts();

    if (slirp_pcap_fileinit(s))
        goto out;
    ret = 0;
out:
    return ret;
}

uint64_t slirp_get_pcap_ts(uint32_t *sec, uint32_t *usec)
{
    uint64_t now;

    now = get_clock_ns(rt_clock) + epoch_ts;
    *sec = now / CLOCK_BASE;
    *usec = (now/1000) % 1000000LL;

    return now;
}

static void
slirp_dump_packet(SlirpState *s, const uint8_t *buf, size_t len)
{
    static uint64_t ts = 0;
    pcaprec_hdr_t ph;
    uint64_t now;

    if (!s->pcapf)
        return;
    now = slirp_get_pcap_ts(&ph.ts_sec, &ph.ts_usec);
    ph.incl_len = ph.orig_len = len;
    fwrite((void*)&ph, sizeof(ph), 1, s->pcapf);
    fwrite((void*)buf, len, 1, s->pcapf);

    if (!ts || now-ts > CLOCK_BASE*5) {
        ts = now;
        fflush(s->pcapf);
    }
}

#endif

void slirp_output(void *opaque, const uint8_t *pkt, int pkt_len)
{
    SlirpState *s = opaque;

#if defined(SLIRP_DUMP_PCAP)
    if (s->debug_dns_udp_icmp)
        slirp_debug_dmp(s->slirp, pkt, pkt_len, false);
    slirp_dump_packet(s, pkt, pkt_len);
#endif

    slirp_stats_rx(pkt_len);
    qemu_send_packet(&s->nc, pkt, pkt_len);
}

static ssize_t net_slirp_receive(VLANClientState *nc, const uint8_t *buf, size_t size)
{
    SlirpState *s = DO_UPCAST(SlirpState, nc, nc);

#if defined(SLIRP_DUMP_PCAP)
    if (s->debug_dns_udp_icmp)
        slirp_debug_dmp(s->slirp, buf, size, true);
    slirp_dump_packet(s, buf, size);
#endif

    slirp_stats_tx(size);
    slirp_input(s->slirp, buf, size);

    return size;
}

static void net_slirp_cleanup(VLANClientState *nc)
{
    SlirpState *s = DO_UPCAST(SlirpState, nc, nc);

#ifdef SLIRP_THREADED
    slirp_mark_deletion(s->slirp);
#else
    slirp_cleanup(s->slirp);
#endif

    QTAILQ_REMOVE(&slirp_stacks, s, entry);

#ifdef SLIRP_DUMP_PCAP
    if (s->pcapf) {
        fclose(s->pcapf);
        s->pcapf = NULL;
    }
    free(s->pcap_fpath);
    s->pcap_fpath = NULL;
#endif

#ifdef SLIRP_THREADED
    if (QTAILQ_EMPTY(&slirp_stacks))
        slirp_thread_exit();
#endif
}

static NetClientInfo net_slirp_info = {
    .type = NET_CLIENT_TYPE_USER,
    .size = sizeof(SlirpState),
    .receive = net_slirp_receive,
    .cleanup = net_slirp_cleanup,
};

static SlirpState *
net_slirp_init(VLANState *vlan, const char *model,
	       const char *name, int restricted,
	       const char *vnetwork, const char *vhost,
	       const char *vhostname, const char *tftp_export,
	       const char *bootfile, const char *vdhcp_start,
	       const char *vnameserver)
{
    /* default settings according to historic slirp */
    struct in_addr net  = { .s_addr = htonl(0x0a000200) }; /* 10.0.2.0 */
    struct in_addr mask = { .s_addr = htonl(0xffffff00) }; /* 255.255.255.0 */
    struct in_addr host = { .s_addr = htonl(0x0a000202) }; /* 10.0.2.2 */
    struct in_addr dhcp = { .s_addr = htonl(0x0a00020f) }; /* 10.0.2.15 */
    struct in_addr dns  = { .s_addr = htonl(0x0a000203) }; /* 10.0.2.3 */
    VLANClientState *nc;
    SlirpState *s;
    char buf[20];
    uint32_t addr;
    int shift;
    char *end;

    if (!tftp_export) {
        tftp_export = legacy_tftp_prefix;
    }
    if (!bootfile) {
        bootfile = legacy_bootp_filename;
    }

    if (vnetwork) {
        if (get_str_sep(buf, sizeof(buf), &vnetwork, '/') < 0) {
            if (!inet_aton(vnetwork, &net)) {
                return NULL;
            }
            addr = ntohl(net.s_addr);
            if (!(addr & 0x80000000)) {
                mask.s_addr = htonl(0xff000000); /* class A */
            } else if ((addr & 0xfff00000) == 0xac100000) {
                mask.s_addr = htonl(0xfff00000); /* priv. 172.16.0.0/12 */
            } else if ((addr & 0xc0000000) == 0x80000000) {
                mask.s_addr = htonl(0xffff0000); /* class B */
            } else if ((addr & 0xffff0000) == 0xc0a80000) {
                mask.s_addr = htonl(0xffff0000); /* priv. 192.168.0.0/16 */
            } else if ((addr & 0xffff0000) == 0xc6120000) {
                mask.s_addr = htonl(0xfffe0000); /* tests 198.18.0.0/15 */
            } else if ((addr & 0xe0000000) == 0xe0000000) {
                mask.s_addr = htonl(0xffffff00); /* class C */
            } else {
                mask.s_addr = htonl(0xfffffff0); /* multicast/reserved */
            }
        } else {
            if (!inet_aton(buf, &net)) {
                return NULL;
            }
            shift = strtol(vnetwork, &end, 10);
            if (*end != '\0') {
                if (!inet_aton(vnetwork, &mask)) {
                    return NULL;
                }
            } else if (shift < 4 || shift > 32) {
                return NULL;
            } else {
                mask.s_addr = htonl(0xffffffff << (32 - shift));
            }
        }
        net.s_addr &= mask.s_addr;
        host.s_addr = net.s_addr | (htonl(0x0202) & ~mask.s_addr);
        dhcp.s_addr = net.s_addr | (htonl(0x020f) & ~mask.s_addr);
        dns.s_addr  = net.s_addr | (htonl(0x0203) & ~mask.s_addr);
    }

    if (vhost && !inet_aton(vhost, &host)) {
        return NULL;
    }
    if ((host.s_addr & mask.s_addr) != net.s_addr) {
        return NULL;
    }

    if (vdhcp_start && !inet_aton(vdhcp_start, &dhcp)) {
        return NULL;
    }
    if ((dhcp.s_addr & mask.s_addr) != net.s_addr ||
        dhcp.s_addr == host.s_addr || dhcp.s_addr == dns.s_addr) {
        return NULL;
    }

    if (vnameserver && !inet_aton(vnameserver, &dns)) {
        return NULL;
    }
    if ((dns.s_addr & mask.s_addr) != net.s_addr ||
        dns.s_addr == host.s_addr) {
        return NULL;
    }

    nc = qemu_new_net_client(&net_slirp_info, vlan, NULL, model, name);

    snprintf(nc->info_str, sizeof(nc->info_str),
             "net=%s,restrict=%s", inet_ntoa(net),
             restricted ? "on" : "off");

    s = DO_UPCAST(SlirpState, nc, nc);

    s->slirp = slirp_init(restricted, net, mask, host, vhostname,
                          tftp_export, bootfile, dhcp, dns, s);
    QTAILQ_INSERT_TAIL(&slirp_stacks, s, entry);

    return s;

#if 0
error:
    qemu_del_vlan_client(nc);
    return NULL;
#endif
}

#if 0
static SlirpState *slirp_lookup(Monitor *mon, const char *vlan,
				const char *stack)
{

    if (vlan) {
        VLANClientState *nc;
        nc = qemu_find_vlan_client_by_name(mon, strtol(vlan, NULL, 0), stack);
        if (!nc) {
            return NULL;
        }
        if (strcmp(nc->model, "user")) {
            monitor_printf(mon, "invalid device specified\n");
            return NULL;
        }
        return DO_UPCAST(SlirpState, nc, nc);
    } else {
        if (QTAILQ_EMPTY(&slirp_stacks)) {
            monitor_printf(mon, "user mode network stack not in use\n");
            return NULL;
        }
        return QTAILQ_FIRST(&slirp_stacks);
    }
}

void net_slirp_hostfwd_remove(Monitor *mon, const QDict *qdict)
{
    struct in_addr host_addr = { .s_addr = INADDR_ANY };
    int host_port;
    char buf[256];
    const char *src_str, *p;
    SlirpState *s;
    int is_udp = 0;
    int err;
    const char *arg1 = qdict_get_str(qdict, "arg1");
    const char *arg2 = qdict_get_try_str(qdict, "arg2");
    const char *arg3 = qdict_get_try_str(qdict, "arg3");

    if (arg2) {
        s = slirp_lookup(mon, arg1, arg2);
        src_str = arg3;
    } else {
        s = slirp_lookup(mon, NULL, NULL);
        src_str = arg1;
    }
    if (!s) {
        return;
    }

    p = src_str;
    if (!p || get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
        goto fail_syntax;
    }

    if (!strcmp(buf, "tcp") || buf[0] == '\0') {
        is_udp = 0;
    } else if (!strcmp(buf, "udp")) {
        is_udp = 1;
    } else {
        goto fail_syntax;
    }

    if (get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
        goto fail_syntax;
    }
    if (buf[0] != '\0' && !inet_aton(buf, &host_addr)) {
        goto fail_syntax;
    }

    host_port = atoi(p);

    err = slirp_remove_hostfwd(QTAILQ_FIRST(&slirp_stacks)->slirp, is_udp,
                               host_addr, host_port);

    monitor_printf(mon, "host forwarding rule for %s %s\n", src_str,
                   err ? "removed" : "not found");
    return;

 fail_syntax:
    monitor_printf(mon, "invalid format\n");
}
#endif

static int
pipe_can_receive(void *opaque)
{

    return slirp_socket_can_recv(opaque);
}

static void
pipe_receive(void *opaque, const uint8_t *buf, int size)
{

    slirp_socket_recv(opaque, buf, size);
}

static void
pipe_event(void *opaque, int event)
{

    if (event != CHR_EVENT_RESET)
        return;

    slirp_socket_close(opaque);
}

static void *
pipe_open(const char *pipe)
{
    CharDriverState *chr;

    chr = qemu_chr_open("slirp-pipe", pipe, NULL, &slirp_io_handlers);
    if (!chr)
	return NULL;

    return chr;
}

static void *
file_open(const char *file)
{
    CharDriverState *chr;

    chr = qemu_chr_open("slirp-file", file, NULL, &slirp_io_handlers);
    if (!chr)
	return NULL;

    return chr;
}

static int
slirp_hostfwd(SlirpState *s, const yajl_val object)
{
    struct in_addr host_addr = { .s_addr = INADDR_ANY };
    struct in_addr vm_addr = { .s_addr = 0 };
    int host_port, vm_port;
    const char *host_pipe = NULL;
    const char *p;
    int is_udp;

    p = yajl_object_get_string(object, "proto");
    if (!p || !strcmp(p, "tcp"))
        is_udp = 0;
    else if (!strcmp(p, "udp"))
        is_udp = 1;
    else
	goto fail_syntax;

    p = yajl_object_get_string(object, "host_pipe");
    if (p)
	host_pipe = p;

    p = yajl_object_get_string(object, "host_addr");
    if (p && !inet_aton(p, &host_addr))
	goto fail_syntax;

    host_port = yajl_object_get_integer(object, "host_port");
    if (host_port < 1 || host_port > 65535)
	goto fail_syntax;

    p = yajl_object_get_string(object, "vm_addr");
    if (p && !inet_aton(p, &vm_addr))
	goto fail_syntax;

    vm_port = yajl_object_get_integer(object, "vm_port");
    if (vm_port < 1 || vm_port > 65535)
        goto fail_syntax;

    if (host_pipe) {
	CharDriverState *chr;
	void *opaque;
        int close_on_retry;

	chr = pipe_open(host_pipe);
	if (!chr) {
	    error_report("could not open pipe %s", host_pipe);
	    return -1;
	}
	chr->reconnect_on_close = yajl_object_get_bool_default(object, "reconnect-on-close", 0);
	close_on_retry = yajl_object_get_bool_default(object, "close-on-guest-retry", 0);
	opaque = slirp_add_hostfwd_pipe(s->slirp, is_udp, chr,
					host_addr, host_port, vm_addr, vm_port,
                                        chr->reconnect_on_close, close_on_retry);
	if (!opaque) {
	    error_report("could not set up host forwarding rule");
	    return -1;
	}
	qemu_chr_add_handlers(chr, pipe_can_receive, pipe_receive, pipe_event,
			      opaque);
    } else {
	if (slirp_add_hostfwd(s->slirp, is_udp, host_addr, host_port,
			      vm_addr, vm_port) < 0) {
            warn("%s: slirp_add_hostfwd failed", __FUNCTION__);
	    error_report("could not set up host forwarding rule");
	    return -1;
	}
    }
    return 0;

 fail_syntax:
    error_report("invalid host forwarding rule");
    return -1;
}

#if 0
void net_slirp_hostfwd_add(Monitor *mon, const QDict *qdict)
{
    const char *redir_str;
    SlirpState *s;
    const char *arg1 = qdict_get_str(qdict, "arg1");
    const char *arg2 = qdict_get_try_str(qdict, "arg2");
    const char *arg3 = qdict_get_try_str(qdict, "arg3");

    if (arg2) {
        s = slirp_lookup(mon, arg1, arg2);
        redir_str = arg3;
    } else {
        s = slirp_lookup(mon, NULL, NULL);
        redir_str = arg1;
    }
    if (s) {
        slirp_hostfwd(s, redir_str, 0);
    }

}

int net_slirp_redir(const char *redir_str)
{
    struct slirp_config_str *config;

    if (QTAILQ_EMPTY(&slirp_stacks)) {
        config = g_malloc(sizeof(*config));
        pstrcpy(config->str, sizeof(config->str), redir_str);
        config->flags = SLIRP_CFG_HOSTFWD | SLIRP_CFG_LEGACY;
        config->next = slirp_configs;
        slirp_configs = config;
        return 0;
    }

    return slirp_hostfwd(QTAILQ_FIRST(&slirp_stacks), redir_str, 1);
}
#endif

static int
slirp_vmfwd(SlirpState *s, const yajl_val object)
{
    struct in_addr host_addr = { .s_addr = INADDR_ANY };
    struct in_addr vm_addr = { .s_addr = INADDR_ANY };
    int host_port, vm_port = 0;
    const char *host_file = NULL;
    yajl_val host_service = NULL;
    const char *p;
    yajl_val v;
    int is_udp;
    uint64_t byte_limit = 0;
    int64_t tmp;

    p = yajl_object_get_string(object, "proto");
    if (!p || !strcmp(p, "tcp"))
        is_udp = 0;
    else if (!strcmp(p, "udp"))
        is_udp = 1;
    else
	goto fail_syntax;

    p = yajl_object_get_string(object, "host_file");
    if (p)
	host_file = p;

    v = yajl_object_get_object(object, "host_service");
    if (v)
	host_service = v;

    host_port = yajl_object_get_integer(object, "host_port");
    if (host_port < 1 || host_port > 65535)
	goto fail_syntax;

    p = NULL;
    tmp = yajl_object_get_integer_default(object, "byte-count-limit", -1);
    if (tmp > 0)
        byte_limit = tmp;
    else
        p = yajl_object_get_string(object, "byte-count-limit");
    if (p) {
        char tmp[25];
        int plen;
        uint32_t multipl = 1;

        do {
            plen = strlen(p);
            if (!plen || plen > 24)
                break;
            memcpy(tmp, p, plen);
            tmp[plen] = 0;
            switch (tmp[plen - 1]) {
            case 'G':
            case 'g':
                multipl = 1024 * 1024 * 1024;
                break;
            case 'M':
            case 'm':
                multipl = 1024 * 1024;
                break;
            case 'K':
            case 'k':
                multipl = 1024;
                break;
            }
            if (multipl > 1 && plen < 2)
                break;
            if (multipl > 1)
                tmp[plen - 1] = 0;
            if (sscanf(tmp, "%" PRIu64, &byte_limit) > 0)
                byte_limit *= multipl;
            else
                byte_limit = 0;
            if (!(byte_limit + 1) || !(byte_limit + 2))
                byte_limit = 0;
        } while (1 == 0);
        if (!byte_limit)
            warnx("%s: byte-count-limit wrong value (too large number ?)", __FUNCTION__);
    }

    if (byte_limit && !is_udp) {
        byte_limit = 0;
        warnx("%s: byte-count-limit is only supported for udp vmfwd at the moment", __FUNCTION__);
    }

    if (byte_limit)
        debug_printf("%s: byte_limit for vmfwd -> :%d set at %" PRIu64 " bytes\n", __FUNCTION__, host_port, byte_limit);

    if (host_file) {
        CharDriverState *chr;
	void *opaque;

	chr = file_open(host_file);
	if (!chr) {
	    error_report("could not open file %s", host_file);
	    return -1;
	}

	opaque = slirp_add_vmfwd(s->slirp, is_udp, chr,
                                 host_addr, host_port, vm_addr, vm_port, byte_limit);
	if (!opaque) {
	    error_report("could not set up vm forwarding rule");
	    return -1;
	}
    } else if (host_service) {
        void *opaque;
        struct ns_desc *nsd;

        /* FIXME */
        {
            const char *serv = yajl_object_get_string(host_service, "service");
            if (serv && !strcmp(serv, "shared-folders")) {
#if defined(CONFIG_VBOXDRV)
                extern int sf_parse_config(yajl_val config);
                sf_parse_config(host_service);
#endif
                return 0;
            }
        }

        nsd = ns_find_service(yajl_object_get_string(host_service, "service"),
                              is_udp);
        if (nsd == NULL) {
            error_report("unknown service %s for vm service forwarding",
                         yajl_object_get_string(host_service, "service"));
            return -1;
        }

        opaque = slirp_add_vmfwd_service(s->slirp, is_udp,
                                         nsd->service_open, nsd->service_close,
                                         host_service,
                                         host_addr, host_port, vm_addr,
                                         vm_port, byte_limit);
        if (!opaque) {
            error_report("could not set up vm service forwarding rule");
            return -1;
        }

    } else
        goto fail_syntax;

    return 0;

 fail_syntax:
    error_report("invalid guest forwarding rule");
    return -1;
}

#if 0
struct GuestFwd {
    CharDriverState *hd;
    struct in_addr server;
    int port;
    Slirp *slirp;
};

static int guestfwd_can_read(void *opaque)
{
    struct GuestFwd *fwd = opaque;
    return slirp_socket_can_recv(fwd->slirp, fwd->server, fwd->port);
}

static void guestfwd_read(void *opaque, const uint8_t *buf, int size)
{
    struct GuestFwd *fwd = opaque;
    slirp_socket_recv(fwd->slirp, fwd->server, fwd->port, buf, size);
}

static int slirp_guestfwd(SlirpState *s, const char *config_str,
                          int legacy_format)
{
    struct in_addr server = { .s_addr = 0 };
    struct GuestFwd *fwd;
    const char *p;
    char buf[128];
    char *end;
    int port;

    p = config_str;
    if (legacy_format) {
        if (get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
            goto fail_syntax;
        }
    } else {
        if (get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
            goto fail_syntax;
        }
        if (strcmp(buf, "tcp") && buf[0] != '\0') {
            goto fail_syntax;
        }
        if (get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
            goto fail_syntax;
        }
        if (buf[0] != '\0' && !inet_aton(buf, &server)) {
            goto fail_syntax;
        }
        if (get_str_sep(buf, sizeof(buf), &p, '-') < 0) {
            goto fail_syntax;
        }
    }
    port = strtol(buf, &end, 10);
    if (*end != '\0' || port < 1 || port > 65535) {
        goto fail_syntax;
    }

    fwd = g_malloc(sizeof(struct GuestFwd));
    snprintf(buf, sizeof(buf), "guestfwd.tcp.%d", port);
    fwd->hd = qemu_chr_new(buf, p, NULL);
    if (!fwd->hd) {
        error_report("could not open guest forwarding device '%s'", buf);
        g_free(fwd);
        return -1;
    }

    if (slirp_add_exec(s->slirp, 3, fwd->hd, &server, port) < 0) {
        error_report("conflicting/invalid host:port in guest forwarding "
                     "rule '%s'", config_str);
        g_free(fwd);
        return -1;
    }
    fwd->server = server;
    fwd->port = port;
    fwd->slirp = s->slirp;

    qemu_chr_add_handlers(fwd->hd, guestfwd_can_read, guestfwd_read,
                          NULL, fwd);
    return 0;

 fail_syntax:
    error_report("invalid guest forwarding rule '%s'", config_str);
    return -1;
}
#endif

#ifdef MONITOR
void
ic_slirp(Monitor *mon)
{
    SlirpState *s;

    QTAILQ_FOREACH(s, &slirp_stacks, entry) {
        monitor_printf(mon, "VLAN %d (%s):\n",
                       s->nc.vlan ? s->nc.vlan->id : -1,
                       s->nc.name);
        slirp_connection_info(s->slirp, mon);
    }
#ifdef SLIRP_THREADED
    monitor_printf(mon, "slirp threaded: queue max depth in:%lu, out:%lu\n", slirp_inq_max, slirp_outq_max);
#endif
}
#endif  /* MONITOR */

static int
config_slirp_init_post(const char *name, const yajl_val arg, void *opaque)
{
    SlirpState *s = opaque;
    yajl_val v;
    int i;

    if (!strcmp(name, "hostfwd")) {
	if (!YAJL_IS_OBJECT(arg) && !YAJL_IS_ARRAY(arg))
	    warnx("hostfwd arg wrong type: expect map or array of map");
	else
	    YAJL_FOREACH_ARRAY_OR_OBJECT(v, arg, i) {
		if (!YAJL_IS_OBJECT(v)) {
		    warnx("hostfwd arg wrong type: expect map");
		    continue;
		}
		if (slirp_hostfwd(s, v) < 0)
		    /* ignore -- goto error */;
	    }
    } else if (!strcmp(name, "vmfwd")) {
	if (!YAJL_IS_OBJECT(arg) && !YAJL_IS_ARRAY(arg))
	    warnx("vmfwd arg wrong type: expect map or array of map");
	else
	    YAJL_FOREACH_ARRAY_OR_OBJECT(v, arg, i) {
		if (!YAJL_IS_OBJECT(v)) {
		    warnx("vmfwd arg wrong type: expect map");
		    continue;
		}
		if (slirp_vmfwd(s, v) < 0)
		    /* ignore -- goto error */;
	    }
    } else if (!strcmp(name, "proxyfwd")) {
	if (!YAJL_IS_OBJECT(arg) && !YAJL_IS_ARRAY(arg))
	    warnx("proxyfwd arg wrong type: expect map or array of map");
	else
	    YAJL_FOREACH_ARRAY_OR_OBJECT(v, arg, i) {
		if (!YAJL_IS_OBJECT(v)) {
		    warnx("proxyfwd arg wrong type: expect map");
		    continue;
		}
	    }
#if defined(SLIRP_DUMP_PCAP)
    } else if (!strcmp(name, "tcpdump")) {
        if (slirp_pcap_config(s, arg))
            /* ignore -- goto error */;
    } else if (!strcmp(name, "debug-dns-udp-icmp")) {
        if (YAJL_IS_TRUE(arg))
            s->debug_dns_udp_icmp = 1;
        if (s->debug_dns_udp_icmp)
            debug_printf("slirp: debug-dns-udp-icmp active - will dump ICMP, DNS and some other "
                    "UDP packets\n");
#endif

    } else 
        slirp_get_config_option(s->slirp, name, arg);

    return 0;
}

int
net_init_slirp(QemuOpts *opts, Monitor *mon, const char *name,
	       VLANState *vlan)
{
    SlirpState *s;
    const char *vhost;
    const char *vhostname;
    const char *vdhcp_start;
    const char *vnamesrv;
    const char *tftp_export;
    const char *bootfile;
    const char *restrict_opt;
    char *vnet = NULL;
    int restricted = 0;
    int ret;

    vhost       = qemu_opt_get(opts, "host");
    vhostname   = qemu_opt_get(opts, "hostname");
    vdhcp_start = qemu_opt_get(opts, "dhcpstart");
    vnamesrv    = qemu_opt_get(opts, "dns");
    tftp_export = qemu_opt_get(opts, "tftp");
    bootfile    = qemu_opt_get(opts, "bootfile");

    restrict_opt = qemu_opt_get(opts, "restrict");
    if (restrict_opt) {
        if (!strcmp(restrict_opt, "on") ||
            !strcmp(restrict_opt, "yes") || !strcmp(restrict_opt, "y")) {
            restricted = 1;
        } else if (strcmp(restrict_opt, "off") &&
            strcmp(restrict_opt, "no") && strcmp(restrict_opt, "n")) {
            error_report("invalid option: 'restrict=%s'", restrict_opt);
            return -1;
        }
    }

    if (qemu_opt_get(opts, "ip")) {
        const char *ip = qemu_opt_get(opts, "ip");
        int l = strlen(ip) + strlen("/24") + 1;

        vnet = g_malloc(l);

        /* emulate legacy ip= parameter */
        pstrcpy(vnet, l, ip);
        pstrcat(vnet, l, "/24");
    }

    if (qemu_opt_get(opts, "net")) {
        if (vnet)
            g_free(vnet);
        vnet = g_strdup(qemu_opt_get(opts, "net"));
    }

    if (!vlan)
        vlan = qemu_find_vlan(0, 1);

    s = net_slirp_init(vlan, "user", name, restricted, vnet, vhost,
		       vhostname, tftp_export, bootfile, vdhcp_start,
		       vnamesrv);
    if (s) {
#if defined(SLIRP_DUMP_PCAP)
        s->pcapf = NULL;
#endif
	(void)qemu_opt_foreach_object(opts, config_slirp_init_post, s, 0);
	ret = 0;
    } else
	ret = -1;

    g_free(vnet);
    return ret;
}
