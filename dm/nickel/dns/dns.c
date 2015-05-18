/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>

#include <ctype.h>

#include <dm/dict.h>
#include <dm/char.h>
#include <dm/ns.h>
#include <dm/libnickel.h>
#include <nickel.h>
#include <log.h>
#include "dns.h"
#include "dns-fake.h"


#define HYB_EXPIRE_MS   (10 * 60 * 1000)

#include <access-control.h>

#define SLIRP_GW_NAME "417007E91B64.bromium.com"
#define DNS_PACKET_MAXSIZE 700

#define GUEST_DNS_SUFFIX ".internal-domain.local"

#define DDNS(d, fmt, ...) do { if (debug_resolver) NETLOG("(dns-debug) [%s] d:%lx " fmt, \
                             __FUNCTION__, d, ## __VA_ARGS__); } while(1 == 0)
#define DNS_GET_ID(pkt) (unsigned int) (pkt ? (((union dnsmsg_header *)(pkt))->x.id) : -1)

static bool http_proxy_enabled = false;
static bool proxy_used = false;
static int proxy_forbid_nonexistent_dns_name = 0;
static int debug_resolver = 0;
static int ipv6_allowed = 1;
static int no_proxy_mode = 0;

static void ndns_close(CharDriverState *chr);

struct dns_chr_t {
    CharDriverState chr;
    struct nickel *ni;
    void *net_opaque;
    int closing;
};

/* see RFC 1035(4.1.1) */
union dnsmsg_header {
    struct {
        unsigned id:16;
        unsigned rd:1;
        unsigned tc:1;
        unsigned aa:1;
        unsigned opcode:4;
        unsigned qr:1;
        unsigned rcode:4;
        unsigned z:3;
        unsigned ra:1;
        uint16_t qdcount;
        uint16_t ancount;
        uint16_t nscount;
        uint16_t arcount;
    } x;
    uint16_t raw[6];
};

struct dns_meta_data {
    uint16_t type;
    uint16_t class;
};

struct dnsmsg_answer {
    uint16_t name;
    struct dns_meta_data meta;
    uint16_t ttl[2];
    uint16_t rdata_len;
    uint8_t  rdata[0];  /* depends on value at rdata_len */
};

struct ndns_data {
    struct nickel *ni;
    char *dname;
    int denied;
    struct dns_response response;
    union {
        struct {
            struct dns_chr_t *dns_chr;
            uint8_t *dns_req;
            int dns_len;
            int resp_written;
            int proxy_on;
            int is_internal;
            int is_fake;
        };
        struct in_addr fake_ip;
    };
};

static void dns_input_continue(void *opaque);

/* see RFC 1035(4.1) */
static void cstr2qstr(const char *cstr, char *qstr, size_t qstr_len);
static int qstr2cstr(const char *qstr, char *cstr, size_t cstr_len);

/*
 * qstr is z-string with -dot- replaced with \count to next -dot-
 * e.g. ya.ru is \02ya\02ru
 * Note: it's assumed that caller allocates buffer for cstr
 */
static int qstr2cstr(const char *qstr, char *cstr, size_t cstr_len)
{
    int ret = -1;
    const unsigned char *q;
    size_t clen;
    unsigned char blen;

    if (cstr_len == 0)
        goto out;

    blen = 0;
    clen = 0;
    for (q = (const unsigned char *)qstr; *q != '\0' && clen < cstr_len - 1; q++) {
        if (blen == 0) {
            blen = *q;
            if (clen > 0)
                cstr[clen++] = '.';

            continue;
        }

        blen--;
        if (isalpha(*q) || isdigit(*q) || *q == '-' || *q == '_')
            cstr[clen++] = *q;
        else
            goto out; /* not valid dns character ? */
    }

    cstr[clen] = '\0';
    ret = 0;
out:
    return ret;
}

/*
 *
 */
static void cstr2qstr(const char *cstr, char *qstr, size_t qstr_len)
{
    const char *c;
    const char *pc;
    char *q;
    size_t clen = 0;

    assert(qstr_len > 0);
    for (c = cstr, q = qstr; *c != '\0' && clen < qstr_len - 1; q++, clen++) {
        /* at the begining or at -dot- position */
        if (*c == '.' || (c == cstr && q == qstr)) {
            if (c != cstr)
                c++;
            pc = strchr(c, '.');
            *q = pc ? (pc - c) : strlen(c);
        } else {
            *q = *c;
            c++;
        }
    }
    *q = '\0';
}

static void log_attack(char *qname, union dnsmsg_header *hdr)
{
    NETLOG("suspiciously long DNS response built for %s", qname);
    hdr->x.qr = 1;
    hdr->x.aa = 1;
    hdr->x.rd = 1;
    hdr->x.rcode = 3;
}

static void response_dns_nx(char *name, union dnsmsg_header *hdr)
{
    NETLOG2("DNS request to %s failed", name);
    hdr->x.qr = 1;
    hdr->x.aa = 1;
    hdr->x.rd = 1;
    hdr->x.rcode = 3;
}

static void response_dns_denied(char *name, union dnsmsg_header *hdr, const char *msg)
{
    NETLOG("DNS request to %s denied by containment: %s", name, msg);
    hdr->x.qr = 1;
    hdr->x.aa = 1;
    hdr->x.rd = 1;
    hdr->x.rcode = 3;
}

static void response_dns_server_fail(char *name, union dnsmsg_header *hdr)
{
    NETLOG2("DNS server fail response built for %s", name);
    hdr->x.qr = 1;
    hdr->x.aa = 1;
    hdr->x.rd = 1;
    hdr->x.rcode = 2;
}

static void dns_config(yajl_val config)
{
    debug_resolver = yajl_object_get_bool_default(config, "debug", 0);
    if (debug_resolver)
        debug_printf("%s: debug is on\n", __FUNCTION__);
    ipv6_allowed = yajl_object_get_bool_default(config, "ipv6-allowed", 0);
    if (ipv6_allowed)
        debug_printf("%s: IPv6 addresses are allowed and will be processed\n", __FUNCTION__);
    no_proxy_mode = yajl_object_get_bool_default(config, "no-proxy-mode", 0);
    NETLOG("(dns) no-proxy-mode is %s", no_proxy_mode ? "ON" : "OFF");
}

bool dns_is_nickel_domain_name(const char *domain)
{
    return strcasecmp(SLIRP_GW_NAME, domain) == 0;
}

void dns_http_proxy_enabled(void)
{
    http_proxy_enabled = true;
}

struct dns_response dns_lookup(const char *cname)
{
    int64_t cost_ms;
    struct dns_response ret;
    struct addrinfo *i, *info = NULL, hints;
    size_t max_n, k = 0;

    cost_ms = os_get_clock_ms();
    memset(&ret, 0, sizeof(ret));
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_CANONNAME;

    ret.cname = cname;

    DDNS(&ret, "getaddrinfo for %s", ret.cname ? ret.cname : "(null)");

    ret.err = getaddrinfo(ret.cname, NULL, &hints, &info);

    DDNS(&ret, "getaddrinfo err %d", ret.err);

    if (ret.err) {
        NETLOG2("%s: failed dns lookup for %s with err %d", __FUNCTION__, ret.cname, ret.err);
        goto out;
    }

    max_n = 0;
    for (i = info; i; i = i->ai_next)
        max_n++;

    if (!max_n)
        goto out;
    max_n += 1; /* for the NULL one */

    ret.a = calloc(1, max_n * sizeof(*ret.a));
    if (!ret.a) {
        ret.err = EAI_MEMORY;
        warnx("%s: memory error", __FUNCTION__);
        goto out;
    }

    k = 0;
    for (i = info; i; i = i->ai_next) {
        int j;

        /* OSX 10.10 getaddrinfo is buggy in returning ai_canonname
         * so we ignore the canon name for OSX for now.
         */
#ifndef __APPLE__
        if (i->ai_canonname && !ret.canon_name)
            ret.canon_name = strdup(i->ai_canonname);
#endif  /* __APPLE__ */

        if (!i->ai_addr || (i->ai_family != AF_INET && i->ai_family != AF_INET6))
            continue;

        if (i->ai_family == AF_INET6 && !ipv6_allowed)
            continue;

        if (i->ai_family == AF_INET) {
            struct in_addr addr;

            if (i->ai_addrlen < sizeof(struct sockaddr_in))
                continue;
            addr = ((struct sockaddr_in *) i->ai_addr)->sin_addr;
            for (j = 0; j < k; j++) {
                if (ret.a[j].family != AF_INET)
                    continue;
                if (addr.s_addr == ret.a[j].ipv4.s_addr)
                    break;
            }
            if (j != k)
                continue;
            ret.a[k].family = AF_INET;
            ret.a[k].ipv4 = addr;
        } else { /* IPv6 */
            struct in6_addr addr;

            if (i->ai_addrlen < sizeof(struct sockaddr_in6))
                continue;
            addr = ((struct sockaddr_in6 *)i->ai_addr)->sin6_addr;
            for (j = 0; j < k; j++) {
                if (ret.a[j].family != AF_INET6)
                    continue;
                if (memcmp(&addr, &ret.a[j].ipv6, sizeof(addr)) == 0)
                    break;
            }
            if (j != k)
                continue;
            ret.a[k].family = AF_INET6;
            ret.a[k].ipv6 = ((struct sockaddr_in6 *)i->ai_addr)->sin6_addr;
        }
        k++;
    }

out:
    if (info)
        freeaddrinfo(info);
    ret.cost_ms = os_get_clock_ms() - cost_ms;
    DDNS(&ret, "exit k %lu", (unsigned long) k);
    return ret;
}

void dns_response_free(struct dns_response *resp)
{
    free(resp->canon_name);
    resp->canon_name = NULL;
    free(resp->a);
    resp->a = NULL;
}

struct net_addr * dns_ips_dup(const struct net_addr *a)
{
    struct net_addr *ret = NULL;
    size_t len = 0;

    if (!a || !a[0].family)
        goto out;

    while (a[len].family)
        len++;
    ret = calloc(1, (len + 1) * sizeof(*ret));
    if (!ret) {
        warnx("%s: memory error", __FUNCTION__);
        goto out;
    }
    memcpy(ret, a, len * sizeof(*ret));
out:
    return ret;
}

void dns_hyb_update(struct net_addr *a, struct net_addr cn_addr)
{
    size_t i;

    if (!a)
        return;

    i = 0;
    while (a[i].family) {
        if (cn_addr.family != a[i].family) {

            i++;
            continue;
        }
        if (cn_addr.family == AF_INET && memcmp(&cn_addr.ipv4, &a[i].ipv4, sizeof(cn_addr.ipv4)) == 0)
            break;

        if (cn_addr.family == AF_INET6 && memcmp(&cn_addr.ipv6, &a[i].ipv6, sizeof(cn_addr.ipv6)) == 0)
            break;

        i++;
    }

    if (a[i].family)
        a[i].ts_hyb = os_get_clock_ms();
}

const struct net_addr * dns_hyb_addr(struct net_addr *a)
{
    size_t i, j;
    bool found = false;

    if (!a)
        return NULL;

    i = 0;
    while (a[i].family) {
        if (a[i].ts_hyb && !found && a[i].ts_hyb + HYB_EXPIRE_MS > os_get_clock_ms()) {
            j = i;
            found = true;
        } else {
            a[i].ts_hyb = 0;
        }

        i++;
    }

    return found ? a + j : NULL;
}

static void dns_lookup_check(void *opaque)
{
    struct in_addr *ips = NULL;
    char *ret_mask = NULL;
    struct ndns_data *dstate = opaque;

    size_t len4, len;
    int i, j, k = 0;

    DDNS(dstate, "");

    dstate->response = dns_lookup(dstate->dname);

    DDNS(dstate, "dns_lookup err %d", dstate->response.err);
    if (!dstate->ni || !dstate->ni->ac_enabled)
        goto out;
    // blocking check IP adress here
    if (dstate->response.err || !dstate->response.a ||
            !dstate->response.a[0].family) {
        goto out;
    }

    /* FIXME! only check ipv4 addrs for now ... */
    len4 = 0;
    i = 0;
    while (dstate->response.a[i].family) {
        if (dstate->response.a[i].family == AF_INET)
            len4++;
        i++;
    }
    if (!len4)
        goto out;
    len = i;
    ret_mask = calloc(1, (len4 + 1) * sizeof (char));
    ips = calloc(1, len4 * sizeof(*ips));
    if (!ret_mask || !ips) {
        warnx("%s: memory error", __FUNCTION__);
        dstate->response.err = EAI_MEMORY;
        dstate->denied = 1;
        goto out;
    }

    i = 0;
    k = 0;
    while (dstate->response.a[i].family) {
        if (dstate->response.a[i].family == AF_INET)
            ips[k++] = dstate->response.a[i].ipv4;
        i++;
    }

    if (dstate->ni && ac_check_list_ips(dstate->ni, ips, ret_mask, len4) < 0) {
        dstate->denied = 1;
        goto out;
    }

    j = -1;
    i = k = 0;
    while (dstate->response.a[i].family) {
        if (dstate->response.a[i].family != AF_INET) {

            i++;
            continue;
        }
        j++;
        if (!ret_mask[j])
            break;
        if (ret_mask[j] == '1') {
            k++;

            i++;
            continue;
        }
        memmove(dstate->response.a + i, dstate->response.a + i + 1,
                (len - i) * sizeof(dstate->response.a[0]));
    }

    /* all IP addresses denied */
    if (k == 0)
        dstate->denied = 1;
out:
    DDNS(dstate, "exit k %d", k);

    free(ips);
    free(ret_mask);
    return;
}

static void dns_lookup_check_continue(void *opaque)
{
    struct ndns_data *dstate = opaque;

    DDNS(dstate, "");
    if (dstate->denied)
        fakedns_deny_ip(dstate->fake_ip);
    else if (!dstate->response.err)
        fakedns_update_ips(dstate->fake_ip, dstate->response.a);
    else
        fakedns_update_ips(dstate->fake_ip, NULL);

    ni_priv_free(dstate->dname);
    dns_response_free(&dstate->response);
    free(dstate);
}

static void dns_sync_query(void *opaque)
{
    struct ndns_data *dstate = opaque;

    DDNS(dstate, "");
    // blocking check name here ...
    if (!dstate->proxy_on && dstate->ni && dstate->ni->ac_enabled &&
            !ac_is_dnsname_allowed(dstate->ni, dstate->dname)) {
        dstate->denied = 1;
        return;
    }

    dns_lookup_check(dstate);
}

struct dns_response dns_lookup_containment(struct nickel *ni, const char *name, int proxy_on)
{
    struct ndns_data dstate;

    memset(&dstate, 0, sizeof(dstate));
    dstate.ni = ni;
    dstate.dname = ni_priv_strdup(name);
    dstate.proxy_on = proxy_on;
    if (no_proxy_mode)
        dstate.proxy_on = 0;

    dns_sync_query((void *) &dstate);

    ni_priv_free(dstate.dname);
    dstate.dname = NULL;
    if (dstate.denied)
        dstate.response.denied = 1;
    return dstate.response;
}

static void dns_input_continue(void *opaque)
{
    struct ndns_data *dstate = opaque;
    char *pri_name, *cname, *answers, *qname;
    int resp_len = 0, len, i;
    uint16_t off;
    union dnsmsg_header *hdr;
    struct dns_meta_data *meta;
    bool fakeip_dns_check = false;

    DDNS(dstate, "q %s", dstate->dname ? dstate->dname : "(null)");
    /* if chr needs to close, exit */
    if (dstate->dns_chr && qemu_chr_put(&dstate->dns_chr->chr) == 0)
        goto out;
    if (dstate->dns_chr && dstate->dns_chr->closing)
        goto out;

    /* assume the dns packet in the mbuf is not malformed as it
     * was checked in dns_input
     */
    if (!dstate->dns_req || !dstate->dname)
        goto out;

    cname = dstate->dname;
    hdr = (union dnsmsg_header *) dstate->dns_req;
    qname = (char *)&hdr[1];
    resp_len = dstate->dns_len;
    if (dstate->resp_written)
        goto write_response;

    if (dstate->denied) {
        response_dns_denied(cname, hdr, "denied");
        goto write_response;
    }

    if (dstate->is_fake) {
        fakeip_dns_check = true;
        goto process;
    }

    if (dstate->is_internal)
        goto process;

    if (!dstate->response.cname || dstate->response.err ||
            !dstate->response.a || !dstate->response.a[0].family) {

        if (dstate->proxy_on && !proxy_forbid_nonexistent_dns_name) {
            dstate->is_fake = 1;
            goto process;
        }
        if (dstate->response.err == EAI_NONAME || dstate->response.err == EAI_SERVICE)
            response_dns_nx(cname, hdr);
        else
            response_dns_server_fail(cname, hdr);
        goto write_response;
    }

    if (dstate->proxy_on)
        dstate->is_fake = 1;

    /* if we we have at least one ipv6 address, we need to use fake ip functionality */
    i = 0;
    while (dstate->response.a && dstate->response.a[i].family) {
        if (dstate->response.a[i].family == AF_INET6) {
            dstate->is_fake = 1;
            break;
        }
        i++;
    }

process:
    if (dstate->is_internal) {
        free(dstate->response.a);
        dstate->response.a = calloc(1, sizeof(*dstate->response.a) * 2);
        if (!dstate->response.a)
            goto out;
        dstate->response.a[0].family = AF_INET;
        dstate->response.a[0].ipv4.s_addr = ni_get_hostaddr(dstate->ni);
    }

    if (dstate->is_fake) {
        struct in_addr *faddr;

        if (dstate->response.a && dstate->response.a[0].family)
            faddr = fakedns_create_ip(cname, dstate->response.a);
        else
            faddr = fakedns_create_ip(cname, NULL);

        if (!faddr)
            goto out;

        free(dstate->response.a);
        dstate->response.a = calloc(1, sizeof(*dstate->response.a) * 2);
        if (!dstate->response.a)
            goto out;
        dstate->response.a[0].family = AF_INET;
        dstate->response.a[0].ipv4 = *faddr;

        if (fakeip_dns_check && !fakedns_is_denied(faddr)) {
            struct ndns_data *ndstate;

            ndstate = calloc(1, sizeof(struct ndns_data));
            if (!ndstate) {
                warnx("%s: memory error", __FUNCTION__);
                goto out;
            }
            ndstate->ni = dstate->ni;
            ndstate->dname = ni_priv_strdup(dstate->dname);
            ndstate->fake_ip = *faddr;
            if (ni_schedule_bh(ndstate->ni, dns_lookup_check, dns_lookup_check_continue,
                        ndstate)) {

                warnx("%s: nickel_schedule_bh failure", __FUNCTION__);
                ni_priv_free(ndstate->dname);
                free(ndstate);
                goto out;
            }

        }
    }

    if (!dstate->response.a || !dstate->response.a[0].family) {
        response_dns_nx(cname, hdr);
        resp_len = dstate->dns_len;
        goto write_response;
    }

    meta = (struct dns_meta_data *) ((char *) &hdr[1] + strlen(qname) + 1);
    /* answers zone lays after query in response packet */
    answers = (char *)&meta[1];
    resp_len = ((uint8_t *) answers) - dstate->dns_req;

    off = (char *)&hdr[1] - (char *)hdr;
    off |= (0x3 << 14);

    pri_name = cname;
    if (!dstate->is_fake && dstate->response.canon_name &&
            strcasecmp(dstate->response.canon_name, cname)) {

        /* it was a CNAME */
        pri_name = dstate->response.canon_name;
        struct dnsmsg_answer *ans = (struct dnsmsg_answer *)answers;

        resp_len += sizeof(struct dnsmsg_answer);
        len = strlen(pri_name) + 2;
        if (resp_len + len > DNS_PACKET_MAXSIZE) {
            log_attack(cname, hdr);
            resp_len = dstate->dns_len;
            goto write_response;
        }

        ans->name = htons(off);
        ans->meta.type = htons(5); /* CNAME */
        ans->meta.class = htons(1);
        *(uint32_t *)ans->ttl = htonl(1);  /* 1s */
        ans->rdata_len = htons(len);
        ans->rdata[len - 1] = 0;

        cstr2qstr(pri_name, (char *)ans->rdata, len);
        off = (char *)&ans->rdata - (char *)hdr;
        off |= (0x3 << 14);
        answers = (char*)&ans[1] + len;
        resp_len += len;
        hdr->x.ancount++;
        DDNS(dstate, "CNAME %s", pri_name);
    }

    /* add addresses */
    i = 0;
    while (dstate->response.a && dstate->response.a[i].family) {
        assert(dstate->response.a[i].family == AF_INET);
        len = 4; /* IPv4 */
        struct dnsmsg_answer *ans = (struct dnsmsg_answer *)answers;

        if (resp_len + sizeof(struct dnsmsg_answer) + len > DNS_PACKET_MAXSIZE) {
            log_attack(cname, hdr);
            goto out;
        }
        ans->name = htons(off);
        ans->meta.type = htons(1);
        ans->meta.class = htons(1);
        *(uint32_t *)ans->ttl = htonl(1);  /* 1s */
        ans->rdata_len = htons(len);
        *(uint32_t *)ans->rdata = dstate->response.a[i].ipv4.s_addr;
        resp_len += sizeof(struct dnsmsg_answer) + len;

        if (i == 0)
            NETLOG2("(dns) dns-response: %s A %s", dstate->dname, inet_ntoa(dstate->response.a[i].ipv4));

        if (debug_resolver)
            DDNS(dstate, "A %s", inet_ntoa(dstate->response.a[i].ipv4));

        answers = (char *)&ans[1] + len;
        hdr->x.ancount++;
        i++;
    }

    hdr->x.qr = 1; /* response */
    hdr->x.aa = 1;
    hdr->x.rd = 1;
    hdr->x.ra = 1;
    hdr->x.rcode = 0;
    hdr->x.ancount = htons(hdr->x.ancount);

write_response:
    DDNS(dstate, "write_response");
    if (qemu_chr_can_read(&dstate->dns_chr->chr) < resp_len)
        goto out;
    DDNS(dstate, "response id 0x%x rcode %d", DNS_GET_ID(dstate->dns_req),
            (int) (((union dnsmsg_header*)(dstate->dns_req))->x.rcode));
    qemu_chr_read(&dstate->dns_chr->chr, dstate->dns_req, resp_len);

out:
    if (dstate) {
        ni_priv_free(dstate->dname);
        ni_priv_free(dstate->dns_req);
        dns_response_free(&dstate->response);
        free(dstate);
    }
    DDNS(dstate, "exit");
}

static int
ndns_chr_write(CharDriverState *chr, const uint8_t *buf, int blen)
{
    struct ndns_data *dstate = NULL;
    struct dns_chr_t *dns_chr = (struct dns_chr_t *) chr;

    char *qname = NULL, *suffix = NULL;
    char cname[255];
    int cname_len;
    struct dns_meta_data *meta;
    int off, len;

    union dnsmsg_header *hdr;

    DDNS(dstate, "received packet len %d", blen);

    qemu_chr_get(chr);
    off = 0;

    if (blen < off || blen > DNS_PACKET_MAXSIZE) {
        static bool warn_once = false;

        if (blen > 0 && !warn_once) {
            debug_printf("%s: unusual dns req packet len = %d\n", __FUNCTION__, blen);
            warn_once = true;
        }
        goto cleanup;
    }
    hdr = (union dnsmsg_header *) (buf + off);
    off += sizeof(*hdr);
    if (blen < off) {
        debug_printf("%s: bad (short) dns packet\n", __FUNCTION__);
        goto cleanup;
    }

    DDNS(dstate, "id 0x%x", DNS_GET_ID(buf));

    if (hdr->x.qr != 0)
        goto cleanup;

    if (hdr->x.opcode != 0)
        goto cleanup;

    if (ntohs(hdr->x.qdcount) != 1) {
        static bool warn_once = false;

        if (warn_once)
            goto cleanup;
        debug_printf("%s: unsupported Query Count %u\n", __FUNCTION__, ntohs(hdr->x.qdcount));
        warn_once = true;
        goto cleanup;
    }

    dstate = calloc(1, sizeof(struct ndns_data));
    if (!dstate)
        goto cleanup;
    dstate->ni = dns_chr->ni;
    DDNS(dstate, "id 0x%x", DNS_GET_ID(buf));
    if (blen <= off)
        goto cleanup;
    qname = (char *)&hdr[1];
    len = strnlen(qname, blen - off);
    /* check if indeed null terminated */
    if (len == blen - off)
        goto cleanup;

    off += (len + 1);
    meta = (struct dns_meta_data *)(qname + len + 1);

    off += sizeof(*meta);
    if (blen < off)
        goto cleanup;

    memset(cname, 0, sizeof(cname));
    if (qstr2cstr(qname, cname, sizeof(cname) - 1) < 0) {
        debug_printf("%s: qstr2cstr failed\n", __FUNCTION__);
        goto cleanup;
    }
    cname_len = strlen(cname);
    /* Some guests like win-xp adds _dot_ after host name
     * and after domain name (not passed with host resolver)
     * that confuses host resolver.
     */
    if (cname_len > 2 && cname[cname_len - 1] == '.' && cname[cname_len - 2] == '.') {
        cname[cname_len - 1] = 0;
        cname[cname_len - 2] = 0;
    }

    cname_len += 1; /* include null byte */
    dstate->dname = ni_priv_calloc(1, cname_len);
    if (!dstate->dname)
        goto cleanup;
    memcpy(dstate->dname, cname, cname_len);

    dstate->dns_req = ni_priv_calloc(1, DNS_PACKET_MAXSIZE);
    if (!dstate->dns_req)
        goto cleanup;
    assert(blen < DNS_PACKET_MAXSIZE);
    memcpy(dstate->dns_req, buf, blen);
    dstate->dns_len = blen;
    dstate->dns_chr = (struct dns_chr_t *)chr->opaque;

    if (cname_len > sizeof(GUEST_DNS_SUFFIX)) {
        suffix = dstate->dname + (cname_len - sizeof(GUEST_DNS_SUFFIX));
        if (strcasecmp(suffix, GUEST_DNS_SUFFIX) == 0) {
            *suffix = 0;
            cname_len = suffix - dstate->dname + 1;
        } else {
            suffix = NULL;
        }
    }

    NETLOG2("(dns) dns-lookup: %s %s qtype:%hd qclass:%hd",
        dstate->dname, suffix ? "(short name)" : "",
        ntohs(meta->type), ntohs(meta->class));

    DDNS(dstate, "q %s", dstate->dname);
    if (!strcasecmp(dstate->dname, SLIRP_GW_NAME)) {
        dstate->is_internal = 1;
        goto dns_continue;
    }

    if (dstate->ni && (proxy_used || (proxy_used = ac_proxy_set(dstate->ni))))
        dstate->proxy_on = 1;
    if (!http_proxy_enabled || no_proxy_mode)
        dstate->proxy_on = 0;

    if (dstate->proxy_on) {

        // blocking check name here ...
        if (dstate->ni && dstate->ni->ac_enabled && !ac_is_dnsname_allowed(dstate->ni, dstate->dname)) {
            dstate->denied = 1;
            goto dns_continue;
        }

        dstate->is_fake = 1;
        goto dns_continue;
    }

    // non proxy async dns lookup
    if (ni_schedule_bh(dstate->ni, dns_sync_query, dns_input_continue, dstate))
        goto cleanup;

    return 0;

dns_continue:
    DDNS(dstate, "dns_continue");
    dns_input_continue(dstate);
    return 0;

cleanup:
    if (dstate) {
        ni_priv_free(dstate->dname);
        ni_priv_free(dstate->dns_req);
        dns_response_free(&dstate->response);
        free(dstate);
    }
    qemu_chr_put(chr);
    DDNS(dstate, "cleanup");
    return -1;
}

static int
ndns_chr_can_read(void *opaque)
{
    struct dns_chr_t *dns_chr = opaque;

    return ni_can_recv(dns_chr->net_opaque);
}

static void
ndns_chr_read(void *opaque, const uint8_t *buf, int size)
{
    struct dns_chr_t *dns_chr = opaque;

    ni_recv(dns_chr->net_opaque, buf, size);
}

static void ndns_chr_event(CharDriverState *chr, int event)
{
    if (event == CHR_EVENT_NI_CLOSE || event == CHR_EVENT_NI_RST)
        ndns_close(chr);
}

static void
ndns_chr_close(CharDriverState *chr)
{
    struct dns_chr_t *dns_chr = (struct dns_chr_t *)chr->opaque;

    if (dns_chr->net_opaque)
        ni_close(dns_chr->net_opaque);
    dns_chr->net_opaque = NULL;
}

static CharDriverState *
ndns_open(void *opaque, struct nickel *ni, CharDriverState **persist_chr,
        struct sockaddr_in saddr, struct sockaddr_in daddr,
        yajl_val config)
{
    struct dns_chr_t *dns_chr;
    CharDriverState *chr;
    {
        static int once = 0;

        if (!once) {
            dns_config(config);
            once = 1;
        }
    }
    dns_chr = calloc(1, sizeof(*dns_chr));
    if (!dns_chr)
        return NULL;
    dns_chr->ni = ni;
    dns_chr->net_opaque = opaque;
    chr = (CharDriverState *) dns_chr;
    chr->refcnt = 1;
    chr->opaque = dns_chr;
    qemu_chr_add_handlers(chr, ndns_chr_can_read, ndns_chr_read, NULL, dns_chr);
    chr->chr_write = ndns_chr_write;
    chr->chr_send_event = ndns_chr_event;
    chr->chr_close = ndns_chr_close;

    return chr;
}

static void
ndns_close(CharDriverState *chr)
{
    struct dns_chr_t *dns_chr = (struct dns_chr_t *) chr->opaque;

    if (dns_chr->closing)
        return;
    dns_chr->closing = 1;
    qemu_chr_close(chr);
}

static struct ns_desc ndns_desc = {
    .service_type = NS_SERVICE_TYPE_UDP,
    .service_name = "dns-resolver",
    .service_open = ndns_open,
    .service_close = ndns_close,
};

ns_add_service(ndns_desc);
