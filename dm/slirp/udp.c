/*
 * Copyright (c) 1982, 1986, 1988, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)udp_usrreq.c	8.4 (Berkeley) 1/21/94
 * udp_usrreq.c,v 1.4 1994/10/02 17:48:45 phk Exp
 */

/*
 * Changes and additions relating to SLiRP
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#include <slirp.h>
#include "ip_icmp.h"

static uint8_t udp_tos(struct socket *so);
static int udp_vmfwd_input(struct mbuf *m, struct ip *ip, struct udphdr *uh,
                           const uint8_t *, int len);

void
udp_init(Slirp *slirp)
{
    LIST_INIT(&slirp->udb);
    slirp->udp_last_so = LIST_FIRST(&slirp->udb);

    LIST_INIT(&slirp->udp_vmfwd);
}

/* m->m_data  points at ip packet header
 * m->m_len   length ip packet
 * ip->ip_len length data (IPDU)
 */
void
udp_input(struct mbuf *m, int iphlen)
{
    Slirp *slirp = m->slirp;
    struct ip *ip;
    struct udphdr *uh;
    int len;
    struct ip save_ip;
    struct socket *so;

    DEBUG_CALL("udp_input(m = %p, iphlen = %d)", m, iphlen);

    /*
     * Strip IP options, if any; should skip this,
     * make available to user, and use on returned packets,
     * but we don't yet have a way to check the checksum
     * with options still present.
     */
    if (iphlen > sizeof(struct ip)) {
	ip_stripoptions(m, NULL);
	iphlen = sizeof(struct ip);
    }

    /*
     * Get IP and UDP header together in first mbuf.
     */
    ip = mtod(m, struct ip *);
    uh = (struct udphdr *)((caddr_t)ip + iphlen);

    /*
     * Make mbuf data length reflect UDP length.
     * If not enough data to reflect UDP length, drop.
     */
    len = ntohs((uint16_t)uh->uh_ulen);

    if (ip->ip_len != len) {
	if (len > ip->ip_len)
	    goto bad;
	m_adj(m, len - ip->ip_len);
	ip->ip_len = len;
    }

    /*
     * Save a copy of the IP header in case we want restore it
     * for sending an ICMP error message in response.
     */
    save_ip = *ip;
    save_ip.ip_len += iphlen;         /* tcp_input subtracts this */

#ifdef SLIRP_INPUT_CHECKSUM
    /*
     * Checksum extended UDP header and data.
     */
    if (uh->uh_sum) {
	((struct ipovly *)ip)->ih_x0 = 0;
	((struct ipovly *)ip)->ih_x1 = 0;
	((struct ipovly *)ip)->ih_len = uh->uh_ulen;
	if (cksum(m, len + sizeof(struct ip)))
	    goto bad;
    }
#endif

    /*
     *  handle DHCP/BOOTP
     */
    if (ntohs(uh->uh_dport) == BOOTP_SERVER &&
        (ip->ip_dst.s_addr == slirp->vhost_addr.s_addr ||
         ip->ip_dst.s_addr == 0xffffffff)) {
        if (!m->slirp->disable_dhcp)
            bootp_input(m);
        goto bad;
    }

#ifdef SLIRP_PROVIDE_TFTP_SERVER
    /*
     *  handle TFTP
     */
    if (ntohs(uh->uh_dport) == TFTP_SERVER &&
	ip->ip_dst.s_addr == slirp->vhost_addr.s_addr) {
	tftp_input(m);
	goto bad;
    }
#endif	/* SLIRP_PROVIDE_TFTP_SERVER */

    /* handle vmfwd's */
    if ((ip->ip_dst.s_addr & slirp->vnetwork_mask.s_addr) ==
        slirp->vnetwork_addr.s_addr &&
        udp_vmfwd_input(m, ip, uh, (const uint8_t *)&uh[1],
                        len - sizeof(struct udphdr)))
        return; /* mbuf is freed in udp_vmfwd_input */

    if (slirp->restricted)
	goto bad;

    /*
     * Locate pcb for datagram.
     */
    so = slirp->udp_last_so;
    if (!so ||
	so->so_lport != uh->uh_sport ||
	so->so_laddr.s_addr != ip->ip_src.s_addr) {
	LIST_FOREACH(so, &slirp->udb, entry)
	    if (so->so_lport == uh->uh_sport &&
		so->so_laddr.s_addr == ip->ip_src.s_addr)
		break;
	if (so)
	    slirp->udp_last_so = so;
    }

    if (so == NULL) {
	/*
	 * If there's no socket for this packet,
	 * create one
	 */
	so = socreate(slirp);
	if (!so)
	    goto bad;
        so->so_type = IPPROTO_UDP;
	if (udp_attach(so) == -1) {
	    warn("slirp: udp_attach");
	    free(so); /* not sofree() as not attached ! */
	    goto bad;
	}

	/*
	 * Setup fields
	 */
	so->so_laddr = ip->ip_src;
	so->so_lport = uh->uh_sport;

	so->so_iptos = udp_tos(so);
	if (so->so_iptos == 0)
	    so->so_iptos = ip->ip_tos;

	/*
	 * XXXXX Here, check if it's in udpexec_list,
	 * and if it is, do the fork_exec() etc.
	 */
    }

    so->so_faddr = ip->ip_dst; /* XXX */
    so->so_fport = uh->uh_dport; /* XXX */

    iphlen += sizeof(struct udphdr);
    m->m_len -= iphlen;
    m->m_data += iphlen;

    /*
     * Now we sendto() the packet.
     */
    if (sosendto(so, m) == -1) {
	m->m_len += iphlen;
	m->m_data -= iphlen;
	*ip = save_ip;
	DEBUG_MISC("udp tx errno = %d-%s", errno, strerror(errno));
	icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_NET, 0, strerror(errno));
    }

    m_free(so->so_m);   /* used for ICMP if error on sorecvfrom */

    /* restore the orig mbuf packet */
    m->m_len += iphlen;
    m->m_data -= iphlen;
    *ip = save_ip;
    so->so_m = m;         /* ICMP backup */

    return;
  bad:
    m_free(m);
    return;
}

int udp_can_output(struct socket *so)
{
    int ret;

    ret = min(slirp_mtu, slirp_mru) - sizeof(struct udpiphdr);
    return ret <= 0 ? 0 : ret;
}

int udp_output2(struct socket *so, struct mbuf *m,
                struct sockaddr_in *saddr, struct sockaddr_in *daddr,
                int iptos)
{
    struct udpiphdr *ui;
    int error = 0;

    DEBUG_CALL("udp_output(so = %p, m = %p, saddr = %lx, daddr = %lx)",
	       so, m, (unsigned long)saddr->sin_addr.s_addr, (unsigned long)daddr->sin_addr.s_addr);

    /*
     * Adjust for header
     */
    m->m_data -= sizeof(struct udpiphdr);
    m->m_len += sizeof(struct udpiphdr);

    /*
     * Fill in mbuf with extended UDP header
     * and addresses and length put into network format.
     */
    ui = mtod(m, struct udpiphdr *);
    ui->ui_x0 = 0;
    ui->ui_x1 = 0;
    ui->ui_pr = IPPROTO_UDP;
    ui->ui_len = htons(m->m_len - sizeof(struct ip));
    /* XXXXX Check for from-one-location sockets, or from-any-location sockets */
    ui->ui_src = saddr->sin_addr;
    ui->ui_dst = daddr->sin_addr;
    ui->ui_sport = saddr->sin_port;
    ui->ui_dport = daddr->sin_port;
    ui->ui_ulen = ui->ui_len;

    /*
     * Stuff checksum and output datagram.
     */
    ui->ui_sum = 0;
    if ((ui->ui_sum = cksum(m, m->m_len)) == 0)
	ui->ui_sum = 0xffff;
    ((struct ip *)ui)->ip_len = m->m_len;

    ((struct ip *)ui)->ip_ttl = IPDEFTTL;
    ((struct ip *)ui)->ip_tos = iptos;

    error = ip_output(so, m);

    return (error);
}

int udp_output(struct socket *so, struct mbuf *m,
               struct sockaddr_in *addr)

{
    Slirp *slirp = so->slirp;
    struct sockaddr_in saddr, daddr;

    saddr = *addr;
    if ((so->so_faddr.s_addr & slirp->vnetwork_mask.s_addr) ==
        slirp->vnetwork_addr.s_addr) {
        uint32_t inv_mask = ~slirp->vnetwork_mask.s_addr;

        if ((so->so_faddr.s_addr & inv_mask) == inv_mask)
            saddr.sin_addr = slirp->vhost_addr;
	else if (addr->sin_addr.s_addr == loopback_addr.s_addr ||
                   so->so_faddr.s_addr != slirp->vhost_addr.s_addr)
            saddr.sin_addr = so->so_faddr;
    }
    daddr.sin_addr = so->so_laddr;
    daddr.sin_port = so->so_lport;

    return udp_output2(so, m, &saddr, &daddr, so->so_iptos);
}

int udp_respond(struct socket *so, const uint8_t *buf, int size)
{
    int max_size;
    struct mbuf *m;
    struct sockaddr_in saddr, daddr;

    max_size = udp_can_output(so);
    if (!max_size || size > max_size)
        return -1;

    m = m_get(so->slirp);
    if (!m)
        return -1;

    m->m_data += ETH_HLEN;

    m->m_data += sizeof(struct udpiphdr);
    memcpy(mtod(m, uint8_t *), buf, size);
    m->m_len = size;

    memset(&saddr, 0, sizeof(saddr));
    memset(&daddr, 0, sizeof(daddr));
    saddr.sin_family = daddr.sin_family = AF_INET;
    saddr.sin_addr = so->so_faddr;
    saddr.sin_port = so->so_fport;
    daddr.sin_addr = so->so_laddr;
    daddr.sin_port = so->so_lport;

    return udp_output2(so, m, &saddr, &daddr, so->so_iptos);
}

int
udp_attach(struct socket *so)
{
    if ((so->s = qemu_socket(AF_INET, SOCK_DGRAM, 0)) != -1) {
	so->so_expire = curtime + SO_EXPIRE;
	LIST_INSERT_HEAD(&so->slirp->udb, so, entry);
    }
    return(so->s);
}

void
udp_detach(struct socket *so)
{
    closesocket(so->s);
    sofree(so);
}

static const struct tos_t udptos[] = {
    {0, 53, IPTOS_LOWDELAY},			/* DNS */
};

static uint8_t
udp_tos(struct socket *so)
{
    int i;

    for (i = 0; i < sizeof(udptos) / sizeof(udptos[0]); i++)
	if ((udptos[i].fport && ntohs(so->so_fport) == udptos[i].fport) ||
	    (udptos[i].lport && ntohs(so->so_lport) == udptos[i].lport))
	    return udptos[i].tos;

    return 0;
}

/* Keep the BSD spirit alive */
#ifndef __APPLE__
#define bzero(s,n) (void)memset((s), 0, (n))
#endif

struct socket *
udp_listen(Slirp *slirp, uint32_t haddr, u_int hport, uint32_t laddr,
           u_int lport, int flags)
{
    struct sockaddr_in addr;
    struct socket *so;
    socklen_t addrlen = sizeof(struct sockaddr_in), opt = 1;

    so = socreate(slirp);
    if (!so)
	return NULL;
    so->so_type = IPPROTO_UDP;
    so->s = qemu_socket(AF_INET, SOCK_DGRAM, 0);
    so->so_expire = curtime + SO_EXPIRE;
    LIST_INSERT_HEAD(&so->slirp->udb, so, entry);

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = haddr;
    addr.sin_port = hport;

    if (bind(so->s, (struct sockaddr *)&addr, addrlen) < 0) {
	udp_detach(so);
	return NULL;
    }
    setsockopt(so->s, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(int));

    getsockname(so->s, (struct sockaddr *)&addr, &addrlen);
    so->so_fport = addr.sin_port;
    if (addr.sin_addr.s_addr == 0 ||
	addr.sin_addr.s_addr == loopback_addr.s_addr)
	so->so_faddr = slirp->vhost_addr;
    else
	so->so_faddr = addr.sin_addr;
    so->so_lport = lport;
    so->so_laddr.s_addr = laddr;
    if (flags != SS_FACCEPTONCE)
	so->so_expire = 0;

    so->so_state &= SS_PERSISTENT_MASK;
    so->so_state |= SS_ISFCONNECTED | flags;

    return so;
}

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
            struct sockaddr_in, struct sockaddr_in,
            yajl_val);
    void (*service_close)(CharDriverState *);

    uint64_t total_byte_limit;
};

int
is_udp_vmfwd(const struct in_addr dst_ip, const uint16_t dst_port, Slirp *slirp)
{
    struct udp_vmfwd *vmfwd;

    if ((dst_ip.s_addr & slirp->vnetwork_mask.s_addr) != slirp->vnetwork_addr.s_addr)
        return 0;

    LIST_FOREACH(vmfwd, &slirp->udp_vmfwd, entry)
        if (dst_port == vmfwd->host_port)
            return 1;

    return 0;
}

static int
udp_vmfwd_input(struct mbuf *m, struct ip *ip, struct udphdr *uh,
                const uint8_t *buf, int len)
{
    Slirp *slirp = m->slirp;
    struct udp_vmfwd *vmfwd;
    CharDriverState *chr;

    LIST_FOREACH(vmfwd, &slirp->udp_vmfwd, entry)
        if (uh->uh_dport == vmfwd->host_port &&
            (vmfwd->vm_addr.s_addr == INADDR_ANY ||
             ip->ip_src.s_addr == vmfwd->vm_addr.s_addr) &&
            (vmfwd->vm_port == 0 || uh->uh_sport == vmfwd->vm_port))
            break;

    if (!vmfwd)
        return 0;

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

    if (vmfwd->svc_cb) {
        vmfwd->svc_cb(m);
        return 1;
    }

    if (vmfwd->chr)
        chr = vmfwd->chr;
    else {
        struct socket *so;

        so = slirp->udp_last_so;
        if (!so ||
            so->so_lport != uh->uh_sport ||
            so->so_laddr.s_addr != ip->ip_src.s_addr) {
            LIST_FOREACH(so, &slirp->udb, entry)
                if (so->so_lport == uh->uh_sport &&
                    so->so_laddr.s_addr == ip->ip_src.s_addr)
                    break;
	    if (so)
	        slirp->udp_last_so = so;
        }

        if (so == NULL) {
            so = socreate(slirp);
            if (!so)
                goto out;
            so->so_type = IPPROTO_UDP;
            if (udp_attach(so) == -1) {
                free(so);
                goto out;
            }
            so->so_laddr = ip->ip_src;
            so->so_lport = uh->uh_sport;
            so->so_iptos = udp_tos(so);
            if (so->so_iptos == 0)
                so->so_iptos = ip->ip_tos;
        }

        so->so_faddr = ip->ip_dst;
        so->so_fport = uh->uh_dport;

        if (!so->chr) {
            struct sockaddr_in saddr, daddr;

            saddr.sin_family = daddr.sin_family = AF_INET;
            saddr.sin_addr = so->so_laddr;
            saddr.sin_port = so->so_lport;
            daddr.sin_addr = so->so_faddr;
            daddr.sin_port = so->so_fport;
            so->chr = vmfwd->service_open(so, &slirp->nu, &vmfwd->chr, saddr, daddr, vmfwd->service_config);
            if (!so->chr)
                goto out;
            so->chr_close = vmfwd->service_close;
        }
        chr = so->chr;
    }

    assert(chr);
    qemu_chr_fe_write(chr, buf, len);

out:
    m_free(m);
    return 1;
}

void *
udp_vmfwd_add(Slirp *slirp, CharDriverState *chr, void (*svc_cb)(void *),
              struct in_addr host_addr, int host_port,
              struct in_addr vm_addr, int vm_port, uint64_t byte_limit)
{
    struct udp_vmfwd *vmfwd;

    vmfwd = (struct udp_vmfwd *)calloc(1, sizeof(struct udp_vmfwd));
    if (vmfwd == NULL) {
        warnx("%s: malloc", __FUNCTION__);
        return NULL;
    }

    vmfwd->chr = chr;
    vmfwd->svc_cb = svc_cb;

    vmfwd->host_port = host_port;
    vmfwd->vm_addr = vm_addr;
    vmfwd->vm_port = vm_port;

    if (byte_limit)
        vmfwd->total_byte_limit = byte_limit + 1;

    LIST_INSERT_HEAD(&slirp->udp_vmfwd, vmfwd, entry);

    return vmfwd;
}

void *
udp_vmfwd_add_service(Slirp *slirp,
                      CharDriverState *(*service_open)(void *,
                                                       struct net_user *,
                                                       CharDriverState **,
                                                       struct sockaddr_in,
                                                       struct sockaddr_in,
                                                       yajl_val),
                      void (*service_close)(CharDriverState *),
                      yajl_val service_config,
                      struct in_addr host_addr, int host_port,
                      struct in_addr vm_addr, int vm_port, uint64_t byte_limit)
{
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
    vmfwd->service_close = service_close;
    vmfwd->service_config = service_config;

    vmfwd->host_port = host_port;
    vmfwd->vm_addr = vm_addr;
    vmfwd->vm_port = vm_port;

    if (byte_limit)
        vmfwd->total_byte_limit = byte_limit + 1;

    LIST_INSERT_HEAD(&slirp->udp_vmfwd, vmfwd, entry);

    return vmfwd;
}
