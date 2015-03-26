/*
 * Copyright (c) 1982, 1986, 1988, 1993
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
 *	@(#)ip_input.c	8.2 (Berkeley) 1/4/94
 * ip_input.c,v 1.11 1994/11/16 10:17:08 jkh Exp
 */

/*
 * Changes and additions relating to SLiRP are
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#include <slirp.h>
#include "ip_icmp.h"
#ifdef SLIRP_SUPPORT_IPREASS
#include "ip_reass.h"
#endif  /* SLIRP_SUPPORT_IPREASS */

/*
 * IP initialization: fill in IP protocol switch table.
 * All protocols not implemented in kernel go to raw IP protocol handler.
 */
void
ip_init(Slirp *slirp)
{

    BUILD_BUG_ON(sizeof(struct ipovly) != sizeof(struct ip));

#ifdef SLIRP_SUPPORT_IPREASS
    RLIST_INIT(&slirp->ipq, ipq_list);
#endif  /* SLIRP_SUPPORT_IPREASS */

    udp_init(slirp);
    tcp_init(slirp);
    icmp_init(slirp);
}

/*
 * Ip input routine.  Checksum and byte swap header.  If fragmented
 * try to reassemble.  Process options.  Pass to next level.
 */
void
ip_input(struct mbuf *m)
{
    struct ip *ip = NULL;
    int ip_p;
    int hlen;

    DEBUG_VERBOSE("ip_input(m = %p, m_len = %d)", m, m->m_len);

    if (m->m_len < sizeof(struct ip)) {
        LOGSLIRP2("NAT: IP datagram too small");
        m_free(m);
        return;
    }

    ip = mtod(m, struct ip *);

    if (ip->ip_v != IPVERSION)
        goto bad;

    hlen = ip->ip_hl << 2;
    if (hlen < sizeof(struct ip) || hlen > m->m_len) /* min header length */
        goto bad;   /* or packet too short */

#ifdef SLIRP_INPUT_CHECKSUM
    /* keep ip header intact for ICMP reply
     * ip->ip_sum = cksum(m, hlen);
     * if (ip->ip_sum)
     */
    if (cksum(m, hlen))
        goto bad;
#endif

    /*
     * Convert fields to host representation.
     */
    NTOHS(ip->ip_len);
    if (ip->ip_len < hlen)
        goto bad;
    NTOHS(ip->ip_id);
    NTOHS(ip->ip_off);

    /*
     * Check that the amount of data in the buffers
     * is as at least much as the IP header would have us expect.
     * Trim mbufs if longer than we expect.
     * Drop packet if shorter than we expect.
     */
    if (m->m_len < ip->ip_len)
        goto bad;

    /* Should drop packet if mbuf too long? hmmm... */
    if (m->m_len > ip->ip_len)
        m_adj(m, ip->ip_len - m->m_len);

    /* check ip_ttl for a correct ICMP reply */
    if (ip->ip_ttl == 0) {
        icmp_error(m, ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS, 0, "ttl");
        goto bad;
    }

    ip_p = ip->ip_p;

    /*
     * Adjust ip_len to not reflect header.
     */
    ip->ip_len -= hlen;

    /* reserved fragment flag set */
    if (ip->ip_off & IP_RF)
        goto bad;

#ifdef SLIRP_SUPPORT_IPREASS
    /*
     * If offset or IP_MF are set, must reassemble.
     * Otherwise, nothing need be done.
     * (We could look in the reassembly queue to see
     * if the packet was previously fragmented,
     * but it's not worth the time; just let them time out.)
     *
     * XXX This should fail, don't fragment yet
     */
    if (ip->ip_off & ~IP_DF) {
        Slirp *slirp = m->slirp;
        struct mbuf *ipq;
        /*
         * Look for queue of fragments of this datagram.
         */
        RLIST_FOREACH(ipq, &slirp->ipq, ipq_list) {
            struct ip *t = ipqtoip(ipq);
            if (ip->ip_id == t->ip_id &&
                ip->ip_src.s_addr == t->ip_src.s_addr &&
                ip->ip_dst.s_addr == t->ip_dst.s_addr &&
                ip->ip_p == t->ip_p)
                break;
        }

        /*
         * Set ip_mff if more fragments are expected,
         * convert offset of this to bytes.
         */
        if (ip->ip_off & IP_MF)
            ip->ip_tos |= 1;
        else
            ip->ip_tos &= ~1;

        ip->ip_off <<= 3;

        /*
         * If datagram marked as having more fragments
         * or if this is not the first fragment,
         * attempt reassembly; if it succeeds, proceed.
         */
        if (ip->ip_tos & 1 || ip->ip_off) {
            m = ip_reass(slirp, m, ipq);
            if (m == NULL)
                return;
        } else {
            LOGSLIRP("Unreachable ip_input:%d", __LINE__);
            if (ipq)
                ip_freef(slirp, ipq);
        }
    }
#else
    if (ip->ip_off & ~IP_DF) {
        LOGSLIRP("ip_input: fragmented packet, dropped\n");
        m_free(m);
        return;
    }
#endif  /* SLIRP_SUPPORT_IPREASS */

    /*
     * Switch out to protocol's input routine.
     */
    switch (ip_p) {
    case IPPROTO_TCP:
        tcp_input(m, hlen, (struct socket *)NULL);
        break;
    case IPPROTO_UDP:
        udp_input(m, hlen);
        break;
    case IPPROTO_ICMP:
        icmp_input(m, hlen);
        break;
    default:
        m_free(m);
        break;
    }
    return;
  bad:
    if (ip)
        LOGSLIRP2("NAT: IP datagram to %s with size(%d) claimed as bad",
                  inet_ntoa(ip->ip_dst), ip->ip_len);
    m_free(m);
    return;
}

/*
 * Do option processing on a datagram,
 * possibly discarding it if bad options are encountered,
 * or forwarding it if source-routed.
 * Returns 1 if packet has been forwarded/freed,
 * 0 if the packet should be processed further.
 */

#ifdef notdef

int
ip_dooptions(m)
	struct mbuf *m;
{
    struct ip *ip = mtod(m, struct ip *);
    u_char *cp;
    struct ip_timestamp *ipt;
    struct in_ifaddr *ia;
    int opt, optlen, cnt, off, code, type, forward = 0;
    struct in_addr *sin, dst;
    typedef uint32_t n_time;
    n_time ntime;

    dst = ip->ip_dst;
    cp = (u_char *)(ip + 1);
    cnt = (ip->ip_hl << 2) - sizeof (struct ip);
    for (; cnt > 0; cnt -= optlen, cp += optlen) {
	opt = cp[IPOPT_OPTVAL];
	if (opt == IPOPT_EOL)
	    break;
	if (opt == IPOPT_NOP)
	    optlen = 1;
	else {
	    optlen = cp[IPOPT_OLEN];
	    if (optlen <= 0 || optlen > cnt) {
		code = &cp[IPOPT_OLEN] - (u_char *)ip;
		goto bad;
	    }
	}
	switch (opt) {

	default:
	    break;

	    /*
	     * Source routing with record.
	     * Find interface with current destination address.
	     * If none on this machine then drop if strictly routed,
	     * or do nothing if loosely routed.
	     * Record interface address and bring up next address
	     * component.  If strictly routed make sure next
	     * address is on directly accessible net.
	     */
	case IPOPT_LSRR:
	case IPOPT_SSRR:
	    if ((off = cp[IPOPT_OFFSET]) < IPOPT_MINOFF) {
		code = &cp[IPOPT_OFFSET] - (u_char *)ip;
		goto bad;
	    }
	    ipaddr.sin_addr = ip->ip_dst;
	    ia = (struct in_ifaddr *)
		ifa_ifwithaddr((struct sockaddr *)&ipaddr);
	    if (ia == 0) {
		if (opt == IPOPT_SSRR) {
		    type = ICMP_UNREACH;
		    code = ICMP_UNREACH_SRCFAIL;
		    goto bad;
		}
		/*
		 * Loose routing, and not at next destination
		 * yet; nothing to do except forward.
		 */
		break;
	    }
	    off--; /* 0 origin */
	    if (off > optlen - sizeof(struct in_addr)) {
		/*
		 * End of source route.  Should be for us.
		 */
		save_rte(cp, ip->ip_src);
		break;
	    }
	    /*
	     * locate outgoing interface
	     */
	    bcopy((caddr_t)(cp + off), (caddr_t)&ipaddr.sin_addr,
		  sizeof(ipaddr.sin_addr));
	    if (opt == IPOPT_SSRR) {
#define	INA	struct in_ifaddr *
#define	SA	struct sockaddr *
		if ((ia = (INA)ifa_ifwithdstaddr((SA)&ipaddr)) == 0)
		    ia = (INA)ifa_ifwithnet((SA)&ipaddr);
	    } else
		ia = ip_rtaddr(ipaddr.sin_addr);
	    if (ia == 0) {
		type = ICMP_UNREACH;
		code = ICMP_UNREACH_SRCFAIL;
		goto bad;
	    }
	    ip->ip_dst = ipaddr.sin_addr;
	    bcopy((caddr_t)&(IA_SIN(ia)->sin_addr),
		  (caddr_t)(cp + off), sizeof(struct in_addr));
	    cp[IPOPT_OFFSET] += sizeof(struct in_addr);
	    /*
	     * Let ip_intr's mcast routing check handle mcast pkts
	     */
	    forward = !IN_MULTICAST(ntohl(ip->ip_dst.s_addr));
	    break;

	case IPOPT_RR:
	    if ((off = cp[IPOPT_OFFSET]) < IPOPT_MINOFF) {
		code = &cp[IPOPT_OFFSET] - (u_char *)ip;
		goto bad;
	    }
	    /*
	     * If no space remains, ignore.
	     */
	    off--; /* 0 origin */
	    if (off > optlen - sizeof(struct in_addr))
		break;
	    bcopy((caddr_t)(&ip->ip_dst), (caddr_t)&ipaddr.sin_addr,
		  sizeof(ipaddr.sin_addr));
	    /*
	     * locate outgoing interface; if we're the destination,
	     * use the incoming interface (should be same).
	     */
	    if ((ia = (INA)ifa_ifwithaddr((SA)&ipaddr)) == 0 &&
		(ia = ip_rtaddr(ipaddr.sin_addr)) == 0) {
		type = ICMP_UNREACH;
		code = ICMP_UNREACH_HOST;
		goto bad;
	    }
	    bcopy((caddr_t)&(IA_SIN(ia)->sin_addr),
		  (caddr_t)(cp + off), sizeof(struct in_addr));
	    cp[IPOPT_OFFSET] += sizeof(struct in_addr);
	    break;

	case IPOPT_TS:
	    code = cp - (u_char *)ip;
	    ipt = (struct ip_timestamp *)cp;
	    if (ipt->ipt_len < 5)
		goto bad;
	    if (ipt->ipt_ptr > ipt->ipt_len - sizeof (int32_t)) {
		if (++ipt->ipt_oflw == 0)
		    goto bad;
		break;
	    }
	    sin = (struct in_addr *)(cp + ipt->ipt_ptr - 1);
	    switch (ipt->ipt_flg) {

	    case IPOPT_TS_TSONLY:
		break;

	    case IPOPT_TS_TSANDADDR:
		if (ipt->ipt_ptr + sizeof(n_time) +
		    sizeof(struct in_addr) > ipt->ipt_len)
		    goto bad;
		ipaddr.sin_addr = dst;
		ia = (INA)ifaof_ i f p foraddr((SA)&ipaddr,
					       m->m_pkthdr.rcvif);
		if (ia == 0)
		    continue;
		bcopy((caddr_t)&IA_SIN(ia)->sin_addr,
		      (caddr_t)sin, sizeof(struct in_addr));
		ipt->ipt_ptr += sizeof(struct in_addr);
		break;

	    case IPOPT_TS_PRESPEC:
		if (ipt->ipt_ptr + sizeof(n_time) +
		    sizeof(struct in_addr) > ipt->ipt_len)
		    goto bad;
		bcopy((caddr_t)sin, (caddr_t)&ipaddr.sin_addr,
		      sizeof(struct in_addr));
		if (ifa_ifwithaddr((SA)&ipaddr) == 0)
		    continue;
		ipt->ipt_ptr += sizeof(struct in_addr);
		break;

	    default:
		goto bad;
	    }
	    ntime = iptime();
	    bcopy((caddr_t)&ntime, (caddr_t)cp + ipt->ipt_ptr - 1,
		  sizeof(n_time));
	    ipt->ipt_ptr += sizeof(n_time);
	}
    }
    if (forward) {
	ip_forward(m, 1);
	return 1;
    }
    return 0;
  bad:
    icmp_error(m, type, code, 0, 0);

    return 1;
}

#endif /* notdef */

/*
 * Strip out IP options, at higher
 * level protocol in the kernel.
 * Second argument is buffer to which options
 * will be moved, and return value is their length.
 * (XXX) should be deleted; last arg currently ignored.
 */
void
ip_stripoptions(struct mbuf *m, struct mbuf *mopt)
{
    int i;
    struct ip *ip = mtod(m, struct ip *);
    caddr_t opts;
    int olen;

    olen = (ip->ip_hl<<2) - sizeof (struct ip);
    opts = (caddr_t)(ip + 1);
    i = m->m_len - (sizeof (struct ip) + olen);
    memmove(opts, opts  + olen, (unsigned)i);
    m->m_len -= olen;

    ip->ip_hl = sizeof(struct ip) >> 2;
}
