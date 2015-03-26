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

/*
 * Ip reassembly queue.  slirp->ipq is a list pointing to mbuf chains.
 * Each fragment being reassembled is attached to an mbuf chain.  The
 * chains are timed out after mbuf->ipq_ttl drops to 0, and may also
 * be reclaimed if memory becomes tight.
 */

#include "slirp.h"

/*
 * Take incoming datagram fragment and try to
 * reassemble it into whole datagram.  If a chain for
 * reassembly of this datagram already exists, then it
 * is given as ipq; otherwise have to make a chain.
 */
struct mbuf *
ip_reass(Slirp *slirp, struct mbuf *m, struct mbuf *ipq)
{
    struct ip *ip = mtod(m, struct ip *);
    struct mbuf *q, *pq;
    int hlen = ip->ip_hl << 2;
    int next;

    DEBUG_CALL("ip_reass(ip = %p, ipq = %p, m = %p)", ip, ipq, m);

    /*
     * Presence of header sizes in mbufs
     * would confuse code below.
     * Fragment m_data is concatenated.
     */
    m_adj(m, hlen);

    m->reass_hlen = hlen;

    /*
     * If first fragment to arrive, create a reassembly queue.
     */
    if (ipq == NULL) {
        ipq = m;

        /* insert to IP packets list */
        RLIST_INSERT_HEAD(&slirp->ipq, ipq, ipq_list);

        /* insert to IP fragments list */
        RLIST_INIT(ipq, m_list);

        q = RLIST_END(ipq);

        ipq->expiration_date = get_clock_ms(vm_clock) + IPFRAGTTL * SLOWHZ_MS;

        goto insert;
    }

    /*
     * Find a segment which overlaps this one (entirely or partially
     * from the start).
     */
    q = RLIST_START(ipq);
    do {
        struct ip *t = ipqtoip(q);
        int i = t->ip_off - ip->ip_off;
        /* Stop if the segments starts after this one. */
        if (i > 0)
            break;

        /* ip_len here doesn't include IP hdr */
        i += t->ip_len;
        if (i >= 0) {
            /* This is an overlapping segment providing no new data, drop! */
            if (i >= ip->ip_len)
                goto dropfrag;

            /* Drop overlapping data from the incoming segment. */
            m_adj(m, i);
            ip->ip_off += i;
            ip->ip_len -= i;
            q = RLIST_NEXT(q, m_list);
            break;
        }
        q = RLIST_NEXT(q, m_list);
    } while (!RLIST_ENDP(q, ipq));

    /*
     * While we overlap succeeding segments trim them or,
     * if they are completely covered, dequeue them.
     */
    while (!RLIST_ENDP(q, ipq)) {
        struct ip *t = ipqtoip(q);
        int i = (ip->ip_off + ip->ip_len) - t->ip_off;

        if (i <= 0)
            break;

        /* Drop overlapping data from the existing segment. */
        if (i < t->ip_len) {
            t->ip_off += i;
            t->ip_len -= i;
            m_adj(q, i);
            break;
        }

        /*
         * This is an overlapping segment, covering all data in the next
         * existing segment: drop the next existing segment.
         */
        pq = q;
        q = RLIST_NEXT(q, m_list);
        RLIST_REMOVE(pq, m_list);
        m_free(pq);
    }

  insert:
    /*
     * Stick new segment in its place;
     * check for complete reassembly.
     */
    RLIST_INSERT_BEFORE(q, m, m_list);  /* if q == m, nothing changes */

    next = 0;
    q = RLIST_START(ipq);
    do {
        struct ip *t = ipqtoip(q);

        if (t->ip_off != next)
            return NULL;
        next += t->ip_len;

        q = RLIST_NEXT(q, m_list);
    } while(!RLIST_ENDP(q, ipq));

    if (ipqtoip(RLIST_LAST(ipq, m_list))->ip_tos & 1)
        return NULL;

    /*
     * Reassembly is complete; concatenate fragments.
     */
    m = RLIST_START(ipq);
    q = RLIST_NEXT(m, m_list);

    while (!RLIST_ENDP(q, ipq)) {
        m_cat(m, q);

        pq = q;
        q = RLIST_NEXT(q, m_list);
        RLIST_REMOVE(pq, m_list);
        m_free(pq);
    }

    /* Move m_data back up so that mbuf points to ip header again. */
    m->m_len += m->reass_hlen;
    m->m_data -= m->reass_hlen;

    /*
     * Create header for new ip packet by
     * modifying header of first packet;
     * dequeue and discard fragment reassembly header.
     * Make header visible.
     */
    ip = mtod(m, struct ip *);
    ip->ip_len = next;
    ip->ip_tos &= ~1;

    RLIST_REMOVE(m, ipq_list);

    return m;

  dropfrag:
    m_free(m);
    return NULL;
}

/*
 * Free a fragment reassembly header and all
 * associated datagrams.
 */
void
ip_freef(Slirp *slirp, struct mbuf *ipq)
{
    struct mbuf *q;

    DEBUG_CALL("ip_freef(ipq = %p)", ipq);

    while (!RLIST_EMPTY(ipq, m_list)) {
        q = RLIST_FIRST(ipq, m_list);
        RLIST_REMOVE(q, m_list);
        m_free(q);
    }

    RLIST_REMOVE(ipq, ipq_list);
    m_free(ipq);
}

/*
 * IP timer processing:
 * if a timer expires on a reassembly queue, discard it.
 */
void
ip_reass_timo(Slirp *slirp)
{
    struct mbuf *ipq, *tipq;
    uint64_t now = get_clock_ms(vm_clock);

    // DEBUG_CALL("ip_reass_timo");

    RLIST_FOREACH_SAFE(ipq, &slirp->ipq, ipq_list, tipq)
        if (ipq->expiration_date < now)
            ip_freef(slirp, ipq);
}
