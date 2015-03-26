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
 *	@(#)mbuf.h	8.3 (Berkeley) 1/21/94
 * mbuf.h,v 1.9 1994/11/14 13:54:20 bde Exp
 */

#ifndef _MBUF_H_
#define _MBUF_H_

#include <dm/queue2.h>

#define MINCSIZE 4096   /* Amount to increase mbuf if too small */

/*
 * Macros for type conversion
 * mtod(m, t) - convert mbuf pointer to data pointer of correct type
 */
#define mtod(m, t)  ((t)(m)->m_data)

/* XXX About mbufs for slirp:
 * Only one mbuf is ever used in a chain, for each "cell" of data.
 * m_nextpkt points to the next packet, if fragmented.
 * If the data is too large, the M_EXT is used, and a larger block
 * is alloced.  Therefore, m_free[m] must check for M_EXT and if set
 * free the m_ext.  This is inefficient memory-wise, but who cares.
 */

struct mbuf;
RLIST_HEAD(mbufs_list, mbuf);

/* XXX should union some of these! */
/* header at beginning of each mbuf: */
struct m_hdr {
    RLIST_ENTRY(mbufs_list) mh_list;    /* Linked list of mbufs */
    RLIST_ENTRY(mbufs_list) mh_listpkt; /* Linked list of packets */
    int mh_flags;                       /* Misc flags */

    int mh_size;                        /* Size of data */
    struct socket *mh_so;

    caddr_t mh_data;                    /* Location of data */
    int     mh_len;                     /* Amount of data in this mbuf */
};

/*
 * How much room is in the mbuf, from m_data to the end of the mbuf
 */
#define M_ROOM(m) ((m->m_flags & M_EXT) ? \
    (((m)->m_ext + (m)->m_size) - (m)->m_data) \
    : \
    (((m)->m_dat + (m)->m_size) - (m)->m_data))

/*
 * How much free room there is
 */
#define M_FREEROOM(m) (M_ROOM(m) - (m)->m_len)
#define M_TRAILINGSPACE M_FREEROOM

struct mbuf {
    struct m_hdr m_hdr;
    Slirp *slirp;
    union {
        struct {
            bool arp_requested;
            uint64_t expiration_date;
        };
        int reass_hlen;
    };
    /* start of dynamic buffer area, must be last element */
    union M_dat {
        char m_dat_[1]; /* ANSI don't like 0 sized arrays */
        char *m_ext_;
    } M_dat;
};

#define m_list      m_hdr.mh_list
#define m_flags     m_hdr.mh_flags
#define m_len       m_hdr.mh_len
#define m_data      m_hdr.mh_data
#define m_size      m_hdr.mh_size
#define m_dat       M_dat.m_dat_
#define m_ext       M_dat.m_ext_
#define m_so        m_hdr.mh_so

// #define m_dat_to_mbuf(d) container_of((void *)(d), struct mbuf, m_dat)

#define ifq_list    m_hdr.mh_listpkt
#define ifq_so      m_so

#define ipq_list    m_hdr.mh_listpkt
/* ipq mbuf points to data, ip header is at reass_hlen before */
#define ipqtoip(ipq)    ((struct ip *)(mtod((ipq), uint8_t *) - (ipq)->reass_hlen))

#define M_EXT       0x01    /* m_ext points to more (malloced) data */

void m_init(Slirp *);
struct mbuf *m_get(Slirp *);
void m_free(struct mbuf *);
void m_cat(struct mbuf *, struct mbuf *);
void m_inc(struct mbuf *, int);
void m_adj(struct mbuf *, int);
int m_copy(struct mbuf *, struct mbuf *, int, int);

#endif
