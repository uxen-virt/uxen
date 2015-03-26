/*
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#include <slirp.h>

void
if_init(Slirp *slirp)
{
#if defined(SLIRP_IF_OUTPUT_QUEUES)
    RLIST_INIT(&slirp->if_fastq, m_list);
    RLIST_INIT(&slirp->if_batchq, m_list);
    slirp->next_m = RLIST_END(&slirp->if_batchq);
#else
    RLIST_INIT(&slirp->if_queue, m_list);
#endif
}

/*
 * if_output: Queue packet into an output queue.
 * There are 2 output queue's, if_fastq and if_batchq.
 * Each output queue is a doubly linked list of double linked lists
 * of mbufs, each list belonging to one "session" (socket).  This
 * way, we can output packets fairly by sending one packet from each
 * session, instead of all the packets from one session, then all packets
 * from the next session, etc.  Packets on the if_fastq get absolute
 * priority, but if one session hogs the link, it gets "downgraded"
 * to the batchq until it runs out of packets, then it'll return
 * to the fastq (eg. if the user does an ls -alR in a telnet session,
 * it'll temporarily get downgraded to the batchq)
 */
void
if_output(struct socket *so, struct mbuf *ifm)
{
    Slirp *slirp = ifm->slirp;

#if defined(SLIRP_IF_OUTPUT_QUEUES)
    struct mbuf *ifq;
    int on_fastq;

    on_fastq = (so && (so->so_iptos & IPTOS_LOWDELAY));

    DEBUG_VERBOSE("if_output(so = %p, ifm = %p, %s)", so, ifm,
                  on_fastq ? "fast" : "batch");

    /*
     * See if there's already a batchq list for this session.
     * This can include an interactive session, which should go on fastq,
     * but gets too greedy... hence it'll be downgraded from fastq to batchq.
     * We mustn't put this packet back on the fastq (or we'll send it out
     * of order)
     */
    if (so && so->so_ifq) {
        ifm->ifq_so = so;
        RLIST_INSERT_TAIL(so->so_ifq, ifm, ifq_list);
        goto diddit;
    }

    /* No match, check which queue to put it on */
    if (on_fastq) {
	ifq = RLIST_LAST(&slirp->if_fastq, m_list);
	/*
	 * Check if this packet is a part of the last
	 * packet's session
	 */
	if (ifq->ifq_so == so) {
	    ifm->ifq_so = so;
	    RLIST_INSERT_TAIL(ifq, ifm, ifq_list);
            so->so_ifq = ifq;
	    goto diddit;
	}
    } else
	ifq = RLIST_LAST(&slirp->if_batchq, m_list);

    /* Create a new doubly linked list for this session */
    ifm->ifq_so = so;
    RLIST_INIT(ifm, ifq_list);
    RLIST_INSERT_AFTER(ifq, ifm, m_list);
    if (so)
        so->so_ifq = ifm;

  diddit:
    slirp->if_queued++;

    if (so) {
	/* Update *_queued */
	so->so_queued++;
	so->so_nqueued++;
	/*
	 * Check if the interactive session should be downgraded to
	 * the batchq.  A session is downgraded if it has queued 6
	 * packets without pausing, and at least 3 of those packets
	 * have been sent over the link
	 * (XXX These are arbitrary numbers, probably not optimal..)
	 */
	if (on_fastq && ((so->so_nqueued >= 6) &&
			 (so->so_nqueued - so->so_queued) >= 3)) {

	    /* Remove from current queue... */
            /* Note: RLIST_NEXT because ifm is the last packet on
             * ifq_list and need to add/remove the head from m_list */
	    RLIST_REMOVE(RLIST_NEXT(ifm, ifq_list), m_list);

	    /* ...And insert in the new.  That'll teach ya! */
	    RLIST_INSERT_HEAD(&slirp->if_batchq, RLIST_NEXT(ifm, ifq_list),
			      m_list);
	}
    }

#else /* SLIRP_IF_OUTPUT_QUEUES */
    RLIST_INSERT_TAIL(&slirp->if_queue, ifm, m_list);
    slirp->if_queued++;
#endif

#ifndef FULL_BOLT
    /*
     * This prevents us from malloc()ing too many mbufs
     */
    if_start(ifm->slirp);
#endif
}

/*
 * Send a packet
 * We choose a packet based on it's position in the output queues;
 * If there are packets on the fastq, they are sent FIFO, before
 * everything else.  Otherwise we choose the first packet from the
 * batchq and send it.  the next packet chosen will be from the session
 * after this one, then the session after that one, and so on..  So,
 * for example, if there are 3 ftp session's fighting for bandwidth,
 * one packet will be sent from the first session, then one packet
 * from the second session, then one packet from the third, then back
 * to the first, etc. etc.
 */
void
if_start(Slirp *slirp)
{
    uint64_t now = get_clock_ms(vm_clock);
    int requeued = 0;
    struct mbuf *ifm, *ifqt = NULL;

    DEBUG_VERBOSE("if_start");

    if (slirp->if_queued == 0)
	return; /* Nothing to do */

  again:
    /* check if we can really output */
    if (!slirp_can_output(slirp->opaque)) {
	slirp->if_queued += requeued;
	return;
    }

#if defined(SLIRP_IF_OUTPUT_QUEUES)
    /*
     * See which queue to get next packet from
     * If there's something in the fastq, select it immediately
     */
    if (!RLIST_EMPTY(&slirp->if_fastq, m_list))
	ifm = RLIST_FIRST(&slirp->if_fastq, m_list);
    else {
	/* Nothing on fastq, see if next_m is valid */
	ifm = slirp->next_m;
	if (RLIST_ENDP(ifm, &slirp->if_batchq))
	    ifm = RLIST_FIRST(&slirp->if_batchq, m_list);

	/* Set which packet to send on next iteration */
	slirp->next_m = RLIST_NEXT(ifm, m_list);
    }
    /* Remove it from the queue */
    ifqt = RLIST_PREV(ifm, m_list);
    RLIST_REMOVE(ifm, m_list);
    slirp->if_queued--;

    /* Update socket ifq pointer */
    if (ifm->ifq_so && ifm->ifq_so->so_ifq == ifm)
        ifm->ifq_so->so_ifq = RLIST_EMPTY(ifm, ifq_list) ? NULL :
            RLIST_NEXT(ifm, ifq_list);

    /* If there are more packets for this session, re-queue them */
    if (!RLIST_EMPTY(ifm, ifq_list)) {
	RLIST_INSERT_AFTER(ifqt, RLIST_NEXT(ifm, ifq_list), m_list);
	RLIST_REMOVE(ifm, ifq_list);
    }

    /* Update so_queued */
    if (ifm->ifq_so) {
	if (--ifm->ifq_so->so_queued == 0)
	    /* If there's no more queued, reset nqueued */
	    ifm->ifq_so->so_nqueued = 0;
    }

    if (ifm->expiration_date < now)
	/* Expired */
	m_free(ifm);
    else {
	/* Encapsulate the packet for sending */
	if (!if_encap(slirp, ifm)) {
	    /* re-queue */
	    RLIST_INSERT_AFTER(ifqt, ifm, m_list);
	    requeued++;
            if (ifm->ifq_so)
                ifm->ifq_so->so_queued++;
	}
    }

#else
    ifm = ifqt;
    if (!ifm)
        ifm = RLIST_NEXT(&slirp->if_queue, m_list);
    if (slirp->if_queued) {
        ifqt = RLIST_NEXT(ifm, m_list);
        RLIST_REMOVE(ifm, m_list);
        slirp->if_queued--;
        if (ifm->expiration_date < now) {
            m_free(ifm);
        } else if (!if_encap(slirp, ifm)) {
            /* re-queue but keep its original position */
            RLIST_INSERT_BEFORE(ifqt, ifm, m_list);
            requeued++;
        }
    }
#endif

    if (slirp->if_queued)
	goto again;

    slirp->if_queued = requeued;
}
