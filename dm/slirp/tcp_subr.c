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
 *	@(#)tcp_subr.c	8.1 (Berkeley) 6/10/93
 * tcp_subr.c,v 1.5 1994/10/08 22:39:58 phk Exp
 */

/*
 * Changes and additions relating to SLiRP
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#include <slirp.h>

#include <dm/char.h>
#include <dm/async-op.h>

/* patchable/settable parameters for tcp */
/* Don't do rfc1323 performance enhancements */
#define TCP_DO_RFC1323 0

/*
 * Tcp initialization
 */
void
tcp_init(Slirp *slirp)
{
    slirp->tcp_iss = 1;		/* wrong */
    LIST_INIT(&slirp->tcb);
    slirp->tcp_last_so = LIST_FIRST(&slirp->tcb);

    LIST_INIT(&slirp->tcp_vmfwd);
}

/*
 * Create template to be used to send tcp packets on a connection.
 * Call after host entry created, fills
 * in a skeletal tcp/ip header, minimizing the amount of work
 * necessary when the connection is used.
 */
void
tcp_template(struct tcpcb *tp)
{
    struct socket *so = tp->t_socket;
    struct tcpiphdr *n = &tp->t_template;

    n->ti_x0 = 0;
    n->ti_x1 = 0;
    n->ti_pr = IPPROTO_TCP;
    n->ti_len = htons(sizeof (struct tcpiphdr) - sizeof (struct ip));

    n->ti_src = so->so_faddr;
    n->ti_sport = so->so_fport;
    n->ti_dst = so->so_laddr;
    n->ti_dport = so->so_lport;

    n->ti_seq = 0;
    n->ti_ack = 0;
    n->ti_x2 = 0;
    n->ti_off = 5;
    n->ti_flags = 0;
    n->ti_win = 0;
    n->ti_sum = 0;
    n->ti_urp = 0;
}

/*
 * Send a single message to the TCP at address specified by
 * the given TCP/IP header.  If m == 0, then we make a copy
 * of the tcpiphdr at ti and send directly to the addressed host.
 * This is used to force keep alive messages out using the TCP
 * template for a connection tp->t_template.  If flags are given
 * then we send a message back to the TCP which originated the
 * segment ti, and discard the mbuf containing it and any other
 * attached mbufs.
 *
 * In any case the ack and sequence number of the transmitted
 * segment are as specified by the parameters.
 */
void
tcp_respond(struct tcpcb *tp, struct tcpiphdr *ti, struct mbuf *m,
            tcp_seq ack, tcp_seq seq, int flags)
{
    int tlen;
    int win = 0;

    DEBUG_CALL("tcp_respond(tp = %p, ti = %p, m = %p, "
	       "ack = %u, seq = %u, flags = %x)", tp, ti, m,
	       ack, seq, flags);

    if (tp)
	win = sbspace(&tp->t_socket->so_rcv);
    if (m == NULL) {
	if ((m = m_get(tp->t_socket->slirp)) == NULL)
	    return;
	tlen = 0;
	m->m_data += IF_MAXLINKHDR;
	*mtod(m, struct tcpiphdr *) = *ti;
	ti = mtod(m, struct tcpiphdr *);
	flags = TH_ACK;
    } else {
	/*
	 * ti points into m so the next line is just making
	 * the mbuf point to ti
	 */
	m->m_data = (caddr_t)ti;

	m->m_len = sizeof (struct tcpiphdr);
	tlen = 0;
#define xchg(a, b, type) { type t; t = a; a = b; b = t; }
	xchg(ti->ti_dst.s_addr, ti->ti_src.s_addr, uint32_t);
	xchg(ti->ti_dport, ti->ti_sport, uint16_t);
#undef xchg
    }
    ti->ti_len = htons((u_short)(sizeof (struct tcphdr) + tlen));
    tlen += sizeof (struct tcpiphdr);
    m->m_len = tlen;

    ti->ti_x0 = 0;
    ti->ti_x1 = 0;
    ti->ti_seq = htonl(seq);
    ti->ti_ack = htonl(ack);
    ti->ti_x2 = 0;
    ti->ti_off = sizeof (struct tcphdr) >> 2;
    ti->ti_flags = flags;
    if (tp)
	ti->ti_win = htons((uint16_t) (win >> tp->rcv_scale));
    else
	ti->ti_win = htons((uint16_t)win);
    ti->ti_urp = 0;
    ti->ti_sum = 0;
    ti->ti_sum = cksum(m, tlen);
    ((struct ip *)ti)->ip_len = tlen;

    if (flags & TH_RST)
	((struct ip *)ti)->ip_ttl = MAXTTL;
    else
	((struct ip *)ti)->ip_ttl = IPDEFTTL;

    (void)ip_output(NULL, m);
}

/*
 * Create a new TCP control block, making an
 * empty reassembly queue and hooking it to the argument
 * protocol control block.
 */
struct tcpcb *
tcp_newtcpcb(struct socket *so)
{
    struct tcpcb *tp;

    tp = (struct tcpcb *)malloc(sizeof(*tp));
    if (tp == NULL)
	return NULL;

    memset((char *) tp, 0, sizeof(struct tcpcb));

#ifdef SLIRP_TCP_REASS
    RLIST_INIT(&tp->t_fragq, m_list);
#endif

    tp->t_maxseg = TCP_MSS;

    tp->t_flags = TCP_DO_RFC1323 ? (TF_REQ_SCALE | TF_REQ_TSTMP) : 0;
    tp->t_socket = so;

    /*
     * Init srtt to TCPTV_SRTTBASE (0), so we can tell that we have no
     * rtt estimate.  Set rttvar so that srtt + 2 * rttvar gives
     * reasonable initial retransmit time.
     */
    tp->t_srtt = TCPTV_SRTTBASE;
    tp->t_rttvar = TCPTV_SRTTDFLT << 2;
    tp->t_rttmin = TCPTV_MIN;

    TCPT_RANGESET(tp->t_rxtcur,
		  ((TCPTV_SRTTBASE >> 2) + (TCPTV_SRTTDFLT << 2)) >> 1,
		  TCPTV_MIN, TCPTV_REXMTMAX);

    tp->snd_cwnd = TCP_MAXWIN << TCP_MAX_WINSHIFT;
    tp->snd_ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT;
    tp->t_state = TCPS_CLOSED;

    so->so_tcpcb = tp;

    return (tp);
}

/*
 * Drop a TCP connection, reporting
 * the specified error.  If connection is synchronized,
 * then send a RST to peer.
 */
struct tcpcb *tcp_drop(struct tcpcb *tp, int err)
{
    DEBUG_CALL("tcp_drop(tp = %p, errno = %d)", tp, errno);

    if (TCPS_HAVERCVDSYN(tp->t_state)) {
	tp->t_state = TCPS_CLOSED;
	(void) tcp_output(tp);
    }
    return tcp_close(tp);
}

static void hostfwd_soreset(struct socket *so)
{
    so->so_state &= (SS_PERSISTENT_MASK & (~SS_INCOMING));
    so->so_state |= SS_FACCEPTCONN;
    free(so->so_tcpcb);
    so->so_tcpcb = tcp_newtcpcb(so);
    sbreset(&so->so_rcv);
    sbreset(&so->so_snd);
    if (so->hfwd_connect_try && so->hfwd_connect_timer)
        mod_timer(so->hfwd_connect_timer, get_clock_ms(vm_clock) + HFWD_CONNECT_DELAY_MS);
}

static void hostfwd_close_cb(void *opaque)
{
    struct socket *so = opaque;

    if (!(so->so_state & SS_CLOSERETRY))
        LOGSLIRP("%s: closing hostfwd socket & chr", __FUNCTION__);

    if (so->chr) {
        qemu_chr_close(so->chr);
        so->chr = NULL;
    }

    free(so->so_tcpcb);
    so->so_tcpcb = NULL;

    sbfree(&so->so_rcv);
    sbfree(&so->so_snd);
    sofree(so);
}

static void hostfwd_reconnect_cb(void *opaque)
{
    struct socket *so = opaque;
    int ret;
    struct sbuf *sb = &so->so_rcv;

    /* drain the rcv buf */
    while (sb->sb_cc) {
        ret = sowrite(so);
        if (ret <= 0)
            break;
    }

    if (so->chr && so->chr->chr_reconnect)
        so->chr->chr_reconnect(so->chr);
    hostfwd_soreset(so);
    if (so->chr->chr_update_read_handler)
        so->chr->chr_update_read_handler(so->chr);

    so->tcp_closing = 0;
}

/*
 * Close a TCP control block:
 *	discard all space held by the tcp
 *	discard internet protocol block
 *	wake up any sleepers
 */
struct tcpcb *
tcp_close(struct tcpcb *tp)
{
    struct socket *so = tp->t_socket;

    LOGSLIRP5("tcp_close(tp = %p)", tp);

    if (so->tcp_closing)
        return NULL;

#ifdef SLIRP_TCP_REASS
    /* free the reassembly queue, if any */
    while (!RLIST_EMPTY(&tp->t_fragq, m_list)) {
	struct mbuf *m = RLIST_FIRST(&tp->t_fragq, m_list);
	RLIST_REMOVE(m, m_list);
	m_free(m);
    }
#endif

    if (so->s == -1 && so->chr && (so->so_state & SS_HOSTFWD) &&
            (tp->t_state == TCPS_CLOSED || (so->so_state & SS_CLOSERETRY))) {
        so->tcp_closing = 1;
        if (!(so->so_state & SS_FWDCLOSE))
            so_refresh_fport(so);
        if (slirp_schedule_bh(so->slirp, NULL, (so->so_state & SS_FWDCLOSE) ?
             hostfwd_close_cb : hostfwd_reconnect_cb, so)) {

                so->tcp_closing = 0;
        }

        return NULL;
    }

    free(tp);
    so->so_tcpcb = NULL;

    if (so->s == -1 && so->chr) {
	if ((so->so_state & SS_HOSTFWD)) {
            if (so->so_state & SS_INCOMING)
                qemu_chr_disconnect(so->chr);
            hostfwd_soreset(so);
            if (so->chr->chr_update_read_handler)
                so->chr->chr_update_read_handler(so->chr);
            return NULL;
        } else {
            if (so->chr_close)
                so->chr_close(so->chr);
            so->chr = NULL;
        }
    } else if (so->s != -1) {
            /* clobber input socket cache if we're closing the cached connection */
            LOGSLIRP2("conn: %d close tcp socket", so->s);
            closesocket(so->s);
    }

    sbfree(&so->so_rcv);
    sbfree(&so->so_snd);
    sofree(so);
    return NULL;
}

/*
 * TCP protocol interface to socket abstraction.
 */

/*
 * User issued close, and wish to trail through shutdown states:
 * if never received SYN, just forget it.  If got a SYN from peer,
 * but haven't sent FIN, then go to FIN_WAIT_1 state to send peer a FIN.
 * If already got a FIN from peer, then almost done; go to LAST_ACK
 * state.  In all other cases, have already sent FIN to peer (e.g.
 * after PRU_SHUTDOWN), and just have to play tedious game waiting
 * for peer to send FIN or not respond to keep-alives, etc.
 * We can let the user exit from the close as soon as the FIN is acked.
 */
void
tcp_sockclosed(struct tcpcb *tp)
{

    DEBUG_CALL("tcp_sockclosed(tp = %p)", tp);

    switch (tp->t_state) {

    case TCPS_CLOSED:
    case TCPS_LISTEN:
    case TCPS_SYN_SENT:
	tp->t_state = TCPS_CLOSED;
	tp = tcp_close(tp);
	break;

    case TCPS_SYN_RECEIVED:
    case TCPS_ESTABLISHED:
	tp->t_state = TCPS_FIN_WAIT_1;
	break;

    case TCPS_CLOSE_WAIT:
	tp->t_state = TCPS_LAST_ACK;
	break;
    }
    if (tp)
	tcp_output(tp);
}

int tcp_fconnect_ex(struct socket *so, bool nonblocking)
{
    Slirp *slirp = so->slirp;
    int ret = 0;

    DEBUG_CALL("tcp_fconnect_ex(so = %p)", so);

    if ((ret = so->s = qemu_socket(AF_INET, SOCK_STREAM, 0)) >= 0) {
	int opt, s = so->s;
	struct sockaddr_in addr;

        if (nonblocking)
            fd_nonblock(s);
        else
            fd_block(s);
	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_OOBINLINE, (char *)&opt, sizeof(opt));

	addr.sin_family = AF_INET;
	if ((so->so_faddr.s_addr & slirp->vnetwork_mask.s_addr) ==
	    slirp->vnetwork_addr.s_addr) {
	    /* It's an alias */
	    if (so->so_faddr.s_addr == slirp->vnameserver_addr.s_addr) {
		if (get_dns_addr(&addr.sin_addr) < 0)
		    addr.sin_addr = loopback_addr;
	    } else
		addr.sin_addr = loopback_addr;
	} else
	    addr.sin_addr = so->so_faddr;
	addr.sin_port = so->so_fport;

	DEBUG_MISC(" connect()ing, addr.sin_port=%d, "
		   "addr.sin_addr.s_addr=%.16s",
		   ntohs(addr.sin_port), inet_ntoa(addr.sin_addr));
	/* We don't care what port we get */
	ret = connect(s, (struct sockaddr *)&addr, sizeof(addr));

	/*
	 * If it's not in progress, it failed, so we just return 0,
	 * without clearing SS_NOFDREF
	 */
        if (nonblocking)
            soisfconnecting(so);
        else if (ret >= 0)
            soisfconnected(so);
    }

    return ret;
}

/*
 * Connect to a host on the Internet
 * Called by tcp_input
 * Only do a connect, the tcp fields will be set in tcp_input
 * return 0 if there's a result of the connect,
 * else return -1 means we're still connecting
 * The return value is almost always -1 since the socket is
 * nonblocking.  Connect returns after the SYN is sent, and does
 * not wait for ACK+SYN.
 */
int tcp_fconnect(struct socket *so)
{
    return tcp_fconnect_ex(so, true);
}

/*
 * Accept the socket and connect to the local-host
 *
 * We have a problem. The correct thing to do would be
 * to first connect to the local-host, and only if the
 * connection is accepted, then do an accept() here.
 * But, a) we need to know who's trying to connect
 * to the socket to be able to SYN the local-host, and
 * b) we are already connected to the foreign host by
 * the time it gets to accept(), so... We simply accept
 * here and SYN the local-host.
 */
void
tcp_connect(struct socket *inso)
{
    Slirp *slirp = inso->slirp;
    struct socket *so;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct tcpcb *tp;
    int s, opt;

    DEBUG_CALL("tcp_connect(inso = %p)", inso);

    /*
     * If it's an SS_ACCEPTONCE socket, no need to socreate()
     * another socket, just use the accept() socket.
     */
    if (inso->so_state & SS_FACCEPTONCE)
	/* FACCEPTONCE already have a tcpcb */
	so = inso;
    else {
	if ((so = socreate_tcp(slirp)) == NULL) {
	    /* If it failed, get rid of the pending connection */
	    closesocket(accept(inso->s, (struct sockaddr *)&addr, &addrlen));
	    return;
	}
	if (tcp_attach(so) < 0) {
	    slirp->tcp_sockets--;
	    free(so); /* NOT sofree */
	    return;
	}
	so->so_laddr = inso->so_laddr;
	so->so_lport = inso->so_lport;
    }

    tcp_mss(sototcpcb(so), 0);

    if ((s = accept(inso->s, (struct sockaddr *)&addr, &addrlen)) < 0) {
	tcp_close(sototcpcb(so)); /* This will sofree() as well */
	return;
    }
    fd_nonblock(s);
    opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(int));
    opt = 1;
    setsockopt(s, SOL_SOCKET, SO_OOBINLINE, (char *)&opt, sizeof(int));
    opt = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(int));

    so->so_fport = addr.sin_port;
    so->so_faddr = addr.sin_addr;
    /* Translate connections from localhost to the real hostname */
    if (so->so_faddr.s_addr == 0 || so->so_faddr.s_addr == loopback_addr.s_addr)
	so->so_faddr = slirp->vhost_addr;

    /* Close the accept() socket, set right state */
    if (inso->so_state & SS_FACCEPTONCE) {
	closesocket(so->s); /* If we only accept once, close the accept() socket */
	so->so_state = SS_NOFDREF; /* Don't select it yet, even though we have an FD */
	/* if it's not FACCEPTONCE, it's already NOFDREF */
    }
    so->s = s;
    so->so_state |= SS_INCOMING;

    so->so_iptos = 0;
    tp = sototcpcb(so);

    tcp_template(tp);

    tp->t_state = TCPS_SYN_SENT;
    tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_INIT;
    tp->iss = slirp->tcp_iss;
    slirp->tcp_iss += TCP_ISSINCR / 2;
    tcp_sendseqinit(tp);
    tcp_output(tp);
}

/*
 * Attach a TCPCB to a socket.
 */
int
tcp_attach(struct socket *so)
{
    if ((so->so_tcpcb = tcp_newtcpcb(so)) == NULL)
	return -1;

    LIST_INSERT_HEAD(&so->slirp->tcb, so, entry);

    return 0;
}

/*
 * Set the socket's type of service field
 */
static const struct tos_t tcptos[] = { 
    {0, 22, IPTOS_LOWDELAY},	/* ssh */
    {0, 23, IPTOS_LOWDELAY},	/* telnet */
    {0, 80, IPTOS_THROUGHPUT},	/* WWW */
    {0, 513, IPTOS_LOWDELAY},	/* rlogin */
    {0, 514, IPTOS_LOWDELAY},	/* shell */
    {0, 544, IPTOS_LOWDELAY},	/* kshell */
    {0, 543, IPTOS_LOWDELAY},	/* klogin */
    {0, 113, IPTOS_LOWDELAY},	/* identd protocol */
};

/*
 * Return TOS according to the above table
 */
uint8_t
tcp_tos(struct socket *so)
{
    int i;

    for (i = 0; i < sizeof(tcptos) / sizeof(tcptos[0]); i++)
	if ((tcptos[i].fport && (ntohs(so->so_fport) == tcptos[i].fport)) ||
	    (tcptos[i].lport && (ntohs(so->so_lport) == tcptos[i].lport)))
	    return tcptos[i].tos;

    return 0;
}
