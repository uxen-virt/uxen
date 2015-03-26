/*
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#include <slirp.h>
#include <libslirp.h>

#ifdef SLIRP_DEBUG
int slirp_debug = 0 /* |DBG_CALL|DBG_MISC|DBG_ERROR|DBG_XTRA */;
#endif

/*
 * Set fd blocking and non-blocking
 */
void
fd_nonblock(int fd)
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

void
fd_block(int fd)
{
#ifdef FIONBIO
#ifdef _WIN32
    unsigned long opt = 0;
#else
    int opt = 0;
#endif

    ioctlsocket(fd, FIONBIO, &opt);
#else
    int opt;

    opt = fcntl(fd, F_GETFL, 0);
    opt &= ~O_NONBLOCK;
    fcntl(fd, F_SETFL, opt);
#endif
}

#ifdef MONITOR
void slirp_connection_info(Slirp *slirp, Monitor *mon)
{
    const char * const tcpstates[] = {
        [TCPS_CLOSED]       = "CLOSED",
        [TCPS_LISTEN]       = "LISTEN",
        [TCPS_SYN_SENT]     = "SYN_SENT",
        [TCPS_SYN_RECEIVED] = "SYN_RCVD",
        [TCPS_ESTABLISHED]  = "ESTABLISHED",
        [TCPS_CLOSE_WAIT]   = "CLOSE_WAIT",
        [TCPS_FIN_WAIT_1]   = "FIN_WAIT_1",
        [TCPS_CLOSING]      = "CLOSING",
        [TCPS_LAST_ACK]     = "LAST_ACK",
        [TCPS_FIN_WAIT_2]   = "FIN_WAIT_2",
        [TCPS_TIME_WAIT]    = "TIME_WAIT",
    };
    struct in_addr dst_addr;
    struct sockaddr_in src;
    socklen_t src_len;
    uint16_t dst_port;
    struct socket *so;
    const char *state;
    char buf[20];
    int n;

    monitor_printf(mon, "  Protocol[State]    FD  Source Address  Port   "
		   "Dest. Address  Port RecvQ SendQ\n");

    LIST_FOREACH(so, &slirp->tcb, entry) {
        if (so->so_state & SS_HOSTFWD)
            state = "HOST_FORWARD";
	else if (so->so_tcpcb)
            state = tcpstates[so->so_tcpcb->t_state];
	else
            state = "NONE";
        if (so->so_state & (SS_HOSTFWD | SS_INCOMING)) {
            src_len = sizeof(src);
            getsockname(so->s, (struct sockaddr *)&src, &src_len);
            dst_addr = so->so_laddr;
            dst_port = so->so_lport;
        } else {
            src.sin_addr = so->so_laddr;
            src.sin_port = so->so_lport;
            dst_addr = so->so_faddr;
            dst_port = so->so_fport;
        }
        n = snprintf(buf, sizeof(buf), "  TCP[%s]", state);
        memset(&buf[n], ' ', 19 - n);
        buf[19] = 0;
        monitor_printf(mon, "%s %3d %15s %5d ", buf, so->s,
                       src.sin_addr.s_addr ? inet_ntoa(src.sin_addr) : "*",
                       ntohs(src.sin_port));
        monitor_printf(mon, "%15s %5d %5d %5d\n",
                       inet_ntoa(dst_addr), ntohs(dst_port),
                       so->so_rcv.sb_cc, so->so_snd.sb_cc);
    }

    LIST_FOREACH(so, &slirp->udb, entry) {
        if (so->so_state & SS_HOSTFWD) {
            n = snprintf(buf, sizeof(buf), "  UDP[HOST_FORWARD]");
            src_len = sizeof(src);
            getsockname(so->s, (struct sockaddr *)&src, &src_len);
            dst_addr = so->so_laddr;
            dst_port = so->so_lport;
        } else {
            n = snprintf(buf, sizeof(buf), "  UDP[%d sec]",
                         (so->so_expire - curtime) / 1000);
            src.sin_addr = so->so_laddr;
            src.sin_port = so->so_lport;
            dst_addr = so->so_faddr;
            dst_port = so->so_fport;
        }
        memset(&buf[n], ' ', 19 - n);
        buf[19] = 0;
        monitor_printf(mon, "%s %3d %15s %5d ", buf, so->s,
                       src.sin_addr.s_addr ? inet_ntoa(src.sin_addr) : "*",
                       ntohs(src.sin_port));
        monitor_printf(mon, "%15s %5d %5d %5d\n",
                       inet_ntoa(dst_addr), ntohs(dst_port),
                       so->so_rcv.sb_cc, so->so_snd.sb_cc);
    }

    LIST_FOREACH(so, &slirp->icmb, entry) {
        n = snprintf(buf, sizeof(buf), "  ICMP[%d sec]",
                     (so->so_expire - curtime) / 1000);
        src.sin_addr = so->so_laddr;
        dst_addr = so->so_faddr;
        memset(&buf[n], ' ', 19 - n);
        buf[19] = 0;
        monitor_printf(mon, "%s %3d %15s  -    ", buf, so->s,
                       src.sin_addr.s_addr ? inet_ntoa(src.sin_addr) : "*");
        monitor_printf(mon, "%15s  -    %5d %5d\n", inet_ntoa(dst_addr),
                       so->so_rcv.sb_cc, so->so_snd.sb_cc);
    }
}
#endif  /* MONTIOR */
