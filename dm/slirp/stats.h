#ifndef _SLIRP_STATS_H_
#define _SLIRP_STATS_H_

void slirp_stats_sock_start(void);
void slirp_stats_tcp_sock(struct socket *so);
void slirp_stats_sock_end(void);
void stats_guest_in(struct socket *so, int len);
void stats_guest_out(struct socket *so, int len);
int stats_rpc_send(void);

#endif /* _STATS_H_ */
