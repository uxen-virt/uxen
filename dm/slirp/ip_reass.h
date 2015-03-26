
struct mbuf *ip_reass(Slirp *slirp, struct mbuf *m, struct mbuf *ipq);
void ip_freef(Slirp *slirp, struct mbuf *ipq);
void ip_reass_timo(Slirp *slirp);
