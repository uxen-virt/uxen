#ifndef __COMMON_H__
#define __COMMON_H__

#include <dm/qemu_glue.h>

#include <dm/monitor.h>

#include "slirp_config.h"

#ifdef _WIN32
# include <inttypes.h>

typedef char *caddr_t;

# include <winsock2.h>
# include <windows.h>
# include <ws2tcpip.h>
# include <sys/timeb.h>
# include <iphlpapi.h>

# define EWOULDBLOCK WSAEWOULDBLOCK
# define EINPROGRESS WSAEINPROGRESS
# define ENOTCONN WSAENOTCONN
# define EHOSTUNREACH WSAEHOSTUNREACH
# define ENETUNREACH WSAENETUNREACH
# define ECONNREFUSED WSAECONNREFUSED
#else
# define ioctlsocket ioctl
# define closesocket(s) close(s)
# if !defined(__HAIKU__)
#  define O_BINARY 0
# endif
#endif

#include <sys/types.h>
#ifdef HAVE_SYS_BITYPES_H
# include <sys/bitypes.h>
#endif

#include <sys/time.h>

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#include <stdio.h>
#include <errno.h>

#ifndef HAVE_MEMMOVE
#define memmove(x, y, z) bcopy(y, x, z)
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_STRING_H
# include <string.h>
#else
# include <strings.h>
#endif

#ifndef _WIN32
#include <sys/uio.h>
#endif

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifndef HAVE_INET_ATON
int inet_aton(const char *cp, struct in_addr *ia);
#endif

#include <fcntl.h>
#ifndef NO_UNIX_SOCKETS
#include <sys/un.h>
#endif
#include <signal.h>
#ifdef HAVE_SYS_SIGNAL_H
# include <sys/signal.h>
#endif
#ifndef _WIN32
#include <sys/socket.h>
#endif

#if defined(HAVE_SYS_IOCTL_H)
# include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include <sys/stat.h>

#ifdef HAVE_SYS_STROPTS_H
#include <sys/stropts.h>
#endif

#include "debug.h"

#include "libslirp.h"
#include "mbuf.h"
#include "ip.h"
#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_var.h"
#include "tcpip.h"
#include "udp.h"
#include "ip_icmp.h"
#include "sbuf.h"
#include "socket.h"
#include "if.h"
#include "misc.h"

#include "bootp.h"
#include "tftp.h"
#include <dm/net-user.h>

#define SLOWHZ_MS       500     /* 2 slow timeouts per second */

#define ETH_ALEN 6
#define ETH_HLEN 14

#define ETH_P_IP  0x0800        /* Internet Protocol packet  */
#define ETH_P_ARP 0x0806        /* Address Resolution packet */

#define ARPOP_REQUEST 1         /* ARP request */
#define ARPOP_REPLY   2         /* ARP reply   */

#define HFWD_CONNECT_DELAY_MS 100

struct ethhdr {
    unsigned char  h_dest[ETH_ALEN];   /* destination eth addr */
    unsigned char  h_source[ETH_ALEN]; /* source ether addr    */
    unsigned short h_proto;            /* packet type ID field */
};

struct arphdr {
    unsigned short ar_hrd;      /* format of hardware address */
    unsigned short ar_pro;      /* format of protocol address */
    unsigned char  ar_hln;      /* length of hardware address */
    unsigned char  ar_pln;      /* length of protocol address */
    unsigned short ar_op;       /* ARP opcode (command)       */

    /*
     *  Ethernet looks like this : This bit is variable sized however...
     */
    unsigned char ar_sha[ETH_ALEN]; /* sender hardware address */
    uint32_t      ar_sip;           /* sender IP address       */
    unsigned char ar_tha[ETH_ALEN]; /* target hardware address */
    uint32_t      ar_tip;           /* target IP address       */
} QEMU_PACKED;

#define ARP_TABLE_SIZE 16

typedef struct ArpTable {
    struct arphdr table[ARP_TABLE_SIZE];
    int next_victim;
} ArpTable;

void arp_table_add(Slirp *slirp, uint32_t ip_addr, uint8_t ethaddr[ETH_ALEN]);

bool arp_table_search(Slirp *slirp, uint32_t ip_addr,
                      uint8_t out_ethaddr[ETH_ALEN]);

void arp_table_save(QEMUFile *, Slirp *);
void arp_table_load(QEMUFile *, Slirp *);

#define DNS_CONTROL_PORT_NUMBER 53

struct Slirp {
    QTAILQ_ENTRY(Slirp) entry;

    /* virtual network configuration */
    struct in_addr vnetwork_addr;
    struct in_addr vnetwork_mask;
    struct in_addr vhost_addr;
    struct in_addr vdhcp_startaddr;
    struct in_addr vnameserver_addr;

    struct in_addr client_ipaddr;
    char client_hostname[33];

    int restricted;
    struct timeval tt;

    int log_level;
    int disable_dhcp;
    uint32_t tcp_sockets;

    /* if states */
    int if_queued;          /* number of packets queued so far */
#if defined(SLIRP_IF_OUTPUT_QUEUES)
    struct mbuf if_fastq;   /* fast queue (for interactive data) */
    struct mbuf if_batchq;  /* queue for non-interactive data */
    struct mbuf *next_m;    /* pointer to next mbuf to output */
#else
    struct mbuf if_queue;   /* simple if queue */
#endif

    /* ip states */
#ifdef SLIRP_SUPPORT_IPREASS
    struct mbuf ipq;        /* ip reass. queue */
#endif

    uint16_t ip_id;         /* ip packet ctr, for ids */

    /* bootp/dhcp states */
    BOOTPClient bootp_clients[NB_BOOTP_CLIENTS];
    char *bootp_filename;

    /* tcp states */
    struct sockets_list tcb;
    struct socket *tcp_last_so;
    tcp_seq tcp_iss;        /* tcp initial send seq # */
    uint32_t tcp_now;       /* for RFC 1323 timestamps */

    /* udp states */
    struct sockets_list udb;
    struct socket *udp_last_so;

    /* icmp states */
    struct sockets_list icmb;

    /* tftp states */
    char *tftp_prefix;
    struct tftp_session tftp_sessions[TFTP_SESSIONS_MAX];

    /* vmfwd states */
    struct tcp_vmfwd_list tcp_vmfwd;
    struct udp_vmfwd_list udp_vmfwd;

    ArpTable arp_table;

    void *opaque;
#ifdef SLIRP_THREADED
    int mark_deletion;
#endif
    int disable_tcp_time_wait;
    struct net_user nu;
};

extern Slirp *slirp_instance;

enum sock_save_type {
    SOSV_SLIRP = 1,
    SOSV_RST,
    SOSV_PROXY
};


#ifndef NULL
#define NULL (void *)0
#endif

#ifndef FULL_BOLT
void if_start(Slirp *);
#else
void if_start(struct ttys *);
#endif

#ifndef _WIN32
#include <netdb.h>
#endif

#define SO_OPTIONS DO_KEEPALIVE
#define TCP_MAXIDLE (TCPTV_KEEPCNT * TCPTV_KEEPINTVL)

/* slirp.c */
extern u_int curtime;
extern struct in_addr loopback_addr;
int if_encap(Slirp *slirp, struct mbuf *ifm);
ssize_t slirp_send(struct socket *so, const void *buf, size_t len, int flags);
void slirp_buffer_change(struct socket *so);
void slirp_mbuf_output(void *opaque, struct mbuf *m, int send);
struct socket * slirp_socket_load(QEMUFile *f, Slirp *slirp, int type);
void slirp_socket_save(QEMUFile *f, struct socket *so, int type);
#ifdef SLIRP_THREADED
extern unsigned long slirp_thid;
int slirp_loop_init(void);
#endif

/* cksum.c */
int cksum(struct mbuf *m, int len);

/* if.c */
void if_init(Slirp *);
void if_output(struct socket *, struct mbuf *);

/* ip_input.c */
void ip_init(Slirp *);
void ip_input(struct mbuf *);
void ip_stripoptions(struct mbuf *, struct mbuf *);

/* ip_output.c */
int ip_output(struct socket *, struct mbuf *);

/* tcp_input.c */
void tcp_input(struct mbuf *, int, struct socket *);
uint16_t tcp_mss(struct tcpcb *, uint16_t);

/* tcp_output.c */
int tcp_output(struct tcpcb *);
void tcp_setpersist(struct tcpcb *);

/* tcp_subr.c */
void tcp_init(Slirp *);
void tcp_template(struct tcpcb *);
void tcp_respond(struct tcpcb *, struct tcpiphdr *, struct mbuf *, tcp_seq, tcp_seq, int);
struct tcpcb * tcp_newtcpcb(struct socket *);
struct tcpcb * tcp_close(struct tcpcb *);
void tcp_sockclosed(struct tcpcb *);
int tcp_fconnect(struct socket *);
int tcp_fconnect_ex(struct socket *, bool nonblocking);
void tcp_connect(struct socket *);
int tcp_attach(struct socket *);
uint8_t tcp_tos(struct socket *);
int tcp_emu(struct socket *, struct mbuf *);
int tcp_ctl(struct socket *);
struct tcpcb *tcp_drop(struct tcpcb *tp, int err);
void slirp_log_buf(const char *buf, size_t len);

extern unsigned  slirp_mtu;
extern unsigned  slirp_mru;


#define MIN_MRU 128
#define MAX_MRU 16384

#ifndef _WIN32
#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifdef _WIN32
#undef errno
#define errno (WSAGetLastError())
#endif

extern int slirp_log_level;

#define LOGSLIRP_LEVEL(level, fmt, ...) do {                        \
        if (slirp_log_level < (level))                              \
            break;                                                  \
        debug_printf("slirp%d: " fmt "\n", level, ## __VA_ARGS__);  \
    } while (0)
#define LOGSLIRP(fmt, ...)  LOGSLIRP_LEVEL(1, fmt,  ## __VA_ARGS__)
#define LOGSLIRP2(fmt, ...) LOGSLIRP_LEVEL(2, fmt,  ## __VA_ARGS__)
#define LOGSLIRP3(fmt, ...) LOGSLIRP_LEVEL(3, fmt,  ## __VA_ARGS__)
#define LOGSLIRP4(fmt, ...) LOGSLIRP_LEVEL(4, fmt,  ## __VA_ARGS__)
#define LOGSLIRP5(fmt, ...) LOGSLIRP_LEVEL(5, fmt,  ## __VA_ARGS__)

#define LOGREL LOGSLIRP

#define LOGSLIRPBUF(buf, len) do {                          \
        slirp_log_buf(buf, len);                            \
    } while(0)


#endif
