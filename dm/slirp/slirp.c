/*
 * libslirp glue
 *
 * Copyright (c) 2004-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "slirp.h"
#ifdef SLIRP_SUPPORT_IPREASS
#include "ip_reass.h"
#endif  /* SLIRP_SUPPORT_IPREASS */

#include <dm/async-op.h>
#include <dm/char.h>
#include <dm/clock.h>
#include <dm/file.h>
#include <dm/ioh.h>
#include <dm/os.h>

#include "stats.h"

#define DEFAULT_TIMEOUT_MS 10000
#define SLIRP_LOOP_DELAY_WARN 800 /* ms */

#define SLIRP_TH_DEBUG  1

#include <dm/base64.h>

/* host loopback address */
struct in_addr loopback_addr;

/* emulated hosts use the MAC addr 52:55:IP:IP:IP:IP */
static const uint8_t special_ethaddr[ETH_ALEN] = {
    0x52, 0x55, 0x00, 0x00, 0x00, 0x00
};
unsigned slirp_mtu = IF_MTU;
unsigned slirp_mru = IF_MRU;

#ifndef _WIN32
/* XXX: suppress those select globals */
fd_set *global_readfds, *global_writefds, *global_xfds;
#endif

u_int curtime;
static u_int time_fasttimo, last_slowtimo;
static int do_slowtimo;

static QTAILQ_HEAD(slirp_instances, Slirp) slirp_instances =
    QTAILQ_HEAD_INITIALIZER(slirp_instances);

int slirp_log_level = 1;

struct io_handler_queue slirp_io_handlers;
#ifdef _WIN32
WSAEVENT slirp_event;
#endif
WaitObjects *slirp_wait_objects = NULL;

#if defined(SLIRP_THREADED)
int slirp_exit_now = 0;
critical_section slirp_mx;
static WaitObjects _slirp_wait_objects;
static TimerQueue slirp_active_timers[2];
#if defined(_WIN32)
uxen_thread slirp_thread;
critical_section queue_mx;
ioh_event slirp_deqin_ev;
ioh_event slirp_deqout_ev;
unsigned long slirp_thid = 0;
unsigned long slirp_pid = 0;
#endif

int slirp_request_exit = 0;
struct mbuf in_mbufq, out_mbufq;
unsigned long slirp_inq_max = 0, slirp_outq_max = 0;
unsigned long inq_n = 0, outq_n = 0;
#endif

struct async_op_ctx *slirp_async_op_ctx = NULL;

static struct in_addr dns_addr;
static u_int dns_addr_time;

size_t slirp_socket_can_recv(void *opaque);
void slirp_socket_recv(void *opaque, const uint8_t *buf, int size);
void slirp_socket_send(void *opaque);
void slirp_socket_close(void *opaque);
static int slirp_add_wait_object(void *sopaque, ioh_event *event, WaitObjectFunc *func, void *opaque);
static void slirp_del_wait_object(void *sopaque, ioh_event *event);
#ifndef _WIN32
int slirp_add_wait_fd(void *sopaque, int fd, int events, WaitObjectFunc2 *func2, void *opaque);
void slirp_del_wait_fd(void *sopaque, int fd);
#endif
static int slirp_schedule_bh_permanent(void *nopaque, void (*cb)(void *), void *opaque);

#ifdef _WIN32

int get_dns_addr(struct in_addr *pdns_addr)
{
    FIXED_INFO *FixedInfo = NULL;
    ULONG BufLen;
    DWORD ret;
    IP_ADDR_STRING *pIPAddr;
    struct in_addr tmp_addr;

    if (dns_addr.s_addr != 0 && (curtime - dns_addr_time) < 1000) {
        *pdns_addr = dns_addr;
        return 0;
    }

    FixedInfo = (FIXED_INFO *)GlobalAlloc(GPTR, sizeof(FIXED_INFO));
    BufLen = sizeof(FIXED_INFO);

    if (ERROR_BUFFER_OVERFLOW == GetNetworkParams(FixedInfo, &BufLen)) {
        if (FixedInfo) {
            GlobalFree(FixedInfo);
            FixedInfo = NULL;
        }
        FixedInfo = GlobalAlloc(GPTR, BufLen);
    }

    if ((ret = GetNetworkParams(FixedInfo, &BufLen)) != ERROR_SUCCESS) {
        printf("GetNetworkParams failed. ret = %08x\n", (u_int)ret );
        if (FixedInfo) {
            GlobalFree(FixedInfo);
            FixedInfo = NULL;
        }
        return -1;
    }

    pIPAddr = &(FixedInfo->DnsServerList);
    inet_aton(pIPAddr->IpAddress.String, &tmp_addr);
    *pdns_addr = tmp_addr;
    dns_addr = tmp_addr;
    dns_addr_time = curtime;
    if (FixedInfo) {
        GlobalFree(FixedInfo);
        FixedInfo = NULL;
    }
    return 0;
}

static void winsock_cleanup(void)
{
    WSACleanup();
}

#else

static struct stat dns_addr_stat;

int get_dns_addr(struct in_addr *pdns_addr)
{
    char buff[512];
    char buff2[257];
    FILE *f;
    int found = 0;
    struct in_addr tmp_addr;

    if (dns_addr.s_addr != 0) {
        struct stat old_stat;
        if ((curtime - dns_addr_time) < 1000) {
            *pdns_addr = dns_addr;
            return 0;
        }
        old_stat = dns_addr_stat;
        if (stat("/etc/resolv.conf", &dns_addr_stat) != 0)
            return -1;
        if ((dns_addr_stat.st_dev == old_stat.st_dev)
            && (dns_addr_stat.st_ino == old_stat.st_ino)
            && (dns_addr_stat.st_size == old_stat.st_size)
            && (dns_addr_stat.st_mtime == old_stat.st_mtime)) {
            *pdns_addr = dns_addr;
            return 0;
        }
    }

    f = fopen("/etc/resolv.conf", "r");
    if (!f)
        return -1;

    DEBUG_MISC("IP address of your DNS(s): ");
    while (fgets(buff, 512, f) != NULL) {
        if (sscanf(buff, "nameserver%*[ \t]%256s", buff2) == 1) {
            if (!inet_aton(buff2, &tmp_addr))
                continue;
            /* If it's the first one, set it to dns_addr */
            if (!found) {
                *pdns_addr = tmp_addr;
                dns_addr = tmp_addr;
                dns_addr_time = curtime;
            }
            else
                DEBUG_MISC(", ");
            if (++found > 3) {
                DEBUG_MISC("(more)");
                break;
            }
            else
                DEBUG_MISC("%s", inet_ntoa(tmp_addr));
        }
    }
    fclose(f);
    if (!found)
        return -1;
    return 0;
}

#endif

static uint32_t slirp_get_hostaddr(void *nopaque)
{
    Slirp *slirp = nopaque;

    return slirp->vhost_addr.s_addr;
}

static void slirp_init_once(void)
{
    static int initialized = 0;
#ifdef _WIN32
    WSADATA Data;
#endif

    if (initialized)
        return;
    initialized = 1;

    ioh_queue_init(&slirp_io_handlers);

    slirp_async_op_ctx = async_op_init();

#ifdef _WIN32
    WSAStartup(MAKEWORD(2, 0), &Data);
    atexit(winsock_cleanup);
#endif

#ifdef _WIN32
    slirp_event = WSACreateEvent();
#endif

#ifdef SLIRP_THREADED
    if (slirp_loop_init())
        warnx("slirp_loop_init failed");
#endif


#ifdef _WIN32
    ioh_add_wait_object(&slirp_event, slirp_select_poll, NULL,
                        slirp_wait_objects);
#endif

    loopback_addr.s_addr = htonl(INADDR_LOOPBACK);
}

static void slirp_input_mbuf(struct mbuf *m);
static void slirp_state_save(QEMUFile *f, void *opaque);
static int slirp_state_load(QEMUFile *f, void *opaque, int version_id);

Slirp *slirp_init(int restricted, struct in_addr vnetwork,
                  struct in_addr vnetmask, struct in_addr vhost,
                  const char *vhostname, const char *tftp_path,
                  const char *bootfile, struct in_addr vdhcp_start,
                  struct in_addr vnameserver, void *opaque)
{
    Slirp *slirp = g_malloc0(sizeof(Slirp));

    slirp->log_level = slirp_log_level;

    slirp_init_once();

    slirp->restricted = restricted;

    if_init(slirp);
    ip_init(slirp);

    /* Initialise mbufs *after* setting the MTU */
    m_init(slirp);

    slirp->vnetwork_addr = vnetwork;
    slirp->vnetwork_mask = vnetmask;
    slirp->vhost_addr = vhost;
    if (vhostname)
        pstrcpy(slirp->client_hostname, sizeof(slirp->client_hostname),
                vhostname);
    if (tftp_path)
        slirp->tftp_prefix = g_strdup(tftp_path);
    if (bootfile)
        slirp->bootp_filename = g_strdup(bootfile);
    slirp->vdhcp_startaddr = vdhcp_start;
    slirp->vnameserver_addr = vnameserver;

    slirp->opaque = opaque;

    slirp->nu.opaque = slirp;
    slirp->nu.can_recv = slirp_socket_can_recv;
    slirp->nu.recv = slirp_socket_recv;
    slirp->nu.close = slirp_socket_close;
    slirp->nu.add_wait_object = slirp_add_wait_object;
    slirp->nu.del_wait_object = slirp_del_wait_object;
#ifndef _WIN32
    slirp->nu.add_wait_fd = slirp_add_wait_fd;
    slirp->nu.del_wait_fd = slirp_del_wait_fd;
#endif
    slirp->nu.schedule_bh = slirp_schedule_bh;
    slirp->nu.schedule_bh_permanent = slirp_schedule_bh_permanent;
    slirp->nu.get_hostaddr = slirp_get_hostaddr;

    register_savevm(NULL, "slirp", 0, 13,
                    slirp_state_save, slirp_state_load, slirp);


    QTAILQ_INSERT_TAIL(&slirp_instances, slirp, entry);

    return slirp;
}

void slirp_get_config_option(Slirp *slirp, const char *name, const yajl_val arg)
{
    if (!slirp)
        return;

    if (!strcmp(name, "log_level")) {
        if (YAJL_IS_INTEGER(arg)) {
            slirp_log_level = YAJL_GET_INTEGER(arg);
            slirp->log_level = slirp_log_level;
        } else
            warnx("log_level arg wrong type: expect integer");
    } else if (!strcmp(name, "disable_dhcp")) {
        if (YAJL_IS_TRUE(arg)) {
            slirp->disable_dhcp = 1;
            LOGSLIRP2("dhcp disabled");
        } else if (!YAJL_IS_FALSE(arg)) {
            warnx("disable_dhcp arg wrong type: expect boolean");
        }
    } else if (!strcmp(name, "disable-tcp-time-wait")) {
        if (YAJL_IS_TRUE(arg)) {
            slirp->disable_tcp_time_wait = 1;
            LOGSLIRP("tcp TIME_WATE state disabled");
        } else if (!YAJL_IS_FALSE(arg)) {
            warnx("disable-tcp-time-wait arg wrong type: expect boolean");
        }
    }
}

#ifdef SLIRP_THREADED
void slirp_th_lock(void)
{
#if defined(_WIN32) && defined(SLIRP_TH_DEBUG)
    if (slirp_thid && slirp_thid != GetCurrentThreadId()) {
        LOGSLIRP4("debug: accessing slirp from another thread, thid = %lu",
                (unsigned long) GetCurrentThreadId());
    }
#endif

    critical_section_enter(&slirp_mx);
}

void slirp_th_unlock(void)
{
    critical_section_leave(&slirp_mx);
}

void slirp_mark_deletion(Slirp *slirp)
{
    slirp->mark_deletion = 1;
    ioh_event_set(&slirp_deqin_ev);
}

void slirp_thread_start(void)
{
    slirp_th_unlock();
}
void slirp_thread_exit(void)
{

    if (!slirp_thread)
        return;

    slirp_request_exit = 1;

    ioh_event_set(&slirp_deqin_ev);
    wait_thread(slirp_thread);
    slirp_thread = NULL;
}

void slirp_thread_exit_sync(void)
{

    if (!slirp_thread)
        return;

    slirp_th_lock();
    slirp_exit_now = 1;
    slirp_th_unlock();

    ioh_event_set(&slirp_deqin_ev);
    wait_thread(slirp_thread);
    slirp_thread = NULL;
}
#else
void slirp_th_lock(void) { return ; }
void slirp_th_unlock(void) { return ; }
#endif

void slirp_exit(void)
{

#if defined(SLIRP_THREADED)
    slirp_thread_exit_sync();
#endif

}

void slirp_cleanup(Slirp *slirp)
{
    QTAILQ_REMOVE(&slirp_instances, slirp, entry);

    /* unregister_savevm(NULL, "slirp", slirp); */

    g_free(slirp->tftp_prefix);
    g_free(slirp->bootp_filename);
    g_free(slirp);
}

#define CONN_CANFSEND(so) \
    (((so)->so_state & (SS_FCANTSENDMORE | SS_ISFCONNECTED)) == SS_ISFCONNECTED)
#define CONN_CANFRCV(so) \
    (((so)->so_state & (SS_FCANTRCVMORE | SS_ISFCONNECTED)) == SS_ISFCONNECTED)

#ifndef _WIN32
#define FD_readfds POLLIN
#define FD_writefds POLLOUT
#define FD_xfds POLLERR
#define FD_rderr POLLERR /* XXXPM */
#define FD_closefds 0 /* XXXPM */
#define GET_NETWORK_EVENTS(fd) do { } while(0)
#define DEBUG_NETWORK_EVENTS(fd) do { } while(0)
#define SO_ISSET(so, set) ( so->revents & FD_ ## set )
/* XXXCL needed on unix? */
#define SO_ISERR(so, set) 0

#define update_fdevents(so, _events) do {                       \
        if (so->events != _events) {                            \
            if (so->events)                                     \
                ioh_del_wait_fd(so->s, NULL);                   \
            so->events = _events;                               \
            if (so->events)                                     \
                ioh_add_wait_fd(so->s, so->events,              \
                                slirp_fdevent, so, NULL);       \
        }                                                       \
    } while (0)

#else
#define ERROR_LOG(fmt, ...) error_printf(fmt, ## __VA_ARGS__)

#define POLLIN  0x1
#define POLLOUT 0x4
#define POLLERR 0x8
#define update_fdevents(so, events) do {                                \
        if (!events)                                                    \
           break;                                                       \
        int rc = WSAEventSelect((so)->s, slirp_event, FD_ALL_EVENTS);   \
        if (rc == SOCKET_ERROR) {                                       \
            ERROR_LOG("slirp: WSAEventSelect(%d) failed at %d: error %d\n", \
                      (so)->s, __LINE__, WSAGetLastError());            \
        }                                                               \
    } while(0)

#define GET_NETWORK_EVENTS(fd) do {					\
	int rc = WSAEnumNetworkEvents((fd), slirp_event, &NetworkEvents); \
	if (rc == SOCKET_ERROR) {					\
	    ERROR_LOG("slirp: WSAEnumNetworkEvents(%d) failed at %d: error %d\n", \
		      (fd), __LINE__, WSAGetLastError());		\
	}								\
    } while(0)
#define FD_acceptfds FD_ACCEPT
#define FD_acceptfds_BIT FD_ACCEPT_BIT
#define FD_closefds FD_CLOSE
#define FD_closefds_BIT FD_CLOSE_BIT
#define FD_connectfds FD_CONNECT
#define FD_connectfds_BIT FD_CONNECT_BIT
#define FD_readfds FD_READ
#define FD_readfds_BIT FD_READ_BIT
#define FD_writefds FD_WRITE
#define FD_writefds_BIT FD_WRITE_BIT
#define FD_xfds FD_OOB
#define FD_xfds_BIT FD_OOB_BIT
#define SO_ISSET(so, set) (					\
	(NetworkEvents.lNetworkEvents & FD_ ## set) &&		\
	(NetworkEvents.iErrorCode[FD_ ## set ## _BIT] == 0)	\
	)
#define SO_ISERR(so, set) (					\
	(NetworkEvents.lNetworkEvents & FD_ ## set) &&		\
	(NetworkEvents.iErrorCode[FD_ ## set ## _BIT])		\
	)

#define DEBUG_NETWORK_EVENTS(fd) do {					\
	DEBUG_VERBOSE(							\
	    "NetworkEvents fd %d:%s%s%s%s%s%s%s error:%s%s%s%s%s%s\n", fd \
	    , NetworkEvents.lNetworkEvents ? " event:" : ""		\
	    ,(NetworkEvents.lNetworkEvents & FD_ACCEPT) ? " ACCEPT" : "" \
	    ,(NetworkEvents.lNetworkEvents & FD_CLOSE) ? " CLOSE" : ""	\
	    ,(NetworkEvents.lNetworkEvents & FD_CONNECT) ? " CONNECT" : "" \
	    ,(NetworkEvents.lNetworkEvents & FD_READ) ? " READ" : ""	\
	    ,(NetworkEvents.lNetworkEvents & FD_WRITE) ? " WRITE" : ""	\
	    ,(NetworkEvents.lNetworkEvents & FD_OOB) ? " OOB" : ""	\
	    ,(NetworkEvents.iErrorCode[FD_ACCEPT_BIT]) ? " ACCEPT" : "" \
	    ,(NetworkEvents.iErrorCode[FD_CLOSE_BIT]) ? " CLOSE" : ""	\
	    ,(NetworkEvents.iErrorCode[FD_CONNECT_BIT]) ? " CONNECT" : "" \
	    ,(NetworkEvents.iErrorCode[FD_READ_BIT]) ? " READ" : ""	\
	    ,(NetworkEvents.iErrorCode[FD_WRITE_BIT]) ? " WRITE" : ""	\
	    ,(NetworkEvents.iErrorCode[FD_OOB_BIT]) ? " OOB" : ""	\
	    );								\
    } while (0)
#endif

#ifdef __APPLE__
void slirp_fdevent(void *opaque, int revents)
{
   struct socket *so = (struct socket *) opaque;
   if (!so)
       return;
   so->revents = revents;
   slirp_select_poll(opaque);
}
#endif

void slirp_for_each_instance(int (*callback)(Slirp *slirp, void *opaque),
        void *opaque)
{
    Slirp *slirp, *next_s;

    if (QTAILQ_EMPTY(&slirp_instances))
	return;
    if (!callback)
        return;

    QTAILQ_FOREACH_SAFE(slirp, &slirp_instances, entry, next_s)
        if (callback(slirp, opaque))
            break;
}

void slirp_select_fill(int *timeout)
{
    Slirp *slirp;
    struct socket *so, *so_next;
    int timeout_ms;

    if (QTAILQ_EMPTY(&slirp_instances))
	return;

    /*
     * First, TCP sockets
     */
    do_slowtimo = 0;

    slirp_stats_sock_start();
    QTAILQ_FOREACH(slirp, &slirp_instances, entry) {
#ifdef SLIRP_THREADED
    if (slirp->mark_deletion)
        continue;
#endif
	/*
	 * *_slowtimo needs calling if there are IP fragments
	 * in the fragment queue, or there are TCP connections active
	 */
	do_slowtimo |= !LIST_EMPTY(&slirp->tcb);
#ifdef SLIRP_SUPPORT_IPREASS
	do_slowtimo |= !RLIST_EMPTY(&slirp->ipq, ipq_list);
#endif

	/* always add the ICMP socket */
	/* TODO */

	LIST_FOREACH_SAFE(so, &slirp->tcb, entry, so_next) {
            int fdevents = 0;

            slirp_stats_tcp_sock(so);
	    /*
	     * See if we need a tcp_fasttimo
	     */
	    if (time_fasttimo == 0 && so->so_tcpcb &&
		so->so_tcpcb->t_flags & TF_DELACK)
		time_fasttimo = curtime; /* Flag when we want a fasttimo */

	    /*
	     * NOFDREF can include still connecting to local-host,
	     * newly socreated() sockets etc. Don't want to select these.
	     */
	    if (so->so_state & SS_NOFDREF || so->s == -1)
               continue;

	    /*
	     * Set for reading sockets which are accepting
	     */
	    if (so->so_state & SS_FACCEPTCONN) {
               update_fdevents(so, POLLIN);
               continue;
	    }

	    /*
	     * Set for writing sockets which are connecting
	     */
	    if (so->so_state & SS_ISFCONNECTING) {
               update_fdevents(so, POLLOUT);
               continue;
	    }

	    /*
	     * Set for writing if we are connected, can send more, and
	     * we have something to send
	     */
	    if (CONN_CANFSEND(so) && so->so_rcv.sb_cc)
                fdevents |= POLLOUT;

	    /*
	     * Set for reading (and urgent data) if we are connected, can
	     * receive more, and we have room for it XXX /2 ?
	     */
	    if (CONN_CANFRCV(so) &&
		(so->so_snd.sb_cc < (so->so_snd.sb_datalen/2))
#ifdef _WIN32
		&& !(so->so_state & SS_ISFCONNECTING)
#endif
		) {
#ifdef _WIN32
                /* if so->so_snd was full, reenable WSAEventSelect by a 0 bytes recv */
                if (so->so_snd_full) {
                    so->so_snd_full = 0;
                    recv(so->s, 0, 0, 0);
                }
#endif
                fdevents |= POLLIN | POLLERR;
            }

            /* if (fdevents) */
                update_fdevents(so, fdevents);
	}

	/*
	 * UDP sockets
	 */
	LIST_FOREACH_SAFE(so, &slirp->udb, entry, so_next) {
	    /*
	     * See if it's timed out
	     */
	    if (so->so_expire) {
		if (so->so_expire <= curtime) {
		    /* XXX so->so_timeout hook */
		    udp_detach(so);
		    continue;
		} else
		    do_slowtimo = 1; /* Let socket expire */
	    }

	    /*
	     * When UDP packets are received from over the
	     * link, they're sendto()'d straight away, so
	     * no need for setting for writing
	     * Limit the number of packets queued by this session
	     * to 4.  Note that even though we try and limit this
	     * to 4 packets, the session could have more queued
	     * if the packets needed to be fragmented
	     * (XXX <= 4 ?)
	     */
	    if ((so->so_state & SS_ISFCONNECTED) && so->so_queued <= 4)
                update_fdevents(so, POLLIN);
            else
                update_fdevents(so, 0);
	}

	/*
	 * ICMP sockets
	 */
	LIST_FOREACH_SAFE(so, &slirp->icmb, entry, so_next) {
	    /*
	     * See if it's timed out
	     */
	    if (so->so_expire) {
		if (so->so_expire <= curtime) {
		    icmp_detach(so);
		    continue;
		} else
		    do_slowtimo = 1; /* Let socket expire */
	    }

	    if (so->so_state & SS_ISFCONNECTED)
                update_fdevents(so, POLLIN);
            else
                update_fdevents(so, 0);
	}
    }
    slirp_stats_sock_end();

    if (time_fasttimo)
	timeout_ms = 200 - (curtime - time_fasttimo);
    else if (do_slowtimo)
	timeout_ms = 500 - (curtime - last_slowtimo);
    else
	timeout_ms = 3600 * 1000;
    if (timeout_ms < 0)
	timeout_ms = 0;

    if (*timeout > timeout_ms)
	*timeout = timeout_ms;
}

void slirp_check_timeout(void)
{
    Slirp *slirp;
    int timofast, timoslow;

    if (QTAILQ_EMPTY(&slirp_instances))
        return;

    curtime = get_clock_ms(vm_clock);

    timofast = (time_fasttimo && ((curtime - time_fasttimo) >= 199));
    if (timofast)
	time_fasttimo = 0;
    timoslow = (do_slowtimo && ((curtime - last_slowtimo) >= 499));
    if (timoslow) {
	do_slowtimo = 0;
	last_slowtimo = curtime;
    }

    if (!timofast && !timoslow)
	return;

    QTAILQ_FOREACH(slirp, &slirp_instances, entry) {
#ifdef SLIRP_THREADED
    if (slirp->mark_deletion)
        continue;
#endif
	/*
	 * See if anything has timed out
	 */
	if (timofast)
	    tcp_fasttimo(slirp);
	if (timoslow) {
#ifdef SLIRP_SUPPORT_IPREASS
	    ip_reass_timo(slirp);
#endif  /* SLIRP_SUPPORT_IPREASS */
	    tcp_slowtimo(slirp);
	}
    }
}

void slirp_select_poll(void *opaque)
{
    Slirp *slirp;
    struct socket *so, *so_next, *sel_so;
    int ret;
#ifdef _WIN32
    WSANETWORKEVENTS NetworkEvents;
#endif

    sel_so = (struct socket *)opaque;

    slirp_th_lock();
    if (QTAILQ_EMPTY(&slirp_instances))
        goto out;

    slirp_check_timeout();

    QTAILQ_FOREACH(slirp, &slirp_instances, entry) {
#ifdef SLIRP_THREADED
    if (slirp->mark_deletion)
        continue;
#endif

    /*
     * Check TCP sockets
     */
    LIST_FOREACH_SAFE(so, &slirp->tcb, entry, so_next) {

        if (sel_so && sel_so != so)
            continue;

        /*
         * FD_ISSET is meaningless on these sockets
         * (and they can crash the program)
         */
        if (so->so_state & SS_NOFDREF || so->s == -1)
            continue;

        GET_NETWORK_EVENTS(so->s);
        DEBUG_NETWORK_EVENTS(so->s);

        /*
         * Check for URG data
         * This will soread as well, so no need to
         * test for readfds below if this succeeds
         */
        if (SO_ISSET(so, xfds)
#ifdef _WIN32
            && !SO_ISSET(so, closefds)
#endif
            )
            sorecvoob(so);
        /*
         * Check sockets for reading
         */
        else if (SO_ISSET(so, readfds)
#ifdef _WIN32
                 || SO_ISSET(so, acceptfds)
#endif
            ) {
#ifdef _WIN32
            if (SO_ISSET(so, connectfds)) {
                /* ZZZ slirpConnectOrWrite */
                debug_printf("read connect\n");
                if (so->so_state & SS_ISFCONNECTING) {
                    /* Connected */
                    so->so_state &= ~SS_ISFCONNECTING;
                    tcp_input((struct mbuf *)NULL, sizeof(struct ip), so);
                }
            }
#endif
            /*
             * Check for incoming connections
             */
            if (so->so_state & SS_FACCEPTCONN) {
                tcp_connect(so);
                if (!SO_ISSET(so, closefds))
                    continue;
            } /* else */
            ret = soread(so);

            /* Output it if we read something */
            if (ret > 0)
                tcp_output(sototcpcb(so));
        }

#ifdef _WIN32
        /* On Windows: mostly seen WSAECONNABORTED, but
         * reflect all error-close events into the VM as a RST
         * packet. */
        if (SO_ISERR(so, closefds)) {
            if (so->so_closing_cb && !so->so_closing_cb(so))
                continue;
            sofcantrcvmore(so);
            sototcpcb(so)->t_flags |= TF_RST;
            tcp_sockclosed(sototcpcb(so));
            tcp_close(sototcpcb(so));
            continue;
        }
#endif

        /*
         * Check for FD_CLOSE events.  Flush any pending data.
         * Socket is actually marked closed in soread().
         */
        if (SO_ISSET(so, closefds) /* || (so->so_close == 1) */) {
            /*
             * drain the socket
             */
            while ((ret = soread(so)) > 0)
                tcp_output(sototcpcb(so));

#if 0
            /* XXXCL so_close: see comments in vbox slirp tcp_subr.c */
            /* mark the socket for termination _after_ it was
             * drained */
            so->so_close = 1;
#endif

#if 0 /* XXXPM */
            /* No idea about Windows but on Posix, POLLHUP
             * means that we can't send more.  Actually in the
             * specific error scenario, POLLERR is set as
             * well. */
#ifndef _WIN32
            if (SO_ISSET(so, rderr))
                sofcantsendmore(so);
#endif
#endif
            continue;
        }

        /*
         * Check sockets for writing
         */
        if (SO_ISSET(so, writefds)
#ifdef _WIN32
            || SO_ISSET(so, connectfds)
#endif
            ) {
            /*
             * Check for non-blocking, still-connecting sockets
             */
            if (so->so_state & SS_ISFCONNECTING) {
                /* Connected */
                so->so_state &= ~SS_ISFCONNECTING;

                sototcpcb(so)->syn_ack_time = get_clock_ms(vm_clock);
                LOGSLIRP2("conn: %d Ack to syn from port %04x @ %s cost %" PRIu64 " ms",
                     so->s, ntohs(so->so_fport), inet_ntoa(so->so_faddr),
                     sototcpcb(so)->syn_ack_time - sototcpcb(so)->syn_time);
                LOGSLIRP2("slirp stats: #tcp sockets %u",
                    so->slirp->tcp_sockets);

                ret = send(so->s, (const void *) &ret, 0, 0);
                if (ret < 0) {
                    /* XXXXX Must fix, zero bytes is a NOP */
                    if (errno == EAGAIN || errno == EWOULDBLOCK ||
                        errno == EINPROGRESS || errno == ENOTCONN)
                        continue;

                    /* else failed */
                    so->so_state &= SS_PERSISTENT_MASK;
                    so->so_state |= SS_NOFDREF;
                }
                /* else so->so_state &= ~SS_ISFCONNECTING; */

                /*
                 * Continue tcp_input
                 */
                tcp_input((struct mbuf *)NULL, sizeof(struct ip), so);
                /* continue; */
            } else
                ret = sowrite(so);
            /*
             * XXXXX If we wrote something (a lot), there
             * could be a need for a window update.
             * In the worst case, the remote will send
             * a window probe to get things going again
             */
        }
#ifdef _WIN32
        else if (so->so_write_needed) {
            ret = sowrite(so);
        }
        so->so_write_needed = 0;
#endif

        /*
         * Probe a still-connecting, non-blocking socket
         * to check if it's still alive
         */
#ifdef PROBE_CONN
        if (so->so_state & SS_ISFCONNECTING) {
            ret = qemu_recv(so->s, &ret, 0, 0);
            if (ret < 0) {
                /* XXX */
                if (errno == EAGAIN || errno == EWOULDBLOCK ||
                    errno == EINPROGRESS || errno == ENOTCONN)
                    continue; /* Still connecting, continue */

                /* else failed */
                so->so_state &= SS_PERSISTENT_MASK;
                so->so_state |= SS_NOFDREF;

                /* tcp_input will take care of it */
            } else {
                ret = send(so->s, &ret, 0, 0);
                if (ret < 0) {
                    /* XXX */
                    if (errno == EAGAIN || errno == EWOULDBLOCK ||
                        errno == EINPROGRESS || errno == ENOTCONN)
                        continue;
                    /* else failed */
                    so->so_state &= SS_PERSISTENT_MASK;
                    so->so_state |= SS_NOFDREF;
                } else
                    so->so_state &= ~SS_ISFCONNECTING;
            }
            tcp_input((struct mbuf *)NULL, sizeof(struct ip), so);
        } /* SS_ISFCONNECTING */
#endif
    }

    /*
     * Now UDP sockets.
     * Incoming packets are sent straight away, they're not buffered.
     * Incoming UDP data isn't buffered either.
     */
    LIST_FOREACH_SAFE(so, &slirp->udb, entry, so_next) {
        if (sel_so && sel_so != so)
            continue;

        if (so->s == -1)
            continue;

        GET_NETWORK_EVENTS(so->s);
        DEBUG_NETWORK_EVENTS(so->s);

        if (SO_ISSET(so, readfds))
            sorecvfrom(so);
    }

    /*
     * Check incoming ICMP relies.
     */
    LIST_FOREACH_SAFE(so, &slirp->icmb, entry, so_next) {
        if (sel_so && sel_so != so)
            continue;

        if (so->s == -1)
            continue;

        GET_NETWORK_EVENTS(so->s);
        DEBUG_NETWORK_EVENTS(so->s);

        if (SO_ISSET(so, readfds))
            icmp_receive(so);
    }

	/*
	 * See if we can start outputting
	 */
	if (slirp->if_queued)
	    if_start(slirp);
    }

out:
    slirp_th_unlock();
}



static void arp_input(struct mbuf *m_in)
{
    Slirp *slirp = m_in->slirp;
    struct arphdr *ah = (struct arphdr *) (mtod(m_in, uint8_t *) + ETH_HLEN);
    struct mbuf *m;
    uint8_t *arp_reply;
    struct ethhdr *reh;
    struct arphdr *rah;
    int ar_op;

    ar_op = ntohs(ah->ar_op);
    switch(ar_op) {
    case ARPOP_REQUEST:
        if (ah->ar_tip == ah->ar_sip) {
            /* Gratuitous ARP */
            arp_table_add(slirp, ah->ar_sip, ah->ar_sha);
            goto out;
        }

        if ((ah->ar_tip & slirp->vnetwork_mask.s_addr) ==
            slirp->vnetwork_addr.s_addr) {
            if (ah->ar_tip == slirp->vnameserver_addr.s_addr ||
                ah->ar_tip == slirp->vhost_addr.s_addr)
                goto arp_ok;
	    /* XXXCL maybe connection filtering */
            goto out;
        arp_ok:
            m = m_get(slirp);
            if (!m)
                goto out;
            m->m_len = max(ETH_HLEN + sizeof(struct arphdr), 64);
            assert(m->m_size >= m->m_len);
            arp_reply = (uint8_t*) m->m_data;
            reh = (struct ethhdr *)arp_reply;
            rah = (struct arphdr *)(arp_reply + ETH_HLEN);

            arp_table_add(slirp, ah->ar_sip, ah->ar_sha);

            /* ARP request for alias/dns mac address */
            memcpy(reh->h_dest, mtod(m_in, uint8_t *) + ETH_ALEN, ETH_ALEN);
            memcpy(reh->h_source, special_ethaddr, ETH_ALEN - 4);
            memcpy(&reh->h_source[2], &ah->ar_tip, 4);
            reh->h_proto = htons(ETH_P_ARP);

            rah->ar_hrd = htons(1);
            rah->ar_pro = htons(ETH_P_IP);
            rah->ar_hln = ETH_ALEN;
            rah->ar_pln = 4;
            rah->ar_op = htons(ARPOP_REPLY);
            memcpy(rah->ar_sha, reh->h_source, ETH_ALEN);
            rah->ar_sip = ah->ar_tip;
            memcpy(rah->ar_tha, ah->ar_sha, ETH_ALEN);
            rah->ar_tip = ah->ar_sip;
            slirp_mbuf_output(slirp->opaque, m, 0);
        }
        break;
    case ARPOP_REPLY:
        arp_table_add(slirp, ah->ar_sip, ah->ar_sha);
        break;
    default:
        break;
    }

out:
    m_free(m_in);
}

#ifdef SLIRP_THREADED
static void slirp_queue_input(struct mbuf *m)
{
    critical_section_enter(&queue_mx);
    RLIST_INSERT_TAIL(&in_mbufq, m, m_list);
    inq_n++;
    if (inq_n > slirp_inq_max)
        slirp_inq_max = inq_n;
    critical_section_leave(&queue_mx);
    ioh_event_set(&slirp_deqin_ev);
}

static void slirp_dequeue_input(void *unused)
{
    struct mbuf *m;
    for (;;) {
       critical_section_enter(&queue_mx);
       if (RLIST_EMPTY(&in_mbufq, m_list)) {
            critical_section_leave(&queue_mx);
            break;
       }
       m = RLIST_FIRST(&in_mbufq, m_list);
       RLIST_REMOVE(m, m_list);
       inq_n--;
       critical_section_leave(&queue_mx);

       slirp_th_lock();
       slirp_input_mbuf(m);
       slirp_th_unlock();
    }
}

void slirp_dequeue_output(void *unused)
{
    struct mbuf *m;
    for (;;) {
        critical_section_enter(&queue_mx);
        if (RLIST_EMPTY(&out_mbufq, m_list)) {
            critical_section_leave(&queue_mx);
            break;
        }
        m = RLIST_FIRST(&out_mbufq, m_list);
        RLIST_REMOVE(m, m_list);
        outq_n--;
        critical_section_leave(&queue_mx);
        slirp_mbuf_output(m->slirp->opaque, m, 1);
    }
}

#if defined(_WIN32)
static DWORD WINAPI slirp_thread_run(void *unused)
{
    int timeout, wait_time;
    int64_t delay_ms = 0;
    Slirp *slirp, *next_s;
    slirp_thid = GetCurrentThreadId();
    slirp_pid = GetProcessIdOfThread(slirp_thread);

    slirp_th_lock();
    LOGSLIRP2("slirp thread running, thread id = %lu ( pid = %lu )", (unsigned long) slirp_thid, slirp_pid);

    for (;;) {

        if (slirp_request_exit && QTAILQ_EMPTY(&slirp_instances))
            break;

        timeout = DEFAULT_TIMEOUT_MS;
        slirp_select_fill(&timeout);
        slirp_th_unlock();

        if (delay_ms) {
            delay_ms = get_clock_ms(vm_clock) - delay_ms;
            delay_ms -= wait_time;

            if (delay_ms > SLIRP_LOOP_DELAY_WARN)
                LOGSLIRP("%s: warning! blocking slirp thread? latency %" PRIi64 "ms",
                        __FUNCTION__, delay_ms);
        }
        delay_ms = get_clock_ms(vm_clock);
        ioh_wait_for_objects(&slirp_io_handlers, slirp_wait_objects, slirp_active_timers,
                &timeout, &wait_time);

        if (slirp_exit_now)
            goto out;

        slirp_th_lock();
        QTAILQ_FOREACH_SAFE(slirp, &slirp_instances, entry, next_s) {
            if (slirp->mark_deletion)
                slirp_cleanup(slirp);
        }

        async_op_process(slirp_async_op_ctx);
        slirp_check_timeout();
    }

    slirp_th_unlock();

out:
    debug_printf("slirp thread exit\n");
    ExitThread(0);
    return 0;
}
#endif

int slirp_loop_init(void)
{
    RLIST_INIT(&in_mbufq, m_list);
    RLIST_INIT(&out_mbufq, m_list);
    critical_section_init(&slirp_mx);
    critical_section_init(&queue_mx);

    timers_init(slirp_active_timers);
    slirp_wait_objects = &_slirp_wait_objects;
    ioh_init_wait_objects(slirp_wait_objects);
    ioh_event_init(&slirp_deqin_ev);
    ioh_event_init(&slirp_deqout_ev);
    ioh_add_wait_object(&slirp_deqin_ev, slirp_dequeue_input, NULL,
                        slirp_wait_objects);
    ioh_add_wait_object(&slirp_deqout_ev, slirp_dequeue_output, NULL, NULL);

    slirp_th_lock(); /* make slirp thread wait for start moment */
    if (create_thread(&slirp_thread, slirp_thread_run, NULL) < 0) {
        warnx("%s: cannot create slirp thread", __FUNCTION__);
        return -1;
    }
    elevate_thread(slirp_thread);
    return 0;
}
#endif

static void
slirp_input_mbuf(struct mbuf *m)
{
    int proto;

    /* m->m_len >= ETH_HLEN already checked */
    proto = ntohs(*(uint16_t *)(mtod(m, uint8_t*) + 12));

    switch(proto) {
    case ETH_P_ARP:
        arp_input(m);
        break;
    case ETH_P_IP:
        m_adj(m, ETH_HLEN);
        ip_input(m);
        break;
    default:
        break;
    }
}

void slirp_input(Slirp *slirp, const uint8_t *pkt, int pkt_len)
{
    struct mbuf *m;
    int proto;

    if (pkt_len < ETH_HLEN)
        return;

    proto = ntohs(*(uint16_t *)(pkt + 12));
    if (proto != ETH_P_ARP && proto != ETH_P_IP)
        return;

    m = m_get(slirp);
    if (!m)
        return;
    if (M_FREEROOM(m) < pkt_len)
        m_inc(m, pkt_len);
    m->m_len = pkt_len;
    memcpy(m->m_data, pkt, pkt_len);

#ifdef SLIRP_THREADED
     slirp_queue_input(m);
#else
     slirp_input_mbuf(m);
#endif
}

void slirp_mbuf_output(void *opaque, struct mbuf *m, int send)
{
#ifdef SLIRP_THREADED
    if (!send) {
        critical_section_enter(&queue_mx);
        RLIST_INSERT_TAIL(&out_mbufq, m, m_list);
        outq_n++;
        if (outq_n > slirp_outq_max)
            slirp_outq_max = outq_n;
        critical_section_leave(&queue_mx);
        ioh_event_set(&slirp_deqout_ev);
        return;
    }
#endif
    slirp_output(opaque, (const uint8_t*)m->m_data, m->m_len);
    m_free(m);
}

/* Output the IP packet to the ethernet device. Returns 0 if the packet must be
 * re-queued.
 */
int if_encap(Slirp *slirp, struct mbuf *ifm)
{
    struct ethhdr *eh;
    uint8_t ethaddr[ETH_ALEN];
    const struct ip *iph = (const struct ip *)ifm->m_data;

    if ((ifm->m_size - M_ROOM(ifm)) < ETH_HLEN) {
	/* Expect ETH_HLEN room for the eth header before the packet data. */
	DEBUG_BREAK();
	m_free(ifm);
	return 1;
    }

    if (!arp_table_search(slirp, iph->ip_dst.s_addr, ethaddr)) {
        struct mbuf *m;
        uint8_t *arp_req;
        struct ethhdr *reh;
        struct arphdr *rah;

        if (!ifm->arp_requested) {
            m = m_get(slirp);
            if (!m)
                return 0;
            m->m_len = ETH_HLEN + sizeof(struct arphdr);
            assert(m->m_size >= m->m_len);
            arp_req = (uint8_t*) m->m_data;
            reh = (struct ethhdr *)arp_req;
            rah = (struct arphdr *)(arp_req + ETH_HLEN);

            /* If the client addr is not known, send an ARP request */
            memset(reh->h_dest, 0xff, ETH_ALEN);
            memcpy(reh->h_source, special_ethaddr, ETH_ALEN - 4);
            memcpy(&reh->h_source[2], &slirp->vhost_addr, 4);
            reh->h_proto = htons(ETH_P_ARP);
            rah->ar_hrd = htons(1);
            rah->ar_pro = htons(ETH_P_IP);
            rah->ar_hln = ETH_ALEN;
            rah->ar_pln = 4;
            rah->ar_op = htons(ARPOP_REQUEST);

            /* source hw addr */
            memcpy(rah->ar_sha, special_ethaddr, ETH_ALEN - 4);
            memcpy(&rah->ar_sha[2], &slirp->vhost_addr, 4);

            /* source IP */
            rah->ar_sip = slirp->vhost_addr.s_addr;

            /* target hw addr (none) */
            memset(rah->ar_tha, 0, ETH_ALEN);

            /* target IP */
            rah->ar_tip = iph->ip_dst.s_addr;
            slirp->client_ipaddr = iph->ip_dst;
            slirp_mbuf_output(slirp->opaque, m, 0);
            ifm->arp_requested = true;

            /* Expire request and drop outgoing packet after 1 second */
            ifm->expiration_date = get_clock_ms(vm_clock) + 1000;
        }
        return 0;
    }

    ifm->m_data -= ETH_HLEN;
    ifm->m_len += ETH_HLEN;

    eh = mtod(ifm, struct ethhdr *);

    memcpy(eh->h_dest, ethaddr, ETH_ALEN);
    memcpy(eh->h_source, special_ethaddr, ETH_ALEN - 4);
    /* XXX: not correct */
    memcpy(&eh->h_source[2], &slirp->vhost_addr, 4);
    eh->h_proto = htons(ETH_P_IP);

    slirp_mbuf_output(slirp->opaque, ifm, 0);

    return 1;
}

/* Drop host forwarding rule, return 0 if found. */
int slirp_remove_hostfwd(Slirp *slirp, int is_udp, struct in_addr host_addr,
                         int host_port)
{
    struct socket *so;
    struct sockaddr_in addr;
    int port = htons(host_port);
    socklen_t addr_len;

    LIST_FOREACH(so, is_udp ? &slirp->udb : &slirp->tcb, entry) {
        addr_len = sizeof(addr);
        if ((so->so_state & SS_HOSTFWD) &&
            getsockname(so->s, (struct sockaddr *)&addr, &addr_len) == 0 &&
            addr.sin_addr.s_addr == host_addr.s_addr &&
            addr.sin_port == port) {
            close(so->s);
            sofree(so);
            return 0;
        }
    }

    return -1;
}

int slirp_add_hostfwd(Slirp *slirp, int is_udp, struct in_addr host_addr,
                      int host_port, struct in_addr guest_addr, int guest_port)
{
    if (!guest_addr.s_addr)
        guest_addr = slirp->vdhcp_startaddr;
    if (is_udp) {
        if (!udp_listen(slirp, host_addr.s_addr, htons(host_port),
                        guest_addr.s_addr, htons(guest_port), SS_HOSTFWD))
            return -1;
    } else {
        if (!tcp_listen(slirp, host_addr.s_addr, htons(host_port),
                        guest_addr.s_addr, htons(guest_port), SS_HOSTFWD))
            return -1;
    }
    return 0;
}

void *
slirp_add_hostfwd_pipe(Slirp *slirp, int is_udp, void *host_pipe_chr,
		       struct in_addr host_addr, int host_port,
		       struct in_addr guest_addr, int guest_port,
                       int close_reconnect, int close_on_retry)
{
    void *opaque = NULL;

    if (!guest_addr.s_addr)
        guest_addr = slirp->vdhcp_startaddr;
    if (is_udp)
	warnx("udp hostfwd not supported");
    else
	opaque = tcp_listen_pipe(slirp, host_pipe_chr,
				 host_addr.s_addr, htons(host_port),
				 guest_addr.s_addr, htons(guest_port),
				 SS_HOSTFWD |
                                    (close_reconnect ? 0 : SS_FWDCLOSE) |
                                    (close_on_retry ? SS_CLOSERETRY : 0));
                                     /* SS_FWDCLOSE set so that the pipe is closed
                                     when guest (tcp part) closes the connection */
                                     /* SS_CLOSERETRY set so that the pipe is closed
                                      even while retrying to connect to guest */

    return opaque;
}

void *
slirp_add_vmfwd(Slirp *slirp, int is_udp, void *host_chr,
                struct in_addr host_addr, int host_port,
                struct in_addr vm_addr, int vm_port, uint64_t byte_limit)
{
    void *opaque = NULL;

    if (!vm_addr.s_addr)
        vm_addr = slirp->vdhcp_startaddr;
    if (is_udp)
	opaque = udp_vmfwd_add(slirp, host_chr, NULL,
                               host_addr, htons(host_port),
                               vm_addr, htons(vm_port), byte_limit);
    else
        warnx("tcp vmfwd not supported");

    return opaque;
}

void *
slirp_add_vmfwd_service(Slirp *slirp, int is_udp,
                        void *service_open, void *service_close,
                        yajl_val service_config,
                        struct in_addr host_addr, int host_port,
                        struct in_addr vm_addr, int vm_port, uint64_t byte_limit)
{
    void *opaque = NULL;

    if (!vm_addr.s_addr)
        vm_addr = slirp->vdhcp_startaddr;
    if (is_udp)
        opaque = udp_vmfwd_add_service(slirp, service_open, service_close,
                                       service_config,
                                       host_addr, htons(host_port),
                                       vm_addr, htons(vm_port), byte_limit);
    else
        opaque = tcp_vmfwd_add_service(slirp, service_open, service_close,
                                       service_config,
                                       host_addr, htons(host_port),
                                       vm_addr, htons(vm_port));

    return opaque;
}

ssize_t
slirp_send(struct socket *so, const void *buf, size_t len, int flags)
{
    if (so->s == -1 && so->chr)
    	return qemu_chr_fe_write(so->chr, buf, len);

    return send(so->s, buf, len, flags);
}

/* We do not check here whether there is actually room available, because
   the chr_event function must check it anyway */
void slirp_buffer_change(struct socket *so)
{
    if (so->s == -1 && so->chr)
        qemu_chr_send_event_async(so->chr, CHR_EVENT_BUFFER_CHANGE);
}

#if 0
static struct socket *
slirp_find_ctl_socket(Slirp *slirp, struct in_addr guest_addr, int guest_port)
{
    struct socket *so;

    LIST_FOREACH(so, &slirp->tcb, entry)
        if (so->so_faddr.s_addr == guest_addr.s_addr &&
            htons(so->so_fport) == guest_port)
            return so;
    return NULL;
}

size_t
slirp_socket_can_recv(Slirp *slirp, struct in_addr guest_addr,
		      int guest_port)
{
    struct iovec iov[2];
    struct socket *so;

    so = slirp_find_ctl_socket(slirp, guest_addr, guest_port);

    if (!so || so->so_state & SS_NOFDREF)
	return 0;

    if (!CONN_CANFRCV(so) || so->so_snd.sb_cc >= (so->so_snd.sb_datalen / 2))
	return 0;

    return sopreprbuf(so, iov, NULL);
}

void
slirp_socket_recv(Slirp *slirp, struct in_addr guest_addr, int guest_port,
		  const uint8_t *buf, int size)
{
    int ret;
    struct socket *so = slirp_find_ctl_socket(slirp, guest_addr, guest_port);

    if (!so)
        return;

    ret = soreadbuf(so, (const char *)buf, size);

    if (ret > 0)
        tcp_output(sototcpcb(so));
}
#else
static void
slirp_hfwd_connect(struct socket *so)
{
    struct tcpcb *tp;

    if (so->so_state & SS_INCOMING)
        return;

    so->so_state |= SS_INCOMING;

    so->so_iptos = 0;
    tp = sototcpcb(so);

    tcp_mss(sototcpcb(so), 0);

    tcp_template(tp);

    tp->t_state = TCPS_SYN_SENT;
    tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_INIT;
    tp->iss = so->slirp->tcp_iss;
    so->slirp->tcp_iss += TCP_ISSINCR / 2;
    tcp_sendseqinit(tp);
    tcp_output(tp);
}

static void
slirp_hfwd_connect_cb(void *opaque)
{
    slirp_hfwd_connect(opaque);
}

size_t
slirp_socket_can_recv(void *opaque)
{
    struct iovec iov[2];
    struct socket *so = opaque;
    int ret = 0;

    slirp_th_lock();

    if (so && so->so_type == IPPROTO_UDP) {
        ret = udp_can_output(so);
        goto out;
    }

    if (!so || so->so_state & SS_NOFDREF)
        goto out;

    if ((so->so_state & SS_HOSTFWD) && !(so->so_state & SS_INCOMING)) {
        if (!so->hfwd_connect_try) {
            so->hfwd_connect_try = 1;
            slirp_hfwd_connect(so);
        } else if (!so->hfwd_connect_timer) {
            so->hfwd_connect_timer = slirp_new_vm_timer(HFWD_CONNECT_DELAY_MS, slirp_hfwd_connect_cb, so);
        }
    }

    if (!CONN_CANFRCV(so) || so->so_snd.sb_cc >= (so->so_snd.sb_datalen / 2))
        goto out;

    ret = sopreprbuf(so, iov, NULL);

out:
    slirp_th_unlock();
    return ret;
}

void
slirp_socket_recv(void *opaque, const uint8_t *buf, int size)
{
    int ret;
    struct socket *so = opaque;

    if (!so)
        return;

    slirp_th_lock();
    if (so->so_type == IPPROTO_UDP) {
        udp_respond(so, buf, size);
        goto out;
    }
    ret = soreadbuf(so, (const char *)buf, size);

    if (ret > 0)
        tcp_output(sototcpcb(so));
out:
    slirp_th_unlock();
}

void
slirp_socket_send(void *opaque)
{
    struct socket *so = opaque;

    if (!so)
        return;

    slirp_th_lock();
    /* ret = */ sowrite(so);
    slirp_th_unlock();
}

void
slirp_socket_close(void *opaque)
{
    struct socket *so = opaque;

    if (!so)
        return;

    slirp_th_lock();
    if ((so->so_state & SS_HOSTFWD) && !(so->so_state & SS_INCOMING))
        goto out;
    if (!sototcpcb(so))
        goto out;
    if (so->so_closing_cb && !so->so_closing_cb(so))
        goto out;

    so->so_state &= ~SS_INCOMING;

    sofcantrcvmore(so);
    if ((so->so_state & SS_HOSTFWD) && !(so->so_state & SS_FWDCLOSE))
        tcp_drop(sototcpcb(so), 0);
    else
        tcp_sockclosed(sototcpcb(so));

out:
    slirp_th_unlock();
}

static int slirp_add_wait_object(void *sopaque, ioh_event *event, WaitObjectFunc *func, void *opaque)
{
    return ioh_add_wait_object(event, func, opaque, slirp_wait_objects);
}

static void slirp_del_wait_object(void *sopaque, ioh_event *event)
{
    ioh_del_wait_object(event, slirp_wait_objects);
}

#ifndef _WIN32
int slirp_add_wait_fd(void *sopaque, int fd, int events, WaitObjectFunc2 *func2, void *opaque)
{
    return ioh_add_wait_fd(fd, events, func2, opaque, slirp_wait_objects);
}

void slirp_del_wait_fd(void *sopaque, int fd)
{
    ioh_del_wait_fd(fd, slirp_wait_objects);
}
#endif
#endif

static void
slirp_sbuf_save(QEMUFile *f, struct sbuf *sbuf)
{
    uint32_t off;

    qemu_put_be32(f, sbuf->sb_cc);
    qemu_put_be32(f, sbuf->sb_datalen);
    off = (uint32_t)(sbuf->sb_wptr - sbuf->sb_data);
    qemu_put_be32(f, off);
    off = (uint32_t)(sbuf->sb_rptr - sbuf->sb_data);
    qemu_put_be32(f, off);
    qemu_put_buffer(f, (unsigned char*)sbuf->sb_data, sbuf->sb_datalen);
}

static void slirp_tcp_save(QEMUFile *f, struct tcpcb *tp)
{
    int i;

    qemu_put_sbe16(f, tp->t_state);
    for (i = 0; i < TCPT_NTIMERS; i++)
        qemu_put_sbe16(f, tp->t_timer[i]);
    qemu_put_sbe16(f, tp->t_rxtshift);
    qemu_put_sbe16(f, tp->t_rxtcur);
    qemu_put_sbe16(f, tp->t_dupacks);
    qemu_put_be16(f, tp->t_maxseg);
    qemu_put_sbyte(f, tp->t_force);
    qemu_put_be16(f, tp->t_flags);
    qemu_put_be32(f, tp->snd_una);
    qemu_put_be32(f, tp->snd_nxt);
    qemu_put_be32(f, tp->snd_up);
    qemu_put_be32(f, tp->snd_wl1);
    qemu_put_be32(f, tp->snd_wl2);
    qemu_put_be32(f, tp->iss);
    qemu_put_be32(f, tp->snd_wnd);
    qemu_put_be32(f, tp->rcv_wnd);
    qemu_put_be32(f, tp->rcv_nxt);
    qemu_put_be32(f, tp->rcv_up);
    qemu_put_be32(f, tp->irs);
    qemu_put_be32(f, tp->rcv_adv);
    qemu_put_be32(f, tp->snd_max);
    qemu_put_be32(f, tp->snd_cwnd);
    qemu_put_be32(f, tp->snd_ssthresh);
    qemu_put_sbe16(f, tp->t_idle);
    qemu_put_sbe16(f, tp->t_rtt);
    qemu_put_be32(f, tp->t_rtseq);
    qemu_put_sbe16(f, tp->t_srtt);
    qemu_put_sbe16(f, tp->t_rttvar);
    qemu_put_be16(f, tp->t_rttmin);
    qemu_put_be32(f, tp->max_sndwnd);
    qemu_put_byte(f, tp->t_oobflags);
    qemu_put_byte(f, tp->t_iobc);
    qemu_put_sbe16(f, tp->t_softerror);
    qemu_put_byte(f, tp->snd_scale);
    qemu_put_byte(f, tp->rcv_scale);
    qemu_put_byte(f, tp->request_r_scale);
    qemu_put_byte(f, tp->requested_s_scale);
    qemu_put_be32(f, tp->ts_recent);
    qemu_put_be32(f, tp->ts_recent_age);
    qemu_put_be32(f, tp->last_ack_sent);
}

void
slirp_socket_save(QEMUFile *f, struct socket *so, int type)
{
    if (so->chr && so->chr->chr_save_check && so->chr->chr_save_check(so->chr) != 0)
        return;
    qemu_put_byte(f, type);

    qemu_put_be32(f, so->so_urgc);
    qemu_put_be32(f, so->so_faddr.s_addr);
    qemu_put_be32(f, so->so_laddr.s_addr);
    qemu_put_be16(f, so->so_fport);
    qemu_put_be16(f, so->so_lport);
    qemu_put_byte(f, so->so_iptos);
    qemu_put_byte(f, so->so_type);
    qemu_put_be32(f, so->so_state);
    qemu_put_be32(f, so->so_expire - get_clock_ms(vm_clock));
    qemu_put_be32(f, so->so_queued);
    qemu_put_be32(f, so->so_nqueued);

    slirp_sbuf_save(f, &so->so_rcv);
    slirp_sbuf_save(f, &so->so_snd);

    slirp_tcp_save(f, so->so_tcpcb);

    if (so->chr && so->chr->chr_save)
        so->chr->chr_save(so->chr, f);

    /* put save data end marker */
    qemu_put_be32(f, 0);
}

static void
slirp_socket_save_reset(QEMUFile *f, struct socket *so)
{
    struct tcpcb *tp = so->so_tcpcb;
    uint32_t faddr;
    int fport;

    if (!tp)
        return;

    /* marker for saved socket data to be reset on resume,
     *  must be SOSV_RST ( = 2 ) */
    qemu_put_byte(f, SOSV_RST);

    faddr = so->so_faddr.s_addr;
    fport = so->so_fport;

    qemu_put_be32(f, faddr);
    qemu_put_be32(f, so->so_laddr.s_addr);
    qemu_put_be16(f, fport);
    qemu_put_be16(f, so->so_lport);
    qemu_put_be32(f, tp->snd_nxt);

}

static void
slirp_bootp_save(QEMUFile *f, Slirp *slirp)
{
    int i;

    for (i = 0; i < NB_BOOTP_CLIENTS; i++) {
        qemu_put_be16(f, slirp->bootp_clients[i].allocated);
        qemu_put_buffer(f, slirp->bootp_clients[i].macaddr, 6);
    }
}

#if defined(CONFIG_VBOXDRV)
void vbsfSaveHandleTable(QEMUFile *f);
int vbsfLoadHandleTable(QEMUFile *f);
#endif

static void
slirp_state_save(QEMUFile *f, void *opaque)
{
    Slirp *slirp = opaque;
    struct socket *so;

    slirp_th_lock();

    LIST_FOREACH(so, &slirp->tcb, entry) {
        if (so->chr && (so->so_state & SS_PROXY))
            slirp_socket_save(f, so, SOSV_PROXY);
        else if (so->chr && (so->so_state & SS_VMFWD))
            slirp_socket_save(f, so, SOSV_SLIRP);
        else
            slirp_socket_save_reset(f, so);
    }
    /* marker for end of saved sockets (== 0) */
    qemu_put_byte(f, 0);

#if defined(CONFIG_VBOXDRV)
    vbsfSaveHandleTable(f);
#endif

    qemu_put_be16(f, slirp->ip_id);

    slirp_bootp_save(f, slirp);

    arp_table_save(f, slirp);

    slirp_th_unlock();
}

static int
slirp_sbuf_load(QEMUFile *f, struct sbuf *sbuf)
{
    uint32_t off, sb_cc, sb_datalen;
    int ret = 0;

    sb_cc = qemu_get_be32(f);
    sb_datalen = qemu_get_be32(f);

    if (!sbuf)
        goto out_skip;

    sbreserve(sbuf, sb_datalen);
    if (sbuf->sb_datalen != sb_datalen) {
        warnx("%s: sbreserve", __FUNCTION__);
        ret = -ENOMEM;
        goto out_skip;
    }

    sbuf->sb_cc = sb_cc;

    off = qemu_get_be32(f);
    sbuf->sb_wptr = sbuf->sb_data + off;
    off = qemu_get_be32(f);
    sbuf->sb_rptr = sbuf->sb_data + off;
    qemu_get_buffer(f, (unsigned char*)sbuf->sb_data, sbuf->sb_datalen);

    return 0;

  out_skip:
    (void)qemu_get_be32(f);     /* wptr */
    (void)qemu_get_be32(f);     /* rptr */
    qemu_file_skip(f, sbuf->sb_datalen); /* data */
    return ret;
}

static void slirp_tcp_load(QEMUFile *f, struct tcpcb *tp)
{
    struct tcpcb _tp;
    int i;

    if (!tp)
        tp = &_tp;

    tp->t_state = qemu_get_sbe16(f);
    for (i = 0; i < TCPT_NTIMERS; i++)
        tp->t_timer[i] = qemu_get_sbe16(f);
    tp->t_rxtshift = qemu_get_sbe16(f);
    tp->t_rxtcur = qemu_get_sbe16(f);
    tp->t_dupacks = qemu_get_sbe16(f);
    tp->t_maxseg = qemu_get_be16(f);
    tp->t_force = qemu_get_sbyte(f);
    tp->t_flags = qemu_get_be16(f);
    tp->snd_una = qemu_get_be32(f);
    tp->snd_nxt = qemu_get_be32(f);
    tp->snd_up = qemu_get_be32(f);
    tp->snd_wl1 = qemu_get_be32(f);
    tp->snd_wl2 = qemu_get_be32(f);
    tp->iss = qemu_get_be32(f);
    tp->snd_wnd = qemu_get_be32(f);
    tp->rcv_wnd = qemu_get_be32(f);
    tp->rcv_nxt = qemu_get_be32(f);
    tp->rcv_up = qemu_get_be32(f);
    tp->irs = qemu_get_be32(f);
    tp->rcv_adv = qemu_get_be32(f);
    tp->snd_max = qemu_get_be32(f);
    tp->snd_cwnd = qemu_get_be32(f);
    tp->snd_ssthresh = qemu_get_be32(f);
    tp->t_idle = qemu_get_sbe16(f);
    tp->t_rtt = qemu_get_sbe16(f);
    tp->t_rtseq = qemu_get_be32(f);
    tp->t_srtt = qemu_get_sbe16(f);
    tp->t_rttvar = qemu_get_sbe16(f);
    tp->t_rttmin = qemu_get_be16(f);
    tp->max_sndwnd = qemu_get_be32(f);
    tp->t_oobflags = qemu_get_byte(f);
    tp->t_iobc = qemu_get_byte(f);
    tp->t_softerror = qemu_get_sbe16(f);
    tp->snd_scale = qemu_get_byte(f);
    tp->rcv_scale = qemu_get_byte(f);
    tp->request_r_scale = qemu_get_byte(f);
    tp->requested_s_scale = qemu_get_byte(f);
    tp->ts_recent = qemu_get_be32(f);
    tp->ts_recent_age = qemu_get_be32(f);
    tp->last_ack_sent = qemu_get_be32(f);
    tcp_template(tp);
}

struct socket *
slirp_socket_load(QEMUFile *f, Slirp *slirp, int type)
{
    struct socket *so, _so;
    uint32_t n;
    int ret = 0;

    /* marker consumed by loop calling slirp_socket_load */

    so = socreate_tcp(slirp);
    if (!so) {
	warnx("%s: socreate_tcp", __FUNCTION__);
        so = &_so;
        ret = 1;
    } else {
        ret = tcp_attach(so);
        if (ret < 0)
            warnx("%s: tcp_attach", __FUNCTION__);
    }

    so->so_urgc = qemu_get_be32(f);
    so->so_faddr.s_addr = qemu_get_be32(f);
    so->so_laddr.s_addr = qemu_get_be32(f);
    so->so_fport = qemu_get_be16(f);
    so->so_lport = qemu_get_be16(f);
    so->so_iptos = qemu_get_byte(f);
    so->so_type = qemu_get_byte(f);
    so->so_state = qemu_get_be32(f);
    /* Add 1s */
    so->so_expire = get_clock_ms(vm_clock) + qemu_get_be32(f) + 1000;
    so->so_queued = qemu_get_be32(f);
    so->so_nqueued = qemu_get_be32(f);

    ret |= slirp_sbuf_load(f, so != &_so ? &so->so_rcv : NULL);
    ret |= slirp_sbuf_load(f, so != &_so ? &so->so_snd : NULL);

    slirp_tcp_load(f, so->so_tcpcb);

    /* only match with vmfwd rules if there was no error and we're not
     * skipping input anyway */
    if (!ret && so != &_so)
        tcp_vmfwd_input(so, slirp);

    if (so->chr && so->chr->chr_restore)
        so->chr->chr_restore(so->chr, f);
    else
        /* if we didn't match a vmfwd rule (incl. any errors), skip
         * vmfwd save data */
        while ((n = qemu_get_be32(f)))
            qemu_file_skip(f, n);

    if (ret && so != &_so)
        sofree(so);

    return ret || so == &_so ? NULL : so;
}

static void
slirp_socket_load_reset(QEMUFile *f, Slirp *slirp)
{
    struct mbuf *m = NULL;
    uint32_t laddr, faddr;
    int fport, lport;
    struct tcpiphdr *ti;
    tcp_seq snd_nxt;

    faddr = qemu_get_be32(f);
    laddr = qemu_get_be32(f);
    fport = qemu_get_be16(f);
    lport = qemu_get_be16(f);
    snd_nxt = qemu_get_be32(f);

    /* prepare a tcp RST mbuf */
    m = m_get(slirp);
    if (!m)
        goto err;

    m->m_data += IF_MAXLINKHDR;
    ti = mtod(m, struct tcpiphdr *);
    m->m_len = sizeof(*ti);

    ti->ti_x0 = 0;
    ti->ti_x1 = 0;
    ti->ti_pr = IPPROTO_TCP;
    ti->ti_len = htons(sizeof (struct tcpiphdr) - sizeof (struct ip));

    /* reversed order as tcp_respond will reverse back */
    ti->ti_src.s_addr = laddr;
    ti->ti_sport = lport;
    ti->ti_dst.s_addr = faddr;
    ti->ti_dport = fport;

    ti->ti_seq = 0;
    ti->ti_ack = 0;
    ti->ti_x2 = 0;
    ti->ti_off = 5;
    ti->ti_flags = 0;
    ti->ti_win = 0;
    ti->ti_sum = 0;
    ti->ti_urp = 0;

    LOGSLIRP3("%s: sending RST to guest from %s:%d to port %d", __FUNCTION__,
            inet_ntoa(ti->ti_dst), ntohs(fport), ntohs(lport));
    tcp_respond(NULL, ti, m, 0, snd_nxt, TH_RST);

    return;

err:
    if (m)
        m_free(m);
}

static void
slirp_bootp_load(QEMUFile *f, Slirp *slirp)
{
    int i;

    for (i = 0; i < NB_BOOTP_CLIENTS; i++) {
        slirp->bootp_clients[i].allocated = qemu_get_be16(f);
        qemu_get_buffer(f, slirp->bootp_clients[i].macaddr, 6);
    }
}

static int
slirp_state_load(QEMUFile *f, void *opaque, int version_id)
{
    Slirp *slirp = opaque;
    int err = -1, type;

    slirp_th_lock();
    if (version_id < 4 && qemu_get_byte(f) != 0) {
        debug_printf("incompatible slirp save state\n");
        goto out;
    }

    while (version_id >= 6 && (type = qemu_get_byte(f)) != 0)
        if (version_id >= 8 && type == SOSV_RST)
            slirp_socket_load_reset(f, slirp);
        else
            slirp_socket_load(f, slirp, type);

#if defined(CONFIG_VBOXDRV)
    if (version_id >= 8) {
        err = vbsfLoadHandleTable(f);
        if (err) {
            warnx("vbsfLoadHandleTable error code 0x%x", err);
            goto out;
        } else
            warnx("vbsfLoadHandleTable load ok");
    }
#endif

    if (version_id >= 2)
        slirp->ip_id = qemu_get_be16(f);

    if (version_id >= 3)
        slirp_bootp_load(f, slirp);

    if (version_id >= 5)
        arp_table_load(f, slirp);

    slirp_log_level = slirp->log_level;

    err = 0;

out:
    slirp_th_unlock();
    return err;
}

void slirp_log_buf(const char *buf, size_t len)
{
    const int char_per_line = 16;
    char tmp[3*char_per_line + 4];
    size_t i = 0, j;
    while (i < len) {
        int n = len - i;
        if (n > char_per_line)
            n = char_per_line;
        for (j = 0; j < n; j++)
            snprintf(tmp + j * 3, 4, " %02x", (unsigned char) (buf[i + j]));
        debug_printf("\t<%03d:%03d-%03d>:%s\n", (int) len, (int) i,
                     (int) (i + j - 1), tmp);
        i += n;
    }
}

Timer *
slirp_new_vm_timer(int64_t delay_ms, void (*cb)(void *opaque), void *opaque)
{
    Timer *t;

#if defined(SLIRP_THREADED)
    t = new_timer_ms_ex(slirp_active_timers, vm_clock, cb, opaque);
#else
    t = new_timer_ms(vm_clock, cb, opaque);
#endif

    if (!t)
        return NULL;
    mod_timer(t, get_clock_ms(vm_clock) + delay_ms);
    return t;
}

static int slirp_schedule_bh_permanent(void *nopaque, void (*cb)(void *), void *opaque)
{
    return async_op_add_bh(slirp_async_op_ctx, opaque, cb);
}

int slirp_schedule_bh(void *nopaque, void (*cb1) (void *), void (*cb2)(void *), void *opaque)
{
    int ret = -1;
    ioh_event *pevent = NULL;

#if defined(SLIRP_THREADED)
    pevent = &slirp_deqin_ev;
#endif

    if (async_op_add(slirp_async_op_ctx, opaque, pevent, cb1, cb2)) {
        warnx("%s: async_op_add failed", __FUNCTION__);
        goto out;
    }

    ret = 0;
out:
    return ret;
}

struct in_addr slirp_get_addr(void)
{
    struct in_addr ret = {.s_addr = 0 };
    Slirp *slirp;

    if (QTAILQ_EMPTY(&slirp_instances))
	goto out;
    slirp = TAILQ_FIRST(&slirp_instances);
    ret = slirp->vhost_addr;
out:
    return ret;
}

#if defined(SLIRP_DUMP_PCAP)
typedef struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        uint32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

void slirp_debug_dmp(Slirp *slirp, const uint8_t *buf, size_t len, bool input)
{
    struct ip *ip;
    struct udphdr *udp;
    int p_len, off, iphlen;
    pcaprec_hdr_t ph;
    char *str1 = NULL, *str2 = NULL;

    off = 0;
    p_len = len;
    if (p_len <= ETH_HLEN)
        goto out;

    if (ntohs(*(uint16_t *)(buf + 12)) != ETH_P_IP)
        goto out;

    off += ETH_HLEN;
    p_len -= ETH_HLEN;
    if (p_len <= sizeof(*ip))
        goto out;
    ip = (struct ip *) (buf + off);
    iphlen = ip->ip_hl << 2;
    if (ip->ip_v != IPVERSION || (ip->ip_p != IPPROTO_UDP &&
        ip->ip_p != IPPROTO_ICMP)) {

        goto out;
    }
    if (iphlen >= p_len)
        goto out;

    if (ip->ip_p == IPPROTO_ICMP)
        goto write;

    /* udp, check port */
    off += iphlen;
    p_len -= iphlen;
    udp = (struct udphdr *) (buf + off);
    if (p_len < sizeof(*udp))
        goto write;

    /* we debug DNS but not other UDP services */
    if (input && ntohs(udp->uh_dport) != 53 && is_udp_vmfwd(ip->ip_dst, udp->uh_dport, slirp))
        goto out;
    if (!input && ntohs(udp->uh_sport) != 53 && is_udp_vmfwd(ip->ip_src, udp->uh_sport, slirp))
        goto out;

write:
    slirp_get_pcap_ts(&ph.ts_sec, &ph.ts_usec);
    ph.incl_len = ph.orig_len = len;

    str1 = base64_encode((const unsigned char *)&ph, sizeof(ph));
    str2 = base64_encode((const unsigned char *)buf, len);
    if (!str1 || !str2) {
        warnx("%s: base64_encode failed", __FUNCTION__);
        goto out;
    }
    debug_printf("DNET %s %s\n", str1, str2);
out:
    free(str2);
    free(str1);
}
#endif
