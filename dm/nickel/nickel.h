/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _NICKEL_H_
#define _NICKEL_H_

#include "constants.h"
#include <dm/yajl.h>
#include <dm/libnickel.h>
#include "proto.h"
#include "buff.h"
#include "tcpip.h"
#include "access-control.h"

#define NI_MAX_MTU 65536
#define NI_DEFAULT_MTU  9000 /* jumbo frames for e1000 */
#define NI_TCPIP_HLEN   40

#define SS_HOSTFWD      0x01
#define SS_FWDCLOSE     0x02
#define SS_CLOSERETRY   0x04
#define SS_VMFWD        0x08
#define SS_NAV          0x010


struct tcp_vmfwd;
struct udp_vmfwd;
struct prx_fwd;
LIST_HEAD(tcp_vmfwd_list, tcp_vmfwd);
LIST_HEAD(udp_vmfwd_list, udp_vmfwd);
LIST_HEAD(prx_fwd_list, prx_fwd);

extern int ni_log_level;
struct nickel {
    /* aligned data */
    uint64_t s_pkt_rx;
    uint64_t s_pkt_tx;
    uint32_t n_pkt_rx;
    uint32_t n_pkt_tx;
    uint32_t number_tcp_sockets;
    uint32_t number_total_tcp_sockets;
    uint32_t number_tcp_nav_sockets;
    uint32_t number_udp_sockets;
    uint32_t tcpip_last_tcp_data;
    uint32_t tcp_nav_rx;
    uint32_t tcp_nav_tx;
    uint32_t number_tcp_established;
    uint32_t suspend_request;
    uint32_t number_lava_events;

    void *nc_opaque;
    int vm_paused;
    struct in_addr network_addr;
    struct in_addr network_mask;
    struct in_addr host_addr;
    struct in_addr dhcp_startaddr;

    int eth_vm_resolved;
    uint8_t eth_vm[ETH_ALEN];
    uint8_t eth_nickel[ETH_ALEN];
    uint32_t mtu;
    uint16_t tcp_mss;
    uint16_t ip_id;

    uint32_t if_rx;
    uint32_t if_tx;

    uint8_t *udps_buf;
    size_t udps_maxlen;
    struct buff output_list;
    struct buff noarp_output_list;
    ioh_event deqout_ev;
    struct async_op_ctx *async_op_ctx;
    int async_op_max_threads;
#if defined(_WIN32)
    ioh_event so_event;
#endif
    ioh_event event;
    struct io_handler_queue io_handlers;
    WaitObjects wait_objects;

#if defined (NICKEL_THREADED)
    uxen_thread threadh;
    ioh_event suspend_ev;
    ioh_event suspend_ok_ev;
    int exit_request;
    TimerQueue *active_timers;
    ioh_event start_event;
    ioh_event deqin_ev;
    struct buff in_bufq;
    critical_section queue_in_mx;
    critical_section queue_out_mx;
    unsigned long inq_max;
    unsigned long inq_n;
#endif

    FILE *pcapf;
    int pcap_user_enable;
    unsigned int pcap_max_len;
    uint32_t pcap_user_duration;
    char *pcap_fpath;
    Timer *pcap_timer;

    int log_level;
    int disable_dhcp;
    int crash_dump_on_ipc_rst;
    int debug_dns_udp_icmp;
    int dns_resolver_ok;
    int http_proxy_svc_ok;
    int tcp_service_ok;
    int webdav_svc_ok;
    int tcp_disable_window_scale;

    int ac_enabled;
    int ac_event_log_enabled;
    int ac_policy;
    int ac_proxy_has_config;
    int ac_prev_policy;
    int ac_default_policy;
    int ac_block_other_udp_icmp;
    int ac_allow_well_known_ports;
    int ac_dns_ip_only;
    size_t ac_max_tcp_conn;

    void (*http_evt_cb) (void *);
    void (*ac_evt_cb) (void *);
    struct ac_host *ac_denied_hosts[1<<BAC_HASHSIZE];
    struct ac_host *ac_allowed_hosts[1<<BAC_HASHSIZE];
    uint32_t ac_n_denied_hosts;
    uint32_t ac_n_allowed_hosts;
    uint32_t ac_n_denied_networks;
    uint32_t ac_n_allowed_networks;
    uint32_t ac_n_allowed_dns_ips;
    struct ac_network *ac_denied_networks[1<<BAC_HASHSIZE];
    struct ac_network *ac_allowed_networks[1<<BAC_HASHSIZE];
    int lava_events_per_host;
    critical_section ac_lk;

    struct buff *bf_dbg;

    /* socket */
    LIST_HEAD(, socket) sock_list;
    LIST_HEAD(, socket) defered_list;
    uint32_t number_remote_sockets;
    uint32_t number_total_remote_sockets;

    /* tcpip */
    LIST_HEAD(, ni_socket) tcp;
    LIST_HEAD(, ni_socket) udp;
    LIST_HEAD(, ni_socket) gc_tcpip;
    uint16_t g_last_ip;
    uint64_t us_max_ping_rtt;
    int64_t ping_sent_ts;
    int ping_warn;
    int ping_probe_n;
    int64_t tcpip_stats_ts;
    struct ni_socket *tcp_lst_so;
    uint16_t tcp_free_port_base; /* host order */
    uint16_t tcp_last_free_port;
    uint16_t tcp_free_port_end; /* host order */

    struct tcp_vmfwd_list tcp_vmfwd;
    struct udp_vmfwd_list udp_vmfwd;
    struct prx_fwd_list prx_fwd;
};

struct np_desc {
    const char *name;

    void (*init) (yajl_val config);
    CharDriverState *(*open)(void *, uint32_t, uint16_t);

    int  (*save_check) (void *opaque);
    void  (*save) (void *opaque, QEMUFile *f);
    void  (*restore) (void *opaque, QEMUFile *f);
    LIST_ENTRY(np_desc) entry;
};

void * ni_priv_calloc(size_t nmemb, size_t size);
void * ni_priv_malloc(size_t nmemb);
void * ni_priv_realloc(void *ptr, size_t size);
void ni_priv_free(void *ptr);
char * ni_priv_strdup(const char *s);
char * ni_priv_strndup(const char *s, size_t len);
struct buff * ni_netbuff(struct nickel *ni, size_t len);

struct in_addr ni_get_addr(void);
int64_t ni_get_pcap_ts(uint32_t *sec, uint32_t *usec);
size_t ni_can_recv(void *opaque);
void ni_recv(void *opaque, const uint8_t *buf, int size);
void ni_buf_change(void *opaque);
void ni_close(void *opaque);
void ni_event(void *opaque, int event);
int ni_send_fin(void *opaque);
void ni_set_chr_close(void *opaque, void (*cb) (CharDriverState *));
void ni_buff_output(struct nickel *ni, struct buff *bf);
CharDriverState *
ni_tcp_connect(struct nickel *ni, struct sockaddr_in gaddr, struct sockaddr_in faddr,
        void *opaque);
CharDriverState *
ni_udp_open(struct nickel *ni, struct sockaddr_in gaddr,
        struct sockaddr_in faddr, void *opaque);

Timer *
ni_new_vm_timer(struct nickel *ni, int64_t delay_ms, void (*cb)(void *opaque), void *opaque);
Timer *
ni_new_rt_timer(struct nickel *ni, int64_t delay_ms, void (*cb)(void *opaque), void *opaque);

void ni_wakeup_loop(struct nickel *ni);
void _np_add_service(struct np_desc *);

#endif /* _NICKEL_H_ */
