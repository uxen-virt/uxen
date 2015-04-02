#ifndef _LIBSLIRP_H
#define _LIBSLIRP_H

#ifndef _WIN32
#include <netinet/in.h> /* for in_addr */
#endif

#include <dm/dict.h>

struct Slirp;
struct mbuf;
#ifndef _TYPEDEF_H_
typedef struct Slirp Slirp;
#endif  /* _TYPEDEF_H_ */

extern struct io_handler_queue slirp_io_handlers;
#ifdef _WIN32
extern WSAEVENT slirp_event;
#endif
extern WaitObjects *slirp_wait_objects;

#ifdef SLIRP_THREADED
extern unsigned long slirp_inq_max, slirp_outq_max;
#endif

extern struct async_op_ctx *slirp_async_op_ctx;

int get_dns_addr(struct in_addr *pdns_addr);

Slirp *slirp_init(int restricted, struct in_addr vnetwork,
                  struct in_addr vnetmask, struct in_addr vhost,
                  const char *vhostname, const char *tftp_path,
                  const char *bootfile, struct in_addr vdhcp_start,
                  struct in_addr vnameserver, void *opaque);
void slirp_exit(void);
void slirp_get_config_option(Slirp *slirp, const char *name,
                             const yajl_val arg);
void slirp_cleanup(Slirp *slirp);
void slirp_for_each_instance(int (*callback)(Slirp *slirp, void *opaque),
        void *opaque);
struct in_addr slirp_get_addr(void);
void slirp_select_fill(int *timeout);
void slirp_select_poll(void *opaque);
void slirp_check_timeout(void);
#ifdef SLIRP_THREADED
void slirp_dequeue_output(void *);
void slirp_mark_deletion(Slirp *slirp);
void slirp_thread_start(void);
void slirp_thread_exit(void);
void slirp_thread_exit_sync(void);
#endif
void slirp_th_lock(void);
void slirp_th_unlock(void);

void slirp_input(Slirp *slirp, const uint8_t *pkt, int pkt_len);

/* you must provide the following functions: */
int slirp_can_output(void *opaque);
void slirp_output(void *opaque, const uint8_t *pkt, int pkt_len);

int slirp_add_hostfwd(Slirp *slirp, int is_udp,
                      struct in_addr host_addr, int host_port,
                      struct in_addr guest_addr, int guest_port);
void *slirp_add_hostfwd_pipe(Slirp *slirp, int is_udp, void *host_pipe_chr,
			     struct in_addr host_addr, int host_port,
			     struct in_addr guest_addr, int guest_port,
                             int close_reconnect, int close_on_retry);
int slirp_remove_hostfwd(Slirp *slirp, int is_udp,
                         struct in_addr host_addr, int host_port);

void *slirp_add_vmfwd(Slirp *slirp, int is_udp, void *host_pipe_chr,
			     struct in_addr host_addr, int host_port,
			     struct in_addr vm_addr, int vm_port,
                             uint64_t byte_limit);

void *slirp_add_vmfwd_service(Slirp *slirp, int is_udp,
                              void *service_open, void *service_close,
                              yajl_val service_config,
                              struct in_addr host_addr, int host_port,
                              struct in_addr vm_addr, int vm_port,
                              uint64_t byte_limit);
void *slirp_add_proxy(Slirp *slirp, void *proxy_open, void *proxy_close, void *proxy_size,
                              yajl_val proxy_config);

int slirp_command_stats(void *opaque, const char *id, const char *opt,
            dict d, void *command_opaque);
void slirp_connection_info(Slirp *slirp, Monitor *mon);
Timer *
slirp_new_vm_timer(int64_t delay_ms, void (*cb)(void *opaque), void *opaque);
int slirp_schedule_bh(void *nopaque, void (*cb1) (void*), void (*cb2)(void *), void *opaque);

#if 0
void slirp_socket_recv(Slirp *slirp, struct in_addr guest_addr,
                       int guest_port, const uint8_t *buf, int size);
size_t slirp_socket_can_recv(Slirp *slirp, struct in_addr guest_addr,
                             int guest_port);
#else
void slirp_socket_recv(void *opaque, const uint8_t *buf, int size);
size_t slirp_socket_can_recv(void *opaque);
void slirp_socket_send(void *opaque);
void slirp_socket_close(void *opaque);
#endif
void slirp_stats(unsigned int *n_nav_sockets, unsigned int *n_conn_ever,
        unsigned int *ms_last_packet, unsigned int *bytes_rx, unsigned int *bytes_tx,
        unsigned int *bytes_nav_rx, unsigned int *bytes_nav_tx);
void slirp_stats_rx(size_t len);
void slirp_stats_tx(size_t len);

#if defined(SLIRP_DUMP_PCAP)
void slirp_debug_dmp(Slirp *slirp, const uint8_t *buf, size_t len, bool input);
uint64_t slirp_get_pcap_ts(uint32_t *sec, uint32_t *usec);
int slirp_pcap_global_dump(void *opaque, const char *id, const char *opt,
        dict d, void *command_opaque);
#endif
#endif
