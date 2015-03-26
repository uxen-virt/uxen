#include "slirp.h"
#include <dm/control.h>
#include "stats.h"

#if defined(SLIRP_THREADED)
#include <dm/async-op.h>
#else
#include <dm/bh.h>
#endif

#define IS_NAV_SO(so) ((!((so)->chr) || (so->so_state & SS_PROXY)) && \
        sototcpcb(so) &&   \
        sototcpcb(so)->t_state >= TCPS_SYN_SENT &&      \
        sototcpcb(so)->t_state <= TCPS_ESTABLISHED)

static unsigned int n_so_nav_total = 0;
static unsigned int last_n_so = 0;
static unsigned int last_nav_so = 0;

static unsigned int crt_rx = 0;
static unsigned int crt_tx = 0;
static unsigned int crt_nav_rx = 0;
static unsigned int crt_nav_tx = 0;
static int64_t last_guest_in = -1;
static int64_t last_guest_out = -1;

static int64_t last_nav_guest_in = -1;
static int64_t last_nav_guest_out = -1;

static int add_int64_str(dict d, const char *name, int64_t n)
{
    char tmp[32];

    tmp[31] = tmp[30] = 0;
    if (snprintf(tmp, 31, "%" PRId64, n) < 0)
        return -1;
    return dict_put_string(d, name, tmp);
}

void stats_guest_in(struct socket *so, int len)
{
    last_guest_in = get_clock_ms(rt_clock);
    if (IS_NAV_SO(so)) {
        last_nav_guest_in = last_guest_in;
        crt_nav_rx += len;
    }
}

void stats_guest_out(struct socket *so, int len)
{
    last_guest_out = get_clock_ms(rt_clock);
    if (IS_NAV_SO(so)) {
        last_nav_guest_out = last_guest_out;
        crt_nav_tx += len;
    }
}

static void send_stats_cb(void *unused)
{
    stats_rpc_send();
}

int slirp_command_stats(void *opaque, const char *id, const char *opt,
            dict d, void *command_opaque)
{
    int ret = -1;

#if defined(SLIRP_THREADED)
    if (async_op_add(slirp_async_op_ctx, NULL, &slirp_event, NULL, send_stats_cb)) {
        warnx("%s: async_op_add failed", __FUNCTION__);
        goto out;
    }
#else
    {
        BH *bh;

        bh = bh_new(send_stats_cb, NULL);
        if (bh) {
           bh_schedule(bh);
        } else {
            warnx("%s: bh_new failed", __FUNCTION__);
            goto out;
        }
    }
#endif

    ret = 0;
out:
    return ret;
}

int stats_rpc_send(void)
{
    int ret = -1;
    int64_t now;
    dict d;

    d = dict_new();
    if (!d) {
        warnx("%s: malloc error", __FUNCTION__);
        goto out;
    }

    now = get_clock_ms(rt_clock);
    if (add_int64_str(d, "number-so", last_n_so))
        goto out;
    if (add_int64_str(d, "number-nav-so", last_nav_so))
        goto out;
    if (add_int64_str(d, "last-guest-in", last_guest_in > 0 ?
                now - last_guest_in : -1))
        goto out;
    if (add_int64_str(d, "last-nav-guest-in", last_nav_guest_in > 0 ?
                now - last_nav_guest_in : -1))
        goto out;
    if (add_int64_str(d, "last-guest-out", last_guest_out > 0 ?
                now - last_guest_out : -1))
        goto out;
    if (add_int64_str(d, "last-nav-guest-out", last_nav_guest_out > 0 ?
                now - last_nav_guest_out : -1))
        goto out;
    if ((ret = control_send_command("slirp-stats", d, NULL, NULL))) {
        warnx("%s: control_send_command failed, %d", __FUNCTION__, ret);
        goto out;
    }
    ret = 0;
out:
    if (d)
        dict_free(d);
    return ret;
}

static unsigned int n_so;
static unsigned int n_nav_so;
static unsigned int last_so_number = 0;
static unsigned int max_so_number = 0;
void slirp_stats_sock_start(void)
{
    n_so = n_nav_so = 0;
    if (last_nav_guest_in < 0)
        last_guest_in = get_clock_ms(rt_clock);
    if (last_nav_guest_out < 0)
        last_guest_out = get_clock_ms(rt_clock);
}

void slirp_stats_sock_end(void)
{
    last_n_so = n_so;
    last_nav_so = n_nav_so;
    last_so_number = max_so_number;
}

void slirp_stats_tcp_sock(struct socket *so)
{
    n_so++;

    if (!IS_NAV_SO(so))
        return;

    n_nav_so++;
    if (so->so_number > last_so_number) {
        n_so_nav_total++;
        if (so->so_number > max_so_number)
            max_so_number = so->so_number;
    }
}

void slirp_stats_rx(size_t len)
{
    crt_rx += len;
}

void slirp_stats_tx(size_t len)
{
    crt_tx += len;
}

void slirp_stats(unsigned int *n_nav_sockets, unsigned int *n_conn_ever,
        unsigned int *ms_last_packet, unsigned int *bytes_rx, unsigned int *bytes_tx,
        unsigned int *bytes_nav_rx, unsigned int *bytes_nav_tx)
{
    *bytes_rx = crt_rx;
    *bytes_tx = crt_tx;
    *bytes_nav_rx = crt_nav_rx;
    *bytes_nav_tx = crt_nav_tx;

    crt_rx = crt_tx = 0;
    crt_nav_rx = crt_nav_tx = 0;

    *n_nav_sockets = last_nav_so;
    *n_conn_ever = n_so_nav_total;
    *ms_last_packet = 0;
    if (last_nav_guest_in > 0 && last_guest_out > 0) {
        int64_t now = get_clock_ms(rt_clock);
        *ms_last_packet = MIN(now - last_nav_guest_in, now - last_nav_guest_out);
    }
}
