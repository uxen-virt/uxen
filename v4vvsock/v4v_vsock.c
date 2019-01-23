/*
 * Copyright 2016-2019, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/poll.h>
#include <linux/skbuff.h>
#include <linux/kref.h>
#include <net/sock.h>

#include <uxen-v4vlib.h>
#include <uxen-util.h>

#define V4V_RING_LEN 262144
#define RESERVED_MAX_PORT   1024

static rwlock_t vsock_lock;
static struct list_head vsock_list;
static u32 last_port;
static struct tasklet_struct vsock_tasklet;

struct send_ent {
    struct list_head node;
    v4v_addr_t remote_addr;
    size_t len;
    u8 data[];
};

struct vsock {
    struct sock sk; /* needs to be first */
    uxen_v4v_ring_t *recv_ring;
    rwlock_t send_lock;
    wait_queue_head_t readq;
    struct list_head send_list;
    struct list_head node;
    struct list_head node_bh;
    int closing;
    int remote_connected;
    int bh_process;
    u32 local_port;
    struct sockaddr_vm local_addr;
    struct sockaddr_vm remote_addr;
    struct kref kref;
    struct completion released;
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0))
static inline int memcpy_from_msg(void *data, struct msghdr *msg, int len)
{
        return memcpy_fromiovec(data, msg->msg_iov, len);
}

static inline int skb_copy_datagram_msg(const struct sk_buff *from, int offset,
                                        struct msghdr *msg, int size)
{
	return skb_copy_datagram_iovec(from, offset, msg->msg_iov, size);
}
#endif

static void v_release(struct kref *kref)
{
    struct vsock *vsk = container_of(kref, struct vsock, kref);

    complete(&vsk->released);
}

static void vsock_get(struct vsock *vsk)
{
    kref_get(&vsk->kref);
}

static int vsock_put(struct vsock *vsk)
{
    return kref_put(&vsk->kref, v_release);
}

static int vsock_addr_cast(const struct sockaddr *addr, size_t len, struct sockaddr_vm **out_addr)
{
    struct sockaddr_vm *vaddr;

    if (len < sizeof(**out_addr))
        return -EFAULT;
    vaddr = (struct sockaddr_vm *)addr;
    if (vaddr->family != AF_VSOCK)
        return -EFAULT;

    *out_addr = vaddr;
    return 0;
}

/* needs ring_list_lock taken */
static bool local_port_in_use(u32 port)
{
    struct vsock *vsk;

    list_for_each_entry(vsk, &vsock_list, node) {
        if (vsk->local_port == port)
            return true;
    }

    return false;
}

static uint32_t next_free_port(void)
{
    uint32_t port = last_port;
    uint32_t pass = 0;
    unsigned long flags;

    write_lock_irqsave(&vsock_lock, flags);
    for (;;) {
        port++;
        if (!port)
            port++;
        pass++;
        if (!pass) {
            port = 0;
            break;
        }

        if (!local_port_in_use(port)) {
            last_port = port;
            break;
        }
    }
    write_unlock_irqrestore(&vsock_lock, flags);

    return port;
}

static void vsock_irq(void *unused)
{
    tasklet_schedule(&vsock_tasklet);
}

static void vsock_bh(unsigned long unused)
{
    unsigned long flags;
    struct vsock *vsk, *vsk_tmp;
    struct list_head bh_list;

    INIT_LIST_HEAD(&bh_list);

    write_lock_irqsave(&vsock_lock, flags);
    list_for_each_entry(vsk, &vsock_list, node) {
        if (vsk->recv_ring && !vsk->bh_process) {
            vsock_get(vsk);
            vsk->bh_process = 1;
            list_add(&vsk->node_bh, &bh_list);
        }
    }
    write_unlock_irqrestore(&vsock_lock, flags);

    list_for_each_entry_safe(vsk, vsk_tmp, &bh_list, node_bh) {
        struct send_ent *s_ent, *s_tmp;
        bool sent, wakeup_send;

        sent = false;
        wakeup_send = false;
        if (uxen_v4v_copy_out(vsk->recv_ring, NULL, NULL, NULL, 0, 0) > 0) {
            wake_up_interruptible_all(&vsk->readq);
            vsk->sk.sk_data_ready(&vsk->sk);
        }
        if (!vsk->remote_connected) {
            int ok = 0;

            if (uxen_v4v_notify_space(vsk->remote_addr.v4v.domain,
                                      vsk->remote_addr.v4v.port, 1, &ok) == 0) {

                vsk->remote_connected = 1;
                wakeup_send = true;
            }
        }
        write_lock_irqsave(&vsk->send_lock, flags);
        list_for_each_entry_safe(s_ent, s_tmp, &vsk->send_list, node) {
            if (uxen_v4v_send_from_ring(vsk->recv_ring, &s_ent->remote_addr,
                                         &(s_ent->data[0]), s_ent->len, V4V_PROTO_DGRAM) < 0) {

                break;
            }
            list_del(&s_ent->node);
            kfree(s_ent);
            sent = true;
        }
        if (sent && list_empty(&vsk->send_list))
            wakeup_send = true;
        write_unlock_irqrestore(&vsk->send_lock, flags);

        if (wakeup_send) {
            struct sock *sk = &vsk->sk;

            sk->sk_write_space(sk);
        }

        list_del(&vsk->node_bh);
        mb();
        vsk->bh_process = 0;
        vsock_put(vsk);
    }
}

static int __vsock_bind(struct sock *sk, struct sockaddr_vm *vm_addr)
{
    int ret = 0;
    struct vsock *vsk = (struct vsock *) sk;
    domid_t partner = 0;
    u32 local_port = 0;

    if (vsk->recv_ring && !vm_addr) {
        ret = 0;
        goto out;
    }

    if (vm_addr) {
        partner = vm_addr->partner;
        local_port = vm_addr->v4v.port;
    }

    if (!local_port) {
        local_port = next_free_port();
        if (!local_port) {
            ret = -ENOSPC;
            goto out;
        }
    }

    if (vsk->recv_ring && vsk->local_addr.partner == partner &&
        vsk->local_addr.v4v.port == local_port) {

        ret = 0;
        goto out;
    }

    if (vsk->recv_ring) {
        uxen_v4v_ring_free(vsk->recv_ring);
        vsk->recv_ring = NULL;
    }

    vsk->local_addr.partner = partner;
    vsk->local_addr.v4v.port = local_port;

    vsk->recv_ring = uxen_v4v_ring_bind(vsk->local_addr.v4v.port, vsk->local_addr.partner,
                                        V4V_RING_LEN, vsock_irq, NULL);
    if (!vsk->recv_ring) {
        ret = -ENOMEM;
        goto out;
    }

    if (IS_ERR(vsk->recv_ring)) {
        ret = PTR_ERR(vsk->recv_ring);
        vsk->recv_ring = NULL;
        goto out;
    }

out:
    return ret;
}

static int
vsock_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
    int ret = 0;
    struct sock *sk;
    struct sockaddr_vm *vm_addr;

    if (vsock_addr_cast(addr, addr_len, &vm_addr))
        return -EINVAL;

    sk = sock->sk;
    lock_sock(sk);
    ret = __vsock_bind(sk, vm_addr);
    release_sock(sk);
    return ret;
}

static int vsock_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{
    int ret;
    int ok;
    struct sock *sk;
    struct vsock *vsk;
    struct sockaddr_vm *remote_addr;

    ret = vsock_addr_cast(addr, addr_len, &remote_addr);
    if (ret)
        return ret;

    sk = sock->sk;

    lock_sock(sk);
    ret = __vsock_bind(sk, NULL);
    if (ret)
        goto out;

    vsk = (struct vsock *) sk;
    vsk->remote_addr = *remote_addr;

    if (uxen_v4v_notify_space(vsk->remote_addr.v4v.domain,
                              vsk->remote_addr.v4v.port, 1, &ok) == 0) {

        vsk->remote_connected = 1;
    }

    sock->state = SS_CONNECTED;

out:
    release_sock(sk);
    return ret;
}

static unsigned int vsock_poll(struct file *file, struct socket *sock, poll_table *wait)
{
    unsigned int mask = 0;
    struct sock *sk;
    struct vsock *vsk;
    unsigned long flags;

    sk = sock->sk;
    vsk = (struct vsock *) sk;

    poll_wait(file, sk_sleep(sk), wait);

    lock_sock(sk);
    if (!vsk->recv_ring)
        goto out;

    if (uxen_v4v_copy_out(vsk->recv_ring, NULL, NULL, NULL, 0, 0) > 0)
        mask |= POLLIN;

    if (!vsk->remote_connected) {
        int ok = 0;
        if (uxen_v4v_notify_space(vsk->remote_addr.v4v.domain,
                                  vsk->remote_addr.v4v.port, 1, &ok) == 0) {

            vsk->remote_connected = 1;
        }
    }

    if (vsk->remote_connected) {
        write_lock_irqsave(&vsk->send_lock, flags);
        if (list_empty(&vsk->send_list))
            mask |= POLLOUT;
        write_unlock_irqrestore(&vsk->send_lock, flags);
    }
out:
    release_sock(sk);
    return mask;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0))
static int vsock_sendmsg(struct kiocb *kiocb, struct socket *sock,
                         struct msghdr *msg, size_t len)
#else
static int vsock_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
#endif

{
    int ret = 0;
    struct sock *sk;
    struct vsock *vsk;
    struct sockaddr_vm *remote_addr;
    struct send_ent *send_buf = NULL;
    unsigned long flags;

    sk = sock->sk;
    lock_sock(sk);
    ret = __vsock_bind(sk, NULL);
    if (ret)
        goto out;

    vsk = (struct vsock *) sk;
    remote_addr = &vsk->remote_addr;
    if (msg->msg_name && vsock_addr_cast(msg->msg_name, msg->msg_namelen, &remote_addr) < 0) {
        ret = -EINVAL;
        goto out;
    }

    write_lock_irqsave(&vsk->send_lock, flags);
    if (!list_empty(&vsk->send_list))
        ret = -EAGAIN;
    write_unlock_irqrestore(&vsk->send_lock, flags);

    if (ret)
        goto out;

    send_buf = kmalloc(sizeof(*send_buf) + len, GFP_KERNEL);
    if (!send_buf) {
        ret = -ENOMEM;
        goto out;
    }

    memcpy_from_msg(&(send_buf->data[0]), msg, len);
    ret = (int) uxen_v4v_send_from_ring(vsk->recv_ring, &remote_addr->v4v,
                                        &(send_buf->data[0]), len, V4V_PROTO_DGRAM);
    if (ret < 0) {
        write_lock_irqsave(&vsk->send_lock, flags);
        ret = -EAGAIN;
        if (list_empty(&vsk->send_list)) {
                ret = len;
                send_buf->remote_addr = remote_addr->v4v;
                send_buf->len = len;
                list_add_tail(&(send_buf->node), &vsk->send_list);
                send_buf = NULL;
        }
        write_unlock_irqrestore(&vsk->send_lock, flags);
        goto out;
    }

out:
    release_sock(sk);
    if (send_buf)
        kfree(send_buf);
    return ret;
}

static int vsock_getname(struct socket *sock,
			 struct sockaddr *addr, int *addr_len, int peer)
{
    return -EOPNOTSUPP;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0))
static int vsock_recvmsg(struct kiocb *kiocb, struct socket *sock,
                         struct msghdr *msg, size_t len, int flags)
#else
static int vsock_recvmsg(struct socket *sock, struct msghdr *msg, size_t len, int flags)
#endif
{
    int ret = 0;
    int noblock;
    struct sk_buff *skb = NULL;
    size_t dlen;
    ssize_t s;
    struct sock *sk = sock->sk;
    struct vsock *vsk;

    noblock = flags & MSG_DONTWAIT;

    lock_sock(sk);
    vsk = (struct vsock *) sk;
    ret = __vsock_bind(sk, NULL);
    if (ret)
        goto out_unlock;

    if (!len) {
        ret = 0;
        goto out_unlock;
    }

    ret = 0;
    if (!noblock) {
        vsock_get(vsk);
        release_sock(sk);

        ret = wait_event_interruptible(vsk->readq,
                uxen_v4v_copy_out(vsk->recv_ring, NULL, NULL, NULL, 0, 0) > 0);

        if (vsk->closing) {
            vsock_put(vsk);
            ret = -EAGAIN;
            goto out;
        }

        lock_sock(sk);
        vsock_put(vsk);

        if (ret)
            goto out_unlock;
    }

    s = uxen_v4v_copy_out(vsk->recv_ring, NULL, NULL, NULL, 0, 0);
    if (s < 0) {
        ret = s;
        goto out_unlock;
    }

    if (s == 0) {
        ret = -EAGAIN;
        goto out_unlock;
    }

    skb = alloc_skb(s, GFP_KERNEL);
    if (!skb) {
        ret = -ENOMEM;
        goto out_unlock;
    }
    if (uxen_v4v_copy_out(vsk->recv_ring, NULL, NULL, skb_put(skb, s), s, 1) <= 0) {
        ret = -EAGAIN;
        goto out_unlock;
    }
    uxen_v4v_notify();

    dlen = skb->len;
    if (dlen > len) {
        dlen = len;
        msg->msg_flags |= MSG_TRUNC;
    }

    ret = skb_copy_datagram_msg(skb, 0, msg, dlen);
    if (ret)
        goto out_unlock;

    ret = dlen;
out_unlock:
    release_sock(sk);
out:
    if (skb)
        kfree_skb(skb);
    return ret;
}

static int vsock_release(struct socket *sock)
{
    struct sock *sk = sock->sk;

    if (sk) {
        struct vsock *vsk = (struct vsock *) sk;
        unsigned long flags;
        struct send_ent *s_ent, *s_tmp;
        struct sk_buff *skb;

        vsk->closing = 1;

        write_lock_irqsave(&vsock_lock, flags);
        list_del(&vsk->node);
        write_unlock_irqrestore(&vsock_lock, flags);

        vsock_put(vsk);
        while (wait_for_completion_interruptible(&vsk->released))
            ;

        if (vsk->recv_ring) {
            uxen_v4v_ring_free(vsk->recv_ring);
            vsk->recv_ring = NULL;
        }

        write_lock_irqsave(&vsk->send_lock, flags);
        list_for_each_entry_safe(s_ent, s_tmp, &vsk->send_list, node) {
            list_del(&s_ent->node);
            kfree(s_ent);
        }
        write_unlock_irqrestore(&vsk->send_lock, flags);

        lock_sock(sk);
        sock_orphan(sk);
        sk->sk_shutdown = SHUTDOWN_MASK;
        while ((skb = skb_dequeue(&sk->sk_receive_queue)))
            kfree_skb(skb);

        release_sock(sk);
        sock_put(sk);
    }

    sock->sk = NULL;
    sock->state = SS_FREE;

    return 0;
}

static struct proto vsock_proto = {
    .name = "AF_VSOCK",
    .owner = THIS_MODULE,
    .obj_size = sizeof(struct vsock),
};

static const struct proto_ops vsock_dgram_ops = {
    .family = PF_VSOCK,
    .owner = THIS_MODULE,
    .release = vsock_release,
    .bind = vsock_bind,
    .connect = vsock_connect,
    .socketpair = sock_no_socketpair,
    .accept = sock_no_accept,
    .getname = vsock_getname,
    .poll = vsock_poll,
    .ioctl = sock_no_ioctl,
    .listen = sock_no_listen,
    .shutdown = sock_no_shutdown,
    .setsockopt = sock_no_setsockopt,
    .getsockopt = sock_no_getsockopt,
    .sendmsg = vsock_sendmsg,
    .recvmsg = vsock_recvmsg,
    .mmap = sock_no_mmap,
    .sendpage = sock_no_sendpage,
};

static int vsock_create(struct net *net, struct socket *sock,
			int protocol, int kern)
{
    struct sock *sk;
    struct vsock *vsk;
    unsigned long flags;

    if (!sock)
        return -EINVAL;

    if (protocol && protocol != PF_VSOCK)
        return -EPROTONOSUPPORT;

    switch (sock->type) {
    case SOCK_DGRAM:
        sock->ops = &vsock_dgram_ops;
        break;
    case SOCK_STREAM:
        return -ESOCKTNOSUPPORT; /* NOT YET */
        break;
    default:
        return -ESOCKTNOSUPPORT;
    }

    sock->state = SS_UNCONNECTED;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0))
    sk = sk_alloc(net, AF_VSOCK, GFP_KERNEL, &vsock_proto);
#else
    sk = sk_alloc(net, AF_VSOCK, GFP_KERNEL, &vsock_proto, kern);
#endif

    if (!sk)
        return -ENOMEM;

    sock_init_data(sock, sk);

    vsk = (struct vsock *) sk;
    memset(sk + 1, 0, sizeof(*vsk) - sizeof(*sk));
    INIT_LIST_HEAD(&vsk->send_list);
    rwlock_init(&vsk->send_lock);
    kref_init(&vsk->kref);
    init_completion(&vsk->released);
    init_waitqueue_head(&vsk->readq);

    write_lock_irqsave(&vsock_lock, flags);
    list_add(&vsk->node, &vsock_list);
    write_unlock_irqrestore(&vsock_lock, flags);

    return 0;
}

static const struct net_proto_family vsock_family_ops = {
    .family = AF_VSOCK,
    .create = vsock_create,
    .owner = THIS_MODULE,
};

static int __init v4v_vsock_init(void)
{
    int ret;

    rwlock_init (&vsock_lock);
    INIT_LIST_HEAD(&vsock_list);
    last_port = RESERVED_MAX_PORT;
    tasklet_init(&vsock_tasklet, vsock_bh, 0);
    ret = proto_register(&vsock_proto, 0);
    if (ret)
        goto out;
    ret = sock_register(&vsock_family_ops);
    if (ret) {
        proto_unregister(&vsock_proto);
        goto out;
    }

out:
    return ret;
}

static void __exit v4v_vsock_exit(void)
{
    tasklet_kill(&vsock_tasklet);
    sock_unregister(AF_VSOCK);
    proto_unregister(&vsock_proto);
}

module_init(v4v_vsock_init);
module_exit(v4v_vsock_exit);
MODULE_AUTHOR("paulian.marinca@bromium.com");
MODULE_DESCRIPTION("v4v vsock");
MODULE_LICENSE("GPL");
