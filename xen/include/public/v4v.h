/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __V4V_H__
#define __V4V_H__

/* Compiler specific hacks */
#if !defined(__GNUC__)
#define V4V_PACKED
#define V4V_INLINE __inline
#else /* __GNUC__ */

/* #include  <xen/types.h> */
#define V4V_PACKED __attribute__((packed))
#define V4V_INLINE inline
#endif /* __GNUC__ */

/* Get domid_t defined */
#ifdef __XEN__
#include <xen/types.h>
#include <public/xen.h>

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef int ssize_t;            //FIXME this needs to be somewhere else
#endif

#define V4V_VOLATILE
#else
#if defined(__unix__)
#define V4V_VOLATILE volatile
/* If we're running on unix we can use the Xen headers */
#ifdef __KERNEL__
#include <xen/interface/xen.h>
#else
#include <xen/xen.h>
#endif
#else
#define V4V_VOLATILE volatile
#include "xen.h"
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef int ssize_t;
#endif
#endif
#endif

#if !defined(__GNUC__)
#pragma pack(push, 1)
#pragma warning(push)
#pragma warning(disable: 4200)
#endif

#define V4V_PCI_VENDOR 0x5836
#define V4V_PCI_DEVICE 0xc244
#define V4V_PCI_CLASS  0xff0000
#define V4V_PCI_REVISION 0x01

#define V4V_PROTO_DGRAM		0x3c2c1db8
#define V4V_PROTO_STREAM	0x70f6a8e5

#define V4V_RING_MAX_SIZE	(16777216ULL)

/************** Structure definitions **********/

#ifdef __i386__
#define V4V_RING_MAGIC  0xdf6977f231abd910ULL
#define V4V_PFN_LIST_MAGIC  0x91dd6159045b302dULL
#else
#define V4V_RING_MAGIC  0xdf6977f231abd910
#define V4V_PFN_LIST_MAGIC  0x91dd6159045b302d
#endif
#define V4V_DOMID_SELF      (0x7FF0U)
#define V4V_DOMID_INVALID   (0x7FFFU)
#define V4V_DOMID_NONE	V4V_DOMID_INVALID
#define V4V_DOMID_ANY	V4V_DOMID_INVALID
#define V4V_PORT_NONE   0

typedef struct v4v_iov
{
    uint64_t iov_base;
    uint64_t iov_len;
} V4V_PACKED v4v_iov_t;

DEFINE_XEN_GUEST_HANDLE (v4v_iov_t);

typedef struct v4v_addr
{
    uint32_t port;
    domid_t domain;
} V4V_PACKED v4v_addr_t;

DEFINE_XEN_GUEST_HANDLE (v4v_addr_t);


typedef struct v4v_ring_id
{
    struct v4v_addr addr;
    domid_t partner;
} V4V_PACKED v4v_ring_id_t;

DEFINE_XEN_GUEST_HANDLE (v4v_ring_id_t);

typedef uint64_t v4v_pfn_t;
DEFINE_XEN_GUEST_HANDLE (v4v_pfn_t);

typedef struct v4v_pfn_list
{
    uint64_t magic;
    uint32_t npage;
    uint32_t pad;
    uint64_t reserved[3];
    v4v_pfn_t pages[];
} V4V_PACKED v4v_pfn_list_t;

DEFINE_XEN_GUEST_HANDLE (v4v_pfn_list_t);


typedef struct v4v_ring
{
    uint64_t magic;
    struct v4v_ring_id id;      /*Identifies ring_id - xen only looks at this during register/unregister and will fill in id.addr.domain */
    uint32_t len;               /*length of ring[], must be a multiple of 8 */
    V4V_VOLATILE uint32_t rx_ptr; /*rx_ptr - modified by domain */
    V4V_VOLATILE uint32_t tx_ptr; /*tx_ptr - modified by xen */
    uint64_t reserved[4];
    V4V_VOLATILE uint8_t ring[];
} V4V_PACKED v4v_ring_t;

DEFINE_XEN_GUEST_HANDLE (v4v_ring_t);

#ifdef __i386__
#define V4V_RING_DATA_MAGIC	0x4ce4d30fbc82e92aULL
#else
#define V4V_RING_DATA_MAGIC	0x4ce4d30fbc82e92a
#endif

#define V4V_RING_DATA_F_EMPTY       1U << 0 /*Ring is empty */
#define V4V_RING_DATA_F_EXISTS      1U << 1 /*Ring exists */
#define V4V_RING_DATA_F_PENDING     1U << 2 /*Pending interrupt exists - do not rely on this field - for profiling only */
#define V4V_RING_DATA_F_SUFFICIENT  1U << 3 /*Sufficient space to queue space_required bytes exists */

typedef struct v4v_ring_data_ent
{
    struct v4v_addr ring;
    uint16_t flags;
    uint32_t space_required;
    uint32_t max_message_size;
} V4V_PACKED v4v_ring_data_ent_t;

DEFINE_XEN_GUEST_HANDLE (v4v_ring_data_ent_t);

typedef struct v4v_ring_data
{
    uint64_t magic;
    uint32_t nent;
    uint32_t pad;
    uint64_t reserved[4];
    struct v4v_ring_data_ent data[];
} V4V_PACKED v4v_ring_data_t;

DEFINE_XEN_GUEST_HANDLE (v4v_ring_data_t);


#define V4V_ROUNDUP(a) (((a) +0xf ) & ~0xf)
/* Messages on the ring are padded to 128 bits */
/* len here refers to the exact length of the data not including the 128 bit header*/
/* the the message uses ((len +0xf) & ~0xf) + sizeof(v4v_ring_message_header) bytes */


#define V4V_SHF_SYN		(1 << 0)
#define V4V_SHF_ACK		(1 << 1)
#define V4V_SHF_RST		(1 << 2)

#define V4V_SHF_PING		(1 << 8)
#define V4V_SHF_PONG		(1 << 9)

struct v4v_stream_header
{
    uint32_t flags;
    uint32_t conid;
} V4V_PACKED;

struct v4v_ring_message_header
{
    uint32_t len;
    struct v4v_addr source;
    uint16_t pad;
    uint32_t protocol;
    uint8_t data[];

} V4V_PACKED;

/************************** Hyper calls ***************/

/*Prototype of hypercall is */
/*long do_v4v_op(int cmd,XEN_GUEST_HANDLE(void),XEN_GUEST_HANDLE(void),XEN_GUEST_HANDLE(void),uint32_t,uint32_t)*/


#define V4VOP_register_ring 	1
/*int, XEN_GUEST_HANDLE(v4v_ring_t) ring, XEN_GUEST_HANDLE(v4v_pfn_list_t) */

/* Registers a ring with Xen, if a ring with the same v4v_ring_id exists,
 * this ring takes its place, registration will not change tx_ptr 
 * unless it is invalid */

#define V4VOP_unregister_ring 	2
/*int, XEN_GUEST_HANDLE(v4v_ring_t) ring */

#define V4VOP_send 		3
/*int, XEN_GUEST_HANDLE(v4v_addr_t) src,XEN_GUEST_HANDLE(v4v_addr_t) dst,XEN_GUEST_HANDLE(void) buf, UINT32_t len,uint32_t protocol*/

/* Sends len bytes of buf to dst, giving src as the source address (xen will
 * ignore src->domain and put your domain in the actually message), xen
 * first looks for a ring with id.addr==dst and id.partner==sending_domain
 * if that fails it looks for id.addr==dst and id.partner==DOMID_ANY. 
 * protocol is the 32 bit protocol number used from the message
 * most likely V4V_PROTO_DGRAM or STREAM. If insufficient space exists
 * it will return -EAGAIN and xen will twing the V4V_INTERRUPT when
 * sufficient space becomes available */


#define V4VOP_notify 		4
/*int, XEN_GUEST_HANDLE(v4v_ring_data_t) buf*/

/* Asks xen for information about other rings in the system */
/* v4v_ring_data_t contains an array of v4v_ring_data_ent_t
 *
 * ent->ring is the v4v_addr_t of the ring you want information on
 * the same matching rules are used as for V4VOP_send.
 *
 * ent->space_required  if this field is not null xen will check
 * that there is space in the destination ring for this many bytes
 * of payload. If there is it will set the V4V_RING_DATA_F_SUFFICIENT
 * and CANCEL any pending interrupt for that ent->ring, if insufficient
 * space is available it will schedule an interrupt and the flag will
 * not be set.
 *
 * The flags are set by xen when notify replies
 * V4V_RING_DATA_F_EMPTY	ring is empty
 * V4V_RING_DATA_F_PENDING	interrupt is pending - don't rely on this
 * V4V_RING_DATA_F_SUFFICIENT	sufficient space for space_required is there
 * V4V_RING_DATA_F_EXISTS	ring exists
 */


#define V4VOP_sendv		5
/*int, XEN_GUEST_HANDLE(v4v_addr_t) src,XEN_GUEST_HANDLE(v4v_addr_t) dst,XEN_GUEST_HANDLE(v4v_iov_t) , UINT32_t niov,uint32_t protocol*/

/* Identical to V4VOP_send except rather than buf and len it takes 
 * an array of v4v_iov_t and a length of the array */

#define V4VOP_poke		6
/*int, XEN_GUEST_HANDLE(v4v_addr_t) dst */

/* Send a blank notification to the destination domain/ring */

#define V4VOP_create_ring	7
/*XEN_GUEST_HANDLE(v4v_ring_id_t) dst */

/* If the caller is privaledged, attempts to create a ring in the destination domain, */
/* returns zero if the ring already existed or if it was successfully created */
/* the usual way of calling this is to make a call to send, receive -ECONREFUSED, */
/* call create_ring, then retry the call to send, thus scheduling a notification */

#define V4VOP_test		0x10
/* Print out the arguments to the xen log to check the various hypercall register shuffles work etc. */

#define V4VOP_debug		0x11
/* Press the '4' debug key without admin privs. */

#if !defined(__GNUC__)
#pragma warning(pop)
#pragma pack(pop)
#endif


#define V4V_MAX_RING_SIZE (16777216ULL)



/************ Internal RING 0/-1 parts **********/
//#if !defined(V4V_EXCLUDE_INTERNAL)
//

#if !defined(__GNUC__)
extern void _mm_mfence(void);
#pragma intrinsic(_mm_mfence)

static __inline void
v4v_mb (void)
{
    _mm_mfence ();
    _ReadWriteBarrier ();
}
#elif !defined(__LINUX__)
static __inline void 
v4v_mb (void)
{
    __sync_synchronize();
    asm volatile("":::"memory");
}
#endif

/*************** Utility functions **************/

static V4V_INLINE uint32_t
v4v_ring_bytes_to_read (volatile struct v4v_ring *r)
{
    int32_t ret;
    ret = r->tx_ptr - r->rx_ptr;
    if (ret >= 0)
        return ret;
    return (uint32_t) (r->len + ret);
}


/* Copy at most t bytes of the next message in the ring, into the buffer */
/* at _buf, setting from and protocol if they are not NULL, returns */
/* the actual length of the message, or -1 if there is nothing to read */


static V4V_INLINE ssize_t
v4v_copy_out (struct v4v_ring *r, struct v4v_addr *from, uint32_t * protocol,
              void *_buf, size_t t, int consume)
{
    volatile struct v4v_ring_message_header *mh;
    /* unnecessary cast from void * required by MSVC compiler */
    uint8_t *buf = (uint8_t *) _buf; 
    uint32_t btr = v4v_ring_bytes_to_read (r);
    uint32_t rxp = r->rx_ptr;
    uint32_t bte;
    uint32_t len;
    ssize_t ret;


    if (btr < sizeof (*mh))
        return -1;

/*Becuase the message_header is 128 bits long and the ring is 128 bit aligned, we're gaurunteed never to wrap*/
    mh = (volatile struct v4v_ring_message_header *) &r->ring[r->rx_ptr];

    len = mh->len;
    if (btr < len)
        return -1;

#if defined(__GNUC__) 
    if (from)
        *from = mh->source;
#else
	/* MSVC can't do the above */
    if (from)
	memcpy((void *) from, (void *) &(mh->source), sizeof(struct v4v_addr));
#endif

    if (protocol)
        *protocol = mh->protocol;

    rxp += sizeof (*mh);
    if (rxp == r->len)
        rxp = 0;
    len -= sizeof (*mh);
    ret = len;

    bte = r->len - rxp;

    if (bte < len)
      {
          if (t < bte)
            {
                if (buf)
                  {
                      memcpy (buf, (void *) &r->ring[rxp], t);
                      buf += t;
                  }

                rxp = 0;
                len -= bte;
                t = 0;
            }
          else
            {
                if (buf)
                  {
                      memcpy (buf, (void *) &r->ring[rxp], bte);
                      buf += bte;
                  }
                rxp = 0;
                len -= bte;
                t -= bte;
            }
      }

    if (buf && t)
        memcpy (buf, (void *) &r->ring[rxp], (t < len) ? t : len);


    rxp += V4V_ROUNDUP (len);
    if (rxp == r->len)
        rxp = 0;

    v4v_mb ();

    if (consume)
        r->rx_ptr = rxp;


    return ret;
}

static V4V_INLINE void
v4v_memcpy_skip (void *_dst, const void *_src, size_t len, size_t *skip)
{
    const uint8_t *src =  (const uint8_t *) _src;
    uint8_t *dst = (uint8_t *) _dst;

    if (!*skip)
      {
          memcpy (dst, src, len);
          return;
      }

    if (*skip >= len)
      {
          *skip -= len;
          return;
      }

    src += *skip;
    dst += *skip;
    len -= *skip;
    *skip = 0;

    memcpy (dst, src, len);
}

/* Copy at most t bytes of the next message in the ring, into the buffer 
 * at _buf, skipping skip bytes, setting from and protocol if they are not 
 * NULL, returns the actual length of the message, or -1 if there is 
 * nothing to read */

static V4V_INLINE ssize_t
v4v_copy_out_offset (struct v4v_ring *r, struct v4v_addr *from,
                     uint32_t * protocol, void *_buf, size_t t, int consume,
                     size_t skip)
{
    volatile struct v4v_ring_message_header *mh;
    /* unnecessary cast from void * required by MSVC compiler */
    uint8_t *buf = (uint8_t *) _buf;
    uint32_t btr = v4v_ring_bytes_to_read (r);
    uint32_t rxp = r->rx_ptr;
    uint32_t bte;
    uint32_t len;
    ssize_t ret;

    buf -= skip;

    if (btr < sizeof (*mh))
        return -1;

/*Becuase the message_header is 128 bits long and the ring is 128 bit aligned, we're gaurunteed never to wrap*/
    mh = (volatile struct v4v_ring_message_header *) &r->ring[r->rx_ptr];

    len = mh->len;
    if (btr < len)
        return -1;

#if defined(__GNUC__) 
    if (from)
        *from = mh->source;
#else
	/* MSVC can't do the above */
    if (from)
	memcpy((void *) from, (void *) &(mh->source), sizeof(struct v4v_addr));
#endif

    if (protocol)
        *protocol = mh->protocol;

    rxp += sizeof (*mh);
    if (rxp == r->len)
        rxp = 0;
    len -= sizeof (*mh);
    ret = len;

    bte = r->len - rxp;

    if (bte < len)
      {
          if (t < bte)
            {
                if (buf)
                  {
                      v4v_memcpy_skip (buf, (void *) &r->ring[rxp], t, &skip);
                      buf += t;
                  }

                rxp = 0;
                len -= bte;
                t = 0;
            }
          else
            {
                if (buf)
                  {
                      v4v_memcpy_skip (buf, (void *) &r->ring[rxp], bte,
                                       &skip);
                      buf += bte;
                  }
                rxp = 0;
                len -= bte;
                t -= bte;
            }
      }

    if (buf && t)
        v4v_memcpy_skip (buf, (void *) &r->ring[rxp], (t < len) ? t : len,
                         &skip);


    rxp += V4V_ROUNDUP (len);
    if (rxp == r->len)
        rxp = 0;

    v4v_mb ();

    if (consume)
        r->rx_ptr = rxp;


    return ret;
}

//#endif /* V4V_EXCLUDE_INTERNAL */

#endif /* __V4V_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
