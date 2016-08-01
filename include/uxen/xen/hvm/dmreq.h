/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _XEN_HVM_DMREQ_H_
#define _XEN_HVM_DMREQ_H_

#define DMREQ_GPFN_UNUSED ~0x0
#define DMREQ_GPFN_ERROR ~0x1
#define DMREQ_GPFN_INVALID ~0x2
#define DMREQ_GPFN_SET_MASK ~0x3
#define dmreq_gpfn_valid(gpfn)                                  \
    (((gpfn) & DMREQ_GPFN_SET_MASK) != DMREQ_GPFN_SET_MASK)
#define dmreq_gpfn_error(gpfn) ((gpfn) == DMREQ_GPFN_ERROR)
#define dmreq_gpfn_invalid(gpfn) ((gpfn) == DMREQ_GPFN_INVALID)

#define DMREQ_GPFN_ACCESS_READ 0
#define DMREQ_GPFN_ACCESS_WRITE 1

struct dmreq {
    union {
        struct {
            uint32_t vp_eport; /* evtchn for notifications to/from dm */
            uint32_t dmreq_gpfn;
            uint32_t dmreq_gpfn_loaded;
            uint16_t dmreq_gpfn_size;
            uint8_t dmreq_gpfn_access;
        };
        uint8_t _fill[64];
    };
};

struct dmreq_page {
    struct dmreq dmreq_dom0;
    struct dmreq dmreq_vcpu[63];
};

#endif  /* _XEN_HVM_DMREQ_H_ */
