/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_XNU_ERRNO_H_
#define _UXEN_XNU_ERRNO_H_

#define uxen_translate_xen_errno(xen_e) (({             \
                int os_e;                               \
                switch (xen_e) {                        \
                case -11: os_e = EAGAIN; break;         \
                case -40: os_e = ENOSYS; break;         \
                case -90: os_e = EMSGSIZE; break;       \
                case -111: os_e = ECONNREFUSED; break;  \
                default: os_e = -(xen_e); break;        \
                }                                       \
                os_e;                                   \
            }))

#endif
