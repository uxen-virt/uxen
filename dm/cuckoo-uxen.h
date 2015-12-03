/*
 * Copyright 2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __CUCKOO_UXEN_H__
#define __CUCKOO_UXEN_H__

struct cuckoo_context;
struct cuckoo_callbacks;

int cuckoo_uxen_init(struct cuckoo_context *cuckoo_context,
                     struct cuckoo_callbacks *ret_ccb, void **ret_opaque,
                     HANDLE cancel_event);
void cuckoo_uxen_close(struct cuckoo_context *cuckoo_context, void *opaque);

#endif /* __CUCKOO_UXEN_H__ */
