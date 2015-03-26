/*
 *  uxen_logging.h
 *  uxen
 *
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef _UXEN_LOGGING_H_
#define _UXEN_LOGGING_H_

#define LOGGING_DEFAULT_BUFFER_SIZE                     \
    ((64 << 10) - sizeof(struct uxen_logging_buffer))
#define LOGGING_MAX_BUFFER_SIZE                         \
    ((1024 << 10) - sizeof(struct uxen_logging_buffer))

struct uxen_logging_buffer_desc {
    struct uxen_logging_buffer *buffer;
    uxen_pfn_t *mfns;
    lck_spin_t *lock;
    int npages;
    uint32_t size;
    struct map_pfn_array_pool_entry map_handle;
    struct notification_event event;
};
#define UXEN_LOGGING_BUFFER_DESC_INITIALIZER { NULL, NULL, 0, 0, }

struct uxen_logging_mapping_desc {
    struct uxen_logging_buffer_desc *buffer_desc;
    struct uxen_logging_buffer *user_mapping;
};

int logging_init(struct uxen_logging_buffer_desc *, uint32_t);
struct fd_assoc;
int uxen_op_logging(struct uxen_logging_desc *, struct fd_assoc *);
void logging_unmap(struct uxen_logging_mapping_desc *, struct fd_assoc *);
void logging_free(struct uxen_logging_buffer_desc *);
int uxen_op_logging_vprintk(struct vm_info_shared *, const char *, va_list);

#endif  /* _UXEN_LOGGING_H_ */
