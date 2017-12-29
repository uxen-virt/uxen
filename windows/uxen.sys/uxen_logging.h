/*
 *  uxen_logging.h
 *  uxen
 *
 * Copyright 2013-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef _UXEN_LOGGING_H_
#define _UXEN_LOGGING_H_

#define LOGGING_DEFAULT_BUFFER_SIZE                             \
    ((64 << 10) - sizeof(struct uxen_logging_buffer) - 1)
#define LOGGING_MAX_BUFFER_SIZE                                 \
    ((1024 << 10) - sizeof(struct uxen_logging_buffer) - 1)

struct uxen_logging_buffer_desc {
    struct uxen_logging_buffer *buffer;
    uxen_pfn_t *mfns;
    KEVENT *event;
    KSPIN_LOCK lock;
    struct fd_assoc *event_fda;
    int npages;
    uint32_t size;
};
#define UXEN_LOGGING_BUFFER_DESC_INITIALIZER { NULL, NULL, NULL, 0, NULL, 0, 0 }

struct uxen_logging_mapping_desc {
    struct uxen_logging_buffer_desc *buffer_desc;
    struct uxen_logging_buffer *user_mapping;
};

int logging_init(struct uxen_logging_buffer_desc *, uint32_t);
int uxen_op_logging(struct uxen_logging_desc *, struct fd_assoc *);
void logging_unmap(struct uxen_logging_mapping_desc *, struct fd_assoc *);
void logging_free(struct uxen_logging_buffer_desc *);
int uxen_op_logging_vprintk(struct vm_info_shared *, const char *, va_list);

#endif  /* _UXEN_LOGGING_H_ */
