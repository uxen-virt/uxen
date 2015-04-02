/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <stdint.h>

#include "queue.h"
#include "ioh.h"

void ioh_queue_init(struct io_handler_queue *iohq)
{
    TAILQ_INIT(&iohq->queue);
    critical_section_init(&iohq->lock);
}

#ifdef CONFIG_NETEVENT

#define CALL_OFFSET(func) \
    (size_t)((char *)__builtin_return_address(0) - (char *)func)

/* XXX: fd_read_poll should be suppressed, but an API change is
   necessary in the character devices to suppress fd_can_read(). */
int ioh_set_fd_handler2(int fd,
                        struct io_handler_queue *iohq,
                        IOCanRWHandler *fd_read_poll,
                        IOHandler *fd_read,
                        IOCanRWHandler *fd_write_poll,
                        IOHandler *fd_write,
                        void *opaque)
{
    IOHandlerRecord *ioh;

    if (!iohq)
        iohq = &io_handlers;

    critical_section_enter(&iohq->lock);
    TAILQ_FOREACH(ioh, &iohq->queue, queue)
	if (ioh->fd == fd)
	    break;

    if (!fd_read && !fd_write) {
        if (!ioh) {
            debug_printf("%s: ioh delete of unknown ioh"
                         " from %p (%"PRIxSIZE")\n",
                         __FUNCTION__, __builtin_return_address(0),
                         CALL_OFFSET(ioh_set_fd_handler2));
            critical_section_leave(&iohq->lock);
            return 0;
        }
	ioh->deleted = 1;
    } else {
	if (ioh == NULL) {
	    ioh = calloc(1, sizeof(IOHandlerRecord));
	    TAILQ_INSERT_HEAD(&iohq->queue, ioh, queue);
	}
        ioh->fd = fd;
        ioh->fd_read_poll = fd_read_poll;
        ioh->fd_read = fd_read;
        ioh->fd_write_poll = fd_write_poll;
        ioh->fd_write = fd_write;
        ioh->opaque = opaque;
        ioh->deleted = 0;
    }
    critical_section_leave(&iohq->lock);
    return 0;
}

int ioh_set_fd_handler(int fd,
                       struct io_handler_queue *iohq,
                       IOHandler *fd_read,
                       IOHandler *fd_write,
                       void *opaque)
{
    IOHandlerRecord *ioh;

    if (!iohq)
        iohq = &io_handlers;

    critical_section_enter(&iohq->lock);
    TAILQ_FOREACH(ioh, &iohq->queue, queue)
	if (ioh->fd == fd)
	    break;

    if (!fd_read && !fd_write) {
        if (!ioh) {
            debug_printf("%s: ioh delete of unknown ioh"
                         " from %p (%"PRIxSIZE")\n",
                         __FUNCTION__, __builtin_return_address(0),
                         CALL_OFFSET(ioh_set_fd_handler));
            critical_section_leave(&iohq->lock);
            return 0;
        }
	ioh->deleted = 1;
    } else {
	if (ioh == NULL) {
	    ioh = calloc(1, sizeof(IOHandlerRecord));
	    TAILQ_INSERT_HEAD(&iohq->queue, ioh, queue);
	}
        ioh->fd = fd;
        ioh->fd_read_poll = NULL;
        ioh->fd_read = fd_read;
        ioh->fd_write_poll = NULL;
        ioh->fd_write = fd_write;
        ioh->opaque = opaque;
        ioh->deleted = 0;
    }
    critical_section_leave(&iohq->lock);
    return 0;
}

#endif  /* CONFIG_NETEVENT */

extern WaitObjects wait_objects;

static void __attribute__((constructor)) ioh_init(void)
{
    ioh_queue_init(&io_handlers);
    ioh_init_wait_objects(&wait_objects);
}
