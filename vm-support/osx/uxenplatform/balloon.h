/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _BALLOON_H_
#define _BALLOON_H_

#include <IOKit/IOLib.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

#include <sys/queue.h>

struct balloon_pages
{
    TAILQ_ENTRY(balloon_pages) entry;
    IOBufferMemoryDescriptor *desc;
};

class uXenPlatform;

class uXenBalloon
{
public:
    bool init(uXenPlatform *p);
    void free(void);

    IOReturn set_size(size_t target_mb);
    size_t get_size(void);

private:
    IOReturn add_pages(struct balloon_pages *pages);
    void remove_pages(struct balloon_pages *pages);
    IOReturn share_pages(struct balloon_pages *pages);

    uXenPlatform *platform;
    unsigned long size;
    IOLock *lock;
    TAILQ_HEAD(, balloon_pages) page_list;
};

#endif /* _BALLOON_H_ */
