/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _MONITOR_H_
#define _MONITOR_H_

struct except_info
{
    DWORD process_id;
    DWORD thread_id;
    EXCEPTION_POINTERS *exception_pointers;
};

#define EXCEPTION_SHM_FILE_NAME         "2f343046-ed25-4a4e-a45f-c7b696dba0b5"
#define EXCEPTION_CLIENT_MUTEX_NAME     "d54af5ff-b158-4f98-9154-259c47b2e6c1"
#define EXCEPTION_MONITOR_MUTEX_NAME    "c219f3c0-0a61-41e3-8ac2-b3f18c3a2de4"
#define EXCEPTION_NOTIFY_EVENT_NAME     "58ad6c8b-1c0f-4a8f-8956-2b6b71f04759"
#define EXCEPTION_CONTINUE_EVENT_NAME   "c1f79bda-0dbd-4376-961b-67081d12f662"

#endif /* _MONITOR_H_ */
