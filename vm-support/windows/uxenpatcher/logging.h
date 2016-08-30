/*
 * Copyright 2016, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENPATCHER_H_
#define _UXENPATCHER_H_

extern int verbose;

#define UXENPATCHER_UDP_LOGGING 1

#ifndef UXENPATCHER_UDP_LOGGING
#define debug_log(fmt, ...) do {                                        \
        if (verbose) {                                                  \
            fprintf(stderr, "%s: " fmt "\n", __FUNCTION__, ## __VA_ARGS__); \
            fflush(stderr);                                             \
        }                                                               \
    } while (0)
#else
#define debug_log(fmt, ...) \
    logging_printf(fmt, ## __VA_ARGS__)
#endif

#define LOGGING_DEFAULT_PORT 44452
#define LOGGING_SOURCE_PORT 5002

int logging_vprintf(const char *fmt, va_list ap);
int logging_printf(const char *fmt, ...);
int logging_init(void);

#endif  /* _UXENPATCHER_H_ */
