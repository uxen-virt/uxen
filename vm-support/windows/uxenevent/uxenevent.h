/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENEVENT_H_
#define _UXENEVENT_H_

extern int verbose;

#define UXENEVENT_UDP_LOGGING 1

#ifndef UXENEVENT_UDP_LOGGING
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

#define LOGGING_DEFAULT_PORT 44451
#define LOGGING_SOURCE_PORT 5001

int logging_vprintf(const char *fmt, va_list ap);
int logging_printf(const char *fmt, ...);
int logging_init(void);

#define JPWerr(a, ...)  do { Wwarn( __VA_ARGS__ ); Sleep(20000); Werr(a,  ## __VA_ARGS__ ); } while (0)

#endif  /* _UXENEVENT_H_ */
