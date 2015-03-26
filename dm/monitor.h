/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#if !defined(_MONITOR_H_) && defined(MONITOR)
#define _MONITOR_H_

extern Monitor *cur_mon;

void monitor_flush(Monitor *mon);
void monitor_puts(Monitor *mon, const char *str);
void monitor_vprintf(Monitor *mon, const char *fmt, va_list ap)
    __attribute__ ((__format__ (printf, 2, 0)));
void monitor_printf(Monitor *mon, const char *fmt, ...)
    __attribute__ ((__format__ (printf, 2, 3)));
void monitor_print_filename(Monitor *mon, const char *filename);
int monitor_suspend(Monitor *mon);
void monitor_resume(Monitor *mon);
void monitor_init(CharDriverState *hd, int show_banner);

#endif	/* _MONITOR_H_ */
