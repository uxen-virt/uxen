/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _NET_H_
#define _NET_H_

#include "opts.h"

int net_client_init(Monitor *mon, QemuOpts *opts, int is_netdev);
void net_check_clients(void);
void net_cleanup(void);

#endif  /* _NET_H_ */
