/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_STATE_H_
#define _UXEN_STATE_H_

//#include <uxen/platform_interface.h>

struct uxp_state_bar;

void uxen_set_state_bar(struct uxp_state_bar *);
struct uxp_state_bar **uxen_get_state_bar_ptr(void);

#endif	/* _UXEN_STATE_H_ */
