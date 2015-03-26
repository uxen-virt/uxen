/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _BH_H_
#define _BH_H_

typedef void BHFunc(void *opaque);

typedef struct BH BH;

void bh_init(void);
BH *bh_new(BHFunc *cb, void *opaque);
BH *bh_new_with_data(BHFunc *cb, int data_size, void **data);
int bh_poll(void);
void bh_schedule_idle(BH *bh);
void bh_schedule(BH *bh);
void bh_schedule_one_shot(BH *bh);
void bh_cancel(BH *bh);
void bh_delete(BH *bh);
void bh_update_timeout(int *timeout);

#endif	/* _BH_H_ */
