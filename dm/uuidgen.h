/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __UUIDGEN_H__
#define __UUIDGEN_H__
#include <uuid/uuid.h>
void uuid_generate_truly_random(uuid_t uuid);
#endif
