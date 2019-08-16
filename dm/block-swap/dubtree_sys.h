/*
 * Copyright 2012-2019, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __DUBTREE_SYS_H__
#define __DUBTREE_SYS_H__

#include "../config.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#define printf(...) debug_printf("swap: " __VA_ARGS__)

#endif /* __DUBTREE_SYS_H__ */
