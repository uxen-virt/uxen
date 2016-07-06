/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#define CONFIG_BLOCK_SWAP 1

#ifndef LIBIMG
#define CONFIG_NET 1
#define CONFIG_NETEVENT 1
#define CONFIG_NICKEL 1
#define HAS_AUDIO 1
#endif

#if defined(CONFIG_DUMP_CPU_STAT) && !defined(_WIN32)
#undef CONFIG_DUMP_CPU_STAT
#endif  /* CONFIG_DUMP_CPU_STAT && !_WIN32 */

#if defined(CONFIG_DUMP_BLOCK_STAT) || \
    defined(CONFIG_DUMP_CPU_STAT) || \
    defined(CONFIG_DUMP_MEMORY_STAT) || \
    defined(CONFIG_DUMP_SWAP_STAT)
#define CONFIG_DUMP_PERIODIC_STATS 1
#endif  /* CONFIG_DUMP_*_STAT */

#define TARGET_ARCH "i386"
#define TARGET_I386 1

// #define DEBUG_SCREEN_RESIZE

// #define WORDS_BIGENDIAN

/* use our definition of struct iovec */
#define _STRUCT_IOVEC

#ifdef OSX_NOT_YET
#undef HAS_AUDIO
#endif

#include "os.h"

#include "compiler.h"
#include "debug.h"
#include "ioh.h"
#include "lib.h"
#include "typedef.h"

#ifdef MONITOR
#include "monitor-cmds.h"
#endif  /* MONITOR */

#include "defensive.h"

#endif	/* _CONFIG_H_ */
