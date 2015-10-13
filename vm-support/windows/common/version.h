/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _VERSION_H_
#define _VERSION_H_

#ifdef BUILD_INFO
#include BUILD_INFO
#endif

#ifndef UXEN_DRIVER_VERSION_CHANGESET
#define UXEN_DRIVER_VERSION_CHANGESET "undefined"
#endif

#ifndef UXEN_DRIVER_FILEVERSION1
#define UXEN_DRIVER_FILEVERSION1 0x0
#endif
#ifndef UXEN_DRIVER_FILEVERSION2
#define UXEN_DRIVER_FILEVERSION2 0x0
#endif
#ifndef UXEN_DRIVER_FILEVERSION3
#define UXEN_DRIVER_FILEVERSION3 0x0
#endif
#ifndef UXEN_DRIVER_FILEVERSION4
#define UXEN_DRIVER_FILEVERSION4 0x0
#endif

#endif
