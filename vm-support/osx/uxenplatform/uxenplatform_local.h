/*
 * Copyright 2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENPLATFORM_LOCAL_H_
#define _UXENPLATFORM_LOCAL_H_

#include <uxen/platform_interface.h>

union uxp_bus_device_config_block
{
		struct uxp_bus_device device;
		uint8_t bytes[UXENBUS_DEVICE_CONFIG_LENGTH];
};

#endif
