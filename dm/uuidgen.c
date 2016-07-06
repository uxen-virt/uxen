/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include "os.h"
#include <uuid/uuid.h>

/* Generates a version-4 compliant UUID using the OS' random source. */
void uuid_generate_truly_random(uuid_t uuid)
{
    if (generate_random_bytes(uuid, sizeof(uuid_t)))
        errx(1, "generating uuid failed");
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
}
