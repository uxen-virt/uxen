/*
 * Copyright 2020, Bromium, Inc.
 * Author: Simon Haggett <simon.haggett@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#pragma once

#include "v4v_char.h"

/*
 * \brief Performs character device initialisation.
 *
 * \param context The struct v4v_char_context instance.
 * \param name The character device name to use. The memory for this pointer must be retained until
 * v4v_char_device_free() is called.
 *
 * \return Zero on success, or an errno error value on failure.
 */
int v4v_char_device_init(struct v4v_char_context *context, const char *name);

/*
 * \brief Frees character device structures.
 *
 * \param context The struct v4v_char_context instance.
 */
void v4v_char_device_free(struct v4v_char_context *context);
