/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef RESAMPLER_H_
#define RESAMPLER_H_

struct resampler_16_2 *resampler_16_2_init(double ratio, int dst_channels);
void resampler_16_2_free(struct resampler_16_2 *r);
int resampler_16_2_add_frames(struct resampler_16_2 *r, void *src, int frames);
int resample_16_2(struct resampler_16_2 *r, void *dst, int *frames);
int resampler_16_2_get_padding_frames(struct resampler_16_2 *r);

#endif
