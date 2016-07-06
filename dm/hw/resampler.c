// Adapted from chromium sources:
// https://code.google.com/p/chromium/codesearch#chromium/src/media/base/sinc_resampler.cc
//
// License:
// Use of this source code is governed by a BSD-style license
//
// Copyright 2012 The Chromium Authors. All rights reserved.
// Copyright 2014 Bromium. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include "../os.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <intrin.h>
#include <malloc.h>
#include "resampler.h"
#include "../debug.h"

enum {
    kKernelSize = 32,
    kBlockSize = 256,
    kKernelOffsetCount = 32,
    kKernelStorageSize = kKernelSize * (kKernelOffsetCount+1),
    kBufferSize = kBlockSize + kKernelSize,
    kStagingBufferSize = 4096
};

typedef int (*read_cb_t)(float *ptr, int frames, void *opaque);

struct resampler {
    double io_sample_rate_ratio_;
    double virtual_source_idx_;
    int buffer_primed_;
    int buffer_frames_;
    float *kernel_storage_;
    float *input_buffer_;
    float * r0_;
    float * r1_;
    float * r2_;
    float * r3_;
    float * r4_;
    float * r5_;
};

struct channel {
    struct resampler *res;
    float *src, *dst;
    int src_avail, src_consumed;
};

struct resampler_16_2 {
    struct channel l, r;
    int dst_channels;
};

static float convolve_sse(const float* input_ptr, const float* k1,
                                  const float* k2,
                                  double kernel_interpolation_factor)
{
  __m128 m_input;
  __m128 m_sums1 = _mm_setzero_ps();
  __m128 m_sums2 = _mm_setzero_ps();
  int i;

  // Based on |input_ptr| alignment, we need to use loadu or load.  Unrolling
  // these loops hurt performance in local testing.
  if (((uintptr_t)input_ptr) & 0x0F) {
    for (i = 0; i < kKernelSize; i += 4) {
      m_input = _mm_loadu_ps(input_ptr + i);
      m_sums1 = _mm_add_ps(m_sums1, _mm_mul_ps(m_input, _mm_load_ps(k1 + i)));
      m_sums2 = _mm_add_ps(m_sums2, _mm_mul_ps(m_input, _mm_load_ps(k2 + i)));
    }
  } else {
    for (i = 0; i < kKernelSize; i += 4) {
      m_input = _mm_load_ps(input_ptr + i);
      m_sums1 = _mm_add_ps(m_sums1, _mm_mul_ps(m_input, _mm_load_ps(k1 + i)));
      m_sums2 = _mm_add_ps(m_sums2, _mm_mul_ps(m_input, _mm_load_ps(k2 + i)));
    }
  }

  // Linearly interpolate the two "convolutions".
  m_sums1 = _mm_mul_ps(m_sums1, _mm_set_ps1(
      (float)(1.0 - kernel_interpolation_factor)));
  m_sums2 = _mm_mul_ps(m_sums2, _mm_set_ps1(
      (float)(kernel_interpolation_factor)));
  m_sums1 = _mm_add_ps(m_sums1, m_sums2);

  // Sum components together.
  float result;
  m_sums2 = _mm_add_ps(_mm_movehl_ps(m_sums1, m_sums1), m_sums1);
  _mm_store_ss(&result, _mm_add_ss(m_sums2, _mm_shuffle_ps(
      m_sums2, m_sums2, 1)));

  return result;
}

/* how many source frames required to provide given destination frames */
static int src_frames_required(struct resampler *res, int dst_frames)
{
    int src_frames_req = (int)ceil(dst_frames *
                                   res->io_sample_rate_ratio_);
    if (src_frames_req % kBlockSize == 0)
        src_frames_req = (src_frames_req / kBlockSize) * kBlockSize;
    else
        src_frames_req = (src_frames_req / kBlockSize + 1) * kBlockSize;
    if (!res->buffer_primed_)
        src_frames_req += kKernelSize / 2;
    return src_frames_req;
}

static void resample(struct resampler *r, float *destination, int frames,
                     read_cb_t read_cb, void *cb_opaque)
{
  int remaining_frames = frames;

  if (!r->buffer_primed_) {
      read_cb(r->r0_, kBlockSize + kKernelSize / 2, cb_opaque);
      r->buffer_primed_ = 1;
    }

  // Step (2) -- Resample!
  while (remaining_frames) {
    while (r->virtual_source_idx_ < kBlockSize) {
      // |virtual_source_idx_| lies in between two kernel offsets so figure out
      // what they are.
      int source_idx = (int)(r->virtual_source_idx_);
      double subsample_remainder = r->virtual_source_idx_ - source_idx;

      double virtual_offset_idx = subsample_remainder * kKernelOffsetCount;
      int offset_idx = (int)(virtual_offset_idx);

      // We'll compute "convolutions" for the two kernels which straddle
      // |virtual_source_idx_|.
      float* k1 = r->kernel_storage_ + offset_idx * kKernelSize;
      float* k2 = k1 + kKernelSize;

      // Initialize input pointer based on quantized |virtual_source_idx_|.
      float* input_ptr = r->r1_ + source_idx;

      // Figure out how much to weight each kernel's "convolution".
      double kernel_interpolation_factor = virtual_offset_idx - offset_idx;
      *destination++ = convolve_sse(
          input_ptr, k1, k2, kernel_interpolation_factor);

      // Advance the virtual index.
      r->virtual_source_idx_ += r->io_sample_rate_ratio_;

      if (!--remaining_frames)
        return;
    }

    // Wrap back around to the start.
    r->virtual_source_idx_ -= kBlockSize;

    // Step (3) Copy r3_ to r1_ and r4_ to r2_.
    // This wraps the last input frames back to the start of the buffer.
    memcpy(r->r1_, r->r3_, sizeof(*r->input_buffer_) * (kKernelSize / 2));
    memcpy(r->r2_, r->r4_, sizeof(*r->input_buffer_) * (kKernelSize / 2));

    // Step (4)
    // Refresh the buffer with more input.
    read_cb(r->r5_, kBlockSize, cb_opaque);
  }
}

static void initialize_kernel(struct resampler *r)
{
  // Blackman window parameters.
  //static const double kAlpha = 0.16;
  static const double kA0 = 0.5 * (1.0 - 0.16);
  static const double kA1 = 0.5;
  static const double kA2 = 0.5 * 0.16;
  int offset_idx, i;

  // |sinc_scale_factor| is basically the normalized cutoff frequency of the
  // low-pass filter.
  double sinc_scale_factor =
      r->io_sample_rate_ratio_ > 1.0 ? 1.0 / r->io_sample_rate_ratio_ : 1.0;

  // The sinc function is an idealized brick-wall filter, but since we're
  // windowing it the transition from pass to stop does not happen right away.
  // So we should adjust the low pass filter cutoff slightly downward to avoid
  // some aliasing at the very high-end.
  // TODO(crogers): this value is empirical and to be more exact should vary
  // depending on kKernelSize.
  sinc_scale_factor *= 0.9;

  // Generates a set of windowed sinc() kernels.
  // We generate a range of sub-sample offsets from 0.0 to 1.0.
  for (offset_idx = 0; offset_idx <= kKernelOffsetCount; ++offset_idx) {
    double subsample_offset =
        (double)(offset_idx) / kKernelOffsetCount;

    for (i = 0; i < kKernelSize; ++i) {
      // Compute the sinc with offset.
      double s =
          sinc_scale_factor * M_PI * (i - kKernelSize / 2 - subsample_offset);
      double sinc = (!s ? 1.0 : sin(s) / s) * sinc_scale_factor;

      // Compute Blackman window, matching the offset of the sinc().
      double x = (i - subsample_offset) / kKernelSize;
      double window = kA0 - kA1 * cos(2.0 * M_PI * x) + kA2
          * cos(4.0 * M_PI * x);

      // Window the sinc() function and store at the correct offset.
      r->kernel_storage_[i + offset_idx * kKernelSize] = sinc * window;
    }
  }
}

struct resampler *resampler_init(double io_rate_ratio)
{
    struct resampler *r = calloc(1, sizeof(struct resampler));
    if (!r)
        return 0;
    r->io_sample_rate_ratio_ = io_rate_ratio;
    r->kernel_storage_ = _mm_malloc(sizeof(float) * kKernelStorageSize, 16);
    if (!r->kernel_storage_) {
        free(r);
        return 0;
    }
    r->input_buffer_ = _mm_malloc(sizeof(float) * kBufferSize, 16);
    if (!r->input_buffer_) {
        _mm_free(r->kernel_storage_);
        free(r);
        return 0;
    }

    // Setup various region pointers in the buffer (see diagram above).
    r->r0_ = r->input_buffer_ + kKernelSize / 2;
    r->r1_ = r->input_buffer_;
    r->r2_ = r->r0_;
    r->r3_ = r->r0_ + kBlockSize - kKernelSize / 2;
    r->r4_ = r->r0_ + kBlockSize;
    r->r5_ = r->r0_ + kKernelSize / 2;

    memset(r->kernel_storage_, 0,
           sizeof(*r->kernel_storage_) * kKernelStorageSize);
    memset(r->input_buffer_, 0, sizeof(*r->input_buffer_) * kBufferSize);
    initialize_kernel(r);
    return r;
}

void resampler_free(struct resampler *r)
{
    if (r) {
        _mm_free(r->kernel_storage_);
        _mm_free(r->input_buffer_);
        free(r);
    }
}

static int channel_init(struct channel *ch, double ratio)
{
    memset(ch, 0, sizeof(*ch));

    ch->res = resampler_init(ratio);
    if (!ch->res)
        goto err;

    ch->src = malloc(sizeof(float) * kStagingBufferSize);
    if (!ch->src)
        goto err;

    ch->dst = malloc(sizeof(float) * kStagingBufferSize);
    if (!ch->dst)
        goto err;

    ch->src_avail = 0;

    return 1;
err:
    free(ch->dst);
    free(ch->src);
    free(ch->res);
    return 0;
}

static void channel_free(struct channel *ch)
{
    free(ch->dst);
    free(ch->src);
    free(ch->res);
}

static void channel_rewind(struct channel *ch)
{
    if (ch->src_consumed < kStagingBufferSize) {
        if (ch->src_consumed)
            memmove(ch->src,
                    ch->src + ch->src_consumed,
                    ch->src_avail * sizeof(float));
    } else {
        ch->src_avail = 0;
    }
    ch->src_consumed = 0;
}

struct resampler_16_2 *resampler_16_2_init(double ratio, int dst_channels)
{
    struct resampler_16_2 *r = 0;

    if (dst_channels < 1)
        goto err;

    r = calloc(1, sizeof(struct resampler_16_2));
    if (!r)
        goto err;
    r->dst_channels = dst_channels;
    if (!channel_init(&r->l, ratio))
        goto err;

    if (!channel_init(&r->r, ratio))
        goto err;

    return r;

err:
    if (r) {
        channel_free(&r->l);
        channel_free(&r->r);
    }
    free(r);

    return 0;
}

void resampler_16_2_free(struct resampler_16_2 *r)
{
    if (r) {
        channel_free(&r->l);
        channel_free(&r->r);
        free(r);
    }
}

int resampler_16_2_add_frames(struct resampler_16_2 *res, void *src, int frames)
{
    int16_t *p = src;
    float *l = res->l.src + res->l.src_avail;
    float *r = res->r.src + res->r.src_avail;
    int added = 0;
    while (added < frames &&
           res->l.src_avail < kStagingBufferSize) {
        *l++ = (*p++) / (32768.0f*1.05f);
        *r++ = (*p++) / (32768.0f*1.05f);
        ++added;
        ++res->l.src_avail;
    }
    res->r.src_avail = res->l.src_avail;
    return added;
}

static int get_frames_cb(float *dst, int frames, void *opaque)
{
    struct channel *ch = (struct channel*)opaque;

    assert(frames <= ch->src_avail);
    memcpy(dst, ch->src + ch->src_consumed, frames * sizeof(float));
    ch->src_consumed += frames;
    ch->src_avail -= frames;
    return frames;
}

int resample_16_2(struct resampler_16_2 *res, void *dst, int *p_dst_frames)
{
    int16_t *out = dst;
    float *l = res->l.dst;
    float *r = res->r.dst;
    int consumed;
    int dst_frames = *p_dst_frames;

    if (dst_frames > kStagingBufferSize)
        dst_frames = kStagingBufferSize;

    /* figure out how many destination frames we can cover */
    while (dst_frames) {
        int src_frames_req =
            src_frames_required(res->l.res, dst_frames);
        if (src_frames_req <= res->l.src_avail)
            break;
        dst_frames -= 128;
        if (dst_frames < 0) dst_frames = 0;
    }

    if (!dst_frames) {
        /* not enough source frames, do nothing */
        *p_dst_frames = 0;
        return 0;
    }

    resample(res->l.res, l, dst_frames, get_frames_cb, &res->l);
    resample(res->r.res, r, dst_frames, get_frames_cb, &res->r);

    *p_dst_frames = dst_frames;
    switch (res->dst_channels) {
    case 1:
        /* STEREO -> MONO */
        while (dst_frames--)
            *out++ = (int16_t)(((*l++ + *r++)/2) * 0x7fff);
        break;
    case 2:
        while (dst_frames--) {
            *out++ = (int16_t)((*l++) * 0x7fff);
            *out++ = (int16_t)((*r++) * 0x7fff);
        }
        break;
    case 4:
        while (dst_frames--) {
            *out++ = (int16_t)((*l) * 0x7fff);
            *out++ = (int16_t)((*r) * 0x7fff);
            *out++ = (int16_t)((*l++) * 0x7fff);
            *out++ = (int16_t)((*r++) * 0x7fff);
        }
        break;
    default:
        while (dst_frames--) {
            int pad;

            *out++ = (int16_t)((*l++) * 0x7fff);
            *out++ = (int16_t)((*r++) * 0x7fff);
            for (pad = 2; pad < res->dst_channels; ++pad)
                *out++ = 0;
        }
        break;
    }

    assert(res->l.src_consumed == res->r.src_consumed);
    consumed = res->l.src_consumed;
    channel_rewind(&res->l);
    channel_rewind(&res->r);

    return consumed;
}
