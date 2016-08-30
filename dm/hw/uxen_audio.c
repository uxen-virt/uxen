/*
 * Copyright (C) 2006 InnoTek Systemberatung GmbH
 *
 * This file is part of VirtualBox Open Source Edition (OSE), as
 * available from http://www.virtualbox.org. This file is free software;
 * you can redistribute it and/or modify it under the terms of the GNU
 * General Public License as published by the Free Software Foundation,
 * in version 2 as it comes in the "COPYING" file of the VirtualBox OSE
 * distribution. VirtualBox OSE is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY of any kind.
 *
 * If you received this file as part of a commercial VirtualBox
 * distribution, then only the terms of your commercial VirtualBox
 * license agreement apply instead of the previous paragraph.
 */
/*
 * uXen changes:
 *
 * Copyright 2013-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <dm/config.h>
#include <dm/qemu_glue.h>
#include <dm/dm.h>
#include <dm/bh.h>
#include <dm/mr.h>
#include <dm/qemu_glue.h>
#include <dm/qemu/hw/pci.h>
#include <dm/qemu/audio/audio.h>
#include <dm/timer.h>
#include <dm/control.h>
#include <dm/vm.h>
#include <dm/hw/pci-ram.h>
#include <dm/hw/uxen_audio.h>
#include <dm/hw/wasapi.h>

//#define DEBUG_UXENAUDIO

#ifdef DEBUG_UXENAUDIO
#define DPRINTF(fmt, ...) debug_printf(fmt, ## __VA_ARGS__)
#else
#define DPRINTF(fmt, ...) do {} while (0)
#endif

#define SILENCE_SAMPLES (44100 * 4)

static UXenAudioState *state = NULL;

static int transfer(UXenAudioVoice *v);
static void set_out_mode(UXenAudioVoice *v, uxenaudio_out_mode_t new);
static uint32_t stream_pos(UXenAudioVoice *v);
static uint32_t out_where(UXenAudioVoice *v);
static uint32_t inp_where(UXenAudioVoice *v);
static void control_audio_notify(void *opaque);

/* Audio Interfaces */

static int
voice_running(UXenAudioVoice *v)
{
    return v->wv != NULL;
}

static int
num_running_voices(void)
{
    int i, r = 0;

    if (!state)
        return 0;
    for (i = 0; i < NVOICE; ++i)
        if (voice_running(&state->voices[i]))
            ++r;
    return r;
}

static void
on_start_stop(void)
{
    int voices = num_running_voices();

    if (!state)
        return;

    if (voices) {
        vm_set_vpt_coalesce(0);
        timeBeginPeriod(1);
    } else {
        vm_set_vpt_coalesce(1);
        timeEndPeriod(1);
    }
}

static void
need_data_cb(wasapi_voice_t wv, void *opaque)
{
    UXenAudioVoice *v = (UXenAudioVoice *)opaque;

    if (v->wv) {
        transfer(v);
        if (!v->capture)
            wasapi_mute_voice(v->wv, v->buf->silence >= SILENCE_SAMPLES);
    }
}

static void
voice_init(UXenAudioVoice *v)
{
    memset(&v->guest_fmt, 0, sizeof(v->guest_fmt));
    v->guest_fmt.wFormatTag = WAVE_FORMAT_PCM;
    v->guest_fmt.nChannels = 2;
    v->guest_fmt.nSamplesPerSec = 44100;
    v->guest_fmt.nAvgBytesPerSec = 44100 * 4;
    v->guest_fmt.nBlockAlign = 4;
    v->guest_fmt.cbSize = 0;
    v->guest_fmt.wBitsPerSample = 16;
}

static void
voice_init_cb(wasapi_voice_t wv, void *opaque, int err)
{
    UXenAudioVoice *v = (UXenAudioVoice*)opaque;

    if (err)
        v->omode = UXENAUDIO_OUT_NULL;
}

static int
voice_start_internal(UXenAudioVoice *v, uint32_t fmt)
{
    v->wv = 0;
    v->frames_written = 0;
    v->virt_pos_t0 = qemu_get_clock(rt_clock);
    v->resampler = 0;
    v->dst_frames_remainder = 0;

    wasapi_init_voice(&v->wv, v->capture, &v->guest_fmt,
                      voice_init_cb, v);

    on_start_stop();

    wasapi_set_data_cb(v->wv, need_data_cb, v);
    wasapi_start(v->wv);

    return 0;
}

static void
voice_stop_noreset(UXenAudioVoice *v, uint32_t *pos)
{
    if (v->wv) {
        wasapi_stop(v->wv);
        if (pos)
            *pos = v->capture ? inp_where(v) : out_where(v);
        wasapi_release_voice(v->wv);
        v->wv = 0;
        resampler_16_2_free(v->resampler);
        v->resampler = 0;
        on_start_stop();
    }
}

static void
voice_stop(UXenAudioVoice *v)
{
    UXenAudioState *s = v->s;

    if (!s->ram_ptr)
        return;

    voice_stop_noreset(v, NULL);

    v->running = 0;
    v->rptr = 0;
}

static void
voice_release(UXenAudioVoice *v)
{
    voice_stop(v);
}

static uint32_t
bytes_since(UXenAudioVoice *v, uint64_t t0)
{
    uint64_t dt = qemu_get_clock(rt_clock) - t0;

    return (uint32_t)(dt *  v->guest_fmt.nAvgBytesPerSec / 1000);
}

static uint32_t
stream_virt_pos(UXenAudioVoice *v)
{
    uint32_t p = bytes_since(v, v->virt_pos_t0) &
        ~((uint32_t)v->guest_fmt.nBlockAlign-1);
    p /= AUDIO_QUANTUM_BYTES;
    p *= AUDIO_QUANTUM_BYTES;
    return p;
}

static uint32_t
stream_pos(UXenAudioVoice *v)
{
    uint64_t pos_ns = 0;
    uint64_t pos = 0;

    if (v->wv) {
        wasapi_get_position(v->wv, &pos_ns);
        pos = pos_ns * v->guest_fmt.nAvgBytesPerSec / 1000000000;
    }
    pos &= ~((uint64_t)v->guest_fmt.nBlockAlign-1);
    return (uint32_t)pos;
}

static void
set_out_mode(UXenAudioVoice *v, uxenaudio_out_mode_t new)
{
    uxenaudio_out_mode_t old = v->omode;

    if (new == old)
        return;

    debug_printf("audio: change output mode %d\n", new);
    v->omode = new;

    if (new == UXENAUDIO_OUT_NULL) {
        /* mute host audio, switch to virtual position use */
        v->virt_pos_t0 = qemu_get_clock(rt_clock);
        v->position_offset += v->last_realpos;
        voice_stop_noreset(v, NULL);
    } else if (old == UXENAUDIO_OUT_NULL &&
               new == UXENAUDIO_OUT_HOST_VIRT_POS) {
        voice_start_internal(v, v->regs.fmt);
    } else if (old == UXENAUDIO_OUT_HOST_VIRT_POS &&
               new == UXENAUDIO_OUT_HOST) {
        /* keep host audio unmuted, switch to real position use */
        v->position_offset += stream_virt_pos(v);
    } else {
        warnx("unexpected audio mode transition: %d -> %d", old, new);
        v->omode = old;
    }
    control_audio_notify(v->s);
}

static uint32_t
out_where(UXenAudioVoice *v)
{
    uint32_t spos, ret = 0;

    switch (v->omode) {
    case UXENAUDIO_OUT_HOST:
        ret = stream_pos(v);
        v->last_realpos = ret;
        break;
    case UXENAUDIO_OUT_NULL:
        ret = stream_virt_pos(v);
        break;
    case UXENAUDIO_OUT_HOST_VIRT_POS:
        spos = stream_pos(v);
        v->last_realpos = spos;
        if (spos) {
            /* real stream started producing positions (!= 0),
             * switch to regular host playback mode */
            ret = spos;
            set_out_mode(v, UXENAUDIO_OUT_HOST);
        } else
            ret = stream_virt_pos(v);
        break;
    }

    ret /= AUDIO_QUANTUM_BYTES;
    ret *= AUDIO_QUANTUM_BYTES;
    return v->position_offset + ret;
}

static uint32_t
inp_where(UXenAudioVoice *v)
{
    uint32_t spos = v->frames_written * v->guest_fmt.nBlockAlign;

    spos /= AUDIO_QUANTUM_BYTES;
    spos *= AUDIO_QUANTUM_BYTES;
    v->last_realpos = spos;
    return v->position_offset + spos;;
}

static void
control_audio_notify(void *opaque)
{
    UXenAudioState *s = (UXenAudioState *)opaque;
    int running = 0;
    int out_used = 0;
    int inp_used = 0;
    int i;

    for (i = 0; i < NVOICE; ++i) {
        UXenAudioVoice *v = &s->voices[i];

        if (v->running && (v->capture || v->omode == UXENAUDIO_OUT_HOST)) {
            running++;
            if (v->capture)
                inp_used++;
            else if (v->buf->silence >= SILENCE_SAMPLES)
                DPRINTF("silence detected: %d\n", v->buf->silence);
            else
                out_used++;
        }
    }

    if (out_used != s->last_out_used) {
        s->last_out_used = out_used;
        control_send_status("audio-output", out_used ? "on" : "off", NULL);
    }

    if (inp_used != s->last_inp_used) {
        s->last_inp_used = inp_used;
        control_send_status("audio-input", inp_used ? "on" : "off", NULL);
    }

    if (running)
        advance_timer(s->control_notify_timer, get_clock_ms(vm_clock) + 5000);
    else
        del_timer(s->control_notify_timer);
}

static int
initialize_voice_pointers(UXenAudioState *s)
{
    unsigned int i;

    for (i = 0; i < NVOICE; ++i) {
        UXenAudioVoice *v = &s->voices[i];

        v->buf->signature = UXAU_VM_SIGNATURE_VALUE;
        v->buf->wptr = 0;
        v->buf->rptr = 0;
        v->buf->sts = 0;
    }

    return 0;
}

static void
update_voice_pointers(void *ram_ptr, void *opaque)
{
    UXenAudioState *s = opaque;
    unsigned int i;

    if (ram_ptr) {
        for (i = 0; i < NVOICE; ++i) {
            UXenAudioVoice *v = &s->voices[i];

            v->buf = (struct UXenAudioBuf *)(ram_ptr + v->mmio_offset);
        }
        if (!s->ram_ptr)
            initialize_voice_pointers(s);
    }


    s->ram_ptr = ram_ptr;
}

static int
voice_resample(UXenAudioVoice *v,
         double src_dst_ratio, int dst_channels,
         void *src, int src_frames, void *dst, int max_dst_frames,
         int *frames_read, int *frames_written)
{
    int f_read, f_written;

    if (!v->resampler)
        v->resampler = resampler_16_2_init(src_dst_ratio, dst_channels);
    if (!v->resampler)
        return -ENOMEM;

    f_read = resampler_16_2_add_frames(v->resampler, src, src_frames);
    f_written = max_dst_frames;
    resample_16_2(v->resampler, dst, &f_written);
    *frames_read = f_read;
    *frames_written = f_written;
    return 0;
}

static int
move_frames(UXenAudioVoice *v,
            int src_channels, int dst_channels,
            int src_rate, int dst_rate,
            void *src, int src_frames,
            void *dst, int max_dst_frames,
            int *frames_read, int *frames_written)
{
    UXenAudioState *state = v->s;
    int n = src_frames;
    int fr_read = 0, fr_written = 0;
    double src_dst_ratio = (double)src_rate / dst_rate;
    double dst_src_ratio = 1.0 / src_dst_ratio;
    int silence = state->dev_mute || v->buf->silence >= SILENCE_SAMPLES;
    WAVEFORMATEX *dst_fmt = NULL;
    int dst_align;

    wasapi_get_play_fmt(v->wv, &dst_fmt);
    dst_align = dst_fmt->nBlockAlign;

    if (n > max_dst_frames)
        n = max_dst_frames;

    if (!v->capture && silence) {
        /* drop resampler if any */
        if (v->resampler) {
            resampler_16_2_free(v->resampler);
            v->resampler = NULL;
        }

        /* output silence */
        v->dst_frames_remainder += src_frames * dst_src_ratio;
        n = (int)v->dst_frames_remainder;
        if (n > max_dst_frames)
            n = max_dst_frames;
        memset(dst, 0, n*dst_align);
        v->dst_frames_remainder -= n;
        fr_read = src_frames;
        fr_written = n;
    } else if (src_rate == dst_rate && src_channels == dst_channels) {
        /* equal rates and channels, no resampling required */
        memcpy(dst, src, n*dst_align);
        fr_read = fr_written = n;
    } else {
        voice_resample(v, src_dst_ratio, dst_channels,
                       src, n,
                       dst, max_dst_frames,
                       &fr_read, &fr_written);
        v->dst_frames_remainder += fr_read * dst_src_ratio;
        v->dst_frames_remainder -= fr_written;
    }
    assert(fr_written <= max_dst_frames);
    v->frames_written += fr_written;
    *frames_read = fr_read;
    *frames_written = fr_written;
    return 0;
}

/* return actual number of frames consumed */
static int
consume_out_samples(UXenAudioVoice *v, uint8_t *src, int frames)
{
    WAVEFORMATEX *fmt;
    wasapi_voice_t wv = v->wv;
    void *buffer = 0;
    int max_frames = 0;
    int fr_written = 0, fr_read = 0;
    int src_rate = v->guest_fmt.nSamplesPerSec;
    int src_channels = v->guest_fmt.nChannels;
    int dst_rate, dst_channels;

    if (!wv)
        return 0;

    wasapi_get_play_fmt(wv, &fmt);
    dst_rate = fmt->nSamplesPerSec;
    dst_channels = fmt->nChannels;

    if (wasapi_pb_lock_buffer(wv, &max_frames, &buffer))
        return 0;

    move_frames(v,
                src_channels, dst_channels,
                src_rate, dst_rate,
                src, frames,
                buffer, max_frames,
                &fr_read, &fr_written);

    wasapi_pb_unlock_buffer(wv, fr_written);

    return fr_read;
}

static void
consume_inp_samples(UXenAudioVoice *v, void *src, int silent, int frames)
{
    WAVEFORMATEX *fmt;
    wasapi_voice_t wv = v->wv;
    int dst_rate = v->guest_fmt.nSamplesPerSec;
    int dst_channels = v->guest_fmt.nChannels;
    int src_rate, src_channels;
    int align = v->guest_fmt.nBlockAlign;

    if (!wv)
        return;

    wasapi_get_play_fmt(wv, &fmt);
    src_rate = fmt->nSamplesPerSec;
    src_channels = fmt->nChannels;

    if (silent)
        memset(src, 0, frames * align);

    while (frames) {
        void *dst = (void*)&v->buf->buf[v->wptr];
        int space = v->buf_len - v->wptr;
        int max_frames = space / align;
        int fr_read = 0, fr_written = 0;

        move_frames(v,
                    src_channels, dst_channels,
                    src_rate, dst_rate,
                    src, frames,
                    dst, max_frames,
                    &fr_read, &fr_written);

        v->wptr = (v->wptr + fr_written*align) % v->buf_len;
        src += fr_read * align;
        frames -= fr_read;
    }
    v->buf->wptr = v->wptr;
}

static int
transfer_out(UXenAudioVoice *v)
{
    uint32_t wptr;
    uint32_t sum_fr_read = 0;
    int align = v->guest_fmt.nBlockAlign;

    wptr = v->buf->wptr;

    if (!voice_running(v)
         && v->omode == UXENAUDIO_OUT_HOST)
        return 0;

    if (wptr == v->rptr)
        return 0;
    if (wptr >= v->buf_len)
        return 0;

    while (wptr != v->rptr) {
        uint32_t fr_read, acquired;

        if (v->rptr < wptr)
            acquired = wptr - v->rptr;
        else
            acquired = v->buf_len - v->rptr;

        acquired &= ~(align-1);
        if (!acquired)
            break;

        fr_read = consume_out_samples(v, (uint8_t*)&v->buf->buf[v->rptr], acquired / align);
        if (fr_read == 0)
            break;

        sum_fr_read += fr_read;
        v->rptr = (v->rptr + fr_read*align) % v->buf_len;
    }

    v->buf->rptr = v->rptr;
    return sum_fr_read;
}

static int
transfer_in(UXenAudioVoice *v)
{
    int frames, silent, done = 0;
    void *buffer = NULL;

    for (;;) {
        if (wasapi_cap_next_packet_size(v->wv, &frames) || !frames)
            break;
        if (wasapi_cap_lock_buffer(v->wv, &frames, &silent, &buffer))
            break;
        consume_inp_samples(v, buffer, silent, frames);
        wasapi_cap_unlock_buffer(v->wv, frames);
        done += frames;
    }
    return done;
}

static int
transfer(UXenAudioVoice *v)
{
    if (!v->s->ram_ptr || !v->running)
        return 0;

    if (v->capture)
        return transfer_in(v);
    else
        return transfer_out(v);
}

static void
voice_re_start(UXenAudioVoice *v)
{
    UXenAudioState *s = v->s;

    if (!s->ram_ptr)
        return;

    if (voice_running(v))
        return;

    v->running = 0;
    v->last_realpos = 0;

    DPRINTF("v->regs.fmt=%x\n", v->regs.fmt);

    if (v->regs.fmt != UXAU_V_AVFMT_44100_16_2)
        return;

    v->buf->rptr = v->rptr;
    v->buf->sts = 0;
    v->buf->silence = 0;

    v->running = true;
    voice_start_internal(v, v->regs.fmt);
    control_audio_notify(v->s);
}

static void
voice_start(UXenAudioVoice *v)
{
    UXenAudioState *s = v->s;

    if (!s->ram_ptr)
        return;

    v->rptr = v->buf->rptr = 0;
    v->wptr = v->buf->wptr = 0;
    v->position_offset = 0;
    voice_re_start(v);
}

static int
uxenaudio_post_load(void *opaque, int version_id)
{
    UXenAudioState *s = opaque;
    int i;

    if (version_id < 2)
        return -EINVAL;

    pci_ram_post_load(&s->dev, version_id);

    for (i = 0; i < NVOICE; ++i) {
        UXenAudioVoice *v = &s->voices[i];

        if (v->running) {
            if (s->ram_ptr) {
                v->buf->wptr = v->wptr;
                /* transient virtual position reporting avoids
                 * position stall and rare but total wreck of
                 * restored audio stream */
                v->omode = UXENAUDIO_OUT_HOST_VIRT_POS;
                voice_re_start(v);
	    } else
	        v->running = 0;
	}
    }

    return 0;
}

static void
uxenaudio_pre_save(void *opaque)
{
    UXenAudioState *s = opaque;
    int i;

    del_timer(s->control_notify_timer);
    if (s->ram_ptr) {
        for (i = 0; i < NVOICE; ++i) {
            UXenAudioVoice *v = &s->voices[i];

            v->wptr = v->buf->wptr;
            if (v->running)
                voice_stop_noreset(v, &v->position_offset);
        }
    }

    pci_ram_pre_save(&s->dev);
}

static void
uxenaudio_post_save(void *opaque)
{
    UXenAudioState *s = opaque;

    pci_ram_post_save(&s->dev);
}

static const VMStateDescription vmstate_uxenaudiovoice = {
    .name = "uxenaudiovoice",
    .version_id = 2,
    .minimum_version_id = 2,
    .minimum_version_id_old = 2,
    .fields = (VMStateField[]) {
        VMSTATE_INT32 (running, UXenAudioVoice),
        VMSTATE_INT32 (capture, UXenAudioVoice),
        VMSTATE_UINT32 (wptr, UXenAudioVoice),
        VMSTATE_UINT32 (rptr, UXenAudioVoice),
        VMSTATE_UINT32 (position_offset, UXenAudioVoice),
        VMSTATE_UINT32 (regs.gain0, UXenAudioVoice),
        VMSTATE_UINT32 (regs.gain1, UXenAudioVoice),
        VMSTATE_UINT32 (regs.fmt, UXenAudioVoice),
        VMSTATE_END_OF_LIST ()
    }
};

static const VMStateDescription vmstate_uxenaudio = {
    .name = "uxenaudio",
    .version_id = 2,
    .minimum_version_id = 2,
    .minimum_version_id_old = 2,
    .pre_save = uxenaudio_pre_save,
    .post_load = uxenaudio_post_load,
    .post_save = uxenaudio_post_save,
    .resume = uxenaudio_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE (dev, UXenAudioState),
        VMSTATE_UINT32(unused1, UXenAudioState),
        VMSTATE_UINT64(unused2, UXenAudioState),
        VMSTATE_STRUCT_ARRAY(voices,
                             UXenAudioState,
                             NVOICE,
                             1,
                             vmstate_uxenaudiovoice,
                             UXenAudioVoice),
        VMSTATE_END_OF_LIST ()
    }
};

static void
test_voice_lost(UXenAudioVoice *v)
{
    if (v->running) {
        if (v->wv && wasapi_lost_voice(v->wv)) {
            /* voice is lost on audio endpoint changes (ex. when plugging headphones) */
            debug_printf("audio voice lost\n");
            voice_stop_noreset(v, &v->position_offset);
            voice_re_start(v);
            v->omode = UXENAUDIO_OUT_HOST_VIRT_POS;
        }
    }
}

static uint32_t
voice_io_read(UXenAudioState *s, unsigned int vn, uint32_t offset)
{
    UXenAudioVoice *v;

    uint32_t ret = ~0;

    if (!s->ram_ptr)
        return ~0;

    v = &s->voices[vn];

    switch (offset) {
    case UXAU_V_SIGNATURE:
        ret = UXAU_V_SIGNATURE_VALUE;
        break;
    case UXAU_V_MMIOBASE:
        ret = v->mmio_offset;
        break;
    case UXAU_V_BUFLEN:
        ret = v->buf_len;
        break;
    case UXAU_V_AVFEAT:
        ret = 0;
        break;
    case UXAU_V_AVFMT:
        ret = UXAU_V_AVFMT_44100_16_2;
        break;
    case UXAU_V_CTL:
        ret = v->running ? UXAU_V_CTL_RUN_NSTOP : 0;
        break;
    case UXAU_V_FMT:
        ret = v->regs.fmt;
        break;
    case UXAU_V_POSITION:
        if (v->running) {
            test_voice_lost(v);
            ret = v->capture ? inp_where(v) : out_where(v);
        } else
            ret = ~0;
        break;
    case UXAU_V_POSITION_STEP:
        return 0;
    case UXAU_V_LWM:
        ret = 0;
        break;
    case UXAU_V_TARGETLAG:
	ret = dict_get_integer(vm_audio, "target_lag");
	if (!ret)
	    ret = TARGET_LAG;
        break;
    case UXAU_V_GAIN0:
        ret = v->regs.gain0;
        break;
    case UXAU_V_GAIN1:
        ret = v->regs.gain1;
        break;
    }

    return ret;
}

static void
voice_ctl_write(UXenAudioVoice *v, uint32_t val)
{
    uint32_t run_nstop = val & UXAU_V_CTL_RUN_NSTOP;
    uint32_t capture = val & UXAU_V_CTL_RUN_CAPTURE;

    DPRINTF("v->running=%d run_nstop=%d\n",
            v->running, run_nstop);

    if (!(!!v->running ^ !!run_nstop))
        return;

    if (!run_nstop) {
        /* Stop */
        voice_stop(v);
        return;
    }

    if (capture && !v->s->capture_enabled)
        return;

    /* Start */
    v->capture = !!capture;
    voice_start(v);
}

static void
voice_io_write(UXenAudioState *s, unsigned int vn, uint32_t offset,
               uint32_t val)
{
    UXenAudioVoice *v;

    v = &s->voices[vn];

    switch (offset) {
    case UXAU_V_FMT:
        v->regs.fmt = val;
        break;
    case UXAU_V_CTL:
        voice_ctl_write(v, val);
        break;
    case UXAU_V_GAIN0:
        v->regs.gain0 = val;
        break;
    case UXAU_V_GAIN1:
        v->regs.gain1 = val;
        break;
    case 0x80:
        v->regs.check_start = val;
        break;
    case 0x84:
#ifdef DEBUG_UXENAUDIO
        analyse_voice(v, "from ioreq", v->regs.check_start, val);
#endif
        break;
    }
}

static uint32_t
global_io_read(UXenAudioState *s, uint32_t offset)
{
    switch (offset) {
    case UXAU_SIGNATURE:
        return UXAU_SIGNATURE_VALUE;
    case UXAU_VERSION:
        return 0x00010001;
    case UXAU_NVOICE:
        return NVOICE;
    }

    return ~0;
}

static void
global_io_write(UXenAudioState *s, uint32_t offset, uint32_t val)
{
}

static uint64_t
ram_read(void *opaque, target_phys_addr_t addr, unsigned size)
{
    UXenAudioState *s = opaque;
    uint64_t ret = ~0;

    if (!s->ram_ptr)
        return ~0;

    switch (size) {
    case 8:
        ret = *(uint64_t *)(s->ram_ptr + addr);
        break;
    case 4:
        ret = *(uint32_t *)(s->ram_ptr + addr);
        break;
    case 2:
        ret = *(uint16_t *)(s->ram_ptr + addr);
        break;
    case 1:
        ret = *(uint8_t *)(s->ram_ptr + addr);
        break;
    }

    DPRINTF("audio: ram_read%d(%lx)=%lx\n", size * 8,
            (unsigned long)addr, (unsigned long)ret);

    return ret;
}

static void
ram_write(void *opaque, target_phys_addr_t addr, uint64_t val, unsigned size)
{
    UXenAudioState *s = opaque;

    DPRINTF("audio: ram_write%d(%lx,%lx)\n", size * 8,
            (unsigned long)addr, (unsigned long)val);

    if (!s->ram_ptr)
        return;

    switch (size) {
    case 8:
        *(uint64_t *)(s->ram_ptr + addr) = val;
        break;
    case 4:
        *(uint32_t *)(s->ram_ptr + addr) = val;
        break;
    case 2:
        *(uint16_t *)(s->ram_ptr + addr) = val;
        break;
    case 1:
        *(uint8_t *)(s->ram_ptr + addr) = val;
        break;
    }
}


static uint64_t
io_read(void *opaque, target_phys_addr_t addr, unsigned size)
{
    UXenAudioState *s = opaque;
    uint32_t offset;
    unsigned int vn;
    uint64_t ret = ~0;

    if (size == 4) {
        if (addr < 0x1000)
            ret = (uint64_t)global_io_read(s, (uint32_t)addr);
        else {
            vn = (addr >> 16) - 1;
            offset = addr & 0xffff;

            if (vn >= NVOICE)
                ret = ~0;
            else
                ret = (uint64_t)voice_io_read(s, vn, offset);
        }
    }

    return ret;
}

static void
io_write(void *opaque, target_phys_addr_t addr, uint64_t val, unsigned size)
{
    UXenAudioState *s = opaque;
    uint32_t offset;
    unsigned int vn;

    if (size != 4)
        return;

    if (addr < 0x1000) {
        global_io_write(s, (uint32_t)addr, (uint32_t)val);
        return;
    }

    vn = (addr >> 16) - 1;
    offset = addr & 0xffff;

    if (vn >= NVOICE)
        return;

    voice_io_write(s, vn, offset, (uint32_t)val);
}

static const MemoryRegionOps uxenaudio_io_ops = {
    .read = io_read,
    .write = io_write
};

static const MemoryRegionOps uxenaudio_ram_ops = {
    .read = ram_read,
    .write = ram_write
};

static void
uxenaudio_on_reset(void *opaque)
{
    UXenAudioState *s = opaque;
    int i;

    for (i = 0; i < NVOICE; ++i) {
        UXenAudioVoice *v = &s->voices[i];

        voice_stop(v);
        v->regs.gain0 = 0x8000;
        v->regs.gain1 = 0x8000;
        v->regs.fmt = 0;
    }
}

static int
init_buffers(UXenAudioState *s)
{

    uint32_t offset = 0;
    unsigned int i;
    uint32_t bar_size;

    for (i = 0; i < NVOICE; ++i) {
        UXenAudioVoice *v = &s->voices[i];
        memset(v, 0, sizeof (*v));
        v->s = s;
        v->index = i;
        v->buf_len = DEFAULT_BUFLEN;
        v->mmio_offset = offset;
        v->omode = UXENAUDIO_OUT_HOST;

        voice_init(v);

        offset += sizeof(struct UXenAudioBuf) + v->buf_len;
    }


    for (bar_size = 1; bar_size <= offset; bar_size <<= 1)
        ;

    memory_region_init_io(&s->buffer, &uxenaudio_ram_ops, s, "uxenaudio ram",
                          bar_size);
    memory_region_add_ram_range(&s->buffer, 0, bar_size,
                                update_voice_pointers, s);

    return 0;
}

static int
uxenaudio_initfn(PCIDevice *dev)
{
    UXenAudioState *s = DO_UPCAST(UXenAudioState, dev, dev);
    uint8_t *c = s->dev.config;

    state = s;

    s->saved_process_pri = 0;
    s->last_inp_used = s->last_out_used = 0;
    s->control_notify_timer = new_timer_ms(vm_clock, control_audio_notify, s);

    s->ram_ptr = NULL;
    s->dev_mute = 0;
    s->capture_enabled = dict_get_boolean(vm_audio, "capture");

    pci_set_word(c + PCI_STATUS,
                 PCI_STATUS_FAST_BACK | PCI_STATUS_DEVSEL_MEDIUM);
    pci_set_word(c + PCI_SUBSYSTEM_VENDOR_ID, 0);
    pci_set_word(c + PCI_SUBSYSTEM_ID, 0);

    c[PCI_INTERRUPT_PIN] = 1;
    c[PCI_MIN_GNT] = 0x06;
    c[PCI_MAX_LAT] = 0xff;

    AUD_register_card("uxenaudio", &s->card);

    init_buffers(s);

    memory_region_init_io(&s->io, &uxenaudio_io_ops, s, "uxenaudio io",
                           4 << 16);

    pci_register_bar(&s->dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->io);
    pci_register_bar(&s->dev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->buffer);

    dev->config[PCI_BASE_ADDRESS_0] |= 0x0; /* memory, 32bit, non prefetchable */
    dev->config[PCI_BASE_ADDRESS_1] |= 0x8; /* memory, 32bit, prefetchable */

    dev->wmask[PCI_BASE_ADDRESS_0] &= ~0xf;
    dev->wmask[PCI_BASE_ADDRESS_1] &= ~0xf;

    qemu_register_reset(uxenaudio_on_reset, s);
    uxenaudio_on_reset(s);

    if (vm_audio && dict_get_boolean_default(vm_audio, "output-disabled", 0))
        s->dev_mute = 1;

    return 0;
}

static int
uxenaudio_exitfn(PCIDevice *dev)
{
    UXenAudioState *s = DO_UPCAST(UXenAudioState, dev, dev);
    int i;

    for (i = 0; i < NVOICE; ++i)
        voice_release(&s->voices[i]);

    memory_region_del_ram_range(&s->buffer, 0);
    memory_region_destroy(&s->io);
    memory_region_destroy(&s->buffer);

    del_timer(s->control_notify_timer);

    return 0;
}

static PCIDeviceInfo uxenaudio_info = {
    .qdev.name = "uxen-audio",
    .qdev.desc = "uXen audio",
    .qdev.size = sizeof(UXenAudioState),
    .qdev.vmsd = &vmstate_uxenaudio,
    .init = uxenaudio_initfn,
    .exit = uxenaudio_exitfn,
    .vendor_id = PCI_VENDOR_ID_XEN,
    .device_id = 0xc2ad,
    .revision = 0x01,
    .class_id = PCI_CLASS_MULTIMEDIA_AUDIO,
    .config_write = pci_ram_config_write,
};

static void
uxenaudio_register(void)
{
    pci_qdev_register(&uxenaudio_info);
}

device_init(uxenaudio_register);

int
uxenaudio_mute(int mute)
{
    if (state) state->dev_mute = mute;
    return 0;
}

int
uxenaudio_init(PCIBus *bus)
{
    pci_create_simple(bus, -1, "uxen-audio");
    wasapi_init();
    return 0;
}

void
uxenaudio_exit(void)
{
    int i;

    if (state)
        for (i = 0; i < NVOICE; ++i)
            voice_release(&state->voices[i]);
    wasapi_exit();
}
