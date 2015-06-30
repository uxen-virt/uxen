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
 * Copyright 2013-2015, Bromium, Inc.
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

#include "../config.h"

#include <dm/qemu_glue.h>

#include <dm/dm.h>
#include <dm/bh.h>
#include <dm/mr.h>
#include <dm/qemu_glue.h>
#include <dm/qemu/hw/pci.h>
#include <dm/qemu/audio/audio.h>
#include <dm/timer.h>
#include <dm/control.h>

#include "pci-ram.h"

#include "uxen_audio.h"
#include "wasapi.h"
#include "../vm.h"

//#define DEBUG_UXENAUDIO

#ifdef DEBUG_UXENAUDIO
#define DPRINTF(fmt, ...) debug_printf(fmt, ## __VA_ARGS__)
#else
#define DPRINTF(fmt, ...) do {} while (0)
#endif

#define SILENCE_SAMPLES (44100 * 4)

static UXenAudioState *state = NULL;

static int transfer_out(UXenAudioVoiceOut *v);
static void set_out_mode(UXenAudioVoiceOut *v, uxenaudio_out_mode_t new);
static uint32_t waveout_pos(UXenAudioVoiceOut *v);
static uint32_t out_where(UXenAudioVoiceOut *v);

/* Audio Interfaces */

static int
out_running(UXenAudioVoiceOut *v)
{
    return v->wv != NULL;
}

static int
out_num_running_voices(void)
{
    int i, r = 0;

    if (!state)
        return 0;
    for (i = 0; i < NVOICEOUT; ++i)
        if (out_running(&state->voiceout[i]))
            ++r;
    return r;
}

static void
on_start_stop(void)
{
    int playing = out_num_running_voices();

    if (!state)
        return;

    if (playing) {
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
    UXenAudioVoiceOut *v = (UXenAudioVoiceOut *)opaque;
    if (v->wv) {
        transfer_out(v);
        wasapi_mute_voice(v->wv, v->buf->silence >= SILENCE_SAMPLES);
    }
}

static void
out_init(UXenAudioVoiceOut *v)
{
    memset(&v->ww_wfx, 0, sizeof(v->ww_wfx));
    v->ww_wfx.wFormatTag = WAVE_FORMAT_PCM;
    v->ww_wfx.nChannels = 2;
    v->ww_wfx.nSamplesPerSec = 44100;
    v->ww_wfx.nAvgBytesPerSec = 44100 * 4;
    v->ww_wfx.nBlockAlign = 4;
    v->ww_wfx.cbSize = 0;
    v->ww_wfx.wBitsPerSample = 16;
}

static void
out_release(UXenAudioVoiceOut *v)
{
}

static int
out_start(UXenAudioVoiceOut *v, uint32_t fmt)
{
    v->wv = 0;
    v->out_sent = 0;
    v->virt_pos_t0 = qemu_get_clock(rt_clock);
    v->resampler = 0;
    v->dst_frames_remainder = 0;

    wasapi_init_voice(&v->wv, &v->ww_wfx);
    if (!v->wv) {
        set_out_mode(v, UXENAUDIO_OUT_NULL);
        return -1;
    }

    on_start_stop();

    wasapi_set_data_cb(v->wv, need_data_cb, v);
    transfer_out(v);
    wasapi_play(v->wv);

    return 0;
}

static void
out_stop(UXenAudioVoiceOut *v, uint32_t *pos)
{
    if (v->wv) {
        wasapi_stop(v->wv);
        if (pos)
            *pos = out_where(v);
        wasapi_release_voice(v->wv);
        v->wv = 0;
        resampler_16_2_free(v->resampler);
        v->resampler = 0;
        on_start_stop();
    }

}

static uint32_t
bytes_since(UXenAudioVoiceOut *v, uint64_t t0)
{
    uint64_t dt = qemu_get_clock(rt_clock) - t0;

    return (uint32_t)(dt *  v->ww_wfx.nAvgBytesPerSec / 1000);
}

static uint32_t
waveout_virt_pos(UXenAudioVoiceOut *v)
{
    return bytes_since(v, v->virt_pos_t0) &
        ~((uint32_t)v->ww_wfx.nBlockAlign-1);
}

static uint32_t
waveout_pos(UXenAudioVoiceOut *v)
{
    uint64_t pos_ns = 0;
    uint64_t pos = 0;
    if (v->wv) {
        wasapi_get_position(v->wv, &pos_ns);
        pos = pos_ns * v->ww_wfx.nAvgBytesPerSec / 1000000000;
    }
    pos &= ~((uint64_t)v->ww_wfx.nBlockAlign-1);
    return (uint32_t)pos;
}

static void
set_out_mode(UXenAudioVoiceOut *v, uxenaudio_out_mode_t new)
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
        out_stop(v, NULL);
    } else if (old == UXENAUDIO_OUT_NULL &&
               new == UXENAUDIO_OUT_HOST_VIRT_POS) {
        out_start(v, v->regs.fmt);
    } else if (old == UXENAUDIO_OUT_HOST_VIRT_POS &&
               new == UXENAUDIO_OUT_HOST) {
        /* keep host audio unmuted, switch to real position use */
        v->position_offset += waveout_virt_pos(v);
    } else {
        warnx("unexpected audio mode transition: %d -> %d", old, new);
        v->omode = old;
    }
}

static uint32_t
out_where(UXenAudioVoiceOut *v)
{
    uint32_t wv_pos, ret = 0;

    switch (v->omode) {
    case UXENAUDIO_OUT_HOST:
        ret = waveout_pos(v);
        v->last_realpos = ret;
        break;
    case UXENAUDIO_OUT_NULL:
        ret = waveout_virt_pos(v);
        break;
    case UXENAUDIO_OUT_HOST_VIRT_POS:
        wv_pos = waveout_pos(v);
        v->last_realpos = wv_pos;
        if (wv_pos) {
            /* real stream started producing positions (!= 0),
             * switch to regular host playback mode */
            ret = wv_pos;
            v->position_offset -= wv_pos;
            set_out_mode(v, UXENAUDIO_OUT_HOST);
        } else
            ret = waveout_virt_pos(v);

        break;
    }

    return v->position_offset + ret;
}

static void
control_audio_notify(void *opaque)
{
    UXenAudioState *s = (UXenAudioState *)opaque;
    int running = 0;
    int inuse = 0;
    int ret;
    int i;

    for (i = 0; i < NVOICEOUT; ++i)
    {
        UXenAudioVoiceOut *v = &s->voiceout[i];
        int silent = 0;
	if (v->running && v->omode != UXENAUDIO_OUT_NULL) {
            running++;
            silent = v->buf->silence >= SILENCE_SAMPLES;
            if (!silent)
                inuse++;
            else {
                DPRINTF("silence detected: %d\n", v->buf->silence);
                /* request muting of host audio due to silence */
                v->silence_mute = 1;
            }
        }
    }

    ret = control_send_status("audio-output", inuse ? "on" : "off", NULL);

    if (running && (!ret || errno == EBUSY)) {
        int tout;

        tout = ret ? 100 : 10 * 1000;
        advance_timer(s->control_notify_timer, get_clock_ms(vm_clock) + tout);
    } else
        del_timer(s->control_notify_timer);
}

#ifdef DEBUG_UXENAUDIO
static void
analyse_voice(UXenAudioVoiceOut *v, char *why, uint32_t start, uint32_t len)
{
    int16_t *sp, min, max;
    unsigned int n = len >> 1;
    unsigned int c = 0, p = 0,i;

    DPRINTF("analyse_voice: %s %d-%d [len=%d]\n", why, start, start + len - 1,v->buf_len);

    if (start >= v->buf_len)
        return;
    if ((start + len) > v->buf_len)
        return;

    sp = (int16_t *)&v->buf->buf[start];

    min = max = *sp;

    for (i = 0; i < n; ++i) {
        if (*sp > max)
            max = *sp;
        if (*sp < min)
            min = *sp;
        if (*sp) {
            c++;
            p = i;
        }
        sp++;
    }
    sp = (int16_t *)&v->buf->buf[start];

    DPRINTF("   :[%d,%d] %d non-zero last at %d sob=%p errat=%p\n",
            min, max, c, p + start, sp, sp + p);
}
#endif

/* us */
static int
initialize_voice_pointers(UXenAudioState *s)
{
    unsigned int i;

    for (i = 0; i < NVOICEOUT; ++i) {
        UXenAudioVoiceOut *v = &s->voiceout[i];

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
        for (i = 0; i < NVOICEOUT; ++i) {
            UXenAudioVoiceOut *v = &s->voiceout[i];

            v->buf = (struct UXenAudioBuf *)(ram_ptr + v->mmio_offset);
        }
    }

    if (!s->ram_ptr)
        initialize_voice_pointers(s);

    s->ram_ptr = ram_ptr;
}

typedef int (*handle_audiodata_fun_t)(uint8_t *buf, int bytes, void *opaque);

static int
_transfer_out(UXenAudioVoiceOut *v, handle_audiodata_fun_t handle, void *opaque)
{
    uint32_t wptr;
    uint32_t sum_red, red = 0;
    uint32_t acquired = 0;

    if (!v->s->ram_ptr)
        return 0;

    wptr = v->buf->wptr;

    if (!v->running)
        return 0;

    if (!out_running(v)
         && v->omode == UXENAUDIO_OUT_HOST)
        return 0;

    if (wptr == v->rptr)
        return 0;
    if (wptr >= v->buf_len)
        return 0;

    while (wptr != v->rptr) {
        if (v->rptr < wptr)
            acquired = wptr - v->rptr;
        else
            acquired = v->buf_len - v->rptr;

        acquired &= ~(v->ww_wfx.nBlockAlign-1);

        if (!acquired)
            break;

        red = handle((uint8_t*)&v->buf->buf[v->rptr], acquired, opaque);
        if (red == 0)
            break;

        sum_red += red;
        v->rptr += red;
        v->qemu_free -= red;

        if (v->rptr >= v->buf_len)
            v->rptr = 0;
    }

    v->buf->rptr = v->rptr;
    return sum_red;
}

/* return actual number of bytes consumed */
static int
consume_samples(uint8_t *src, int bytes, void *opaque)
{
    UXenAudioVoiceOut *v = (UXenAudioVoiceOut*)opaque;
    WAVEFORMATEX *fmt;
    wasapi_voice_t wv = v->wv;
    void *buffer = 0;
    int max_frames = 0;
    int fr = bytes / v->ww_wfx.nBlockAlign;
    int fr_written = 0;
    int fr_read = 0;
    int src_rate = v->ww_wfx.nSamplesPerSec;
    int src_channels = v->ww_wfx.nChannels;
    int dst_rate, dst_channels;
    double dst_src_ratio, src_dst_ratio;

    if (!wv)
        return 0;

    wasapi_get_play_fmt(wv, &fmt);
    dst_rate = fmt->nSamplesPerSec;
    dst_channels = fmt->nChannels;
    dst_src_ratio = (double)dst_rate / src_rate;
    src_dst_ratio = 1.0 / dst_src_ratio;

    if (wasapi_lock_buffer(wv, &max_frames, &buffer))
        return 0;

    if (state->dev_mute ||
        v->buf->silence >= SILENCE_SAMPLES) {
        int dst_frames;

        /* drop resampler if any */
        if (v->resampler) {
            resampler_16_2_free(v->resampler);
            v->resampler = NULL;
        }

        /* output silence */
        v->dst_frames_remainder += fr * dst_src_ratio;
        dst_frames = (int)v->dst_frames_remainder;
        if (dst_frames > max_frames)
            dst_frames = max_frames;
        memset(buffer, 0, dst_frames * fmt->nBlockAlign);
        fr_read = fr;
        v->dst_frames_remainder -= dst_frames;
        fr_written = dst_frames;
    } else if (src_rate == dst_rate && src_channels == dst_channels) {
        /* equal rates and channels, no resampling required */
        int max_bytes = max_frames * v->ww_wfx.nBlockAlign;
        int b = bytes < max_bytes ? bytes : max_bytes;
        memcpy(buffer, src, b);
        fr_written = b / v->ww_wfx.nBlockAlign;
        fr_read = fr_written;
    } else {
        /* resample */
        if (!v->resampler)
            v->resampler = resampler_16_2_init(src_dst_ratio, dst_channels);

        if (v->resampler) {
            fr_read = resampler_16_2_add_frames(v->resampler, src, fr);
            v->dst_frames_remainder += fr_read * dst_src_ratio;

            fr_written = max_frames;
            resample_16_2(v->resampler, buffer, &fr_written);
            v->dst_frames_remainder -= fr_written;
        }
    }

    assert(fr_written <= max_frames);

    wasapi_unlock_buffer(wv, fr_written);
    v->out_sent += fr_read * fmt->nBlockAlign;

    return fr_read * v->ww_wfx.nBlockAlign;
}

static int
transfer_out(UXenAudioVoiceOut *v)
{
    return _transfer_out(v, consume_samples, v) / v->ww_wfx.nBlockAlign;
}

static void
update_voice_out_gain(UXenAudioVoiceOut *v)
{
    int mute;
    uint32_t rvol;
    uint32_t lvol;

    mute = (!v->regs.gain0) && (!v->regs.gain1);

    lvol = v->regs.gain0 >> 8;
    if (lvol > 0xff)
        lvol = 0xff;

    rvol = v->regs.gain1 >> 8;
    if (rvol > 0xff)
        rvol = 0xff;

    (void)mute;
    DPRINTF("uxenaudio: implemented setvolume %d %d %d\n", mute, lvol, rvol);
}

static void
re_start_voice_out(UXenAudioVoiceOut *v)
{
    UXenAudioState *s = v->s;

    if (!s->ram_ptr)
        return;

    if (out_running(v))
        return;

    v->running = 0;
    v->last_realpos = 0;

    DPRINTF("v->regs.fmt=%x\n", v->regs.fmt);

    if (v->regs.fmt != UXAU_V_AVFMT_44100_16_2)
        return;

    v->buf->rptr = v->rptr;
    v->buf->sts = 0;

    out_start(v, v->regs.fmt);

    update_voice_out_gain(v);

    v->running = !0;

    control_audio_notify(v->s);
}

static void
start_voice_out(UXenAudioVoiceOut *v)
{
    UXenAudioState *s = v->s;

    if (!s->ram_ptr)
        return;

    v->rptr = 0;
    v->position_offset = 0;

    re_start_voice_out(v);
}

static void
stop_voice_out(UXenAudioVoiceOut *v)
{
    UXenAudioState *s = v->s;

    if (!s->ram_ptr)
        return;

    out_stop(v, NULL);

    v->running = 0;
    v->rptr = 0;
    v->buf->rptr = v->rptr;
}

static int
uxenaudio_post_load(void *opaque, int version_id)
{
    UXenAudioState *s = opaque;
    int i;

    if (version_id < 2)
        return -EINVAL;

    pci_ram_post_load(&s->dev, version_id);

    for (i = 0; i < NVOICEOUT; ++i) {
        UXenAudioVoiceOut *v = &s->voiceout[i];

        if (v->running) {
            if (s->ram_ptr) {
                v->buf->wptr = v->wptr;
                /* transient virtual position reporting avoids
                 * position stall and rare but total wreck of
                 * restored audio stream */
                v->omode = UXENAUDIO_OUT_HOST_VIRT_POS;
                re_start_voice_out (v);
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
        for (i = 0; i < NVOICEOUT; ++i) {
            UXenAudioVoiceOut *v = &s->voiceout[i];
            v->wptr = v->buf->wptr;
            if (v->running)
                out_stop(v, &v->position_offset);
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

static const VMStateDescription vmstate_uxenaudiovoiceout = {
    .name = "uxenaudiovoiceout",
    .version_id = 2,
    .minimum_version_id = 2,
    .minimum_version_id_old = 2,
    .fields = (VMStateField[]) {
        VMSTATE_INT32 (running, UXenAudioVoiceOut),
        VMSTATE_UINT32 (wptr, UXenAudioVoiceOut),
        VMSTATE_UINT32 (rptr, UXenAudioVoiceOut),
        VMSTATE_UINT32 (position_offset, UXenAudioVoiceOut),
        VMSTATE_UINT32 (regs.gain0, UXenAudioVoiceOut),
        VMSTATE_UINT32 (regs.gain1, UXenAudioVoiceOut),
        VMSTATE_UINT32 (regs.fmt, UXenAudioVoiceOut),
        VMSTATE_INT32 (silence_mute, UXenAudioVoiceOut),
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
        VMSTATE_INT32(dev_mute, UXenAudioState),
        VMSTATE_STRUCT_ARRAY(voiceout,
                             UXenAudioState,
                             NVOICEOUT,
                             1,
                             vmstate_uxenaudiovoiceout,
                             UXenAudioVoiceOut),
        VMSTATE_END_OF_LIST ()
    }
};

static void
test_voice_lost(UXenAudioVoiceOut *v)
{
    if (v->running) {
        if (v->wv && wasapi_lost_voice(v->wv)) {
            /* voice is lost on audio endpoint changes (ex. when plugging headphones) */
            debug_printf("audio voice lost\n");
            out_stop(v, &v->position_offset);
            re_start_voice_out(v);
            v->omode = UXENAUDIO_OUT_HOST_VIRT_POS;
        }
    }
}

static uint32_t
voice_io_read(UXenAudioState *s, unsigned int vn, uint32_t offset)
{
    UXenAudioVoiceOut *v;

    uint32_t ret = ~0;

    if (!s->ram_ptr)
        return ~0;

    v = &s->voiceout[vn];

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
            ret = out_where(v);
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
voice_ctl_write(UXenAudioVoiceOut *v, uint32_t val)
{
    unsigned int run_nstop = val & UXAU_V_CTL_RUN_NSTOP;

    DPRINTF("v->running=%d run_nstop=%d\n",
            v->running, run_nstop);

    if (!(!!v->running ^ !!run_nstop))
        return;

    if (!run_nstop) {
        /* Stop */
        stop_voice_out (v);
        return;
    }

    /* Start */

    /* do we like the format*/
    start_voice_out (v);
}

static void
voice_io_write(UXenAudioState *s, unsigned int vn, uint32_t offset,
               uint32_t val)
{
    UXenAudioVoiceOut *v;

    v = &s->voiceout[vn];

    switch (offset) {
    case UXAU_V_FMT:
        v->regs.fmt = val;
        break;
    case UXAU_V_CTL:
        voice_ctl_write(v, val);
        break;
    case UXAU_V_GAIN0:
        v->regs.gain0 = val;
        update_voice_out_gain(v);
        break;
    case UXAU_V_GAIN1:
        v->regs.gain1 = val;
        update_voice_out_gain(v);
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
        return NVOICEOUT;
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

            if (vn >= NVOICEOUT)
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

    if (vn >= NVOICEOUT)
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

    for (i = 0; i < NVOICEOUT; ++i) {
        UXenAudioVoiceOut *v = &s->voiceout[i];
        stop_voice_out (v);

        v->regs.gain0 = 0x8000;
        v->regs.gain1 = 0x8000;
        v->regs.fmt = 0;

        update_voice_out_gain (v);
    }
}

static int
init_buffers(UXenAudioState *s)
{

    uint32_t offset = 0;
    unsigned int i;
    uint32_t bar_size;

    for (i = 0; i < NVOICEOUT; ++i) {
        UXenAudioVoiceOut *v = &s->voiceout[i];
        memset(v, 0, sizeof (*v));
        v->s = s;
        v->index = i;
        v->buf_len = DEFAULT_BUFLEN;
        v->mmio_offset = offset;
        v->omode = UXENAUDIO_OUT_HOST;

        out_init(v);

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
    s->control_notify_timer = new_timer_ms(vm_clock, control_audio_notify, s);

    s->ram_ptr = NULL;
    s->dev_mute = 0;

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

    return 0;
}

static int
uxenaudio_exitfn(PCIDevice *dev)
{
    UXenAudioState *s = DO_UPCAST(UXenAudioState, dev, dev);
    int i;

    for (i = 0; i < NVOICEOUT; ++i) {
        UXenAudioVoiceOut *v = &s->voiceout[i];
        out_stop(v, NULL);
        out_release(v);
    }

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
    if (state) {
        for (i = 0; i < NVOICEOUT; ++i) {
            UXenAudioVoiceOut *v = &state->voiceout[i];
            out_stop(v, NULL);
            out_release(v);
        }
    }
    wasapi_exit();
}
