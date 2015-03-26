/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#define NVOICEOUT			1
#define DEFAULT_BUFLEN			32768
#define TARGET_LAG (1764*8)
#undef DEBUG_UXENAUDIO

#undef USE_QEMUS_BROKEN_AUDIO

#ifndef USE_QEMUS_BROKEN_AUDIO
#include <windows.h>
#include <mmsystem.h>
#endif

#include "wasapi.h"
#include "resampler.h"

#ifndef PACKED
#define PACKED __attribute__ ((packed))
#endif

typedef enum
{
    /* play on host, report real stream positions */
    UXENAUDIO_OUT_HOST = 0,
    /* play on host, report virtual stream positions */
    UXENAUDIO_OUT_HOST_VIRT_POS,
    /* mute on host, report virtual stream positions */
    UXENAUDIO_OUT_NULL
} uxenaudio_out_mode_t;

struct PACKED UXenAudioBuf
{
    uint32_t signature;
    uint32_t wptr;
    uint32_t rptr;
    uint32_t sts;
    uint32_t silence;
    uint32_t reserved[0x1b];
    uint8_t buf[0];
};

struct UXenAudioVoiceOutRegs_struct
{
    uint32_t gain0;
    uint32_t gain1;
    uint32_t fmt;
    uint32_t check_start;
};

struct UXenAudioVoiceOut_struct
{
    struct UXenAudioState_struct *s;
    uint32_t index;
    int running;
    uint32_t buf_len;
    uint32_t mmio_offset;
    uint32_t rptr;
    uint32_t wptr;
    uint32_t position_offset;
    uint32_t out_sent;
    struct UXenAudioVoiceOutRegs_struct regs;
    volatile struct UXenAudioBuf *buf;
    uint32_t qemu_free;
    uxenaudio_out_mode_t omode;
    int silence_mute;
    uint32_t last_realpos;
    uint64_t virt_pos_t0;
    struct resampler_16_2 *resampler;
    double dst_frames_remainder;
#ifdef USE_QEMUS_BROKEN_AUDIO
    SWVoiceOut *voice;
#else
    wasapi_voice_t wv;
    WAVEFORMATEX ww_wfx;
#endif

};
typedef struct UXenAudioVoiceOut_struct UXenAudioVoiceOut;

typedef struct UXenAudioState_struct
{
    PCIDevice dev;
    QEMUSoundCard card;
    UXenAudioVoiceOut voiceout[NVOICEOUT];
    MemoryRegion io;
    MemoryRegion buffer;

    uint32_t unused1;
    uint64_t unused2;

    void *ram_ptr;

    int dev_mute;
#ifndef USE_QEMUS_BROKEN_AUDIO
    Timer *control_notify_timer;
#endif
    DWORD saved_process_pri;
} UXenAudioState;



#include "uxaud_hw.h"


#ifdef DEBUG_UXENAUDIO
#define dolog(...) AUD_log ("uxenaudio", __VA_ARGS__)
#else
#define dolog(...)
#endif
