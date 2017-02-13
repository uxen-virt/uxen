/*
 * Copyright 2013-2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#define NVOICEOUT			1
#define NVOICEIN                        1
#define NVOICE                          (NVOICEOUT+NVOICEIN)
#define AUDIO_QUANTUM_BYTES             1764
#define DEFAULT_BUFLEN                  (AUDIO_QUANTUM_BYTES*30)
#define TARGET_LAG                      (AUDIO_QUANTUM_BYTES*8)
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

struct UXenAudioVoiceRegs_struct
{
    uint32_t gain0;
    uint32_t gain1;
    uint32_t fmt;
    uint32_t check_start;
};

struct UXenAudioVoice_struct
{
    struct UXenAudioState_struct *s;
    uint32_t index;
    int capture;
    int running;
    uint32_t buf_len;
    uint32_t mmio_offset;
    uint32_t rptr;
    uint32_t wptr;
    uint32_t frames_written;
    uint32_t position_offset;
    struct UXenAudioVoiceRegs_struct regs;
    volatile struct UXenAudioBuf *buf;
    uxenaudio_out_mode_t omode;
    uint32_t last_realpos;
    uint64_t virt_pos_t0;
    uint32_t virt_pos_max;
    struct resampler_16_2 *resampler;
    double dst_frames_remainder;
#ifdef USE_QEMUS_BROKEN_AUDIO
    SWVoiceOut *voice;
#else
    wasapi_voice_t wv;
    WAVEFORMATEX guest_fmt;
#endif

};
typedef struct UXenAudioVoice_struct UXenAudioVoice;

typedef struct UXenAudioState_struct
{
    PCIDevice dev;
    QEMUSoundCard card;
    UXenAudioVoice voices[NVOICE];
    MemoryRegion io;
    MemoryRegion buffer;

    uint32_t unused1;
    uint64_t unused2;

    void *ram_ptr;

    int dev_mute;
    int capture_enabled;
    int last_out_used;
    int last_inp_used;
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
