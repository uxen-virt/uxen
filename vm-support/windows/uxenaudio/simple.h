/*++

Copyright (c) 1997-2000  Microsoft Corporation All Rights Reserved

Module Name:

    simple.h

Abstract:

    Node and Pin numbers for simple sample.

--*/
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

#ifndef _UXENAUDIO_SIMPLE_H_
#define _UXENAUDIO_SIMPLE_H_

// Name Guid
// {946A7B1A-EBBC-422a-A81F-F07C8D40D3B4}
#define STATIC_NAME_UXENAUDIO_SIMPLE\
    0x946a7b1a, 0xebbc, 0x422a, 0xa8, 0x1f, 0xf0, 0x7c, 0x8d, 0x40, 0xd3, 0xb4
DEFINE_GUIDSTRUCT("946A7B1A-EBBC-422a-A81F-F07C8D40D3B4", NAME_UXENAUDIO_SIMPLE);
#define NAME_UXENAUDIO_SIMPLE DEFINE_GUIDNAMED(NAME_UXENAUDIO_SIMPLE)

// Pin properties.
#define MAX_OUTPUT_STREAMS          0       // Number of capture streams.
#define MAX_INPUT_STREAMS           1       // Number of render streams.
#define MAX_TOTAL_STREAMS           MAX_OUTPUT_STREAMS + MAX_INPUT_STREAMS                      

// PCM Info
#define MIN_CHANNELS                2       // Min Channels.
#define MAX_CHANNELS_PCM            2       // Max Channels.
#define MIN_BITS_PER_SAMPLE_PCM     16      // Min Bits Per Sample
#define MAX_BITS_PER_SAMPLE_PCM     16      // Max Bits Per Sample
#define MIN_SAMPLE_RATE             44100   // Min Sample Rate
#define MAX_SAMPLE_RATE             44100   // Max Sample Rate

// Wave pins
enum 
{
    KSPIN_WAVE_CAPTURE_SINK = 0,
    KSPIN_WAVE_CAPTURE_SOURCE,
    KSPIN_WAVE_RENDER_SINK, 
    KSPIN_WAVE_RENDER_SOURCE
};

// Wave Topology nodes.
enum 
{
    KSNODE_WAVE_ADC = 0,
    KSNODE_WAVE_DAC
};

// topology pins.
enum
{
    KSPIN_TOPO_WAVEOUT_SOURCE = 0,
    KSPIN_TOPO_SYNTHOUT_SOURCE,
    KSPIN_TOPO_SYNTHIN_SOURCE,
    KSPIN_TOPO_MIC_SOURCE,
    KSPIN_TOPO_LINEOUT_DEST,
    KSPIN_TOPO_WAVEIN_DEST
};

// topology nodes.
enum
{
    KSNODE_TOPO_WAVEOUT_VOLUME = 0,
    KSNODE_TOPO_WAVEOUT_MUTE,
    KSNODE_TOPO_SYNTHOUT_VOLUME,
    KSNODE_TOPO_SYNTHOUT_MUTE,
    KSNODE_TOPO_MIC_VOLUME,
    KSNODE_TOPO_SYNTHIN_VOLUME,
    KSNODE_TOPO_LINEOUT_MIX,
    KSNODE_TOPO_LINEOUT_VOLUME,
    KSNODE_TOPO_WAVEIN_MUX,

    KSNODE_TOPO_DEV_SPECIFIC_BOOL, //9
    KSNODE_TOPO_DEV_SPECIFIC_INT,  //10
    KSNODE_TOPO_DEV_SPECIFIC_UINT  //11
};

#endif

