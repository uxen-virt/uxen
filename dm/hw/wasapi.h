/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef WASAPI_H_
#define WASAPI_H_

struct wasapi_voice;

typedef struct wasapi_voice* wasapi_voice_t;
typedef void (*wasapi_data_cb_t)(wasapi_voice_t, void *opaque);

void wasapi_init(void);
void wasapi_exit(void);
int wasapi_init_voice(wasapi_voice_t*, int capture, WAVEFORMATEX *wf);
void wasapi_set_data_cb(wasapi_voice_t, wasapi_data_cb_t cb, void *opaque);
int wasapi_start(wasapi_voice_t);
int wasapi_stop(wasapi_voice_t);
int wasapi_get_position(wasapi_voice_t, uint64_t *ns_pos);
int wasapi_get_buffer_space(wasapi_voice_t, int *frames);
int wasapi_get_play_fmt(wasapi_voice_t v, WAVEFORMATEX **pf);
int wasapi_pb_lock_buffer(wasapi_voice_t, int *frames, void **buffer);
int wasapi_pb_unlock_buffer(wasapi_voice_t, int frames);
int wasapi_cap_next_packet_size(wasapi_voice_t, int *frames);
int wasapi_cap_lock_buffer(wasapi_voice_t, int *frames, int *silent, void **buffer);
int wasapi_cap_unlock_buffer(wasapi_voice_t, int frames);
void wasapi_mute_voice(wasapi_voice_t, int silence);
void wasapi_release_voice(wasapi_voice_t);
int wasapi_lost_voice(wasapi_voice_t);

#endif
