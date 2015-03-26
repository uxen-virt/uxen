/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_AUDIO_CTRL_H_
#define _UXEN_AUDIO_CTRL_H_

#ifdef HAS_AUDIO
void uxenaudio_mute(int mute);
void uxenaudio_exit(void);
#endif

#endif /* _UXEN_AUDIO_CTRL_H_ */
