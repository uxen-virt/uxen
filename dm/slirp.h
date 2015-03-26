/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#ifndef _SLIRP_H_
#define _SLIRP_H_

#include "qemu_glue.h"

int net_init_slirp(QemuOpts *opts,
                   Monitor *mon,
                   const char *name,
                   VLANState *vlan);

// void net_slirp_hostfwd_add(Monitor *mon, const QDict *qdict);
// void net_slirp_hostfwd_remove(Monitor *mon, const QDict *qdict);

// int net_slirp_redir(const char *redir_str);

// int net_slirp_parse_legacy(QemuOptsList *opts_list, const char *optarg, int *ret);

// int net_slirp_smb(const char *exported_dir);

// void do_info_usernet(Monitor *mon);

#ifdef SLIRP_THREADED
int slirp_loop_init(HANDLE evt, void (*fill)(int*), void (*poll)(void*), void* opaque);
#endif

#ifdef SLIRP_DUMP_PCAP
extern int pcap_user_enable;
void slirp_pcap_usertrig(void);
int slirp_pcap_global_dump(void *opaque, const char *id, const char *opt,
                      dict d, void *command_opaque);
#endif

#endif /* _SLIRP_H_ */
