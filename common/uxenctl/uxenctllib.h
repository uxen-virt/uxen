/*
 *  uxenctllib.h
 *  uxen
 *
 * Copyright 2012-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef _UXENCTLLIB_H_
#define _UXENCTLLIB_H_

#if defined(_WIN32)
#include <windows.h>
#undef ERROR

#undef errno
#define errno (({                               \
                errno_t e;                      \
                _get_errno(&e);                 \
                e;                              \
            }))

#elif defined(__APPLE__)
#include <mach/boolean.h>
typedef boolean_t BOOLEAN;

#define O_BINARY 0

#define _uxenctllib_stderr stderr
#endif

#include <stdint.h>
#include <stdio.h>

#include <uxen/uxen_desc.h>
#include <uxen_desc_sys.h>

#include <xen/sysctl.h>
typedef xen_sysctl_physinfo_t uxen_physinfo_t;

#ifdef _WIN32
void uxen_set_logfile(FILE *);

enum uxen_logtype { uxen_logtype_err = 0, uxen_logtype_warn = 1 };

typedef void (*uxen_logfnc)(const char *line, enum uxen_logtype type);
void uxen_set_log_function(uxen_logfnc fnc);
#endif

struct uxen_init_desc;
int uxen_parse_init_arg(struct uxen_init_desc *,const char *);
int uxen_manage_driver(BOOLEAN, BOOLEAN, const char *);
UXEN_HANDLE_T uxen_open(int, BOOLEAN, const char *);
void uxen_close(UXEN_HANDLE_T);
int uxen_init(UXEN_HANDLE_T, const struct uxen_init_desc *);
int uxen_shutdown(UXEN_HANDLE_T);
int uxen_wait_vm_exit(UXEN_HANDLE_T);
int uxen_load(UXEN_HANDLE_T, const char *);
int uxen_unload(UXEN_HANDLE_T);
int uxen_query_whp_mode(UXEN_HANDLE_T, uint64_t *);
int uxen_driver_changeset(UXEN_HANDLE_T, char *, size_t);
int uxen_output_version_info(UXEN_HANDLE_T, FILE *);
int uxen_trigger_keyhandler(UXEN_HANDLE_T, const char *);
int uxen_power(UXEN_HANDLE_T, uint32_t);
int uxen_hypercall(UXEN_HANDLE_T, struct uxen_hypercall_desc *);
#ifdef _WIN32
int uxen_processexit_helper(UXEN_HANDLE_T);
#endif
int uxen_create_vm(UXEN_HANDLE_T, xen_domain_handle_t, xen_domain_handle_t,
                   uint32_t, uint32_t, uint32_t, uint32_t, uint32_t *);
void *uxen_malloc(UXEN_HANDLE_T, uint32_t);
int uxen_free(UXEN_HANDLE_T, void *, uint32_t);
int uxen_mmapbatch(UXEN_HANDLE_T, struct uxen_mmapbatch_desc *);
int uxen_munmap(UXEN_HANDLE_T, struct uxen_munmap_desc *);
int uxen_target_vm(UXEN_HANDLE_T, xen_domain_handle_t);
int uxen_destroy_vm(UXEN_HANDLE_T, xen_domain_handle_t);
int uxen_execute(UXEN_HANDLE_T, struct uxen_execute_desc *);
int uxen_setup_event(UXEN_HANDLE_T, struct uxen_event_desc *);
int uxen_setup_host_event_channel(UXEN_HANDLE_T,
                                  struct uxen_event_channel_desc *);
int uxen_enum_vms(UXEN_HANDLE_T, int (*)(struct uxen_queryvm_desc *, void *),
                  void *);
#ifdef __APPLE__
int uxen_load_xnu_symbols(UXEN_HANDLE_T, const char *);
int uxen_signal_event(UXEN_HANDLE_T, void *);
int uxen_poll_event(UXEN_HANDLE_T, uint32_t *signaled);
#endif

int uxen_logging(UXEN_HANDLE_T, uint32_t, UXEN_EVENT_HANDLE_T,
                 struct uxen_logging_buffer **);
char *uxen_logging_read(struct uxen_logging_buffer *, uint64_t *, uint32_t *);

int uxen_event_init(UXEN_EVENT_HANDLE_T *);
int uxen_event_wait(UXEN_HANDLE_T, UXEN_EVENT_HANDLE_T, int);

int uxen_map_host_pages(UXEN_HANDLE_T, void *, size_t, uint64_t *);
int uxen_unmap_host_pages(UXEN_HANDLE_T, void *, size_t);

int uxen_physinfo(UXEN_HANDLE_T h, uxen_physinfo_t *up);

int uxen_log_ratelimit(UXEN_HANDLE_T, uint64_t, uint64_t);

#endif /* _UXENCTLLIB_H_ */
