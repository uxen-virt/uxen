/*
 * symbols-dummy.c: dummy symbol-table definitions for the inital partial
 *                  link of the hypervisor image.
 */

#include <xen/config.h>
#include <xen/types.h>

#ifdef SYMBOLS_ORIGIN
const unsigned int symbols_offsets[1];
#else
const unsigned long symbols_addresses[1];
#endif
const unsigned int symbols_num_syms;
const u8 symbols_names[1];

const u8 symbols_token_table[1];
const u16 symbols_token_index[1];

const unsigned int symbols_markers[1];

#if defined(__x86_64__)
#define UI_fn(fn) ui_ ## fn
#else  /* __x86_64__ */
#define UI_fn(fn) _ui_ ## fn
#endif  /* __x86_64__ */

void UI_fn(check_ioreq)(void) {}
void UI_fn(get_host_counter)(void) {}
void UI_fn(get_unixtime)(void) {}
void UI_fn(host_needs_preempt)(void) {}
void UI_fn(kick_cpu)(void) {}
void UI_fn(kick_vcpu)(void) {}
void UI_fn(kick_vcpu_cancel)(void) {}
void UI_fn(map_mfn)(void) {}
void UI_fn(map_page_global)(void) {}
void UI_fn(map_page_range)(void) {}
void UI_fn(mapped_global_va_pfn)(void) {}
void UI_fn(notify_exception)(void) {}
void UI_fn(notify_vram)(void) {}
void UI_fn(on_selected_cpus)(void) {}
void UI_fn(printf)(void) {}
void UI_fn(set_timer_vcpu)(void) {}
void UI_fn(signal_event)(void) {}
void UI_fn(signal_idle_thread)(void) {}
void UI_fn(signal_v4v)(void) {}
void UI_fn(unmap_page_global_va)(void) {}
void UI_fn(unmap_page_range)(void) {}
void UI_fn(user_access_ok)(void) {}
void UI_fn(wake_vm)(void) {}
