/* This file is legitimately included multiple times. */
/*#ifndef __XEN_PERFC_DEFN_H__*/
/*#define __XEN_PERFC_DEFN_H__*/

PERFCOUNTER_ARRAY(exceptions,           "exceptions", 32)

PERFCOUNTER(hvm_cpu_on,                 "hvm cpu on")

#define VMX_PERF_EXIT_REASON_SIZE 56
#define VMX_PERF_VECTOR_SIZE 0x20
PERFCOUNTER_ARRAY(vmexits,              "vmexits", VMX_PERF_EXIT_REASON_SIZE)
PERFCOUNTER_ARRAY(cause_vector,         "cause vector", VMX_PERF_VECTOR_SIZE)

PERFCOUNTER(pv_vmcs_read,               "pv vmcs read")
PERFCOUNTER(pv_vmcs_write,              "pv vmcs write")
PERFCOUNTER(pv_vmcs_read_safe,          "pv vmcs read safe")
PERFCOUNTER(pv_vmcs_idem_write,         "pv vmcs idem write")
PERFCOUNTER(pv_vmcs_idem_write_miss,    "pv vmcs idem write miss")

#ifdef PERF_VMRW
#define VMX_VMWRITES_TABLE_SIZE 0x200
PERFCOUNTER_ARRAY(vmwrites,             "vmwrites", VMX_VMWRITES_TABLE_SIZE)
PERFCOUNTER_ARRAY(vmreads,              "vmreads", VMX_VMWRITES_TABLE_SIZE)
#endif	/* PERF_VMRW */

#define VMEXIT_NPF_PERFC 141
#define SVM_PERF_EXIT_REASON_SIZE (1+141)
PERFCOUNTER_ARRAY(svmexits,             "SVMexits", SVM_PERF_EXIT_REASON_SIZE)

PERFCOUNTER(seg_fixups,             "segmentation fixups")

PERFCOUNTER(apic_timer,             "apic timer interrupts")

PERFCOUNTER(domain_page_tlb_flush,  "domain page tlb flushes")

PERFCOUNTER(calls_to_mmuext_op,         "calls to mmuext_op")
PERFCOUNTER(num_mmuext_ops,             "mmuext ops")
PERFCOUNTER(calls_to_mmu_update,        "calls to mmu_update")
PERFCOUNTER(num_page_updates,           "page updates")
PERFCOUNTER(writable_mmu_updates,       "mmu_updates of writable pages")
PERFCOUNTER(calls_to_update_va,         "calls to update_va_map")
PERFCOUNTER(page_faults,            "page faults")
PERFCOUNTER(copy_user_faults,       "copy_user faults")

PERFCOUNTER(map_domain_page_count,  "map_domain_page count")
PERFCOUNTER(unmap_domain_page_count,  "unmap_domain_page count")
PERFCOUNTER(map_domain_page_global_count,  "map_domain_page_global count")
PERFCOUNTER(unmap_domain_page_global_count,  "unmap_domain_page_global count")
PERFCOUNTER(map_domain_page_direct_count,  "map_domain_page_direct count")
PERFCOUNTER(unmap_domain_page_direct_count,  "unmap_domain_page_direct count")
PERFCOUNTER(map_xen_page_count,     "map_xen_page count")
PERFCOUNTER(unmap_xen_page_count,   "unmap_xen_page count")
PERFCOUNTER(ptwr_emulations,        "writable pt emulations")

PERFCOUNTER(p2m_get_entry_walk,       "p2m get entry walk")
PERFCOUNTER(p2m_get_entry_cached,     "p2m get entry walk cached")
PERFCOUNTER(p2m_get_entry_invalidate, "p2m get entry walk invalidate")
PERFCOUNTER(p2m_set_entry_walk,       "p2m set entry walk")
PERFCOUNTER(p2m_set_entry_cached,     "p2m set entry walk cached")
PERFCOUNTER(p2m_map_ptp,              "p2m map ptp")
PERFCOUNTER(p2m_map_ptp_fallback,     "p2m map ptp fallback")
PERFCOUNTER(mapcache_hash_hit,        "mapcache hash hits")
PERFCOUNTER(mapcache_hash_miss,       "mapcache hash miss")

PERFCOUNTER(exception_fixed,        "pre-exception fixed")

PERFCOUNTER(guest_walk,            "guest pagetable walks")

PERFCOUNTER(mshv_call_sw_addr_space,    "MS Hv Switch Address Space")
PERFCOUNTER(mshv_call_flush_tlb_list,   "MS Hv Flush TLB list")
PERFCOUNTER(mshv_call_flush_tlb_all,    "MS Hv Flush TLB all")
PERFCOUNTER(mshv_call_long_wait,        "MS Hv Notify long wait")
PERFCOUNTER(mshv_rdmsr_osid,            "MS Hv rdmsr Guest OS ID")
PERFCOUNTER(mshv_rdmsr_hc_page,         "MS Hv rdmsr hypercall page")
PERFCOUNTER(mshv_rdmsr_vp_index,        "MS Hv rdmsr vp index")
PERFCOUNTER(mshv_rdmsr_time_ref_count,  "MS Hv rdmsr time reference count")
PERFCOUNTER(mshv_rdmsr_icr,             "MS Hv rdmsr icr")
PERFCOUNTER(mshv_rdmsr_tpr,             "MS Hv rdmsr tpr")
PERFCOUNTER(mshv_rdmsr_apic_assist,     "MS Hv rdmsr APIC assist")
PERFCOUNTER(mshv_rdmsr_tsc_page,        "MS Hv rdmsr TSC page")
PERFCOUNTER(mshv_rdmsr_crash_ctl,       "MS Hv rdmsr crash regisiter")
PERFCOUNTER(mshv_wrmsr_osid,            "MS Hv wrmsr Guest OS ID")
PERFCOUNTER(mshv_wrmsr_hc_page,         "MS Hv wrmsr hypercall page")
PERFCOUNTER(mshv_wrmsr_vp_index,        "MS Hv wrmsr vp index")
PERFCOUNTER(mshv_wrmsr_icr,             "MS Hv wrmsr icr")
PERFCOUNTER(mshv_wrmsr_tpr,             "MS Hv wrmsr tpr")
PERFCOUNTER(mshv_wrmsr_eoi,             "MS Hv wrmsr eoi")
PERFCOUNTER(mshv_wrmsr_apic_assist,     "MS Hv wrmsr APIC assist")
PERFCOUNTER(mshv_wrmsr_tsc_page,        "MS Hv wrmsr TSC page")
PERFCOUNTER(mshv_wrmsr_crash_regs,      "MS Hv wrmsr crash registers")

PERFCOUNTER(realmode_emulations, "realmode instructions emulated")
PERFCOUNTER(realmode_exits,      "vmexits from realmode")

PERFCOUNTER(pauseloop_exits, "vmexits from Pause-Loop Detection")

PERFCOUNTER(hostime_timer,              "Host Timer Interrupt")
PERFCOUNTER(vcpu_timer,                 "per-vcpu Timer Interrupt")

PERFCOUNTER(hostsched_halt_vm,          "Host halt VM")
PERFCOUNTER(hostsched_wake_vm,          "Host wake VM")

PERFCOUNTER(signaled_event,             "Signaled host event channel")
PERFCOUNTER(blocked_in_xen,             "Blocked in Xen to process ioreq")

PERFCOUNTER(vlapic_read,                "vlapic read mmio access")
PERFCOUNTER(vlapic_write,               "vlapic write mmio access")

PERFCOUNTER(do_TIMER_SOFTIRQ,           "TIMER SOFTIRQ")
PERFCOUNTER(do_SCHEDULE_SOFTIRQ,        "SCHEDULE SOFTIRQ")
PERFCOUNTER(do_RCU_SOFTIRQ,             "RCU SOFTIRQ")
PERFCOUNTER(do_TIME_CALIBRATE_SOFTIRQ,  "TIME CALIBRATE SOFTIRQ")
PERFCOUNTER(do_VCPU_KICK_SOFTIRQ,       "VCPU KICK SOFTIRQ")

PERFCOUNTER(external_int_exit,          "External interrupt exits")

PERFCOUNTER(HVMOP_track_dirty_vram,     "HVMOP_track_dirty_vram")
PERFCOUNTER(page_logdirty,              "log dirty page fault")

PERFCOUNTER(dpc_ipis,                   "#IPIs through DPC")

PERFCOUNTER(x86_emulate,                "instructions emulated")
PERFCOUNTER(x86_emulate_restricted,     "instructions emulated restricted")

PERFCOUNTER(compressed_pages, "compressed pages")
PERFCOUNTER(compressed_pages_split, "split compressed pages")
PERFCOUNTER(decompressed_pages, "decompressed pages")
PERFCOUNTER(decompressed_pages_split, "split decompressed pages")
PERFCOUNTER(decompressed_pages_detached, "detached decompressed pages")
PERFCOUNTER(decompressed_shareable, "decompressed pages shareable")
PERFCOUNTER(decompressed_shared, "decompressed pages shared")
PERFCOUNTER(decompressed_unshared, "decompressed pages unshared")
PERFCOUNTER(decompressed_removed, "decompressed pages removed")
PERFCOUNTER(decompressed_in_vain, "pages decompressed in vain")
PERFCOUNTER(populated_zero_pages, "populated zero pages")
PERFCOUNTER(populated_clone_pages, "populated clone pages")

PERFCOUNTER(zp_single,                  "zp single calls")
PERFCOUNTER(zp_multi,                   "zp multi calls")
PERFCOUNTER(zp_shared,                  "zp re-shared pages")
PERFCOUNTER(zp_zeroed,                  "zp zeroed pages")

PERFCOUNTER(pc0,                        "pc0")
PERFCOUNTER(pc1,                        "pc1")
PERFCOUNTER(pc2,                        "pc2")
PERFCOUNTER(pc3,                        "pc3")
PERFCOUNTER(pc4,                        "pc4")
PERFCOUNTER(pc5,                        "pc5")
PERFCOUNTER(pc6,                        "pc6")
PERFCOUNTER(pc7,                        "pc7")
PERFCOUNTER(pc8,                        "pc8")
PERFCOUNTER(pc9,                        "pc9")
PERFCOUNTER(pc10,                       "pc10")
PERFCOUNTER(pc11,                       "pc11")
PERFCOUNTER(pc12,                       "pc12")
PERFCOUNTER(pc13,                       "pc13")
PERFCOUNTER(pc14,                       "pc14")
PERFCOUNTER(pc15,                       "pc15")
PERFCOUNTER(pc16,                       "pc16")
PERFCOUNTER(pc17,                       "pc17")
PERFCOUNTER(pc18,                       "pc18")
PERFCOUNTER(pc19,                       "pc19")

#ifdef CONFIG_X86_EMUL_PERFC
#include "perfc_x86.h"
#endif

/*#endif*/ /* __XEN_PERFC_DEFN_H__ */
