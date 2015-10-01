;
;	This uses MACROS defined in {i386,amd64}/uxen_ops_wrappers.asm
;


null_wrapper MACRO func
EXTRN	&func&:NEAR
;&func&_wrapper PROC PUBLIC FRAME
;	.allocstack 0h
;	.endprolog
;	call &func&
;	ret
&func&_wrapper PROC PUBLIC
	jmp &func&
&func&_wrapper ENDP
	endm



	xmm_wrapper  uxen_printk
	xmm_wrapper  uxen_op_cpu_ipi
	xmm_wrapper  uxen_op_vcpu_ipi
	xmm_wrapper  uxen_op_vcpu_ipi_cancel
	xmm_wrapper  uxen_op_signal_idle_thread
	xmm_wrapper  uxen_op_set_vcpu_timer
	xmm_wrapper  uxen_op_get_unixtime
	xmm_wrapper  uxen_op_get_host_counter
	xmm_wrapper  uxen_op_wake_vm
	xmm_wrapper  uxen_cpu_on_selected
	xmm_wrapper  uxen_mem_map_page
	xmm_wrapper  uxen_mem_unmap_page_va
	xmm_wrapper  uxen_mem_access_page_va
	xmm_wrapper  uxen_mem_map_page_range
	xmm_wrapper  uxen_mem_unmap_page_range
	xmm_wrapper  uxen_mem_mapped_va_pfn
	xmm_wrapper  uxen_mem_mapped_pfn_va
	xmm_wrapper  uxen_op_notify_exception
	xmm_wrapper  uxen_op_notify_vram
	xmm_wrapper  uxen_op_signal_event
	xmm_wrapper  uxen_op_check_ioreq
	xmm_wrapper  uxen_memcache_check
	xmm_wrapper  map_mfn
	null_wrapper uxen_mem_user_access_ok
	xmm_wrapper  uxen_sys_signal_v4v


