/* export.c */
V4V_DLL_EXPORT int uxen_v4v_ring_create(v4v_addr_t *dst, domid_t partner);
V4V_DLL_EXPORT uxen_v4v_ring_handle_t *uxen_v4v_ring_bind (uint32_t local_port, domid_t partner_domain, uint32_t ring_size, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
V4V_DLL_EXPORT void uxen_v4v_ring_free (uxen_v4v_ring_handle_t *ring);
V4V_DLL_EXPORT ssize_t uxen_v4v_send_async(v4v_addr_t *src, v4v_addr_t *dst, void *buf, uint32_t len, uint32_t protocol, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
V4V_DLL_EXPORT ssize_t uxen_v4v_sendv_async(v4v_addr_t *src, v4v_addr_t *dst, v4v_iov_t *iov, uint32_t niov, uint32_t protocol, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
V4V_DLL_EXPORT ssize_t uxen_v4v_send_from_ring_async(uxen_v4v_ring_handle_t *ring, v4v_addr_t *dst, void *buf, uint32_t len, uint32_t protocol, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
V4V_DLL_EXPORT ssize_t uxen_v4v_sendv_from_ring_async(uxen_v4v_ring_handle_t *ring, v4v_addr_t *dst, v4v_iov_t *iov, uint32_t niov, uint32_t protocol, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
V4V_DLL_EXPORT BOOLEAN uxen_v4v_cancel_async(v4v_addr_t *dst, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
V4V_DLL_EXPORT ssize_t uxen_v4v_send(v4v_addr_t *src, v4v_addr_t *dst, void *buf, uint32_t len, uint32_t protocol);
V4V_DLL_EXPORT ssize_t uxen_v4v_sendv(v4v_addr_t *src, v4v_addr_t *dst, v4v_iov_t *iov, uint32_t niov, uint32_t protocol);
V4V_DLL_EXPORT ssize_t uxen_v4v_send_from_ring(uxen_v4v_ring_handle_t *ring, v4v_addr_t *dst, void *buf, uint32_t len, uint32_t protocol);
V4V_DLL_EXPORT ssize_t uxen_v4v_sendv_from_ring(uxen_v4v_ring_handle_t *ring, v4v_addr_t *dst, v4v_iov_t *iov, uint32_t niov, uint32_t protocol);
V4V_DLL_EXPORT ssize_t uxen_v4v_recv (uxen_v4v_ring_handle_t *ring, v4v_addr_t *from, void *buf, int buflen, uint32_t *protocol);
V4V_DLL_EXPORT void uxen_v4v_test(void);
V4V_DLL_EXPORT ssize_t uxen_v4v_poke(v4v_addr_t *dst);
V4V_DLL_EXPORT void uxen_v4v_notify(void);
V4V_DLL_EXPORT void uxen_v4vlib_unset_resume_dpc(KDPC *dpc, void *arg1);
V4V_DLL_EXPORT void uxen_v4vlib_set_resume_dpc(KDPC *dpc, void *arg1);



/* gh_create.c */
ULONG32 gh_v4v_release_context(xenv4v_extension_t *pde, xenv4v_context_t *ctx);
ULONG32 gh_v4v_add_ref_context(xenv4v_extension_t *pde, xenv4v_context_t *ctx);
void gh_v4v_put_all_contexts(xenv4v_extension_t *pde, xenv4v_context_t **ctx_list, ULONG count);
xenv4v_context_t **gh_v4v_get_all_contexts(xenv4v_extension_t *pde, ULONG *count_out);
xenv4v_context_t *gh_v4v_get_context_by_connection_id(xenv4v_extension_t *pde, ULONG64 conn_id);
void gh_v4v_cancel_all_file_irps(xenv4v_extension_t *pde, FILE_OBJECT *pfo);
NTSTATUS NTAPI gh_v4v_dispatch_create(PDEVICE_OBJECT fdo, PIRP irp);
NTSTATUS NTAPI gh_v4v_dispatch_cleanup(PDEVICE_OBJECT fdo, PIRP irp);
NTSTATUS NTAPI gh_v4v_dispatch_close(PDEVICE_OBJECT fdo, PIRP irp);

/* gh_csq.c */
NTSTATUS NTAPI gh_v4v_csq_insert_irp_ex(PIO_CSQ csq, PIRP irp, PVOID insertContext);
void NTAPI gh_v4v_csq_remove_irp(PIO_CSQ csq, PIRP irp);
PIRP NTAPI gh_v4v_csq_peek_next_irp(PIO_CSQ csq, PIRP irp, PVOID peekContext);
void NTAPI gh_v4v_csq_acquire_lock(PIO_CSQ csq, PKIRQL irqlOut);
void NTAPI gh_v4v_csq_release_lock(PIO_CSQ csq, KIRQL irql);
void NTAPI gh_v4v_csq_complete_canceled_irp(PIO_CSQ csq, PIRP irp);
v4v_ring_data_t *gh_v4v_copy_destination_ring_data(xenv4v_extension_t *pde, ULONG *gh_count);

/* gh_hypercall.c */
NTSTATUS gh_v4v_register_ring(xenv4v_extension_t *pde, xenv4v_ring_t *robj);
NTSTATUS gh_v4v_unregister_ring(xenv4v_ring_t *robj);
NTSTATUS gh_v4v_create_ring(v4v_addr_t *dst, domid_t partner);
NTSTATUS gh_v4v_notify(v4v_ring_data_t *ringData);
NTSTATUS gh_v4v_debug();
NTSTATUS gh_v4v_send(v4v_addr_t *src, v4v_addr_t *dest, ULONG32 protocol, void *buf, ULONG32 length, ULONG32 *writtenOut);
NTSTATUS gh_v4v_send_vec(v4v_addr_t *src, v4v_addr_t *dest, v4v_iov_t *iovec, ULONG32 nent, ULONG32 protocol, ULONG32 *writtenOut);

/* gh_ioctl.c */
ULONG gh_v4v_get_accept_private(ULONG code, void *buffer, v4v_accept_private_t **ppriv, struct v4v_addr **ppeer);
void gh_v4v_do_accepts(xenv4v_extension_t *pde, xenv4v_context_t *ctx);
NTSTATUS NTAPI gh_v4v_dispatch_device_control(PDEVICE_OBJECT fdo, PIRP irp);

/* gh_ring.c */
void gh_v4v_dump_ring(v4v_ring_t *r);
void gh_v4v_recover_ring(xenv4v_context_t *ctx);
xenv4v_ring_t *gh_v4v_allocate_ring(uint32_t ring_length);
ULONG32 gh_v4v_add_ref_ring(xenv4v_extension_t *pde, xenv4v_ring_t *robj);
ULONG32 gh_v4v_release_ring(xenv4v_extension_t *pde, xenv4v_ring_t *robj);
uint32_t gh_v4v_random_port(xenv4v_extension_t *pde);
uint32_t gh_v4v_spare_port_number(xenv4v_extension_t *pde, uint32_t port);
BOOLEAN gh_v4v_ring_id_in_use(xenv4v_extension_t *pde, struct v4v_ring_id *id);
void gh_v4v_link_to_ring_list(xenv4v_extension_t *pde, xenv4v_ring_t *robj);

/* gh_rw.c */
void gh_v4v_flush_accepter_queue_data(xenv4v_context_t *ctx);
void gh_v4v_disconnect_stream_and_signal(xenv4v_extension_t *pde, xenv4v_context_t *ctx);
NTSTATUS gh_v4v_process_notify(xenv4v_extension_t *pde);
void gh_v4v_process_context_writes(xenv4v_extension_t *pde, xenv4v_context_t *ctx);
NTSTATUS NTAPI gh_v4v_dispatch_write(PDEVICE_OBJECT fdo, PIRP irp);
VOID gh_v4v_process_context_reads(xenv4v_extension_t *pde, xenv4v_context_t *ctx);
NTSTATUS NTAPI gh_v4v_dispatch_read(PDEVICE_OBJECT fdo, PIRP irp);

/* gh_send.c */
void gh_v4v_send_reset(xenv4v_extension_t *pde, xenv4v_context_t *ctx, uint32_t conn_id, v4v_addr_t *dst, BOOLEAN noq);
NTSTATUS gh_v4v_send_acknowledge(xenv4v_extension_t *pde, xenv4v_context_t *ctx);

/* gh_xenv4v.c */
void gh_v4v_start_connection_timer(xenv4v_extension_t *pde);
void gh_v4v_stop_connection_timer(xenv4v_extension_t *pde, BOOLEAN immediate);
void gh_signaled(void);
NTSTATUS gh_destroy_device(PDRIVER_OBJECT driver_object);
NTSTATUS gh_create_device(PDRIVER_OBJECT driver_object);

/* hypercall.c */
int uxen_v4v_can_make_hypercall(void);
void *uxen_v4v_hypercall_with_priv(int privileged, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5, void *arg6);
void *uxen_v4v_hypercall(void *arg1, void *arg2, void *arg3, void *arg4, void *arg5, void *arg6);

/* main.c */
NTSTATUS DllInitialize(PUNICODE_STRING RegistryPath);
NTSTATUS DllUnload(void);
NTSTATUS DriverEntry(DRIVER_OBJECT *Driver, UNICODE_STRING *ServicesKey);

/* pde.c */
void uxen_v4v_install_pde(xenv4v_extension_t *pde);
xenv4v_extension_t *uxen_v4v_get_pde(void);
void uxen_v4v_put_pde(xenv4v_extension_t *pde);
xenv4v_extension_t *uxen_v4v_remove_pde(void);

/* plumbing.c */
V4V_DLL_EXPORT void uxen_v4vlib_set_state_bar_ptr(struct uxp_state_bar **a);
V4V_DLL_EXPORT void uxen_v4vlib_we_are_dom0(void);
V4V_DLL_EXPORT void uxen_v4vlib_set_hypercall_func(uxen_v4vlib_hypercall_func_t *func);
V4V_DLL_EXPORT void uxen_v4vlib_set_page_notify_func(uxen_v4vlib_page_notify_func_t *func);
V4V_DLL_EXPORT void uxen_v4vlib_deliver_signal(void);
V4V_DLL_EXPORT void uxen_v4vlib_init_driver(PDRIVER_OBJECT pdo);
V4V_DLL_EXPORT void uxen_v4vlib_free_driver(void);
uintptr_t v4v_call_page_notify(v4v_pfn_t *pfn, uint32_t npfn, int map);

/* notify.c */
void uxen_v4v_notify_enqueue (uint32_t len, v4v_addr_t *dst, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
BOOLEAN uxen_v4v_notify_dequeue (v4v_addr_t *dst, uxen_v4v_callback_t *callback, void *callback_data1, void *callback_data2);
unsigned int uxen_v4v_notify_count (xenv4v_extension_t *pde);
unsigned int uxen_v4v_notify_fill_ring_data (xenv4v_extension_t *pde, v4v_ring_data_ent_t *ring_data, unsigned int count);
void uxen_v4v_notify_process_ring_data (xenv4v_extension_t *pde, v4v_ring_data_ent_t *ring_data, unsigned int count);
void uxen_v4v_notify_thread(void *context);

/* resume.c */
void uxen_v4v_check_resume(void);
void uxen_v4v_resume(void);

/* ring.c */
void uxen_v4v_reregister_all_rings(void);
void uxen_v4v_send_read_callbacks(xenv4v_extension_t *pde);
NTSTATUS uxen_v4v_mapring(xenv4v_ring_t *robj, v4v_mapring_values_t *mr);

/* shared.c */
extern uxen_v4vlib_hypercall_func_t *hypercall_func;
extern uxen_v4vlib_page_notify_func_t *page_notify_func;
extern struct uxp_state_bar **state_bar_ptr;
extern xenv4v_extension_t *uxen_v4v_pde;
extern KSPIN_LOCK uxen_v4v_pde_lock;
extern int uxen_v4v_am_dom0;
extern KDPC *uxen_v4vlib_resume_dpcs[];
extern void *uxen_v4vlib_resume_dpcs_arg1[];
void uxen_v4v_init_shared(void);

/* util.c */

/* hook.c */
void uxen_v4vlib_init_driver_hook(PDRIVER_OBJECT pdo);
void uxen_v4vlib_free_driver_unhook(void);
void uxen_v4v_set_notify_fdo (PDEVICE_OBJECT fdo);

