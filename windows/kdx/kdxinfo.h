/*
 * Copyright 2015-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#define usym_sizeof(name) \
    ___usym_sizeof___##name
#define usym_offset(name, field) \
    ___usym___##name##___##field
#define usym_ptr(name, field) \
    ___usym_ptr___##name##___##field
#define usym_addr(name) \
    name##___addr
#define usym_arr(name) \
    name##___arr

#define set_usym(name, field) \
    ___usym___##name##___##field
#define set_usym_sizeof(name) \
    usym_sizeof(name)
#define set_usym_offset(name, field) \
    usym_offset(name, field)
#define set_usym_ptr(name, field) \
    usym_ptr(name, field)
#define set_usym_addr(name, field) \
    usym_addr(usym_ptr(name, field))

#define def_usym(name, field) \
    ULONG set_usym(name, field)
#define def_usym_sizeof(name) \
    ULONG set_usym_sizeof(name)
#define def_usym_offset(name, field) \
    ULONG set_usym_offset(name, field)
#define def_usym_ptr(name, field) \
    ULONG_PTR set_usym_ptr(name, field)
#define def_usym_addr(name, field) \
    ULONG_PTR set_usym_addr(name, field)

#define decl_usym(name, field) \
    extern def_usym(name, field)
#define decl_usym_sizeof(name) \
    extern def_usym_sizeof(name)
#define decl_usym_offset(name, field) \
    extern def_usym_offset(name, field)
#define decl_usym_ptr(name, field) \
    extern def_usym_ptr(name, field)
#define decl_usym_addr(name, field) \
    extern def_usym_addr(name, field)

#define usym_fetch(name, size, fail_action)                                   \
    ExtRemoteData name##_r(usym_addr(name), size);                            \
    UCHAR *name##_buf;                                                        \
    ULONG name##_ret_size;                                                    \
    name##_buf = (UCHAR *)calloc(1, size);                              \
    name##_ret_size = name##_r.ReadBuffer(name##_buf, size, FALSE);           \
    if (size != name##_ret_size) {                                            \
        Out("!!! Failed to read 0x%x bytes @ 0x%p of [%s] from target (read:0x%x)\n", \
            size, usym_addr(name), #name, name##_ret_size);                   \
        fail_action;                                                          \
    }

#define usym_fetch_struct(name, fail_action) \
    usym_fetch(name, usym_sizeof(name), fail_action)

#define usym_fetch_array(name, num, type, fail_action)                        \
    ExtRemoteData name##_r(usym_addr(name), num * sizeof(type));              \
    type *usym_arr(name);                                                     \
    ULONG name##_ret_size;                                                    \
    usym_arr(name) = (type *)calloc(num, sizeof(type));                       \
    if (!usym_arr(name)) {                                                    \
        Out("!!! Failed to allocate 0x%x bytes for [%s]\n",                   \
            num * sizeof(type), #name);                                       \
        fail_action;                                                          \
    }                                                                         \
    name##_ret_size = name##_r.ReadBuffer(usym_arr(name), num * sizeof(type), FALSE); \
    if (num * sizeof(type) != name##_ret_size) {                              \
        Out("!!! Failed to read 0x%x bytes @ 0x%p of [%s] array from target (read:0x%x)\n", \
            num * sizeof(type), usym_addr(name), #name, name##_ret_size);     \
        fail_action;                                                          \
    }
#define usym_free_arr(name) do {                                              \
        if (usym_arr(name))                                                   \
            free(usym_arr(name));                                             \
    } while (0, 0)

#define usym_read_u64(name, field) \
    (*((ULONG64*)&name##_buf[___usym___##name##___##field]))
#define usym_read_u32(name, field) \
     (*((ULONG*)&name##_buf[___usym___##name##___##field]))
#define usym_read_u16(name, field) \
    (*((USHORT*)&name##_buf[___usym___##name##___##field]))
#define usym_read_u8(name, field) \
    (*((UCHAR*)&name##_buf[___usym___##name##___##field]))

#define usym_read_ptr(name, field)                                      \
    (IsPtr64() ?                                                        \
     (*((VM_PTR_TYPE*)&name##_buf[usym_ptr(name, field)])) : \
     ((VM_PTR_TYPE)*((LONG*)&name##_buf[usym_ptr(name, field)])))
#define usym_read_ptr_offset(name, field, offset)                       \
    (IsPtr64() ?                                                        \
     (*((VM_PTR_TYPE*)&name##_buf[usym_ptr(name, field) + offset])) : \
     ((VM_PTR_TYPE)*((LONG*)&name##_buf[usym_ptr(name, field) + offset])))

#define usym_def(name, field, type) \
    type name##_##field = (*((type*)&name##_buf[___usym___##name##___##field]))
#define usym_def_u8(name, field) \
    usym_def(name, field, UCHAR)
#define usym_def_u16(name, field) \
    usym_def(name, field, USHORT)
#define usym_def_u32(name, field) \
    usym_def(name, field, ULONG)
#define usym_def_u64(name, field) \
    usym_def(name, field, ULONG64)
#define usym_def_addr(name, field) \
    VM_PTR_TYPE name##_##field##___addr = usym_read_ptr(name, field)
#define usym_def_addr_offset(var, name, field, offset)             \
    VM_PTR_TYPE var = \
        usym_read_ptr_offset(name, field, offset)

decl_usym_sizeof (page_info);

decl_usym_sizeof (domain);
decl_usym        (domain, domain_id);
decl_usym_ptr    (domain, page_list_next);
decl_usym_ptr    (domain, page_list_tail);
decl_usym_ptr    (domain, vm_info_shared);
decl_usym        (domain, max_vcpus);
decl_usym_ptr    (domain, next_in_list);
decl_usym_ptr    (domain, vcpu);

decl_usym_sizeof (vcpu);
decl_usym        (vcpu, vcpu_id);
decl_usym        (vcpu, is_running);
decl_usym        (vcpu, arch_hvm_vmx_vmcs);
decl_usym        (vcpu, arch_hvm_vmx_vmcs_ma);
decl_usym        (vcpu, arch_hvm_vmx_vmcs_shadow);
decl_usym        (vcpu, arch_hvm_vmx_active_cpu);
decl_usym        (vcpu, arch_hvm_vmx_launched);

decl_usym_offset (page_info, list_next);
decl_usym_offset (page_info, list_prev);
decl_usym_offset (page_info, count_info);
decl_usym_offset (page_info, domain);

decl_usym_offset (page_list, next);
decl_usym_offset (page_list, tail);

decl_usym_ptr    (domain, shared_info);
decl_usym_offset (domain, shared_info_gpfn);
decl_usym_offset (domain, tot_pages);
decl_usym_offset (domain, max_pages);
decl_usym_offset (domain, hidden_pages);
decl_usym_offset (domain, pod_pages);
decl_usym_offset (domain, zero_shared_pages);
decl_usym_offset (domain, tmpl_shared_pages);
decl_usym_offset (domain, xenheap_pages);
decl_usym_offset (domain, host_pages);
decl_usym_offset (domain, refcnt);
decl_usym_ptr    (domain, clone_of);
decl_usym_ptr    (domain, arch_p2m);
