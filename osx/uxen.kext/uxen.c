/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "uxen.h"

#include <mach/mach_types.h>

#include <stdarg.h>

#include <libkern/OSAtomic.h>
#include <libkern/libkern.h>

#include <rbtree/rbtree.h>

#include <xen/domctl.h>
#include <xen/hvm/hvm_op.h>
#include <xen/xen.h>

#define UXEN_DEFINE_SYMBOLS_PROTO
#include <uxen/uxen_link.h>

#include "build_info.h"

struct device_extension _uxen_devext;
struct device_extension *uxen_devext = &_uxen_devext;
static kauth_scope_t uxen_kauth_scope = NULL;

OSMallocTag uxen_malloc_tag = NULL;

lck_grp_t *uxen_lck_grp;
static lck_mtx_t *uxen_lck = NULL;

uint8_t *uxen_hv = NULL;
uint32_t uxen_size = 0;

enum uxen_mode {
    MODE_IDLE,
    MODE_SYMS_LOADED,
    MODE_SHUTDOWN,
    MODE_LOADED,
    MODE_INITIALIZED
};
static enum uxen_mode uxen_mode = MODE_IDLE;

static int uxen_module_start_finish(void);

/*
 * To create a uxen user group:
 *
 * dseditgroup -o create \
       -g BD0208C5-CB53-4DB9-9077-CA700FC90AFF org.uxen.uxen_access
 *
 * To add a specific user to the uxen user group:
 *
 * dseditgroup -o edit -a <username> -t user org.uxen.uxen_access
 *
 * To create a uxen admin group:
 *
 * dseditgroup -o create \
       -g 0541E68D-4FD0-4E28-9402-DC7E3F005E30 org.uxen.uxen_admin_access
 *
 * To add a specific user to the uxen admin group:
 *
 * dseditgroup -o edit -a <username> -t user org.uxen.uxen_admin_access
 *
 */
static guid_t uxen_kauth_user_group_guid = {
    .g_guid = { 0xbd, 0x02, 0x08, 0xc5, 0xcb, 0x53, 0x4d, 0xb9,
                0x90, 0x77, 0xca, 0x70, 0x0f, 0xc9, 0x0a, 0xff },
};
static guid_t uxen_kauth_admin_group_guid = {
    .g_guid = { 0x05, 0x41, 0xe6, 0x8d, 0x4f, 0xd0, 0x4e, 0x28,
                0x94, 0x02, 0xdc, 0x7e, 0x3f, 0x00, 0x5e, 0x30 },
};

#define UXEN_KAUTH_SCOPE "org.uxen.kauth.scope"

static void
prepare_release_fd_assoc(struct fd_assoc *fda)
{

    if (fda->events.lck) {
        struct notification_event *ev;
        lck_spin_lock(fda->events.lck);
        while ((ev = TAILQ_FIRST(&fda->events.queue))) {
            TAILQ_REMOVE(&fda->events.queue, ev, entry);
            ev->id = -1;
        }
        lck_spin_unlock(fda->events.lck);
        lck_spin_free(fda->events.lck, uxen_lck_grp);
        fda->events.lck = NULL;
    }
    if (fda->user_events.lck) {
        struct user_notification_event *ev;
        lck_mtx_lock(fda->user_events.lck);
        while ((ev = (struct user_notification_event *)
                    RB_TREE_MIN(&fda->user_events.events_rbtree))) {
            rb_tree_remove_node(&fda->user_events.events_rbtree, ev);
            ev->notify_address = NULL;
        }
        lck_mtx_unlock(fda->user_events.lck);
        lck_mtx_free(fda->user_events.lck, uxen_lck_grp);
        fda->user_events.lck = NULL;
    }
    if (fda->user_mappings.lck) {
        user_free_all_user_mappings(fda);
        lck_spin_free(fda->user_mappings.lck, uxen_lck_grp);
        fda->user_mappings.lck = NULL;
    }
}

static void
release_fd_assoc(struct fd_assoc *fda)
{
    struct vm_info *vmi;

    /* unmap logging buffer before freeing vmi,
     * in case logging is per-vm logging */
    if (fda->logging_mapping.user_mapping) {
        logging_unmap(&fda->logging_mapping, fda);
        fda->logging_mapping.user_mapping = NULL;
    }

    vmi = fda->vmi;
    if (vmi) {
        uxen_lock();
        if (vmi->vmi_mdm_fda == fda)
            mdm_clear_all(vmi);
        prepare_release_fd_assoc(fda);
        if (fda->vmi_destroy_on_close)
            vmi->vmi_marked_for_destroy = 1;
        OSDecrementAtomic(&vmi->vmi_active_references);
        uxen_vmi_cleanup_vm(vmi);
        uxen_unlock();
    }
}

typedef void *user_notification_event_key;

static intptr_t
notification_user_events_compare_key(void *ctx, const void *b, const void *key)
{
    const struct user_notification_event * const pnp =
        (const struct user_notification_event * const)b;
    const user_notification_event_key * const fhp =
        (const user_notification_event_key * const)key;

    if (pnp->notify_address > *fhp)
        return 1;
    else if (pnp->notify_address < *fhp)
        return -1;
    return 0;
}

static intptr_t
notification_user_events_compare_nodes(void *ctx, const void *parent,
                                       const void *node)
{
    const struct user_notification_event * const np =
        (const struct user_notification_event * const)node;

    return notification_user_events_compare_key(ctx, parent,
                                                &np->notify_address);
}

static const rb_tree_ops_t notification_user_events_rbtree_ops = {
    .rbto_compare_nodes = notification_user_events_compare_nodes,
    .rbto_compare_key = notification_user_events_compare_key,
    .rbto_node_offset = offsetof(struct user_notification_event, rbnode),
    .rbto_context = NULL
};


int
uxen_open(struct fd_assoc *fda, task_t task)
{
    int ret;

    memset((void *)fda, 0, sizeof(struct fd_assoc));

    ret = kauth_authorize_action(uxen_kauth_scope, kauth_cred_get(),
                                 UXEN_KAUTH_OP_OPEN, (uintptr_t)fda, 0, 0, 0);
    if (!ret)
        fda->task = task;

    return ret;
}

void
uxen_close(struct fd_assoc *fda)
{

    release_fd_assoc(fda);
}

#define IOCTL_ADMIN_CHECK(id) do {                                      \
        if (!fda->admin_access) {                                       \
            fail_msg("(" id "): access denied");                        \
            ret = EPERM;                                                \
            goto out;                                                   \
        }                                                               \
    } while (0)

#define IOCTL_VM_ADMIN_CHECK(id) do {                                   \
        if (!fda->admin_access && !fda->vmi_owner) {                    \
            fail_msg("(" id "): access denied");                        \
            ret = EPERM;                                                \
            goto out;                                                   \
        }                                                               \
    } while (0)

#define SET_MODE(m)                             \
    uxen_mode = (m);
#define CHECK_MODE(m, id) do {                                  \
        if (uxen_mode < (m)) {                                  \
            fail_msg("(" id "): invalid sequence");             \
            ret = EINVAL;                                       \
            goto out;                                           \
        }                                                       \
    } while (0)
#define CHECK_MODE_NOT(m, id) do {                              \
        if (uxen_mode >= (m))                                   \
            goto out;                                           \
    } while (0)

#define CHECK_INPUT_BUFFER(name, arg) do {                              \
        if (in_len < sizeof(arg) || in_buf == NULL) {                   \
            fail_msg("(" name "): input arguments");                    \
            ret = EINVAL;                                               \
            goto out;                                                   \
        }                                                               \
    } while (0)

#define CHECK_OUTPUT_BUFFER(name, arg) do {                             \
        if (out_len < sizeof(arg) || out_buf == NULL) {                 \
            fail_msg("(" name "): output arguments");                   \
            ret = EINVAL;                                               \
            goto out;                                                   \
        }                                                               \
    } while (0)

#define CHECK_VMI(name, vmi) do {                                       \
        if (!vmi) {                                                     \
            fail_msg("(" name "): no target vm");                       \
            ret = EEXIST;                                               \
            goto out;                                                   \
        }                                                               \
    } while (0)

static int
init_fd_assoc_events(const char *ident, struct fd_assoc *fda)
{
    int ret = 0;

    if (!fda->events.lck) {
        fda->events.last_id = 0;
        fda->events.lck = lck_spin_alloc_init(uxen_lck_grp, LCK_ATTR_NULL);
        if (!fda->events.lck) {
            fail_msg("%s: events lck alloc failed", ident);
            ret = ENOMEM;
            goto out;
        }
        TAILQ_INIT(&fda->events.queue);
    }
    if (!fda->user_events.lck) {
        fda->user_events.lck = lck_mtx_alloc_init(uxen_lck_grp, LCK_ATTR_NULL);
        if (!fda->user_events.lck) {
            fail_msg("%s: user events lck alloc failed", ident);
            ret = ENOMEM;
            goto out;
        }
        rb_tree_init(&fda->user_events.events_rbtree,
                     &notification_user_events_rbtree_ops);
    }

  out:
    return ret;
}

static int
init_fd_assoc_user_mappings(const char *ident, struct fd_assoc *fda)
{
    int ret = 0;

    if (!fda->user_mappings.lck) {
        fda->user_mappings.lck = lck_spin_alloc_init(uxen_lck_grp,
                                                     LCK_ATTR_NULL);
        if (!fda->user_mappings.lck) {
            fail_msg("%s: user mappings lck alloc failed", ident);
            ret = ENOMEM;
            goto out;
        }
        rb_tree_init(&fda->user_mappings.rbtree,
                     &user_mapping_rbtree_ops);
        fda->user_mappings.vmi = fda->vmi;
    }

  out:
    return ret;
}

#define OP_CALL(name, fn, arg_type, ...) do {                   \
        CHECK_MODE(MODE_INITIALIZED, name);                     \
        CHECK_INPUT_BUFFER(name, arg_type);                     \
        ret = fn((arg_type *)in_buf, ##__VA_ARGS__);            \
        if (ret) {                                              \
            fail_msg("%s: %s failed: %d", name, #fn, ret);      \
            goto out;                                           \
        }                                                       \
    } while (0)

#define DOM0_CALL(name, fn, arg_type, ...) do {                 \
        CHECK_MODE(MODE_INITIALIZED, name);                     \
        CHECK_INPUT_BUFFER(name, arg_type);                     \
        ret = fn((arg_type *)in_buf, ##__VA_ARGS__);            \
        if (ret) {                                              \
            fail_msg("%s: %s failed: %d", name, #fn, ret);      \
            goto out;                                           \
        };                                                      \
    } while (0)


int
uxen_ioctl(u_long cmd, struct fd_assoc *fda, struct vm_info *vmi,
           void *in_buf, size_t in_len, void *out_buf, size_t out_len)
{
    int ret = 0;

    switch (cmd) {
    case UXENVERSION:
        CHECK_OUTPUT_BUFFER("UXENVERSION", struct uxen_version_desc);
        IOCTL_ADMIN_CHECK("UXENVERSION");
        ret = uxen_op_version((struct uxen_version_desc *)out_buf);
        break;
    case UXENLOAD:
#if !defined(__UXEN_EMBEDDED__)
        CHECK_MODE_NOT(MODE_SHUTDOWN, "UXENLOAD");
        CHECK_MODE(MODE_SYMS_LOADED, "UXENLOAD");
        CHECK_INPUT_BUFFER("UXENLOAD", struct uxen_load_desc);
        IOCTL_ADMIN_CHECK("UXENLOAD");
        ret = uxen_load((struct uxen_load_desc *)in_buf);
        if (ret)
            break;
        SET_MODE(MODE_LOADED);
#endif
        break;
    case UXENLOADSYMS:
        CHECK_MODE_NOT(MODE_SHUTDOWN, "UXENLOADSYMS");
        CHECK_INPUT_BUFFER("UXENLOADSYMS", struct uxen_syms_desc);
        IOCTL_ADMIN_CHECK("UXENLOADSYMS");
        ret = uxen_load_xnu_symbols((struct uxen_syms_desc *)in_buf);
        if (ret)
            break;
        init_xnu_symbols();
        ret = uxen_module_start_finish();
        if (ret)
            break;
        SET_MODE(MODE_SYMS_LOADED);
        break;
    case UXENUNLOAD:
        CHECK_MODE(MODE_SHUTDOWN, "UXENUNLOAD");
        IOCTL_ADMIN_CHECK("UXENUNLOAD");
        ret = uxen_unload();
        SET_MODE(MODE_IDLE);
        break;
    case UXENINIT:
        CHECK_MODE_NOT(MODE_INITIALIZED, "UXENINIT");
#if !defined(__UXEN_EMBEDDED__)
        CHECK_MODE(MODE_LOADED, "UXENINIT");
#endif
        ret = uxen_op_init(fda);
        if (ret)
            break;
        SET_MODE(MODE_INITIALIZED);
        break;
    case UXENSHUTDOWN:
        CHECK_MODE(MODE_INITIALIZED, "UXENSHUTDOWN");
        IOCTL_ADMIN_CHECK("UXENSHUTDOWN");
        ret = uxen_op_shutdown();
        if (ret)
            break;
        SET_MODE(MODE_SHUTDOWN);
        break;
    case UXENWAITVMEXIT:
        CHECK_MODE(MODE_LOADED, "UXENWAITVMEXIT");
        IOCTL_ADMIN_CHECK("UXENWAITVMEXIT");
        ret = uxen_op_wait_vm_exit();
        break;
    case UXENKEYHANDLER:
        IOCTL_ADMIN_CHECK("UXENKEYHANDLER");
        OP_CALL("UXENKEYHANDLER", uxen_op_keyhandler, char,
                UXEN_MAX_KEYHANDLER_KEYS);
        break;
    case UXENHYPERCALL: {
        struct uxen_hypercall_desc *uhd =
            (struct uxen_hypercall_desc *)in_buf;
        CHECK_MODE(MODE_INITIALIZED, "UXENHYPERCALL");
        CHECK_INPUT_BUFFER("UXENHYPERCALL", struct uxen_hypercall_desc);
        ret = uxen_hypercall(uhd, SNOOP_USER,
                             &vmi->vmi_shared, &fda->user_mappings,
                             (fda->admin_access ? UXEN_ADMIN_HYPERCALL : 0) |
                             (fda->vmi_owner ? UXEN_VMI_OWNER : 0));
        if (ret < 0) {
            ret = uxen_translate_xen_errno(ret);
            fail_msg("UXENHYPERCALL: uxen_do_hypercall failed: %d", ret);
            goto out;
        }
        uhd->uhd_op = ret;
        ret = 0;
    }
        break;
    case UXENMALLOC:
        ret = init_fd_assoc_user_mappings("UXENMALLOC", fda);
        if (ret)
            goto out;
        OP_CALL("UXENMALLOC", uxen_mem_malloc, struct uxen_malloc_desc, fda);
        break;
    case UXENFREE:
        ret = init_fd_assoc_user_mappings("UXENFREE", fda);
        if (ret)
            goto out;
        OP_CALL("UXENFREE", uxen_mem_free, struct uxen_free_desc, fda);
        break;
    case UXENMMAPBATCH:
        IOCTL_VM_ADMIN_CHECK("UXENMMAPBATCH");
        CHECK_VMI("UXENMMAPBATCH", vmi);
        ret = init_fd_assoc_user_mappings("UXENMMAPBATCH", fda);
        if (ret)
            goto out;
        OP_CALL("UXENMMAPBATCH", uxen_mem_mmapbatch,
                struct uxen_mmapbatch_desc, fda);
        break;
    case UXENMUNMAP:
        IOCTL_VM_ADMIN_CHECK("UXENMUNMAP");
        CHECK_VMI("UXENMUNMAP", vmi);
        ret = init_fd_assoc_user_mappings("UXENMUNMAP", fda);
        if (ret)
            goto out;
        OP_CALL("UXENMUNMAP", uxen_mem_munmap, struct uxen_munmap_desc, fda);
        break;
    case UXENCREATEVM:
        DOM0_CALL("UXENCREATEVM", uxen_op_create_vm,
                  struct uxen_createvm_desc, fda);
        break;
    case UXENTARGETVM:
        IOCTL_ADMIN_CHECK("UXENTARGETVM");
        DOM0_CALL("UXENTARGETVM", uxen_op_target_vm,
                  struct uxen_targetvm_desc, fda);
        break;
    case UXENDESTROYVM:
        DOM0_CALL("UXENDESTROYVM", uxen_op_destroy_vm,
                  struct uxen_destroyvm_desc, fda);
        break;
    case UXENEXECUTE:
        IOCTL_VM_ADMIN_CHECK("UXENEXECUTE");
        CHECK_VMI("UXENEXECUTE", vmi);
        OP_CALL("UXENEXECUTE", uxen_op_execute,
                struct uxen_execute_desc, vmi);
        break;
    case UXENSETEVENT:
        IOCTL_VM_ADMIN_CHECK("UXENSETEVENT");
        CHECK_VMI("UXENSETEVENT", vmi);
        ret = init_fd_assoc_events("UXENSETEVENT", fda);
        if (ret)
            goto out;
        OP_CALL("UXENSETEVENT", uxen_op_set_event,
                struct uxen_event_desc, vmi, &fda->events);
        break;
    case UXENSETEVENTCHANNEL:
        IOCTL_VM_ADMIN_CHECK("UXENSETEVENTCHANNEL");
        CHECK_VMI("UXENSETEVENTCHANNEL", vmi);
        ret = init_fd_assoc_events("UXENSETEVENTCHANNEL", fda);
        if (ret)
            goto out;
        DOM0_CALL("UXENSETEVENTCHANNEL", uxen_op_set_event_channel,
                  struct uxen_event_channel_desc, vmi, fda,
                  &fda->events, &fda->user_events);
        break;
    case UXENPOLLEVENT:
        CHECK_MODE(MODE_INITIALIZED, "UXENPOLLEVENT");
        CHECK_OUTPUT_BUFFER("UXENPOLLEVENT", struct uxen_event_poll_desc);
        IOCTL_VM_ADMIN_CHECK("UXENPOLLEVENT");
        ret = init_fd_assoc_events("UXENPOLLEVENT", fda);
        if (ret)
            goto out;
        ret = uxen_op_poll_event((struct uxen_event_poll_desc *)out_buf,
                                 &fda->events);
        if (ret) {
            fail_msg("UXENPOLLEVENT: uxen_op_poll_event failed: %d", ret);
            goto out;
        }
        break;
    case UXENSIGNALEVENT:
        IOCTL_VM_ADMIN_CHECK("UXENSIGNALEVENT");
        CHECK_VMI("UXENSIGNALEVENT", vmi);
        ret = init_fd_assoc_events("UXENSIGNALEVENT", fda);
        if (ret)
            goto out;
        OP_CALL("UXENSIGNALEVENT", uxen_op_signal_event, void *,
                &fda->user_events);
        break;
    case UXENMEMCACHEINIT: {

        IOCTL_VM_ADMIN_CHECK("UXENMEMCACHEINIT");
        CHECK_VMI("UXENMEMCACHEINIT", vmi);
        ret = init_fd_assoc_user_mappings("UXENMEMCACHEINIT", fda);
        if (ret)
            goto out;

        OP_CALL("UXENMEMCACHEINIT", mdm_init,
                struct uxen_memcacheinit_desc, fda);
        break;
        }
    case UXENMEMCACHEMAP: {
        IOCTL_VM_ADMIN_CHECK("UXENMEMCACHEMAP");
        CHECK_VMI("UXENMEMCACHEMAP", vmi);
        OP_CALL("UUXENMEMCACHEMAP", mdm_map,
                struct uxen_memcachemap_desc, fda);
        break;
    }
    case UXENQUERYVM:
        IOCTL_ADMIN_CHECK("UXENQUERYVM");
        DOM0_CALL("UXENQUERYVM", uxen_op_query_vm, struct uxen_queryvm_desc);
        break;
    case UXENPOWER:
        CHECK_MODE(MODE_INITIALIZED, "UXENPOWER");
        IOCTL_ADMIN_CHECK("UXENPOWER");
        dprintk("%s: UXENPOWER not implemented\n", __FUNCTION__);
        ret = EINVAL;
        break;
    case UXENLOGGING:
        CHECK_MODE(MODE_INITIALIZED, "UXENLOGGING");
        IOCTL_VM_ADMIN_CHECK("UXENLOGGING");
        ret = init_fd_assoc_events("UXENLOGGING", fda);
        if (ret)
            goto out;
        ret = init_fd_assoc_user_mappings("UXENLOGGING", fda);
        if (ret)
            goto out;
        CHECK_INPUT_BUFFER("UXENLOGGING", struct uxen_logging_desc);
        ret = uxen_op_logging((struct uxen_logging_desc *)in_buf, fda);
        if (ret)
            goto out;
        break;
    case UXENMAPHOSTPAGES:
        IOCTL_VM_ADMIN_CHECK("UXENMAPHOSTPAGES");
        CHECK_VMI("UXENMAPHOSTPAGES", vmi);
        ret = init_fd_assoc_user_mappings("UXENMAPHOSTPAGES", fda);
        if (ret)
            goto out;
        OP_CALL("UXENMAPHOSTPAGES", uxen_op_map_host_pages,
                struct uxen_map_host_pages_desc, fda);
        break;
    case UXENUNMAPHOSTPAGES:
        IOCTL_VM_ADMIN_CHECK("UXENUNMAPHOSTPAGES");
        CHECK_VMI("UXENUNMAPHOSTPAGES", vmi);
        ret = init_fd_assoc_user_mappings("UXENUNMAPHOSTPAGES", fda);
        if (ret)
            goto out;
        OP_CALL("UXENUNMAPHOSTPAGES", uxen_op_unmap_host_pages,
                struct uxen_map_host_pages_desc, fda);
        break;
    default:
        dprintk("%s: unknown ioctl %lx\n", __FUNCTION__, cmd);
        ret = EINVAL;
    }

  out:
    return ret;
}

static int
uxen_kauth_scope_listener(kauth_cred_t credential,
                          void *idata,
                          kauth_action_t action,
                          uintptr_t arg0,
                          uintptr_t arg1,
                          uintptr_t arg2,
                          uintptr_t arg3)
{
    int ret = KAUTH_RESULT_DENY;
    uid_t uid = kauth_cred_getuid(credential);
    int is_member;

    switch (action) {
    case UXEN_KAUTH_OP_OPEN: {
        struct fd_assoc *fda = (struct fd_assoc *)arg0;
        gid_t gid;
        int _ret;

        fda->admin_access = false;

        gid = 0;
        _ret = kauth_cred_guid2gid(&uxen_kauth_admin_group_guid, &gid);
        /* group exists, also allow admin access if member */
        if (uid == UID_ROOT ||
            (!_ret && !(gid & 0x80000000) &&
             !kauth_cred_ismember_guid(credential,
                                       &uxen_kauth_admin_group_guid,
                                       &is_member) && is_member)) {
            fda->admin_access = true;
            ret = KAUTH_RESULT_ALLOW;
            break;
        }

        gid = 0;
        _ret = kauth_cred_guid2gid(&uxen_kauth_user_group_guid, &gid);
        if (!_ret && !(gid & 0x80000000)) {
            /* group exists, only allow user access if member */
            if (!kauth_cred_ismember_guid(credential,
                                          &uxen_kauth_user_group_guid,
                                          &is_member) && is_member)
                ret = KAUTH_RESULT_ALLOW;
            break;
        }

        ret = KAUTH_RESULT_ALLOW;
        break;
    }
    default:
        break;
    }

    if (ret == KAUTH_RESULT_DENY)
        fail_msg("denied action: %d", action);

    return ret;
}

int
uxen_driver_load(void)
{
    int ret = EINVAL;

    uxen_kauth_scope = kauth_register_scope(UXEN_KAUTH_SCOPE,
                                            uxen_kauth_scope_listener,
                                            NULL);
    if (!uxen_kauth_scope)
        goto out;

    uxen_malloc_tag = OSMalloc_Tagalloc("UXEN", OSMT_DEFAULT);
    if (uxen_malloc_tag == NULL)
        goto out;

    uxen_lck_grp = lck_grp_alloc_init("UXEN", LCK_GRP_ATTR_NULL);
    if (!uxen_lck_grp)
        goto out;

    uxen_lck = lck_mtx_alloc_init(uxen_lck_grp, LCK_ATTR_NULL);
    if (!uxen_lck)
        goto out;

    ret = uxen_print_init();
    if (ret)
        goto out;

    memset(uxen_devext, 0, sizeof(struct device_extension));

    ret = fast_event_init(&uxen_devext->de_init_done, 0);
    if (ret) {
        fail_msg("event_init de_init_done failed");
        goto out;
    }

    ret = fast_event_init(&uxen_devext->de_shutdown_done, 1);
    if (ret) {
        fail_msg("event_init de_shutdown_done failed");
        goto out;
    }

    ret = fast_event_init(&uxen_devext->de_vm_cleanup_event, 0);
    if (ret) {
        fail_msg("event_init de_vm_cleanup_event failed");
        goto out;
    }

    ret = fast_event_init(&uxen_devext->de_resume_event, 0);
    if (ret) {
        fail_msg("event_init de_resume_event failed");
        goto out;
    }

    ret = fast_event_init(&uxen_devext->de_suspend_event, 0);
    if (ret) {
        fail_msg("event_init de_suspend_event failed");
        goto out;
    }

    ret = uxen_pm_init();
    if (ret) {
        fail_msg("uxen_pm_init failed");
        goto out;
    }

  out:
    if (ret) {
        logging_free(NULL);

        fast_event_destroy(&uxen_devext->de_suspend_event);
        fast_event_destroy(&uxen_devext->de_resume_event);
        fast_event_destroy(&uxen_devext->de_vm_cleanup_event);
        fast_event_destroy(&uxen_devext->de_shutdown_done);
        fast_event_destroy(&uxen_devext->de_init_done);

        uxen_print_exit();

        if (uxen_lck) {
            lck_mtx_free(uxen_lck, uxen_lck_grp);
            uxen_lck = NULL;
        }

        if (uxen_lck_grp) {
            lck_grp_free(uxen_lck_grp);
            uxen_lck_grp = NULL;
        }

        if (uxen_malloc_tag) {
            OSMalloc_Tagfree(uxen_malloc_tag);
            uxen_malloc_tag = NULL;
        }

        if (uxen_kauth_scope) {
            kauth_deregister_scope(uxen_kauth_scope);
            uxen_kauth_scope = NULL;
        }
    }
    return ret;
}

void
uxen_driver_unload(void)
{
    if (uxen_mode >= MODE_INITIALIZED)
        uxen_op_shutdown();

    if (uxen_mode >= MODE_SHUTDOWN)
        uxen_unload();

    SET_MODE(MODE_IDLE);

    uxen_pm_cleanup();

    logging_free(NULL);

    uxen_mem_exit();

#ifdef DEBUG_MALLOC
    debug_check_malloc();
#endif

    fast_event_destroy(&uxen_devext->de_suspend_event);
    fast_event_destroy(&uxen_devext->de_resume_event);
    fast_event_destroy(&uxen_devext->de_vm_cleanup_event);
    fast_event_destroy(&uxen_devext->de_shutdown_done);
    fast_event_destroy(&uxen_devext->de_init_done);

    lck_mtx_free(uxen_lck, uxen_lck_grp);
    lck_grp_free(uxen_lck_grp);
    OSMalloc_Tagfree(uxen_malloc_tag);
    kauth_deregister_scope(uxen_kauth_scope);

    dprintk("kernel extension unloaded\n");

    uxen_print_exit();
}

static int
uxen_module_start_finish(void)
{
    int ret;

    ret = uxen_mem_init();
    if (ret) {
        fail_msg("uxen_mem_init failed");
        goto out;
    }

    ret = logging_init(NULL, 0);
    if (ret) {
        fail_msg("logging_init failed");
        goto out;
    }

  out:
    return ret;
}

void
uxen_lock(void)
{

    uxen_cpu_pin_current();
    lck_mtx_lock(uxen_lck);
}

void
uxen_unlock(void)
{

    lck_mtx_unlock(uxen_lck);
    uxen_cpu_unpin();
}

void
uxen_exec_dom0_start(void)
{

    uxen_cpu_pin_current();
}

void
uxen_exec_dom0_end(void)
{

    uxen_cpu_unpin();
}

intptr_t
uxen_hypercall(struct uxen_hypercall_desc *uhd, int snoop_mode,
               struct vm_info_shared *vmis, void *user_access_opaque,
               uint32_t privileged)
{
    intptr_t ret = 0;

    while (/* CONSTCOND */ 1) {
        map_pfn_array_pool_fill();

        uxen_exec_dom0_start();
        uxen_call(ret =, -EINVAL, _uxen_snoop_hypercall(uhd, snoop_mode),
                  uxen_do_hypercall, uhd, vmis, user_access_opaque,
                  privileged);
        uxen_exec_dom0_end();

        if (ret == -ECONTINUATION && vmis && vmis->vmi_wait_event) {
            struct user_notification_event *completed =
                (struct user_notification_event *)vmis->vmi_wait_event;

            /* dprintk("%s: continuation\n", __FUNCTION__); */
            ret = fast_event_wait(&completed->fast_ev,
                                  EVENT_INTERRUPTIBLE, EVENT_NO_TIMEOUT);
            if (ret) {
                fail_msg("%s: %d: wait interrupted", __FUNCTION__,
                         vmis->vmi_domid);
                ret = -EINTR;
                break;
            }
            fast_event_clear(&completed->fast_ev);
            vmis->vmi_wait_event = NULL;
            /* dprintk("%s: continuation signaled\n", __FUNCTION__); */
            continue;
        }

        if (ret == -ECONTINUATION)
            continue;

        break;
    }

    return ret;
}

intptr_t
uxen_dom0_hypercall(struct vm_info_shared *vmis, void *user_access_opaque,
                    uint32_t privileged, uint64_t op, ...)
{
    struct uxen_hypercall_desc uhd;
    int idx, n_arg;
    int snoop_mode;
    va_list ap;
    intptr_t ret;

    switch (op) {
    case __HYPERVISOR_domctl:
        n_arg = 1;
        break;
    case __HYPERVISOR_event_channel_op:
        n_arg = 2;
        break;
    case __HYPERVISOR_memory_op:
        n_arg = 2;
        break;
    case __HYPERVISOR_sysctl:
        n_arg = 1;
        break;
    default:
        fail_msg("unknown hypercall op: %"PRId64, op);
        return EINVAL;
    }

    snoop_mode = (privileged & UXEN_UNRESTRICTED_ACCESS_HYPERCALL) ?
        SNOOP_KERNEL : SNOOP_USER;

    memset(&uhd, 0, sizeof(struct uxen_hypercall_desc));

    uhd.uhd_op = op;
    va_start(ap, op);
    for (idx = 0; idx < n_arg; idx++)
        uhd.uhd_arg[idx] = va_arg(ap, uintptr_t);
    va_end(ap);

    ret = uxen_hypercall(&uhd, snoop_mode, vmis, user_access_opaque,
                         privileged);

    return ret;
}

int32_t
_uxen_snoop_hypercall(void *udata, int mode)
{
    int ret;
    uint32_t pages = 0;
    struct uxen_hypercall_desc *uhd = (struct uxen_hypercall_desc *)udata;
    int (*copy)(const user_addr_t, void *, size_t);

    switch (mode) {
    case SNOOP_USER:
        copy = copyin_user;
        break;
    case SNOOP_KERNEL:
        copy = copyin_kernel;
        break;
    default:
        fail_msg("unknown mode %d", mode);
        return -EINVAL;
    }

    switch(uhd->uhd_op) {
    case __HYPERVISOR_memory_op:
        switch (uhd->uhd_arg[0]) {
        case XENMEM_populate_physmap: {
            xen_memory_reservation_t res;

            ret = copy(uhd->uhd_arg[1], &res, sizeof(res));
            if (ret)
                return -ret;
            if (res.mem_flags & XENMEMF_populate_on_demand)
                break;
            if (((1ULL << res.extent_order) * res.nr_extents) >=
                (1ULL << 31)) {
                fail_msg("size assert: %"PRIx64,
                         (1ULL << res.extent_order) * res.nr_extents);
                return -ENOMEM;
            }
            pages += (1 << res.extent_order) * (uint32_t)res.nr_extents;
            mm_dprintk("snooped populate_physmap: %d [%lld (%d:%x)]\n", pages,
                       res.nr_extents, res.extent_order, res.mem_flags);
            break;
        }
        case XENMEM_translate_gpfn_list_for_map: {
            xen_translate_gpfn_list_for_map_t list;

            ret = copy(uhd->uhd_arg[1], &list, sizeof(list));
            if (ret)
                return -ret;
            if (list.gpfns_end - list.gpfns_start > 1024)
                return -EINVAL;
            pages += list.gpfns_end - list.gpfns_start;
            if (pages > 1)
                mm_dprintk("snooped translate gpfn list for map: %d\n", pages);
            break;
        }
        }
        break;
    case __HYPERVISOR_hvm_op:
        switch (uhd->uhd_arg[0]) {
        case HVMOP_set_mem_type: {
            struct xen_hvm_set_mem_type a;
            ret = copy(uhd->uhd_arg[1], &a, sizeof(a));
            if (ret)
                return -ret;
            if (a.nr > 1024)
                return -EINVAL;
            pages += a.nr;
            if (pages > 1)
                mm_dprintk("snooped hvm_op set_mem_type: %d\n", pages);
            break;
        }
        }
        break;
    default:
        break;
    }

    return pages + HYPERCALL_RESERVE;
}

int
copyin_user(const user_addr_t uaddr, void *kaddr, size_t size)
{

    return copyin(uaddr, kaddr, size);
}

int
copyin_kernel(const user_addr_t uaddr, void *kaddr, size_t size)
{
    int ret = 0;

    memcpy(kaddr, (const void *)uaddr, size);

    return ret;
}


static intptr_t
pointer_map_compare_key(void *ctx, const void *b, const void *key)
{
    const struct pointer_map * const pnp = (const struct pointer_map * const)b;
    const pointer_map_key * const fhp = (const pointer_map_key * const)key;

    if (pnp->key > *fhp)
        return 1;
    else if (pnp->key < *fhp)
        return -1;
    return 0;
}

static intptr_t
pointer_map_compare_nodes(void *ctx, const void *parent, const void *node)
{
    const struct pointer_map * const np =
        (const struct pointer_map * const)node;

    return pointer_map_compare_key(ctx, parent, &np->key);
}

const rb_tree_ops_t pointer_map_rbtree_ops = {
    .rbto_compare_nodes = pointer_map_compare_nodes,
    .rbto_compare_key = pointer_map_compare_key,
    .rbto_node_offset = offsetof(struct pointer_map, rbnode),
    .rbto_context = NULL
};

