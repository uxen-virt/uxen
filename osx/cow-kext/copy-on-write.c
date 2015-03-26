//
//  copy-on-write.c
//  copy-on-write
//
/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include "copy-on-write-shared.h"

#include <mach/mach_types.h>

struct socket;
struct vfs_attr;
struct sockopt;
struct msg;
struct proc;
struct componentname;
struct knote;
struct sockaddr;
struct msqid_kernel;
struct vnode_attr;

#include <sys/proc.h>
#include <sys/file.h>
#include <security/mac_policy.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <pexpert/pexpert.h>
#include <sys/mount.h>
#include <stdbool.h>
#include <string.h>
#include <libkern/OSMalloc.h>
#include <vfs/vfs_support.h>
#include <kern/locks.h>
#include <sys/kern_control.h>
#include <libkern/OSAtomic.h>
#include <sys/kauth.h>
#include <sys/xattr.h>

#include "dlist.h"

// from xnu/bsd/sys/decmpfs.h
#define DECMPFS_XATTR_NAME "com.apple.decmpfs"

// undeclared in MAC headers, but very useful indeed
int mac_schedule_userret(void);


// change these to reflect the file to be copied-on-write, and destination

static const char copy_suffix[] = ".copy";

static bool policy_registered = false;
static mac_policy_handle_t policy_handle;
static struct mac_policy_conf copy_on_write_mac_policy_conf;
static kauth_listener_t cow_vnode_listener = NULL;
static uint32_t cow_kauth_listener_invocations = 0; // Apple-recommended hack, see TN2127

// Open-addressed hash table of CNIDs with linear probing
struct cnid_table_entry;
struct cnid_table {
    copy_on_write_file_id_t *entries;
    uint32_t num_entries;
};
typedef struct cnid_table cnid_table_t;

/* vnode listener doesn't provide much info, so obtain it in the MAC callback
 * and hold onto it until the thread returns to userspace. */
enum cow_auth_action {
    COW_ACTION_SET_DECMPFS_XATTR = 0x1,
    COW_ACTION_DEL_DECMPFS_XATTR = 0x2,
    COW_ACTION_SET_COMPRESSED_FLAG = 0x4,
};
struct cow_registered_auth_action {
  thread_t thread;
  uint32_t actions;
};
static const unsigned COW_MAX_ACTIONS = 64;
struct cow_auth_action_registry {
  struct cow_registered_auth_action actions[COW_MAX_ACTIONS];
  unsigned num_actions;
};


struct cow {
    OSMallocTag_t tag;

    lck_grp_t *lock_group;
    lck_rw_t *lock;
    lck_rw_t *table_lock;

    kern_ctl_ref ctl_ref;

    char *copy_target_dir;
    uint32_t copy_target_dir_len;       // not including terminating character - important when freeing

    // file IDs to watch
    cnid_table_t cnid_table;
    // list of files being copied
    genc_dlist_head_t active_list;
    // userspace connections
    genc_dlist_head_t conn_list;

    // waiting hardlinking workers
    genc_dlist_head_t hardlink_worker_list;

    // copy files using a root context
    vfs_context_t copy_vfs_ctx;

    struct cow_auth_action_registry auth_actions;
};
typedef struct cow cow_t;

static cow_t cow_ctx;

static bool init(cow_t * cow);
static void destroy(cow_t * cow);

//kern_return_t copy_on_write_start(kmod_info_t * ki, void *d);
//kern_return_t copy_on_write_stop(kmod_info_t * ki, void *d);

static errno_t cow_ctl_connect(kern_ctl_ref kctlref,
                               struct sockaddr_ctl *sac, void **unitinfo);
static errno_t cow_ctl_disconnect(kern_ctl_ref kctlref, u_int32_t unit,
                                  void *unitinfo);

static errno_t cow_ctl_setopt(kern_ctl_ref kctlref, u_int32_t unit,
                              void *unitinfo, int opt, void *data,
                              size_t len);
static errno_t cow_ctl_getopt(kern_ctl_ref kctlref, u_int32_t unit,
                              void *unitinfo, int opt, void *data,
                              size_t * len);

static struct kern_ctl_reg kern_ctl = {
    .ctl_name = BR_COPY_ON_WRITE_KCONTROL_SOCKET_NAME,
    .ctl_id = 0,
    .ctl_unit = 0,
    .ctl_flags = CTL_FLAG_PRIVILEGED,
    .ctl_sendsize = 0,
    .ctl_recvsize = 0,
    .ctl_connect = cow_ctl_connect,
    .ctl_disconnect = cow_ctl_disconnect,
    .ctl_send = NULL,
    .ctl_setopt = cow_ctl_setopt,
    .ctl_getopt = cow_ctl_getopt
};

static kern_return_t deregister_fileop_callbacks(void)
{
    if (cow_vnode_listener) {
        kauth_unlisten_scope(cow_vnode_listener);
        cow_vnode_listener = NULL;
        do { // wait for any existing listener invocations to return, see TN2127
            struct timespec ts = {1, 0};
            msleep(&cow_kauth_listener_invocations, NULL, PUSER, "com_bromium_cow_kauth_listener", &ts);
        } while (cow_kauth_listener_invocations > 0);
    }

    if (policy_registered) {
        kern_return_t res = mac_policy_unregister(policy_handle);
        if (res != KERN_SUCCESS)
            return res;
        policy_registered = false;
    }
    return KERN_SUCCESS;
}

static int cow_vnode_check(
	kauth_cred_t _credential,
	void *_idata,
	kauth_action_t _action,
	uintptr_t _arg0,
	uintptr_t _arg1,
	uintptr_t _arg2,
	uintptr_t _arg3);

kern_return_t copy_on_write_start(kmod_info_t * ki, void *d)
{
    if (!init(&cow_ctx))
        return KERN_FAILURE;
    int res = ctl_register(&kern_ctl, &cow_ctx.ctl_ref);
    if (res == 0) {
        /* register for 2 file operation notification/authorisation callback mechanisms:
         * MAC typically happens first, then built-in OS permission checks, then
         * kauth listeners. Kauth listeners are less granular, so we still need
         * MAC for some things. */
        res =
            mac_policy_register(&copy_on_write_mac_policy_conf,
                                &policy_handle, d);
        if (res == 0) {
            policy_registered = true;

            cow_vnode_listener =
                kauth_listen_scope(KAUTH_SCOPE_VNODE, cow_vnode_check, NULL /* arbitrary */);
            if (cow_vnode_listener) {
                return 0;
            }
            res = KERN_FAILURE;
        }
        deregister_fileop_callbacks();
        ctl_deregister(cow_ctx.ctl_ref);
    }
    destroy(&cow_ctx);
    return res;
}

kern_return_t copy_on_write_stop(kmod_info_t * ki, void *d)
{
    kern_return_t res = deregister_fileop_callbacks();
    if (res == KERN_SUCCESS) {
        res = ctl_deregister(cow_ctx.ctl_ref);
        if (res == 0)
            destroy(&cow_ctx);
    }
    return res;
}

extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);

#ifndef XCODEBUILD
KMOD_EXPLICIT_DECL(net.bromium.kext.cow, "1.0.0d1", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = copy_on_write_start;
__private_extern__ kmod_stop_func_t *_antimain = copy_on_write_stop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__;
#endif

static int vnode_check_setextattr(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	const char *name,
	struct uio *uio);
static int vnode_check_deleteextattr(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *vlabel,
	const char *name);
static void thread_userret(
	struct thread *thread);

static int vnode_check_setflags(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	u_long flags);

static struct mac_policy_ops ops = {
    .mpo_vnode_check_setextattr = vnode_check_setextattr,
    .mpo_vnode_check_deleteextattr = vnode_check_deleteextattr,
    .mpo_thread_userret = thread_userret,
    .mpo_vnode_check_setflags = vnode_check_setflags,
};

static struct mac_policy_conf copy_on_write_mac_policy_conf = {
    .mpc_name = "net.bromium.CopyOnWrite",
    .mpc_fullname = "Bromium Copy On Write",
    .mpc_labelnames = NULL,
    .mpc_labelname_count = 0,
    .mpc_ops = &ops,
    .mpc_loadtime_flags = MPC_LOADTIME_FLAG_UNLOADOK,
    .mpc_field_off = NULL,
    .mpc_runtime_flags = 0
};

enum cnid_table_entry_state {
    ENTRY_EMPTY,
    ENTRY_NO_WATCH,
    ENTRY_WATCH_FOR_WRITE,
    ENTRY_WATCH_FOR_UNLINK_OR_WRITE
};

_Static_assert(sizeof(copy_on_write_file_id_t) == 8,
               "Ensure we're not doing anything silly to blow up the hash table size");


static bool init_cnid_table_with_cnids(cnid_table_t * out_table,
                                       struct copy_on_write_file_id *cnids,
                                       uint32_t num_cnids,
                                       OSMallocTag_t tag)
{
    uint32_t sz = sizeof(struct copy_on_write_file_id) * num_cnids;
    copy_on_write_file_id_t *table = OSMalloc(sz, tag);
    size_t i;
    uint64_t last = 0;
    if (!table)
        return false;
    for (i = 0; i < num_cnids; ++i) {
        uint64_t cnid = cnids[i].cnid;

        /* Input must be sorted. */
        if (!(last < cnid)) {
            printf("table not sorted %llu %llu!\n", last, cnid);
            OSFree(table, sz, tag);
            return false;
        }
        last = cnid;
        table[i] = cnids[i];
        table[i].state = ENTRY_WATCH_FOR_UNLINK_OR_WRITE;
    }
    out_table->entries = table;
    out_table->num_entries = num_cnids;
    return true;
}

static copy_on_write_file_id_t *cnid_table_find_entry(cnid_table_t * table,
                                                 uint64_t cnid)
{
    /* Binary search over sorted list of cnids. */
    size_t half;
    size_t len = table->num_entries;
    copy_on_write_file_id_t *first = table->entries;
    copy_on_write_file_id_t *middle;
    copy_on_write_file_id_t *end = first + len;

    while (len > 0) {
        half = len >> 1;
        middle = first + half;
        if (middle->cnid < cnid) {
            first = middle + 1;
            len = len - half - 1;
        } else
            len = half;
    }
    return (first != end && first->cnid == cnid) ? first : NULL;
}

static void cnid_table_free(cnid_table_t * table, OSMallocTag_t tag)
{
    if (table->entries) {
        uint32_t sz = sizeof(table->entries[0]) * table->num_entries;
        OSFree(table->entries, sz, tag);
    }
    table->entries = NULL;
    table->num_entries = 0;
}

static void lock_table_writing(cow_t * cow);
static void unlock_table_writing(cow_t * cow);
static void lock_table_reading(cow_t * cow);
static void unlock_table_reading(cow_t * cow);

static void lock_writing(cow_t * cow);
static void unlock_writing(cow_t * cow);
static void sleep_and_unlock(cow_t * cow, event_t event);
static void sleep_and_relock_writing(cow_t * cow, event_t event);
static wait_result_t sleep_and_relock_writing_interruptible(cow_t * cow,
                                                            event_t event);
static void wakeup_all(cow_t * cow, event_t event);
static void lock_reading(cow_t * cow);
static void unlock_reading(cow_t * cow);
static wait_result_t sleep_with_timeout_and_relock_writing(cow_t * cow,
                                                           event_t event,
                                                           uint32_t
                                                           timeout_usec);
static void wakeup_one_thread(cow_t * cow, event_t event);

/*
#define STRINGIFY_(X) #X
#define STRINGIFY(X) STRINGIFY_(X)
#define LINESTR() STRINGIFY(__LINE__)
#define lock_writing(c) ({ kprintf("write locking @ " LINESTR() "\n"); lock_writing((c)); kprintf("write locked  @ " LINESTR() "\n"); })
#define lock_reading(c) ({ kprintf(" read locking @ " LINESTR() "\n"); lock_reading((c)); kprintf(" read locked  @ " LINESTR() "\n"); })
#define unlock_writing(c) ({ kprintf("write unlocking @ " LINESTR() "\n"); unlock_writing((c)); })
#define unlock_reading(c) ({ kprintf(" read unlocking @ " LINESTR() "\n"); unlock_reading((c)); })
#define sleep_and_unlock(c, e) ({ kprintf("unlock & sleep @ " LINESTR() " on %p\n", (e)); sleep_and_unlock(c, (e)); })
#define wakeup_all(c, e)       ({ kprintf("waking all     @ " LINESTR() " on %p\n", (e)); wakeup_all(c, (e)); })
*/

struct cow_conn {
    genc_dlist_head_t conn_list_head;
    // needed when sending
    uint32_t unit;

    uint32_t num_dropped_messages;

    bool wants_file_messages;
    cow_t *cow;
};
typedef struct cow_conn cow_conn_t;
static errno_t cow_ctl_connect(kern_ctl_ref kctlref,
                               struct sockaddr_ctl *sac, void **unitinfo)
{
    printf("cow_ctl_connect()\n");
    cow_conn_t *conn = OSMalloc(sizeof(cow_conn_t), cow_ctx.tag);
    if (!conn)
        return ENOMEM;

    lock_writing(&cow_ctx);
    conn->cow = &cow_ctx;
    conn->unit = sac->sc_unit;
    conn->wants_file_messages = false;
    conn->num_dropped_messages = 0;
    genc_dlist_insert_after(&conn->conn_list_head, &cow_ctx.conn_list);
    unlock_writing(&cow_ctx);

    *unitinfo = conn;
    printf("cow_ctl_connect() completed\n");
    return 0;
}

static errno_t cow_ctl_disconnect(kern_ctl_ref kctlref, u_int32_t unit,
                                  void *unitinfo)
{
    printf("cow_ctl_disconnect()\n");
    cow_conn_t *conn = unitinfo;
    lock_writing(conn->cow);
    genc_dlist_remove(&conn->conn_list_head);
    unlock_writing(conn->cow);
    OSFree(conn, sizeof(*conn), conn->cow->tag);
    return 0;
}

static void cow_free_copy_target_dir(cow_t * cow)
{
    if (cow->copy_target_dir) {
        OSFree(cow->copy_target_dir, cow->copy_target_dir_len + 1,
               cow->tag);
        cow->copy_target_dir = NULL;
        cow->copy_target_dir_len = 0;
    }
}

// Created and added to list when userspace worker registers for a link request
struct cow_waiting_hardlink_worker {
    genc_dlist_head_t hardlink_worker_head;

    copy_on_write_link_request_t *link_request;

    /* a sleeping hardlink worker can return because of 3 things:
     * - a file needs linking
     * - kext is shutting down
     * - process interrupted
     * The latter is obvious from the sleep return value; the other 2 are distinguished here:
     */
    bool shutting_down;

    cow_conn_t *connection;
};
typedef struct cow_waiting_hardlink_worker cow_waiting_hardlink_worker_t;

static bool active_file_matches_cnid(genc_dlist_head_t * head,
                                     void *opaque_cnid);
static int report_link_result(cow_t * cow, cow_conn_t * conn,
                              const copy_on_write_link_response_t * res);

static errno_t cow_ctl_setopt(kern_ctl_ref kctlref, u_int32_t unit,
                              void *unitinfo, int opt, void *data,
                              size_t len)
{
    printf("cow_ctl_setopt(unit = %u, opt = %u, data = %p, len = %lu)\n",
           unit, opt, data, len);
    cow_conn_t *conn = unitinfo;
    cow_t *cow = conn->cow;
    switch (opt) {
    case COW_CTL_CopyTargetPath:
        {
            const char *in_str = data;
            size_t in_str_len = strnlen(in_str, len);
            if (in_str_len >
                (UINT32_MAX - 1) /* need space for nul terminator */ )
                return EOVERFLOW;
            uint32_t copy_size = (uint32_t) in_str_len + 1;

            // for concatenation, we need a slash following the path, so add that if missing
            bool add_slash = false;
            if (in_str[in_str_len - 1] != '/') {
                ++copy_size;
                add_slash = true;
            }

            char *copy = OSMalloc(copy_size, cow->tag);
            if (!copy)
                return ENOMEM;
            memcpy(copy, in_str, in_str_len);

            if (add_slash) {
                copy[in_str_len] = '/';
                copy[in_str_len + 1] = '\0';
            } else {
                copy[in_str_len] = '\0';
            }

            vfs_context_t ctx = vfs_context_create(NULL);
            vnode_t dir_vnode = NULL;
            errno_t err = vnode_lookup(copy, 0, &dir_vnode, ctx);
            vfs_context_rele(ctx);

            if (err == 0) {
                if (!vnode_isdir(dir_vnode)) {
                    err = ENOTDIR;
                } else {
                    lock_writing(cow);
                    cow_free_copy_target_dir(cow);
                    cow->copy_target_dir = copy;
                    cow->copy_target_dir_len = copy_size - 1;
                    copy = NULL;
                    unlock_writing(cow);
                }
                vnode_put(dir_vnode);
            }

            if (copy)
                OSFree(copy, copy_size, cow->tag);

            printf("cow_ctl_setopt() SC_CTL_CopyTargetPath done\n");
            return err;
        }

    case COW_CTL_CNIDWatchList:
        {
            size_t num_ids = len / sizeof(copy_on_write_file_id_t);
            if (num_ids > UINT32_MAX)
                return EOVERFLOW;
            printf("got %zu ids\n", num_ids);

            cnid_table_t new_table = { };
            if (!init_cnid_table_with_cnids
                (&new_table, data, (uint32_t) num_ids, cow->tag))
                return ENOMEM;

            lock_table_writing(cow);
            assert(genc_dlist_is_empty(&cow->active_list));
            cnid_table_free(&cow->cnid_table, cow->tag);
            cow->cnid_table = new_table;
            unlock_table_writing(cow);
            printf("cow_ctl_setopt() SC_CTL_CNIDWatchList done\n");
            return 0;
        }

    case COW_CTL_StartReceivingFileEvents:
        lock_writing(cow);
        conn->wants_file_messages = true;
        unlock_writing(cow);
        return 0;

    case COW_CTL_StopReceivingFileEvents:
        lock_writing(cow);
        conn->wants_file_messages = false;
        unlock_writing(cow);
        return 0;

    case COW_CTL_WatchedLinkRequest:
        // mark hardlinking of file as done
        if (len != sizeof(copy_on_write_link_response_t) || !data)
            return EINVAL;

        return report_link_result(cow, conn, data);
    default:
        return EOPNOTSUPP;
    }
}




static errno_t cow_ctl_getopt(kern_ctl_ref kctlref, u_int32_t unit,
                              void *unitinfo, int opt, void *data,
                              size_t * len)
{
    cow_conn_t *conn = unitinfo;
    cow_t *cow = conn->cow;
    switch (opt) {
    case COW_CTL_CopyTargetPath:
        {
            errno_t err = 0;
            lock_reading(cow);
            if (cow->copy_target_dir) {
                if (data) {
                    if (*len > cow->copy_target_dir_len) {
                        *len =
                            strlcpy(data, cow->copy_target_dir, *len) + 1;
                    } else {
                        *len = cow->copy_target_dir_len + 1;
                        err = EOVERFLOW;
                    }
                } else {
                    *len = cow->copy_target_dir_len + 1;
                }
            } else {
                if (data && *len > 0)
                    ((char *) data)[0] = '\0';
                *len = 0;
            }
            unlock_reading(cow);
            return err;
        }


    case COW_CTL_CNIDWatchList:
        {
#if 0 //XXX
            uint64_t *out_cnids = data;
            size_t cur_cnid = 0;
            size_t max_cnids = data ? (*len / sizeof(out_cnids[0])) : 0;
            lock_table_reading(cow);
            lock_reading(cow);

            if (cow->cnid_table.buckets) {
                copy_on_write_file_id_t *bs = cow->cnid_table.buckets;
                for (uint32_t b = 0; b < cow->cnid_table.num_buckets; ++b) {
                    enum cnid_table_entry_state state = bs[b].state;
                    if (state == ENTRY_WATCH_FOR_WRITE
                        || state == ENTRY_WATCH_FOR_UNLINK_OR_WRITE) {
                        if (cur_cnid < max_cnids)
                            out_cnids[cur_cnid] = bs[b].cnid;
                        ++cur_cnid;
                    }
                }
            }

            unlock_reading(cow);
            unlock_table_reading(cow);
            return (cur_cnid > max_cnids && data) ? EOVERFLOW : 0;
#endif
            return EOPNOTSUPP;
        }

    case COW_CTL_WatchedLinkRequest:
        // go to sleep until the kext shuts down, a file needs relinking, or the process is interrupted
        {
            if (*len != sizeof(copy_on_write_link_request_t) || !data)
                return EINVAL;

            copy_on_write_link_request_t *rq = data;
            cow_waiting_hardlink_worker_t worker = { {}
            , rq, false, conn };


            lock_writing(cow);

            genc_dlist_insert_before(&worker.hardlink_worker_head,
                                     &cow->hardlink_worker_list);

            wait_result_t wake_reason =
                sleep_and_relock_writing_interruptible(cow, &worker);

            // if woken by another thread, we're already no longer in the list, otherwise remove from it.

            int res;
            if (wake_reason != THREAD_AWAKENED) {
                res = EINTR;
                genc_dlist_remove(&worker.hardlink_worker_head);
            } else if (worker.shutting_down) {
                res = ESHUTDOWN;
            } else {
                res = 0;
            }
            unlock_writing(cow);
            return res;
        }

    default:
        return EOPNOTSUPP;
    };
}

/* Identifies a file being copied and/or hardlinked. Allocated on the stack
 * of the first kernel thread attempting to get write access to the file.
 * This isn't necessarily the thread performing the copy, if the first access
 * triggered only a hardlink. */
struct cnid_active_list_entry {
    genc_dlist_head_t list_head;
    uint64_t cnid;
    bool copying;
    bool copying_done;
    bool copying_failed;
    bool relinking;
    bool relinking_failed;

    // If file is being linked
    cow_conn_t *worker_conn;
};
typedef struct cnid_active_list_entry cnid_active_list_entry_t;

static void dummy_vfs_context_thread(void* cow_ptr, wait_result_t wait_result)
{
    cow_t* cow = cow_ptr;

    lock_writing(cow);

    cow->copy_vfs_ctx = vfs_context_create(NULL);

    // tell loading thread we've got the context
    wakeup_one_thread(cow, &cow->copy_vfs_ctx);

    // wait until context is no longer needed
    sleep_and_relock_writing(cow, &cow->copy_vfs_ctx);

    // tell shutdown thread we're shutting down.
    thread_t self = current_thread();
    unlock_writing(cow);
    wakeup_one_thread(cow, &cow->copy_vfs_ctx);

    thread_terminate(self);
}

static bool init(cow_t * cow)
{
    cow->tag = OSMalloc_Tagalloc("net.bromium.CopyOnWrite", 0);
    cow->lock_group =
        lck_grp_alloc_init("net.bromium.CopyOnWrite", LCK_GRP_ATTR_NULL);
    cow->lock = lck_rw_alloc_init(cow->lock_group, LCK_ATTR_NULL);
    cow->table_lock = lck_rw_alloc_init(cow->lock_group, LCK_ATTR_NULL);
    genc_dlist_init(&cow->active_list);
    genc_dlist_init(&cow->conn_list);
    genc_dlist_init(&cow->hardlink_worker_list);
    cow->cnid_table.entries = NULL;
    cow->cnid_table.num_entries = 0;

    /* We need to do the file copies as root. To do so, we need a root
     * vfs_context that we can use even when the calling thread isn't owned by
     * root. Create a dummy kernel_task thread, get its vfs_context and keep it
     * around until the kext is unloaded. */
    thread_t dummy_thread = NULL;
    kern_return_t res = kernel_thread_start(dummy_vfs_context_thread, cow /* Thread param */, &dummy_thread);
    assert(res == KERN_SUCCESS);
    if (res != KERN_SUCCESS)
        return false;
    thread_deallocate(dummy_thread);

    // wait for thread to create vfs context
    lock_writing(cow);
    wait_result_t wake = sleep_and_relock_writing_interruptible(cow, &cow->copy_vfs_ctx);
    if (wake == THREAD_INTERRUPTED)
        return false;
    assert(cow->copy_vfs_ctx != NULL);
    unlock_writing(cow);
    return true;
}

static void destroy(cow_t * cow)
{
    lock_table_writing(cow);
    cnid_table_free(&cow->cnid_table, cow->tag);
    unlock_table_writing(cow);

    if (cow->copy_vfs_ctx) {
        vfs_context_rele(cow->copy_vfs_ctx);
        cow->copy_vfs_ctx = NULL;
        // let the dummy thread shut down
        lock_writing(cow);
        wakeup_one_thread(cow, &cow->copy_vfs_ctx);
        sleep_and_unlock(cow, &cow->copy_vfs_ctx);
    }

    lck_rw_free(cow->table_lock, cow->lock_group);
    lck_rw_free(cow->lock, cow->lock_group);
    lck_grp_free(cow->lock_group);
    cow->lock_group = NULL;
    cow->lock = NULL;

    OSMalloc_Tagfree(cow->tag);
    cow->tag = NULL;
}

static bool active_file_matches_cnid(genc_dlist_head_t * head,
                                     void *opaque_cnid)
{
    cnid_active_list_entry_t *entry =
        genc_container_of_notnull(head, cnid_active_list_entry_t,
                                  list_head);
    const uint64_t *cnid_p = opaque_cnid;
    uint64_t cnid = *cnid_p;
    return (entry->cnid == cnid);
}

static bool copy_file(cow_t * cow, vnode_t vp, struct vnode_attr *attrs,
                      vfs_context_t ctx, kauth_cred_t cred, uint64_t cnid);
static void check_file_rescue(cow_t * cow, vnode_t vnode, bool need_copy,
                              kauth_cred_t cred);
static int cow_vnode_op_check(
	kauth_cred_t cred, kauth_action_t action, vfs_context_t vfs_ctx,
    vnode_t vp, vnode_t dvp, int* errptr);

static int cow_vnode_check(
	kauth_cred_t     cred,       // ref to actor's credentials
	void*            opaque,     // opaque pointer supplied when registering (NULL here)
	kauth_action_t   action,     // requested action bitfield of KAUTH_VNODE_*
	uintptr_t        arg0,       // vfs context
	uintptr_t        arg1,       // vnode
	uintptr_t        arg2,       // vnode of parent directory (may be NULL)
	uintptr_t        arg3)       // pointer to errno that will be returned from originating call
{
    OSIncrementAtomic(&cow_kauth_listener_invocations);
    int res = cow_vnode_op_check(
        cred, action, (vfs_context_t)arg0,
        (vnode_t)arg1, (vnode_t)arg2, (int*)arg3);
    OSDecrementAtomic(&cow_kauth_listener_invocations);
    return res;
}

static struct cow_registered_auth_action* cow_find_thread_locked(
    cow_t* cow, thread_t thread)
{
    for (unsigned i = 0; i < cow->auth_actions.num_actions; ++i) {
        if (cow->auth_actions.actions[i].thread == thread) {
            return &cow->auth_actions.actions[i];
        }
    }
    return NULL;
}

static uint32_t cow_find_auth_actions_for_thread(
    cow_t* cow, thread_t thread)
{
    uint32_t actions = 0;
    lock_reading(cow);
    struct cow_registered_auth_action* action = cow_find_thread_locked(cow, thread);
    if (action) {
        actions = action->actions;
    }
    unlock_reading(cow);
    return actions;
}

static void cow_remove_actions_for_thread(
    cow_t* cow, thread_t thread)
{
    lock_writing(cow);
    struct cow_registered_auth_action* action = cow_find_thread_locked(cow, thread);
    if (action) {
        size_t idx = action - cow->auth_actions.actions;
        unsigned remain = --cow->auth_actions.num_actions;
        if (idx != remain) {
            cow->auth_actions.actions[idx] = cow->auth_actions.actions[remain];
        }
        if (remain == COW_MAX_ACTIONS - 1)
            wakeup_one_thread(cow, &cow->auth_actions);
    }
    unlock_writing(cow);
}

static void cow_set_actions_for_thread(
    cow_t* cow, thread_t thread, uint32_t actions)
{
    lock_writing(cow);
    do {
        struct cow_registered_auth_action* action = cow_find_thread_locked(cow, thread);
        if (action) {
            action->actions |= actions;
        }
        else {
            if (cow->auth_actions.num_actions >= COW_MAX_ACTIONS) {
                // no slot available, wait until that changes
                sleep_and_relock_writing(cow, &cow->auth_actions);
                continue;
            }
            action = &cow->auth_actions.actions[cow->auth_actions.num_actions];
            action->thread = thread;
            action->actions = actions;
            ++cow->auth_actions.num_actions;
        }
    } while (false);
    unlock_writing(cow);
}

static copy_on_write_file_id_t* is_file_watched(
    cow_t * cow, vnode_t vnode, bool need_copy, struct vnode_attr* out_attrs);

static int cow_vnode_op_check(
	kauth_cred_t cred, kauth_action_t action, vfs_context_t vfs_ctx,
    vnode_t vp, vnode_t dvp, int* errptr)
{
    if (*errptr != 0)
        // Access has already been denied at an earlier stage, so we know the operation won't go ahead.
        return KAUTH_RESULT_DEFER;

    if (0 == (action & KAUTH_VNODE_ACCESS)) { // don't do anything unless the operation is actually happening
        if ((action & (KAUTH_VNODE_WRITE_DATA | KAUTH_VNODE_APPEND_DATA)) != 0) {
            /* This covers open() for writing and exchangedata() calls. */
            /*char path[MAXPATHLEN] = "";
            int pathlen = sizeof(path);
            vn_getpath(vp, path, &pathlen);
            kprintf("cow_vnode_check: KAUTH_VNODE_WRITE_DATA|KAUTH_VNODE_APPEND_DATA %x '%s'\n", action, path);*/
            check_file_rescue(&cow_ctx, vp, true /* yes copy, hardlink not good enough */, cred);
        }
        else if ((action & KAUTH_VNODE_DELETE) != 0) {
            /* This covers both unlink() and the source [vfs_subr.c:5617] and
             * destination [vfs_subr.c:5636] of rename() */
            /*char path[MAXPATHLEN] = "";
            int pathlen = sizeof(path);
            vn_getpath(vp, path, &pathlen);
            kprintf("cow_vnode_check: KAUTH_VNODE_DELETE %x '%s'\n", action, path); */
            check_file_rescue(&cow_ctx, vp, false /* rename target and deleted file are only unlinked */, cred);
        }
        else if ((action & KAUTH_VNODE_WRITE_SECURITY) != 0)
        {
            uint32_t mac_actions = cow_find_auth_actions_for_thread(&cow_ctx, current_thread());
            if (mac_actions & COW_ACTION_SET_COMPRESSED_FLAG)
            {
                check_file_rescue(&cow_ctx, vp, true /* yes copy, hardlink not good enough */, cred);
            }
        }
        else if ((action & KAUTH_VNODE_WRITE_EXTATTRIBUTES) != 0)
        {
            uint32_t mac_actions = cow_find_auth_actions_for_thread(&cow_ctx, current_thread());
            if (mac_actions & (COW_ACTION_SET_DECMPFS_XATTR | COW_ACTION_DEL_DECMPFS_XATTR))
            {
                check_file_rescue(&cow_ctx, vp, true /* yes copy, hardlink not good enough */, cred);
            }
        }
    }
    return KAUTH_RESULT_DEFER;
}

static int vnode_check_setextattr(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	const char *name,
	struct uio *uio)
{
    /* catch the case where one of the xattrs related to FS compression is
     * changed on a compressed file */
    if (0 == strcmp(name, DECMPFS_XATTR_NAME) || 0 == strcmp(name, XATTR_RESOURCEFORK_NAME))
    {
        struct vnode_attr attrs = {};
        VATTR_INIT(&attrs);
        VATTR_SET_ACTIVE(&attrs, va_flags);
        copy_on_write_file_id_t* entry = is_file_watched(&cow_ctx, vp, true, &attrs);
        if (entry)
        {
            unlock_reading(&cow_ctx);
            if (VATTR_IS_SUPPORTED(&attrs, va_flags) && (attrs.va_flags & UF_COMPRESSED) == 0)
                return 0; // file is not compressed, so (re-)setting the xattr doesn't really matter to us

            /* This is too early to act. Only when the vnode listener receives a
             * KAUTH_VNODE_WRITE_SECURITY before this thread returns to userspace,
             * should we do anything about this. */
            cow_set_actions_for_thread(&cow_ctx, current_thread(), COW_ACTION_SET_DECMPFS_XATTR);
            mac_schedule_userret();
        }
    }
    return 0;
}

static int vnode_check_deleteextattr(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *vlabel,
	const char *name)
{
    /* catch the case where one of the xattrs related to FS compression is
     * deleted on a compressed file */
    if (0 == strcmp(name, DECMPFS_XATTR_NAME) || 0 == strcmp(name, XATTR_RESOURCEFORK_NAME))
    {
        struct vnode_attr attrs = {};
        VATTR_INIT(&attrs);
        VATTR_SET_ACTIVE(&attrs, va_flags);
        copy_on_write_file_id_t* entry = is_file_watched(&cow_ctx, vp, true, &attrs);
        if (entry)
        {
            unlock_reading(&cow_ctx);
            if (VATTR_IS_SUPPORTED(&attrs, va_flags) && (attrs.va_flags & UF_COMPRESSED) == 0)
            {
                unlock_table_reading(&cow_ctx);
                return 0; // file is not compressed, so deleting the xattr doesn't really matter to us
            }

            /* This is too early to act. Only when the vnode listener receives a
             * KAUTH_VNODE_WRITE_SECURITY before this thread returns to userspace,
             * should we do anything about this. */
            cow_set_actions_for_thread(&cow_ctx, current_thread(), COW_ACTION_DEL_DECMPFS_XATTR);
            mac_schedule_userret();
            unlock_table_reading(&cow_ctx);
        }
    }
    return 0;
}


static int vnode_check_setflags(
	kauth_cred_t cred,
	struct vnode *vp,
	struct label *label,
	u_long flags)
{
    /* catch the case where a file is turned into a compressed file */
    if (flags & UF_COMPRESSED)
    {
        struct vnode_attr attrs = {};
        VATTR_INIT(&attrs);
        VATTR_SET_ACTIVE(&attrs, va_flags);
        copy_on_write_file_id_t* entry = is_file_watched(&cow_ctx, vp, true, &attrs);
        if (entry)
        {
            unlock_reading(&cow_ctx);
            if (VATTR_IS_SUPPORTED(&attrs, va_flags) && (attrs.va_flags & UF_COMPRESSED) != 0)
            {
                unlock_table_reading(&cow_ctx);
                return 0; // compressed flag is already set
            }

            /* This is too early to act. Only when the vnode listener receives a
             * KAUTH_VNODE_WRITE_SECURITY before this thread returns to userspace,
             * should we do anything about this. */
            cow_set_actions_for_thread(&cow_ctx, current_thread(), COW_ACTION_SET_COMPRESSED_FLAG);
            mac_schedule_userret();
            unlock_table_reading(&cow_ctx);
        }
    }
    return 0;
}

static void thread_userret(
	struct thread *thread)
{
    // clear any actions registered for this thread
    cow_remove_actions_for_thread(&cow_ctx, thread);
}



static int report_link_result(cow_t * cow, cow_conn_t * conn,
                              const copy_on_write_link_response_t * res)
{
    uint64_t cnid = res->file_id;

    lock_table_reading(cow);
    lock_reading(cow);

    genc_dlist_head_t *active_head =
        genc_dlist_find_in_range(&cow->active_list, &cow->active_list,
                                 active_file_matches_cnid, &cnid);

    // don't worry if we don't find it, but if we do, notify the waiting thread
    if (active_head) {
        cnid_active_list_entry_t *entry =
            genc_container_of_notnull(active_head,
                                      cnid_active_list_entry_t, list_head);

        if (entry->worker_conn != conn) {
            printf
                ("copy-on-write: Warning: report_link_result() for file %llu called from wrong kernel control connection.\n",
                 cnid);
        } else {
            entry->relinking_failed = res->flags != 0;
            // only wake up original thread if another hasn't now additionally started copying the file
            if (!entry->copying)
                wakeup_one_thread(cow, &entry->relinking);
        }
    } else {
        printf
            ("copy-on-write: %s hardlink reported for file %llu, but not found in active list.\n",
             res->flags == 0 ? "successful" : "unsuccessful", cnid);
    }

    unlock_reading(cow);
    unlock_table_reading(cow);
    return 0;
}

static void rescue_watched_file(cow_t * cow, vnode_t vnode, uint64_t cnid,
                                struct vnode_attr *attrs, bool need_copy,
                                vfs_context_t vctx, kauth_cred_t cred,
                                copy_on_write_file_id_t * entry);

// if entry is returned, the table and general locks will be held for reading; out_attrs must be init'd
static copy_on_write_file_id_t* is_file_watched(
    cow_t * cow, vnode_t vnode, bool need_copy, struct vnode_attr* out_attrs)
{
    mount_t mp = vnode_mount(vnode);
    uint64_t flags = vfs_flags(mp);
    if (0 == (flags & MNT_ROOTFS) || !vnode_isreg(vnode))
        return NULL;

    vfs_context_t ctx = cow->copy_vfs_ctx;
    VATTR_SET_ACTIVE(out_attrs, va_fileid);
    int err = vnode_getattr(vnode, out_attrs, ctx);
    if (err != 0 || !VATTR_IS_SUPPORTED(out_attrs, va_fileid)) {
        printf("Failed to get file attributes/inode: %d\n", err);
        return NULL;
    }

    uint64_t cnid = out_attrs->va_fileid;
    lock_table_reading(cow);
    lock_reading(cow);
    if (!cow_ctx.copy_target_dir) {
        unlock_reading(cow);
        unlock_table_reading(cow);
    } else {
        copy_on_write_file_id_t *entry =
            cnid_table_find_entry(&cow->cnid_table, cnid);
        if (entry &&
            ((entry->state == ENTRY_WATCH_FOR_WRITE
              && need_copy)
             || entry->state ==
             ENTRY_WATCH_FOR_UNLINK_OR_WRITE)) {
            return entry;
        } else {
            // file not watched for this kind of event
            unlock_reading(cow);
            unlock_table_reading(cow);
        }
    }
    return NULL;
}

static void check_file_rescue(cow_t * cow, vnode_t vnode, bool need_copy,
                              kauth_cred_t cred)
{
    struct vnode_attr attrs = { };
    VATTR_INIT(&attrs);
    VATTR_SET_ACTIVE(&attrs, va_mode);
    VATTR_SET_ACTIVE(&attrs, va_data_size);
    copy_on_write_file_id_t* file_entry = is_file_watched(cow, vnode, need_copy, &attrs);
    if (file_entry)
    {
        // table & regular locks held for reading
        vfs_context_t ctx = cow->copy_vfs_ctx;
        // returns unlocked:
        rescue_watched_file(cow, vnode, file_entry->id, &attrs,
                            need_copy, ctx, cred, file_entry);
    }
}

static void rescue_existing_active_file(cnid_active_list_entry_t * found,
                                        cow_t * cow, vnode_t vnode,
                                        uint64_t cnid,
                                        struct vnode_attr *attrs,
                                        bool need_copy, vfs_context_t vctx,
                                        kauth_cred_t cred);
static void rescue_new_file(cow_t * cow, vnode_t vnode, uint64_t cnid,
                            struct vnode_attr *attrs, bool need_copy,
                            vfs_context_t vctx, kauth_cred_t cred,
                            copy_on_write_file_id_t * entry);

// when called, the lock is held for reading
static void rescue_watched_file(cow_t * cow, vnode_t vnode, uint64_t cnid,
                                struct vnode_attr *attrs, bool need_copy,
                                vfs_context_t vctx, kauth_cred_t cred,
                                copy_on_write_file_id_t * entry)
{
    cnid_active_list_entry_t *found =
        genc_container_of(genc_dlist_find_in_range
                          (&cow->active_list, &cow->active_list,
                           active_file_matches_cnid, &cnid),
                          cnid_active_list_entry_t, list_head);

    if (found && (found->copying || !need_copy)) {
        // wait for the other thread to finish with the file before going ahead with opening it
        sleep_and_unlock(cow, found);
        unlock_table_reading(cow);
        return;
    }

    unlock_reading(cow); // still keeping the table locked
    lock_writing(cow);

    if (!
        ((entry->state == ENTRY_WATCH_FOR_WRITE && need_copy)
         || entry->state == ENTRY_WATCH_FOR_UNLINK_OR_WRITE)) {
        // file has been handled during the relocking time
        unlock_writing(cow);
        unlock_table_reading(cow);
        return;
    }
    // refresh our knowledge of active entry (could have changed).
    found =
        genc_container_of(genc_dlist_find_in_range
                          (&cow->active_list, &cow->active_list,
                           active_file_matches_cnid, &cnid),
                          cnid_active_list_entry_t, list_head);

    if (found)
        rescue_existing_active_file(found, cow, vnode, cnid, attrs,
                                    need_copy, vctx, cred);
    else
        rescue_new_file(cow, vnode, cnid, attrs, need_copy, vctx, cred,
                        entry);
    unlock_table_reading(cow);
}


static void rescue_existing_active_file(cnid_active_list_entry_t * found,
                                        cow_t * cow, vnode_t vnode,
                                        uint64_t cnid,
                                        struct vnode_attr *attrs,
                                        bool need_copy, vfs_context_t vctx,
                                        kauth_cred_t cred)
{
    // locked for writing, must not unlock until we're waiting for the event.
    // another thread is already taking care of this file, check what it's doing
    if (need_copy && !found->copying) {
        // we need a real copy, the other thread is only hardlinking; take over.
        found->copying = true;

        unlock_writing(cow);

        bool copy_ok = copy_file(cow, vnode, attrs, vctx, cred, cnid);

        lock_writing(cow);

        found->copying_done = true;
        found->copying_failed = !copy_ok;

        wakeup_one_thread(cow, &found->relinking);
        // the original thread can handle notifications & removal from list
        unlock_writing(cow);
    } else {
        // other thread is already doing to the file what we need it to do, wait for it to finish.
        sleep_and_unlock(cow, found);
    }
}

static void rescue_new_file(cow_t * cow, vnode_t vnode, uint64_t cnid,
                            struct vnode_attr *attrs, bool need_copy,
                            vfs_context_t vctx, kauth_cred_t cred,
                            copy_on_write_file_id_t * entry)
{
    // locked for writing
    // sort this file out ourselves
    cow_waiting_hardlink_worker_t *worker = NULL;
    if (!need_copy) {
        worker =
            genc_dlist_remove_first_object(&cow->hardlink_worker_list,
                                           cow_waiting_hardlink_worker_t,
                                           hardlink_worker_head);
        need_copy = (worker == NULL);
    }


    cnid_active_list_entry_t active = {
        .cnid = cnid,
        .copying = need_copy,.relinking = !need_copy,
        .relinking_failed = true,
        .worker_conn = worker ? worker->connection : NULL
    };

    genc_dlist_insert_after(&active.list_head, &cow->active_list);

    if (worker) {
        // fill out the request
        worker->link_request->file_id = cnid;
        int pathlen = sizeof(worker->link_request->file_path);
        int err =
            vn_getpath(vnode, worker->link_request->file_path, &pathlen);
        if (err != 0) {
            need_copy = true;

            // actually, don't need the worker after all.
            genc_dlist_insert_after(&worker->hardlink_worker_head,
                                    &cow->hardlink_worker_list);
        } else {
            // wake up the worker to let it do its job
            wakeup_one_thread(cow, worker);
            // wait for it to complete (or not)
            wait_result_t wake_reason =
                sleep_with_timeout_and_relock_writing(cow,
                                                      &active.relinking,
                                                      500 /* ms */ );
            if (wake_reason != THREAD_AWAKENED) {
                printf
                    ("copy-on-write: Timed out while waiting for file %llu to be relinked.\n",
                     cnid);
                need_copy = true;
            } else if (active.copying) {
                // another thread started copying the file while we were hardlinking; it notifies us when copying finishes in this case, not the hardlinking worker
                assert(active.copying_done);
            } else if (active.relinking_failed) {
                need_copy = true;
            }
        }
    }

    bool copy_ok = true;
    if (need_copy) {
        // don't hold the lock for I/O
        unlock_writing(cow);

        copy_ok = copy_file(cow, vnode, attrs, vctx, cred, cnid);

        lock_writing(cow);
    }
    // clean up & wake up any other threads
    entry->state = need_copy ? ENTRY_NO_WATCH : ENTRY_WATCH_FOR_WRITE;

    genc_dlist_remove(&active.list_head);
    wakeup_all(cow, &active.list_head);

    unlock_writing(cow);

    enum copy_on_write_msg_type msg_type =
        need_copy
        ? active.
        copying_failed ? COW_MSG_FileCopyFailed : COW_MSG_FileCopied :
        COW_MSG_FileReLinked;

    // send triumphant message to any interested userspace parties
    lock_reading(cow);

    for (genc_dlist_head_t * cur = cow_ctx.conn_list.next;
         cur != &cow_ctx.conn_list; cur = cur->next) {
        cow_conn_t *conn =
            genc_container_of_notnull(cur, cow_conn_t, conn_list_head);
        if (conn->wants_file_messages) {
            struct copy_on_write_msg msg =
                { msg_type, 0, conn->num_dropped_messages, cnid };
            int err =
                ctl_enqueuedata(cow->ctl_ref, conn->unit, &msg,
                                sizeof(msg), 0);
            if (err != 0) {
                OSIncrementAtomic(&conn->num_dropped_messages);
            }
        }
    }

    unlock_reading(cow);
}

static bool copy_file(cow_t * cow, vnode_t vp, struct vnode_attr *attrs,
                      vfs_context_t ctx, kauth_cred_t cred, uint64_t cnid)
{
    const char *name = vnode_getname(vp);
    printf("writing to file %s\n", name);
    size_t dest_path_len =
        64 + cow->copy_target_dir_len + sizeof(copy_suffix);
    char dest_path[dest_path_len];
    dest_path[0] = '\0';
    snprintf(dest_path, sizeof(dest_path), "%s%llu%s",
             cow->copy_target_dir, cnid, copy_suffix);
    printf("new file path is %s\n", dest_path);

    bool ok = true;

    vnode_t dest_vn = NULL;
    errno_t err =
        vnode_open(dest_path, O_CREAT | O_WRONLY, attrs->va_mode, 0,
                   &dest_vn, ctx);
    if (err != 0) {
        printf("Failed to copy file: %d\n", err);
        ok = false;
    } else {
        int buflen = PAGE_SIZE * 2;
        uint8_t *iobuf = OSMalloc(buflen, cow->tag);
        if (!iobuf) {
            printf("Failed to alloc memory for copying file\n");
            ok = false;
        } else {
            off_t offset = 0;
            while (offset < attrs->va_data_size) {
                off_t bytes_remain = attrs->va_data_size - offset;
                int bytes_not_done = 0;
                int read_bytes =
                    buflen < bytes_remain ? buflen : (int) bytes_remain;
                err =
                    vn_rdwr(UIO_READ, vp, (caddr_t) iobuf, read_bytes,
                            offset, UIO_SYSSPACE, IO_NOAUTH | IO_SYNC,
                            cred, &bytes_not_done, kernproc);
                if (err != 0 || read_bytes <= bytes_not_done) {
                    printf("File IO failed: %d, %d bytes not read\n", err,
                           bytes_not_done);
                    ok = false;
                    break;
                } else {
                    read_bytes -= bytes_not_done;
                    size_t buf_write_offset = 0;
                    while (read_bytes > 0) {
                        bytes_not_done = 0;
                        //kprintf("File IO succeeded: %d bytes read, %d bytes not read\n", read_bytes, bytes_not_done);
                        err =
                            vn_rdwr(UIO_WRITE, dest_vn,
                                    (caddr_t) iobuf + buf_write_offset,
                                    read_bytes, offset, UIO_SYSSPACE,
                                    IO_NOAUTH | IO_SYNC, cred,
                                    &bytes_not_done, kernproc);
                        if (err != 0 || read_bytes <= bytes_not_done) {
                            printf
                                ("File write failed: %d, %d bytes not written\n",
                                 err, bytes_not_done);
                            ok = false;
                            goto done;
                        } else {
                            //kprintf("File write succeeded: %d bytes written, %d bytes not written\n", read_bytes, bytes_not_done);
                            int did_write = (read_bytes - bytes_not_done);
                            offset += did_write;
                            buf_write_offset += did_write;
                            read_bytes = bytes_not_done;
                        }
                    }
                }
            }
          done:
            OSFree(iobuf, buflen, cow->tag);
        }
        vnode_close(dest_vn, FWASWRITTEN, ctx);
    }
    vnode_putname(name);
    return ok;
}

/*
#undef lock_writing
#undef lock_reading
#undef unlock_reading
#undef unlock_writing
#undef sleep_and_unlock
#undef wakeup_all
*/

static void lock_reading(cow_t * cow)
{
    lck_rw_lock_shared(cow->lock);
}

static void unlock_reading(cow_t * cow)
{
    lck_rw_unlock_shared(cow->lock);
}

static void lock_writing(cow_t * cow)
{
    lck_rw_lock_exclusive(cow->lock);
}

static void unlock_writing(cow_t * cow)
{
    lck_rw_unlock_exclusive(cow->lock);
}

static void sleep_and_unlock(cow_t * cow, event_t event)
{
    lck_rw_sleep(cow->lock, LCK_SLEEP_UNLOCK, event, THREAD_UNINT);
}

static void sleep_and_relock_writing(cow_t * cow, event_t event)
{
    lck_rw_sleep(cow->lock, LCK_SLEEP_EXCLUSIVE, event, THREAD_UNINT);
}

static void lock_table_reading(cow_t * cow)
{
    lck_rw_lock_shared(cow->table_lock);
}

static void unlock_table_reading(cow_t * cow)
{
    lck_rw_unlock_shared(cow->table_lock);
}

static void lock_table_writing(cow_t * cow)
{
    lck_rw_lock_exclusive(cow->table_lock);
}

static void unlock_table_writing(cow_t * cow)
{
    lck_rw_unlock_exclusive(cow->table_lock);
}

#if 0
static void sleep_and_relock_reading(cow_t * cow, event_t event)
{
    lck_rw_sleep(cow->lock, LCK_SLEEP_SHARED, event, THREAD_UNINT);
}
#endif

static wait_result_t sleep_and_relock_writing_interruptible(cow_t * cow,
                                                            event_t event)
{
    return lck_rw_sleep(cow->lock, LCK_SLEEP_EXCLUSIVE, event,
                        THREAD_INTERRUPTIBLE);
}

static wait_result_t sleep_with_timeout_and_relock_writing(cow_t * cow,
                                                           event_t event,
                                                           uint32_t
                                                           timeout_msec)
{
    uint64_t deadline;
    clock_interval_to_deadline(timeout_msec, kMillisecondScale, &deadline);
    return lck_rw_sleep_deadline(cow->lock, LCK_SLEEP_EXCLUSIVE, event,
                                 THREAD_UNINT, deadline);
}

static void wakeup_all(cow_t * cow, event_t event)
{
    thread_wakeup_prim(event, false /* not just one thread */ ,
                       THREAD_AWAKENED);
}

static void wakeup_one_thread(cow_t * cow, event_t event)
{
    thread_wakeup_prim(event, true /* just one thread */ ,
                       THREAD_AWAKENED);
}

