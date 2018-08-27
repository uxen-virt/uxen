/*
 * Copyright 2016-2018, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

//#include <Ntddk.h>
#include <Ntifs.h>
#include <wdm.h>
#include "BDD.hxx"
#include "user_vram.h"
#include "../common/debug.h"

#define NUM_SCRATCH_PAGES 1
#define UVRAM_TAG 'UVRM'

static UserVramMapper *g_mapper;

static void
create_process_notification(
  _In_ HANDLE  ParentId,
  _In_ HANDLE  ProcessId,
  _In_ BOOLEAN Create
)
{
    ParentId;
    if (g_mapper && !Create)
        g_mapper->process_destroyed(ProcessId);
}

UserVramMapper::UserVramMapper()
    : m_vram_mdl(0)
    , m_scratch_page_mdl(0)
    , m_scratch_vram_mdl(0)
    , m_bdd(0)
{
}

bool UserVramMapper::init(BASIC_DISPLAY_DRIVER *bdd, PHYSICAL_ADDRESS vram_start, SIZE_T vram_size)
{
    m_bdd = bdd;

    KeInitializeMutex(&m_map_mutex, 0);
    InitializeListHead(&m_mappings);

    PVOID vram_mem = MmMapIoSpace(vram_start, vram_size, MmCached);

    PMDL vram_mdl = IoAllocateMdl(vram_mem, (ULONG)vram_size, FALSE, FALSE, NULL);
    if (!vram_mdl) {
        uxen_err("failed to allocate mdl\n");
        return false;
    }

    MmBuildMdlForNonPagedPool(vram_mdl);

    if (!init_scratch(vram_size)) {
        uxen_err("failed to init scratch fb\n");
        IoFreeMdl(vram_mdl);
        return false;
    }

    m_vram_mdl = vram_mdl;

    g_mapper = this;

    PsSetCreateProcessNotifyRoutine(create_process_notification, FALSE);

    return true;
}

bool UserVramMapper::init_scratch(SIZE_T vram_size)
{
    int vram_pages = (int) ((vram_size + PAGE_SIZE - 1) >> PAGE_SHIFT);
    PHYSICAL_ADDRESS low  = { 0 };
    PHYSICAL_ADDRESS high = { 0 };
    PHYSICAL_ADDRESS skip = { 0 };

    high.QuadPart = -1;

    /* mdl to describe scratch page(s) */
    PMDL scratch_page_mdl = MmAllocatePagesForMdlEx(low, high, skip, NUM_SCRATCH_PAGES << PAGE_SHIFT,
        MmCached, MM_ALLOCATE_FULLY_REQUIRED);
    if (!scratch_page_mdl) {
        uxen_err("failed to allocate mdl\n");
        return false;
    }

    PFN_NUMBER *scratch_pfns = MmGetMdlPfnArray(scratch_page_mdl);

    /* mdl to describe scratch vram filled with scratch pages */
    PMDL scratch_vram_mdl = IoAllocateMdl(NULL, vram_pages << PAGE_SHIFT, FALSE, FALSE, NULL);

    if (!scratch_vram_mdl) {
        uxen_err("failed to allocate mdl\n");
        MmFreePagesFromMdl(scratch_page_mdl);
        ExFreePool(scratch_page_mdl);

        return false;
    }

    PFN_NUMBER *pfns = MmGetMdlPfnArray(scratch_vram_mdl);
    for (int i = 0; i < vram_pages; ++i) {
        pfns[i] = scratch_pfns[0];
    }

    m_scratch_page_mdl = scratch_page_mdl;
    m_scratch_vram_mdl = scratch_vram_mdl;

    return true;
}

void UserVramMapper::cleanup()
{
    PsSetCreateProcessNotifyRoutine(create_process_notification, TRUE);

    del_all_mappings();

    g_mapper = NULL;

    if (m_scratch_page_mdl) {
        MmFreePagesFromMdl(m_scratch_page_mdl);
        ExFreePool(m_scratch_page_mdl);
        m_scratch_page_mdl = NULL;
    }

    if (m_scratch_vram_mdl) {
        IoFreeMdl(m_scratch_vram_mdl);
        m_scratch_vram_mdl = NULL;
    }

    if (m_vram_mdl) {
        IoFreeMdl(m_vram_mdl);
        m_vram_mdl = NULL;
    }
}

bool UserVramMapper::map_lock()
{
    if (!NT_SUCCESS(KeWaitForMutexObject(&m_map_mutex,
                UserRequest, KernelMode, FALSE, NULL))) {
        uxen_err("failed to acquire mutex\n");
        return false;
    }
    return true;
}

void UserVramMapper::map_unlock()
{
    KeReleaseMutex(&m_map_mutex, FALSE);
}

void *UserVramMapper::_map(HANDLE pid, void *userptr, bool scratch, bool nomodlist)
{
    PMDL mdl = scratch ? m_scratch_vram_mdl : m_vram_mdl;
    const char *descr = scratch ? "scratch vram" : "vram";

    __try {
        PVOID p = MmMapLockedPagesSpecifyCache(mdl, UserMode, MmCached,
                                               userptr, FALSE, NormalPagePriority);
        if (p) {
            if (userptr && p != userptr) {
                uxen_err("failed to map at target address %p, have %p\n", userptr, p);
                MmUnmapLockedPages(p, mdl);
                return NULL;
            }

            if (!nomodlist) {
                if (!add_mapping(pid, p, 0)) {
                    uxen_err("failed to add mapping, pid %p, scratch %d\n", pid, (int)scratch);
                    MmUnmapLockedPages(p, mdl);
                    return NULL;
                }
            }

            uxen_msg("%s @ %p mapped into process %p\n",
                descr, p, pid);
        } else
            uxen_err("error mapping %s, not enough resources\n", descr);
        return p;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER ) {
        uxen_err("exception mapping %s, code %x\n", descr, (int)GetExceptionCode());
        return NULL;
    }
}

void UserVramMapper::_unmap(HANDLE pid, void *mapped, bool scratch, bool nomodlist)
{
    PMDL mdl = scratch ? m_scratch_vram_mdl : m_vram_mdl;
    const char *descr = scratch ? "scratch vram" : "vram";

    MmUnmapLockedPages(mapped, mdl);
    if (!nomodlist)
        del_mapping(pid, mapped);

    uxen_msg("%s @ %p unmapped from process %p\n",
        descr, mapped, pid);
}

void *UserVramMapper::user_map()
{
    map_lock();
    void *p = _map(PsGetCurrentProcessId(), NULL, false, false);
    map_unlock();

    return p;
}

void UserVramMapper::user_unmap(void *mapped)
{
    map_lock();
    _unmap(PsGetCurrentProcessId(), mapped, false, false);
    map_unlock();
}

void *UserVramMapper::scratch_map()
{
    map_lock();
    void *p = _map(PsGetCurrentProcessId(), NULL, true, false);
    map_unlock();

    return p;
}

void UserVramMapper::scratch_unmap(void *mapped)
{
    map_lock();
    _unmap(PsGetCurrentProcessId(), mapped, true, false);
    map_unlock();
}

bool UserVramMapper::add_mapping(HANDLE pid, void *userptr, int scratch)
{
    VramMapping *m = (VramMapping*) ExAllocatePoolWithTag(NonPagedPool,
        sizeof(VramMapping), UVRAM_TAG);
    if (!m) {
        uxen_err("allocation failed\n");
        return false;
    }

    RtlZeroMemory(m, sizeof(*m));
    m->pid = pid;
    m->userptr = userptr;
    m->scratch = scratch;

    InsertTailList(&m_mappings, &m->le);

    return true;
}

void UserVramMapper::del_mapping(VramMapping *m)
{
    RemoveEntryList(&m->le);

    ExFreePoolWithTag(m, UVRAM_TAG);
}

void UserVramMapper::del_all_mappings()
{
    PLIST_ENTRY e = m_mappings.Flink;

    while (e != &m_mappings) {
        PLIST_ENTRY next = e->Flink;
        VramMapping *m = (VramMapping*) CONTAINING_RECORD(e, VramMapping, le);
        del_mapping(m);
        e = next;
    }
}

void UserVramMapper::del_mapping(HANDLE pid)
{
    PLIST_ENTRY e = m_mappings.Flink;

    while (e != &m_mappings) {
        PLIST_ENTRY next = e->Flink;
        VramMapping *m = (VramMapping*) CONTAINING_RECORD(e, VramMapping, le);
        if (m->pid == pid)
            del_mapping(m);
        e = next;
    }
}

void UserVramMapper::del_mapping(HANDLE pid, void *userptr)
{
    PLIST_ENTRY e = m_mappings.Flink;

    while (e != &m_mappings) {
        PLIST_ENTRY next = e->Flink;
        VramMapping *m = (VramMapping*) CONTAINING_RECORD(e, VramMapping, le);
        if (m->pid == pid && m->userptr == userptr)
            del_mapping(m);
        e = next;
    }
}

void UserVramMapper::process_destroyed(HANDLE pid)
{
    map_lock();
    del_mapping(pid);
    map_unlock();
}

NTSTATUS UserVramMapper::mapping_scratchify(VramMapping *m, int enable)
{
    void *userptr = m->userptr;
    HANDLE pid = m->pid;

    uxen_msg("scratchify mapping @ %p, process %p, enable = %d\n", userptr, pid, enable);

    _unmap(pid, userptr, !enable, true);
    void *newptr = _map(pid, userptr, !!enable, true);
    if (newptr != userptr) {
        uxen_msg("scratchify mapping failed, expect user ptr %p  have %p\n",
            userptr,  newptr);

        return STATUS_UNSUCCESSFUL;
    }

    m->scratch = enable;

    return STATUS_SUCCESS;
}

NTSTATUS UserVramMapper::process_scratchify(HANDLE pid, int enable)
{
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    NTSTATUS status;

    uxen_msg("scratchify process %p, enable = %d\n", pid, enable);

    map_lock();

    status = PsLookupProcessByProcessId(pid, &pe);
    if (!NT_SUCCESS(status)) {
        map_unlock();
        uxen_err("failed to lookup process, err %x\n", status);
        return status;
    }

    KeStackAttachProcess(pe, &apc);

    PLIST_ENTRY e = m_mappings.Flink;

    while (e != &m_mappings) {
        PLIST_ENTRY next = e->Flink;
        VramMapping *m = (VramMapping*) CONTAINING_RECORD(e, VramMapping, le);
        if (m->pid == pid && m->scratch != enable) {
            status = mapping_scratchify(m, enable);
            if (!NT_SUCCESS(status))
                break;
        }
        e = next;
    }

    KeUnstackDetachProcess(&apc);

    ObDereferenceObject(pe);

    map_unlock();

    return status;
}
