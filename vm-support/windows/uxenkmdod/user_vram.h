/*
 * Copyright 2016-2017, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __USER_VRAM_H__
#define __USER_VRAM_H__

class BASIC_DISPLAY_DRIVER;

struct VramMapping {
    LIST_ENTRY le;

    HANDLE pid;
    void*  userptr;
    int    scratch;
};

class UserVramMapper {
public:
    UserVramMapper();

    bool init(BASIC_DISPLAY_DRIVER *bdd, PHYSICAL_ADDRESS vram_start, SIZE_T vram_size);
    void cleanup();

    void *user_map();
    void user_unmap(void *mapped);
    void *scratch_map();
    void scratch_unmap(void *mapped);
    void process_destroyed(HANDLE pid);

    // replace all framebuffer mappings in given process witch scratch mapping,
    // process must be suspended
    NTSTATUS process_scratchify(HANDLE pid, int enable);

private:
    void *_map(HANDLE pid, void *userptr, bool scratch, bool nomodlist);
    void _unmap(HANDLE pid, void *mapped, bool scratch, bool nomodlist);

    bool init_scratch(SIZE_T vram_size);
    bool add_mapping(HANDLE pid, void *userptr, int scratch);
    void del_all_mappings();
    void del_mapping(VramMapping *m);
    void del_mapping(HANDLE pid);
    void del_mapping(HANDLE pid, void *userptr);
    NTSTATUS mapping_scratchify(VramMapping *m, int enable);
    bool map_lock();
    void map_unlock();

    BASIC_DISPLAY_DRIVER *m_bdd;
    KMUTEX m_map_mutex;
    PMDL m_vram_mdl;
    PMDL m_scratch_page_mdl;
    PMDL m_scratch_vram_mdl;
    LIST_ENTRY m_mappings;
};

#endif //__USER_VRAM_H__
