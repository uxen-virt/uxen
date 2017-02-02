/*
 * Copyright 2016-2017, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __USER_VRAM_H__
#define __USER_VRAM_H__

class BASIC_DISPLAY_DRIVER;

class UserVramMapper {
public:
    UserVramMapper();

    bool init(BASIC_DISPLAY_DRIVER *bdd, PHYSICAL_ADDRESS vram_start, SIZE_T vram_size);
    void cleanup();

    void *user_map();
    void user_unmap(void *mapped);
    void *scratch_map();
    void scratch_unmap(void *mapped);

private:
    bool init_scratch(SIZE_T vram_size);

    BASIC_DISPLAY_DRIVER *m_bdd;
    PMDL m_vram_mdl;
    PMDL m_scratch_page_mdl;
    PMDL m_scratch_vram_mdl;
};

#endif //__USER_VRAM_H__
