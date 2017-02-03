/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#pragma once

#include <windows.h>

class CAutoLock
{
public:
    CAutoLock(CRITICAL_SECTION* pcs)
    {
        m_pcs = pcs;
        if (m_pcs != NULL) {
            EnterCriticalSection(m_pcs);
        }
    }

    ~CAutoLock(void)
    {
        if (m_pcs != NULL) {
            LeaveCriticalSection(m_pcs);
            m_pcs = NULL;
        }
    }

protected:
    CRITICAL_SECTION*   m_pcs;
};