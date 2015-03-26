/*
 * Copyright 2014-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _HDROP_H
#define _HDROP_H
/* If CF_HDROP clipboard format is available, and has only one filename,
   then try to guess by filename extension which (graphics-related) clipboard
   format we
   can present the contents of the file as. On success returns 
   non-NULL format name, and the actual filename found in CF_HDROP
   in *filename parameter. */
wchar_t *uxenclipboard_get_format_from_hdrop(int clipboard_open_done,
    wchar_t **filename);
#endif


