/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __BR_H264_PIPELINE_H__
#define __BR_H264_PIPELINE_H__

#include <atlbase.h>

struct ID3D11Device;

struct pipeline
{
    CComPtr<IMFTransform> dec;
    CComPtr<IMFTransform> proc;
    CComPtr<ID3D11Device> d3d11_dev;
    bool started;
};

struct pipeline *
create_pipeline(void);

void
destroy_pipeline(struct pipeline *pipeline);

void
start_pipeline(struct pipeline* pipeline);

void
stop_pipeline(struct pipeline* pipeline);

HRESULT
propagate_media_type(struct pipeline *pipeline, UINT32 width, UINT32 height, bool limit = false);

#endif //__BR_H264_PIPELINE_H__
