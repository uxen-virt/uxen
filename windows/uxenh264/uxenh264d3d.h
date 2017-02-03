/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#pragma once

struct uxenh264_d3d_ctx;

struct uxenh264_d3d_ctx *InitDevice(ID3D11Device *d3d11_dev);
HRESULT CreateRenderTarget(struct uxenh264_d3d_ctx *ctx, ID3D11Device *d3d11_dev, UINT width, UINT height, HANDLE *surface);
void CleanupDevice(struct uxenh264_d3d_ctx *ctx);
void Render(struct uxenh264_d3d_ctx *ctx, ID3D11Device *d3d11_dev, CComPtr<ID3D11Texture2D> texture1, CComPtr<ID3D11Texture2D> texture2);
