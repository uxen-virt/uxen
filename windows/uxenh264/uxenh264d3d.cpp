/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <d3d11.h>
#include <dxgi1_3.h>
#include <D3Dcompiler.h>
#include <uxenh264-common.h>
#include <atlbase.h>
#include "uxenh264d3d.h"
#include "debug-user.h"

struct uxenh264_d3d_ctx {
    CComPtr<ID3D11DeviceContext>      pImmediateContext;
    CComPtr<ID3D11Texture2D>          tex;
    CComPtr<ID3D11RenderTargetView>   tex_rt;
    CComPtr<ID3D11Texture2D>          tmp_tex;
    CComPtr<ID3D11RenderTargetView>   tmp_rt;
    CComPtr<ID3D11ShaderResourceView> tmp_sr;
    CComPtr<ID3D11Texture2D>          blank_tex;
    CComPtr<ID3D11ShaderResourceView> blank_sr;
    CComPtr<ID3D11VertexShader>       pVS;
    CComPtr<ID3D11PixelShader>        pPS;
    CComPtr<ID3D11Buffer>             pVBuffer;
    CComPtr<ID3D11InputLayout>        pLayout;
    CComPtr<ID3D11SamplerState>       sampleState;
    D3D11_VIEWPORT                    vp[2];
};

static const char *shaders =
"struct VOut"
"{"
"    float4 position : SV_POSITION;"
"    float2 tex : TEXCOORD0;"
"};"
""
"VOut VShader(float4 position : POSITION, float2 tex : TEXCOORD0)"
"{"
"    VOut output;"
""
"    output.position = position;"
"    output.tex = tex;"
""
"    return output;"
"}"
""
"Texture2D shaderTexture1 : register(t0);"
"Texture2D shaderTexture2 : register(t1);"
"SamplerState SampleType : register(s0);;"
""
"float4 PShader(float4 position : SV_POSITION, float2 tex : TEXCOORD0) : SV_TARGET"
"{"
"    float4 textureColor1;"
"    float4 textureColor2;"
"    float alpha;"
"    textureColor1 = shaderTexture1.Sample(SampleType, tex);"
"    textureColor2 = shaderTexture2.Sample(SampleType, tex);"
"    if (textureColor2.r > 0.0f || textureColor2.g > 0.0f || textureColor2.b > 0.0f) {"
"        alpha = min(max(max(textureColor2.r, textureColor2.g), textureColor2.b) * 4, 1.0f);"
"        return textureColor1 * (1.0f - alpha) + textureColor2 * alpha;"
"    } else {"
"        return textureColor1;"
"    }"
"}";

typedef struct D3DXVECTOR2 {
    FLOAT x;
    FLOAT y;
} D3DXVECTOR2, *LPD3DXVECTOR2;

typedef struct D3DXVECTOR3 {
    FLOAT x;
    FLOAT y;
    FLOAT z;
} D3DXVECTOR3, *LPD3DXVECTOR3;

struct VERTEX
{
    D3DXVECTOR3 position;
    D3DXVECTOR2 texture;
};

D3D11_INPUT_ELEMENT_DESC ied[] =
{
    { "POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0 },
    { "TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT, 0, D3D11_APPEND_ALIGNED_ELEMENT, D3D11_INPUT_PER_VERTEX_DATA, 0 },
};

VERTEX OurVertices[] =
{
    { {-1.0f, -1.0f, 0.0f}, { 0.0f,  1.0f} },
    { {-1.0f,  1.0f, 0.0f}, { 0.0f,  0.0f} },
    { { 1.0f, -1.0f, 0.0f}, { 1.0f,  1.0f} },
    { { 1.0f,  1.0f, 0.0f}, { 1.0f,  0.0f} }
};

HRESULT CreateRenderTarget(struct uxenh264_d3d_ctx *ctx, ID3D11Device *d3d11_dev, UINT width, UINT height, HANDLE *surface)
{
    HRESULT result = S_OK;
    CComQIPtr<IDXGIResource> tex_res;
    D3D11_TEXTURE2D_DESC desc = {};

    ctx->pImmediateContext->OMSetRenderTargets(0, 0, 0);
    ctx->tex.Release();

    desc.Width = width;
    desc.Height = height;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET;

    result = d3d11_dev->CreateTexture2D(&desc, NULL, &ctx->tmp_tex);
    if (FAILED(result)) {
        uxen_err("CreateTexture2D failed 0x%x", result);
        goto exit;
    }

    result = d3d11_dev->CreateRenderTargetView(ctx->tmp_tex, NULL, &ctx->tmp_rt);
    if (FAILED(result)) {
        uxen_err("CreateRenderTargetView failed 0x%x", result);
        goto exit;
    }

    result = d3d11_dev->CreateShaderResourceView(ctx->tmp_tex, NULL, &ctx->tmp_sr);
    if (FAILED(result)) {
        uxen_err("CreateShaderResourceView failed 0x%x", result);
        goto exit;
    }

    result = d3d11_dev->CreateTexture2D(&desc, NULL, &ctx->blank_tex);
    if (FAILED(result)) {
        uxen_err("CreateTexture2D failed 0x%x", result);
        goto exit;
    }

    result = d3d11_dev->CreateShaderResourceView(ctx->blank_tex, NULL, &ctx->blank_sr);
    if (FAILED(result)) {
        uxen_err("CreateShaderResourceView failed 0x%x", result);
        goto exit;
    }

    desc.MiscFlags = D3D11_RESOURCE_MISC_SHARED;

    result = d3d11_dev->CreateTexture2D(&desc, NULL, &ctx->tex);
    if (FAILED(result)) {
        uxen_err("CreateTexture2D failed 0x%x", result);
        goto exit;
    }

    result = d3d11_dev->CreateRenderTargetView(ctx->tex, NULL, &ctx->tex_rt);
    if (FAILED(result)) {
        uxen_err("CreateRenderTargetView failed 0x%x", result);
        goto exit;
    }

    tex_res = ctx->tex;
    if (!tex_res) {
        result = E_FAIL;
        uxen_err("QueryInterface IDXGIResource failed 0x%x", result);
        goto exit;
    }

    result = tex_res->GetSharedHandle(surface);
    if (FAILED(result)) {
        uxen_err("GetSharedHandle failed 0x%x", result);
        goto exit;
    }

    float viewport_res_x = .0f;
    float viewport_res_y = .0f;
    float screen_aspect_ratio = (float)width / (float)height;

    if ((float)width < (UXENH264_FS_OUTPUT_WIDTH * screen_aspect_ratio)) {
        viewport_res_x = (float)width;
        viewport_res_y = (width * UXENH264_FS_OUTPUT_HEIGHT) / (float)UXENH264_FS_OUTPUT_WIDTH;
    }
    else {
        viewport_res_y = (float)height;
        viewport_res_x = (height * UXENH264_FS_OUTPUT_WIDTH) / (float)UXENH264_FS_OUTPUT_HEIGHT;
    }

    uxen_msg("Viewport size %dx%d", (int)viewport_res_x, (int)viewport_res_y);

    // Setup the viewport
    D3D11_VIEWPORT *vp = &ctx->vp[0];
    vp->Width = viewport_res_x;
    vp->Height = viewport_res_y;
    vp->MinDepth = 0.0f;
    vp->MaxDepth = 1.0f;
    vp->TopLeftX = 0;
    vp->TopLeftY = (height - viewport_res_y) / 2;

    vp = &ctx->vp[1];
    vp->Width = (FLOAT)width;
    vp->Height = (FLOAT)height;
    vp->MinDepth = 0.0f;
    vp->MaxDepth = 1.0f;
    vp->TopLeftX = 0;
    vp->TopLeftY = 0;

exit:
    return result;
}

struct uxenh264_d3d_ctx *InitDevice(ID3D11Device *d3d11_dev)
{
    HRESULT result = S_OK;
    struct uxenh264_d3d_ctx *ctx = NULL;

    ctx = (struct uxenh264_d3d_ctx *)calloc(1, sizeof(*ctx));
    if (!ctx) {
        uxen_err("Call to calloc failed.");
        goto exit;
    }

    d3d11_dev->GetImmediateContext(&ctx->pImmediateContext);

    // load and compile the two shaders
    ID3DBlob *VS, *PS;
    result = D3DCompile(shaders, strlen(shaders), "shaders.shader", NULL, NULL, "VShader", "vs_5_0", 0, 0, &VS, NULL);
    if (FAILED(result)) {
        uxen_err("Call to D3DCompile vertex shader has failed 0x%x", result);
        goto exit;
    }
    result = D3DCompile(shaders, strlen(shaders), "shaders.shader", NULL, NULL, "PShader", "ps_5_0", 0, 0, &PS, NULL);
    if (FAILED(result)) {
        uxen_err("Call to D3DCompile pixle shader has failed 0x%x", result);
        goto exit;
    }

    // encapsulate both shaders into shader objects
    result = d3d11_dev->CreateVertexShader(VS->GetBufferPointer(), VS->GetBufferSize(), NULL, &ctx->pVS);
    if (FAILED(result)) {
        uxen_err("Call to CreateVertexShader has failed 0x%x", result);
        goto exit;
    }
    result = d3d11_dev->CreatePixelShader(PS->GetBufferPointer(), PS->GetBufferSize(), NULL, &ctx->pPS);
    if (FAILED(result)) {
        uxen_err("Call to CreatePixelShader has failed 0x%x", result);
        goto exit;
    }

    // set the shader objects
    ctx->pImmediateContext->VSSetShader(ctx->pVS, 0, 0);
    ctx->pImmediateContext->PSSetShader(ctx->pPS, 0, 0);

    D3D11_BUFFER_DESC bd;
    ZeroMemory(&bd, sizeof(bd));
    bd.Usage = D3D11_USAGE_DYNAMIC;
    bd.ByteWidth = sizeof(OurVertices);
    bd.BindFlags = D3D11_BIND_VERTEX_BUFFER;
    bd.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;

    result = d3d11_dev->CreateBuffer(&bd, NULL, &ctx->pVBuffer);
    if (FAILED(result)) {
        uxen_err("Call to d3d11_dev->CreateBuffer has failed 0x%x", result);
        goto exit;
    }

    D3D11_MAPPED_SUBRESOURCE ms;
    ZeroMemory(&ms, sizeof(ms));
    ctx->pImmediateContext->Map(ctx->pVBuffer, NULL, D3D11_MAP_WRITE_DISCARD, NULL, &ms);
    memcpy(ms.pData, OurVertices, sizeof(OurVertices));
    ctx->pImmediateContext->Unmap(ctx->pVBuffer, NULL);

    result = d3d11_dev->CreateInputLayout(ied, 2, VS->GetBufferPointer(), VS->GetBufferSize(), &ctx->pLayout);
    if (FAILED(result)) {
        uxen_err("Call to d3d11_dev->CreateInputLayout has failed 0x%x", result);
        goto exit;
    }
    ctx->pImmediateContext->IASetInputLayout(ctx->pLayout);

    // Create a texture sampler state description.
    D3D11_SAMPLER_DESC samplerDesc;
    ZeroMemory(&samplerDesc, sizeof(samplerDesc));
    samplerDesc.Filter = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
    samplerDesc.AddressU = D3D11_TEXTURE_ADDRESS_WRAP;
    samplerDesc.AddressV = D3D11_TEXTURE_ADDRESS_WRAP;
    samplerDesc.AddressW = D3D11_TEXTURE_ADDRESS_WRAP;
    samplerDesc.MipLODBias = 0.0f;
    samplerDesc.MaxAnisotropy = 1;
    samplerDesc.ComparisonFunc = D3D11_COMPARISON_ALWAYS;
    samplerDesc.BorderColor[0] = 0;
    samplerDesc.BorderColor[1] = 0;
    samplerDesc.BorderColor[2] = 0;
    samplerDesc.BorderColor[3] = 0;
    samplerDesc.MinLOD = 0;
    samplerDesc.MaxLOD = D3D11_FLOAT32_MAX;

    // Create the texture sampler state.
    result = d3d11_dev->CreateSamplerState(&samplerDesc, &ctx->sampleState);
    if (FAILED(result)) {
        uxen_err("Call to d3d11_dev->CreateSamplerState has failed 0x%x", result);
        goto exit;
    }
    ctx->pImmediateContext->PSSetSamplers(0, 1, &ctx->sampleState);

    UINT stride = sizeof(VERTEX);
    UINT offset = 0;
    ctx->pImmediateContext->IASetVertexBuffers(0, 1, &ctx->pVBuffer, &stride, &offset);
    ctx->pImmediateContext->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);

exit:
    return ctx;
}

void Render(struct uxenh264_d3d_ctx *ctx, ID3D11Device *d3d11_dev, CComPtr<ID3D11Texture2D> frame, CComPtr<ID3D11Texture2D> overlay)
{
    HRESULT hr = S_OK;
    const FLOAT black[4] = {};
    ID3D11ShaderResourceView *view[2] = {};
    CComPtr<ID3D11ShaderResourceView> frame_view = NULL;
    CComPtr<ID3D11ShaderResourceView> overlay_view = NULL;

    hr = d3d11_dev->CreateShaderResourceView(frame, NULL, &frame_view);
    if (FAILED(hr)) {
        uxen_err("CreateShaderResourceView frame 0x%x; result 0x%x", frame, hr);
        return;
    }
    hr = d3d11_dev->CreateShaderResourceView(overlay, NULL, &overlay_view);
    if (FAILED(hr)) {
        uxen_err("CreateShaderResourceView overlay 0x%x; result 0x%x", overlay, hr);
        return;
    }

    view[0] = frame_view;
    view[1] = ctx->blank_sr;
    ctx->pImmediateContext->RSSetViewports(1, &ctx->vp[0]);
    ctx->pImmediateContext->PSSetShaderResources(0, 2, view);
    ctx->pImmediateContext->OMSetRenderTargets(1, &ctx->tmp_rt, NULL);
    ctx->pImmediateContext->Draw(4, 0);

    view[0] = ctx->tmp_sr;
    view[1] = overlay_view;
    ctx->pImmediateContext->RSSetViewports(1, &ctx->vp[1]);
    ctx->pImmediateContext->OMSetRenderTargets(1, &ctx->tex_rt, NULL);
    ctx->pImmediateContext->PSSetShaderResources(0, 2, view);
    ctx->pImmediateContext->Draw(4, 0);
    ctx->pImmediateContext->Flush();
}

void CleanupDevice(struct uxenh264_d3d_ctx *ctx)
{
    if (!ctx) return;
    if (ctx->pImmediateContext) ctx->pImmediateContext->ClearState();
    ctx->pImmediateContext.Release();
    ctx->tex.Release();
    ctx->tex_rt.Release();
    ctx->tmp_tex.Release();
    ctx->tmp_rt.Release();
    ctx->tmp_sr.Release();
    ctx->blank_tex.Release();
    ctx->blank_sr.Release();
    ctx->pVS.Release();
    ctx->pPS.Release();
    ctx->pVBuffer.Release();
    ctx->pLayout.Release();
    ctx->sampleState.Release();
    free(ctx);
}
