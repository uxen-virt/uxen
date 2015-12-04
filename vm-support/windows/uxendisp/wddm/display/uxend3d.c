/*
 * uxend3d.c - Xen Windows PV WDDM D3D Display Driver
 *
 * Copyright (c) 2010 Citrix, Inc.
 *
 */

/*
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
/*
 * uXen changes:
 *
 * Copyright 2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <windows.h>
#include <d3d9types.h>
#include <d3dumddi.h>
#include <d3dhal.h>

static HRESULT APIENTRY
uXenD3DSetRenderState(HANDLE hDevice, CONST D3DDDIARG_RENDERSTATE *pSetRenderState)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetRenderState);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DUpdateWInfo(HANDLE hDevice, CONST D3DDDIARG_WINFO *pUpdateWInfo)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pUpdateWInfo);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DValidateDevice(HANDLE hDevice, D3DDDIARG_VALIDATETEXTURESTAGESTATE *pValidateTextureStageState)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pValidateTextureStageState);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetTextureStageState(HANDLE hDevice, CONST D3DDDIARG_TEXTURESTAGESTATE *pSetTextureStageState)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetTextureStageState);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetTexture(HANDLE hDevice, UINT Stage, HANDLE hTexture)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(Stage);
    UNREFERENCED_PARAMETER(hTexture);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetPixelShader(HANDLE hDevice, HANDLE hShader)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(hShader);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetPixelShaderConst(HANDLE hDevice, CONST D3DDDIARG_SETPIXELSHADERCONST *pSetPixelShaderConst, CONST FLOAT *pRegisters)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetPixelShaderConst);
    UNREFERENCED_PARAMETER(pRegisters);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetStreamSourceUm(HANDLE hDevice, CONST D3DDDIARG_SETSTREAMSOURCEUM *pSetStreamSourceUm, CONST VOID *pUmBuffer)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetStreamSourceUm);
    UNREFERENCED_PARAMETER(pUmBuffer);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetIndices(HANDLE hDevice, CONST D3DDDIARG_SETINDICES *pSetIndices)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetIndices);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetIndicesUm(HANDLE hDevice, UINT IndexSize, CONST VOID *pUmBuffer)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(IndexSize);
    UNREFERENCED_PARAMETER(pUmBuffer);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDrawPrimitive(HANDLE hDevice, CONST D3DDDIARG_DRAWPRIMITIVE *pDrawPrimitive, CONST UINT *pFlagBuffer)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pDrawPrimitive);
    UNREFERENCED_PARAMETER(pFlagBuffer);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDrawIndexedPrimitive(HANDLE hDevice, CONST D3DDDIARG_DRAWINDEXEDPRIMITIVE *pDrawIndexedPrimitive)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pDrawIndexedPrimitive);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDrawRectPatch(HANDLE hDevice, CONST D3DDDIARG_DRAWRECTPATCH *pDrawRectPatch, CONST D3DDDIRECTPATCH_INFO *pInfo, CONST FLOAT *pPatch)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pDrawRectPatch);
    UNREFERENCED_PARAMETER(pInfo);
    UNREFERENCED_PARAMETER(pPatch);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDrawTriPatch(HANDLE hDevice, CONST D3DDDIARG_DRAWTRIPATCH *pDrawTriPatch, CONST D3DDDITRIPATCH_INFO *pInfo, CONST FLOAT *pPatch)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pDrawTriPatch);
    UNREFERENCED_PARAMETER(pInfo);
    UNREFERENCED_PARAMETER(pPatch);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDrawPrimitive2(HANDLE hDevice, CONST D3DDDIARG_DRAWPRIMITIVE2 *pDrawPrimitive2)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pDrawPrimitive2);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDrawIndexedPrimitive2(HANDLE hDevice, CONST D3DDDIARG_DRAWINDEXEDPRIMITIVE2 *pDrawIndexedPrimitive2, UINT IndicesSize, CONST VOID *pIndexBuffer, CONST UINT *pFlagBuffer)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pDrawIndexedPrimitive2);
    UNREFERENCED_PARAMETER(IndicesSize);
    UNREFERENCED_PARAMETER(pIndexBuffer);
    UNREFERENCED_PARAMETER(pFlagBuffer);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DVolBlt(HANDLE hDevice, CONST D3DDDIARG_VOLUMEBLT *pVolumeBlt)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pVolumeBlt);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DBufBlt(HANDLE hDevice, CONST D3DDDIARG_BUFFERBLT *pBufferBlt)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pBufferBlt);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DTexBlt(HANDLE hDevice, CONST D3DDDIARG_TEXBLT *pTextBlt)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pTextBlt);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DStateSet(HANDLE hDevice, D3DDDIARG_STATESET *pStateSet)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pStateSet);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetPriority(HANDLE hDevice, CONST D3DDDIARG_SETPRIORITY *pSetPriority)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetPriority);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DClear(HANDLE hDevice, CONST D3DDDIARG_CLEAR *pClear, UINT NumRect, CONST RECT *pRect)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pClear);
    UNREFERENCED_PARAMETER(NumRect);
    UNREFERENCED_PARAMETER(pRect);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DUpdatePalette(HANDLE hDevice, CONST D3DDDIARG_UPDATEPALETTE *pUpdatePalette, CONST PALETTEENTRY *pPaletteEntry)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pUpdatePalette);
    UNREFERENCED_PARAMETER(pPaletteEntry);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetPalette(HANDLE hDevice, CONST D3DDDIARG_SETPALETTE *pSetPalette)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetPalette);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetVertexShaderConst(HANDLE hDevice, CONST D3DDDIARG_SETVERTEXSHADERCONST *pSetVertexShaderConst, CONST VOID *pRegisters)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetVertexShaderConst);
    UNREFERENCED_PARAMETER(pRegisters);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DMultiplyTransform(HANDLE hDevice, CONST D3DDDIARG_MULTIPLYTRANSFORM *pMultiplyTransform)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pMultiplyTransform);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetTransform(HANDLE hDevice, CONST D3DDDIARG_SETTRANSFORM *pSetTransform)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetTransform);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetViewport(HANDLE hDevice, CONST D3DDDIARG_VIEWPORTINFO *pViewPortInfo)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pViewPortInfo);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetZRange(HANDLE hDevice, CONST D3DDDIARG_ZRANGE *pZRange)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pZRange);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetMaterial(HANDLE hDevice, CONST D3DDDIARG_SETMATERIAL *pSetMaterial)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetMaterial);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetLight(HANDLE hDevice, CONST D3DDDIARG_SETLIGHT *pSetLight, CONST D3DDDI_LIGHT *pLight)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetLight);
    UNREFERENCED_PARAMETER(pLight);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DCreateLight(HANDLE hDevice, CONST D3DDDIARG_CREATELIGHT *pCreateLight)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pCreateLight);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDestroyLight(HANDLE hDevice, CONST D3DDDIARG_DESTROYLIGHT *pDestroyLight)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pDestroyLight);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetClipPlane(HANDLE hDevice, CONST D3DDDIARG_SETCLIPPLANE *pSetClipPlane)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetClipPlane);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DGetInfo(HANDLE hDevice, UINT DevInfoID, VOID *pDevInfoStruct, UINT DevInfoSize)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(DevInfoID);
    UNREFERENCED_PARAMETER(pDevInfoStruct);
    UNREFERENCED_PARAMETER(DevInfoSize);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DLock(HANDLE hDevice, D3DDDIARG_LOCK *pLock)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pLock);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DUnlock(HANDLE hDevice, CONST D3DDDIARG_UNLOCK *pUnlock)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pUnlock);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DCreateResource(HANDLE hDevice, D3DDDIARG_CREATERESOURCE *pCreateResource)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pCreateResource);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDestroyResource(HANDLE hDevice, HANDLE hResource)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(hResource);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetDisplayMode(HANDLE hDevice, CONST D3DDDIARG_SETDISPLAYMODE *pSetDisplayMode)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetDisplayMode);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DPresent(HANDLE hDevice, CONST D3DDDIARG_PRESENT *pPresent)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pPresent);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DFlush(HANDLE hDevice)
{
    UNREFERENCED_PARAMETER(hDevice);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DCreateVertexShaderDecl(HANDLE hDevice, D3DDDIARG_CREATEVERTEXSHADERDECL *pCreateVertexShaderDecl, CONST D3DDDIVERTEXELEMENT *pVertexElements)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pCreateVertexShaderDecl);
    UNREFERENCED_PARAMETER(pVertexElements);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetVertexShaderDecl(HANDLE hDevice, HANDLE hShader)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(hShader);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDeleteVertexShaderDecl(HANDLE hDevice, HANDLE hShader)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(hShader);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DCreateVertexShaderFunc(HANDLE hDevice, D3DDDIARG_CREATEVERTEXSHADERFUNC *pCreateVertexShaderFunc, CONST UINT *pCode)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pCreateVertexShaderFunc);
    UNREFERENCED_PARAMETER(pCode);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetVertexShaderFunc(HANDLE hDevice, HANDLE hShader)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(hShader);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDeleteVertexShaderFunc(HANDLE hDevice, HANDLE hShader)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(hShader);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetVertexShaderConstI(HANDLE hDevice, CONST D3DDDIARG_SETVERTEXSHADERCONSTI *pSetVertexShaderConstI, CONST INT *pRegisters)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetVertexShaderConstI);
    UNREFERENCED_PARAMETER(pRegisters);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetVertexShaderConstB(HANDLE hDevice, CONST D3DDDIARG_SETVERTEXSHADERCONSTB *pSetVertexShaderConstB, CONST BOOL *pRegisters)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetVertexShaderConstB);
    UNREFERENCED_PARAMETER(pRegisters);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetScissorRect(HANDLE hDevice, CONST RECT *pRect)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pRect);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetStreamSource(HANDLE hDevice, CONST D3DDDIARG_SETSTREAMSOURCE *pSetStreamSource)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetStreamSource);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetStreamSourceFreq(HANDLE hDevice, CONST D3DDDIARG_SETSTREAMSOURCEFREQ *pSetStreamSourceFreq)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetStreamSourceFreq);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetConvolutionKernelMono(HANDLE hDevice, CONST D3DDDIARG_SETCONVOLUTIONKERNELMONO *pSetConvolutionKernelMono)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetConvolutionKernelMono);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DComposeRects(HANDLE hDevice, CONST D3DDDIARG_COMPOSERECTS *pComposeRects)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pComposeRects);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DBlt(HANDLE hDevice, CONST D3DDDIARG_BLT *pBlt)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pBlt);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DColorFill(HANDLE hDevice, CONST D3DDDIARG_COLORFILL *pColorFill)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pColorFill);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDepthFill(HANDLE hDevice, CONST D3DDDIARG_DEPTHFILL *pDepthFill)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pDepthFill);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DCreateQuery(HANDLE hDevice, D3DDDIARG_CREATEQUERY *pCreateQuery)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pCreateQuery);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDestroyQuery(HANDLE hDevice, HANDLE hQuery)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(hQuery);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DIssueQuery(HANDLE hDevice, CONST D3DDDIARG_ISSUEQUERY *pIssueQuery)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pIssueQuery);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DGetQueryData(HANDLE hDevice, CONST D3DDDIARG_GETQUERYDATA *pGetQueryData)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pGetQueryData);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetRenderTarget(HANDLE hDevice, CONST D3DDDIARG_SETRENDERTARGET *pSetRenderTarget)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetRenderTarget);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetDepthStencil(HANDLE hDevice, CONST D3DDDIARG_SETDEPTHSTENCIL *pSetDepthStencil)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetDepthStencil);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DGenerateMipSubLevels(HANDLE hDevice, CONST D3DDDIARG_GENERATEMIPSUBLEVELS *pGenerateMipSubLevels)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pGenerateMipSubLevels);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetPixelShaderConstI(HANDLE hDevice, CONST D3DDDIARG_SETPIXELSHADERCONSTI* pData, CONST INT *pRegisters)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pData);
    UNREFERENCED_PARAMETER(pRegisters);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetPixelShaderConstB(HANDLE hDevice, CONST D3DDDIARG_SETPIXELSHADERCONSTB *pSetPixelShaderConstB, CONST BOOL *pRegisters)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetPixelShaderConstB);
    UNREFERENCED_PARAMETER(pRegisters);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DCreatePixelShader(HANDLE hDevice, D3DDDIARG_CREATEPIXELSHADER *pCreatePixelShader, CONST UINT *pCode)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pCreatePixelShader);
    UNREFERENCED_PARAMETER(pCode);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDeletePixelShader(HANDLE hDevice, HANDLE hShader)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(hShader);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DCreateDecodeDevice(HANDLE hDevice, D3DDDIARG_CREATEDECODEDEVICE *pCreateDecodeDevice)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pCreateDecodeDevice);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDestroyDecodeDevice(HANDLE hDevice, HANDLE hDecodeDevice)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(hDecodeDevice);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetDecodeRenderTarget(HANDLE hDevice, CONST D3DDDIARG_SETDECODERENDERTARGET *pSetDecodeRenderTarget)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetDecodeRenderTarget);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDecodeBeginFrame(HANDLE hDevice, D3DDDIARG_DECODEBEGINFRAME *pDecodeBeginFrame)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pDecodeBeginFrame);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDecodeEndFrame(HANDLE hDevice, D3DDDIARG_DECODEENDFRAME *pDecodeEndFrame)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pDecodeEndFrame);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDecodeExecute(HANDLE hDevice, CONST D3DDDIARG_DECODEEXECUTE *pDecodeExecute)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pDecodeExecute);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDecodeExtensionExecute(HANDLE hDevice, CONST D3DDDIARG_DECODEEXTENSIONEXECUTE *pDecodeExtensionExecute)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pDecodeExtensionExecute);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DCreateVideoProcessDevice(HANDLE hDevice, D3DDDIARG_CREATEVIDEOPROCESSDEVICE *pCreateVideoProcessDevice)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pCreateVideoProcessDevice);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDestroyVideoProcessDevice(HANDLE hDevice, HANDLE hVideoProcessor)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(hVideoProcessor);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DVideoProcessBeginFrame(HANDLE hDevice, HANDLE hVideoProcessor)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(hVideoProcessor);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DVideoProcessEndFrame(HANDLE hDevice, D3DDDIARG_VIDEOPROCESSENDFRAME *pVideoProcessEndFrame)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pVideoProcessEndFrame);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetVideoProcessRenderTarget(HANDLE hDevice, CONST D3DDDIARG_SETVIDEOPROCESSRENDERTARGET *pSetVideoProcessRenderTarget)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetVideoProcessRenderTarget);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DVideoProcessBlt(HANDLE hDevice, CONST D3DDDIARG_VIDEOPROCESSBLT *pVideoProcessBlt)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pVideoProcessBlt);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DCreateExtensionDevice(HANDLE hDevice, D3DDDIARG_CREATEEXTENSIONDEVICE *pCreateExtensionDevice)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pCreateExtensionDevice);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDestroyExtensionDevice(HANDLE hDevice, HANDLE hExtension)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(hExtension);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DExtensionExecute(HANDLE hDevice, CONST D3DDDIARG_EXTENSIONEXECUTE *pExtensionExecute)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pExtensionExecute);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDestroyDevice(HANDLE hDevice)
{
    UNREFERENCED_PARAMETER(hDevice);
    return S_OK;
}

static HRESULT APIENTRY
uXenD3DCreateOverlay(HANDLE hDevice, D3DDDIARG_CREATEOVERLAY *pCreateOverlay)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pCreateOverlay);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DUpdateOverlay(HANDLE hDevice, CONST D3DDDIARG_UPDATEOVERLAY *pUpdateOverlay)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pUpdateOverlay);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DFlipOverlay(HANDLE hDevice, CONST D3DDDIARG_FLIPOVERLAY *pFlipOverlay)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pFlipOverlay);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DGetOverlayColorControls(HANDLE hDevice, D3DDDIARG_GETOVERLAYCOLORCONTROLS *pGetOverlayColorControls)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pGetOverlayColorControls);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DSetOverlayColorControls(HANDLE hDevice, CONST D3DDDIARG_SETOVERLAYCOLORCONTROLS *pSetOverlayColorControls)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pSetOverlayColorControls);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DDestroyOverlay(HANDLE hDevice, CONST D3DDDIARG_DESTROYOVERLAY *pDestroyOverlay)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pDestroyOverlay);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DQueryResourceResidency(HANDLE hDevice, CONST D3DDDIARG_QUERYRESOURCERESIDENCY *pQueryResourceResidency)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pQueryResourceResidency);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DOpenResource(HANDLE hDevice, D3DDDIARG_OPENRESOURCE *pOpenResource)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pOpenResource);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DGetCaptureAllocationHandle(HANDLE hDevice, D3DDDIARG_GETCAPTUREALLOCATIONHANDLE *pGetCaptureAllocationHandle)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pGetCaptureAllocationHandle);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DCaptureToSysMem(HANDLE hDevice, CONST D3DDDIARG_CAPTURETOSYSMEM *pCaptureToSystem)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pCaptureToSystem);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DLockAsync(HANDLE hDevice, D3DDDIARG_LOCKASYNC *pLockAsync)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pLockAsync);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DUnlockAsync(HANDLE hDevice, CONST D3DDDIARG_UNLOCKASYNC *pUnlockAsync)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pUnlockAsync);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DRename(HANDLE hDevice, CONST D3DDDIARG_RENAME *pRename)
{
    UNREFERENCED_PARAMETER(hDevice);
    UNREFERENCED_PARAMETER(pRename);

    return E_NOTIMPL;
}

static HRESULT APIENTRY
uXenD3DGetCaps(HANDLE hAdapter, CONST D3DDDIARG_GETCAPS *pGetCaps)
{
    UNREFERENCED_PARAMETER(hAdapter);
    UNREFERENCED_PARAMETER(pGetCaps);

    return S_OK;
}

static HRESULT APIENTRY
uXenD3DCreateDevice(HANDLE hAdapter, D3DDDIARG_CREATEDEVICE *pCreateData)
{
    pCreateData->hDevice = hAdapter;
    pCreateData->pDeviceFuncs->pfnSetRenderState                = uXenD3DSetRenderState;
    pCreateData->pDeviceFuncs->pfnUpdateWInfo                   = uXenD3DUpdateWInfo;
    pCreateData->pDeviceFuncs->pfnValidateDevice                = uXenD3DValidateDevice;
    pCreateData->pDeviceFuncs->pfnSetTextureStageState          = uXenD3DSetTextureStageState;
    pCreateData->pDeviceFuncs->pfnSetTexture                    = uXenD3DSetTexture;
    pCreateData->pDeviceFuncs->pfnSetPixelShader                = uXenD3DSetPixelShader;
    pCreateData->pDeviceFuncs->pfnSetPixelShaderConst           = uXenD3DSetPixelShaderConst;
    pCreateData->pDeviceFuncs->pfnSetStreamSourceUm             = uXenD3DSetStreamSourceUm;
    pCreateData->pDeviceFuncs->pfnSetIndices                    = uXenD3DSetIndices;
    pCreateData->pDeviceFuncs->pfnSetIndicesUm                  = uXenD3DSetIndicesUm;
    pCreateData->pDeviceFuncs->pfnDrawPrimitive                 = uXenD3DDrawPrimitive;
    pCreateData->pDeviceFuncs->pfnDrawIndexedPrimitive          = uXenD3DDrawIndexedPrimitive;
    pCreateData->pDeviceFuncs->pfnDrawRectPatch                 = uXenD3DDrawRectPatch;
    pCreateData->pDeviceFuncs->pfnDrawTriPatch                  = uXenD3DDrawTriPatch;
    pCreateData->pDeviceFuncs->pfnDrawPrimitive2                = uXenD3DDrawPrimitive2;
    pCreateData->pDeviceFuncs->pfnDrawIndexedPrimitive2         = uXenD3DDrawIndexedPrimitive2;
    pCreateData->pDeviceFuncs->pfnVolBlt                        = uXenD3DVolBlt;
    pCreateData->pDeviceFuncs->pfnBufBlt                        = uXenD3DBufBlt;
    pCreateData->pDeviceFuncs->pfnTexBlt                        = uXenD3DTexBlt;
    pCreateData->pDeviceFuncs->pfnStateSet                      = uXenD3DStateSet;
    pCreateData->pDeviceFuncs->pfnSetPriority                   = uXenD3DSetPriority;
    pCreateData->pDeviceFuncs->pfnClear                         = uXenD3DClear;
    pCreateData->pDeviceFuncs->pfnUpdatePalette                 = uXenD3DUpdatePalette;
    pCreateData->pDeviceFuncs->pfnSetPalette                    = uXenD3DSetPalette;
    pCreateData->pDeviceFuncs->pfnSetVertexShaderConst          = uXenD3DSetVertexShaderConst;
    pCreateData->pDeviceFuncs->pfnMultiplyTransform             = uXenD3DMultiplyTransform;
    pCreateData->pDeviceFuncs->pfnSetTransform                  = uXenD3DSetTransform;
    pCreateData->pDeviceFuncs->pfnSetViewport                   = uXenD3DSetViewport;
    pCreateData->pDeviceFuncs->pfnSetZRange                     = uXenD3DSetZRange;
    pCreateData->pDeviceFuncs->pfnSetMaterial                   = uXenD3DSetMaterial;
    pCreateData->pDeviceFuncs->pfnSetLight                      = uXenD3DSetLight;
    pCreateData->pDeviceFuncs->pfnCreateLight                   = uXenD3DCreateLight;
    pCreateData->pDeviceFuncs->pfnDestroyLight                  = uXenD3DDestroyLight;
    pCreateData->pDeviceFuncs->pfnSetClipPlane                  = uXenD3DSetClipPlane;
    pCreateData->pDeviceFuncs->pfnGetInfo                       = uXenD3DGetInfo;
    pCreateData->pDeviceFuncs->pfnLock                          = uXenD3DLock;
    pCreateData->pDeviceFuncs->pfnUnlock                        = uXenD3DUnlock;
    pCreateData->pDeviceFuncs->pfnCreateResource                = uXenD3DCreateResource;
    pCreateData->pDeviceFuncs->pfnDestroyResource               = uXenD3DDestroyResource;
    pCreateData->pDeviceFuncs->pfnSetDisplayMode                = uXenD3DSetDisplayMode;
    pCreateData->pDeviceFuncs->pfnPresent                       = uXenD3DPresent;
    pCreateData->pDeviceFuncs->pfnFlush                         = uXenD3DFlush;
    pCreateData->pDeviceFuncs->pfnCreateVertexShaderFunc        = uXenD3DCreateVertexShaderFunc;
    pCreateData->pDeviceFuncs->pfnDeleteVertexShaderFunc        = uXenD3DDeleteVertexShaderFunc;
    pCreateData->pDeviceFuncs->pfnSetVertexShaderFunc           = uXenD3DSetVertexShaderFunc;
    pCreateData->pDeviceFuncs->pfnCreateVertexShaderDecl        = uXenD3DCreateVertexShaderDecl;
    pCreateData->pDeviceFuncs->pfnDeleteVertexShaderDecl        = uXenD3DDeleteVertexShaderDecl;
    pCreateData->pDeviceFuncs->pfnSetVertexShaderDecl           = uXenD3DSetVertexShaderDecl;
    pCreateData->pDeviceFuncs->pfnSetVertexShaderConstI         = uXenD3DSetVertexShaderConstI;
    pCreateData->pDeviceFuncs->pfnSetVertexShaderConstB         = uXenD3DSetVertexShaderConstB;
    pCreateData->pDeviceFuncs->pfnSetScissorRect                = uXenD3DSetScissorRect;
    pCreateData->pDeviceFuncs->pfnSetStreamSource               = uXenD3DSetStreamSource;
    pCreateData->pDeviceFuncs->pfnSetStreamSourceFreq           = uXenD3DSetStreamSourceFreq;
    pCreateData->pDeviceFuncs->pfnSetConvolutionKernelMono      = uXenD3DSetConvolutionKernelMono;
    pCreateData->pDeviceFuncs->pfnComposeRects                  = uXenD3DComposeRects;
    pCreateData->pDeviceFuncs->pfnBlt                           = uXenD3DBlt;
    pCreateData->pDeviceFuncs->pfnColorFill                     = uXenD3DColorFill;
    pCreateData->pDeviceFuncs->pfnDepthFill                     = uXenD3DDepthFill;
    pCreateData->pDeviceFuncs->pfnCreateQuery                   = uXenD3DCreateQuery;
    pCreateData->pDeviceFuncs->pfnDestroyQuery                  = uXenD3DDestroyQuery;
    pCreateData->pDeviceFuncs->pfnIssueQuery                    = uXenD3DIssueQuery;
    pCreateData->pDeviceFuncs->pfnGetQueryData                  = uXenD3DGetQueryData;
    pCreateData->pDeviceFuncs->pfnSetRenderTarget               = uXenD3DSetRenderTarget;
    pCreateData->pDeviceFuncs->pfnSetDepthStencil               = uXenD3DSetDepthStencil;
    pCreateData->pDeviceFuncs->pfnGenerateMipSubLevels          = uXenD3DGenerateMipSubLevels;
    pCreateData->pDeviceFuncs->pfnSetPixelShaderConstI          = uXenD3DSetPixelShaderConstI;
    pCreateData->pDeviceFuncs->pfnSetPixelShaderConstB          = uXenD3DSetPixelShaderConstB;
    pCreateData->pDeviceFuncs->pfnCreatePixelShader             = uXenD3DCreatePixelShader;
    pCreateData->pDeviceFuncs->pfnDeletePixelShader             = uXenD3DDeletePixelShader;
    pCreateData->pDeviceFuncs->pfnCreateDecodeDevice            = uXenD3DCreateDecodeDevice;
    pCreateData->pDeviceFuncs->pfnDestroyDecodeDevice           = uXenD3DDestroyDecodeDevice;
    pCreateData->pDeviceFuncs->pfnSetDecodeRenderTarget         = uXenD3DSetDecodeRenderTarget;
    pCreateData->pDeviceFuncs->pfnDecodeBeginFrame              = uXenD3DDecodeBeginFrame;
    pCreateData->pDeviceFuncs->pfnDecodeEndFrame                = uXenD3DDecodeEndFrame;
    pCreateData->pDeviceFuncs->pfnDecodeExecute                 = uXenD3DDecodeExecute;
    pCreateData->pDeviceFuncs->pfnDecodeExtensionExecute        = uXenD3DDecodeExtensionExecute;
    pCreateData->pDeviceFuncs->pfnCreateVideoProcessDevice      = uXenD3DCreateVideoProcessDevice;
    pCreateData->pDeviceFuncs->pfnDestroyVideoProcessDevice     = uXenD3DDestroyVideoProcessDevice;
    pCreateData->pDeviceFuncs->pfnVideoProcessBeginFrame        = uXenD3DVideoProcessBeginFrame;
    pCreateData->pDeviceFuncs->pfnVideoProcessEndFrame          = uXenD3DVideoProcessEndFrame;
    pCreateData->pDeviceFuncs->pfnSetVideoProcessRenderTarget   = uXenD3DSetVideoProcessRenderTarget;
    pCreateData->pDeviceFuncs->pfnVideoProcessBlt               = uXenD3DVideoProcessBlt;
    pCreateData->pDeviceFuncs->pfnCreateExtensionDevice         = uXenD3DCreateExtensionDevice;
    pCreateData->pDeviceFuncs->pfnDestroyExtensionDevice        = uXenD3DDestroyExtensionDevice;
    pCreateData->pDeviceFuncs->pfnExtensionExecute              = uXenD3DExtensionExecute;
    pCreateData->pDeviceFuncs->pfnCreateOverlay                 = uXenD3DCreateOverlay;
    pCreateData->pDeviceFuncs->pfnUpdateOverlay                 = uXenD3DUpdateOverlay;
    pCreateData->pDeviceFuncs->pfnFlipOverlay                   = uXenD3DFlipOverlay;
    pCreateData->pDeviceFuncs->pfnGetOverlayColorControls       = uXenD3DGetOverlayColorControls;
    pCreateData->pDeviceFuncs->pfnSetOverlayColorControls       = uXenD3DSetOverlayColorControls;
    pCreateData->pDeviceFuncs->pfnDestroyOverlay                = uXenD3DDestroyOverlay;
    pCreateData->pDeviceFuncs->pfnDestroyDevice                 = uXenD3DDestroyDevice;
    pCreateData->pDeviceFuncs->pfnQueryResourceResidency        = uXenD3DQueryResourceResidency;
    pCreateData->pDeviceFuncs->pfnOpenResource                  = uXenD3DOpenResource;
    pCreateData->pDeviceFuncs->pfnGetCaptureAllocationHandle    = uXenD3DGetCaptureAllocationHandle;
    pCreateData->pDeviceFuncs->pfnCaptureToSysMem               = uXenD3DCaptureToSysMem;
    pCreateData->pDeviceFuncs->pfnLockAsync                     = uXenD3DLockAsync;
    pCreateData->pDeviceFuncs->pfnUnlockAsync                   = uXenD3DUnlockAsync;
    pCreateData->pDeviceFuncs->pfnRename                        = uXenD3DRename;

    return S_OK;
}

static HRESULT APIENTRY
uXenD3DCloseAdapter(HANDLE hAdapter)
{
    UNREFERENCED_PARAMETER(hAdapter);

    return S_OK;
}

HRESULT APIENTRY
OpenAdapter(D3DDDIARG_OPENADAPTER *pOpenData)
{
    pOpenData->hAdapter = (HANDLE)1;
    pOpenData->pAdapterFuncs->pfnGetCaps = uXenD3DGetCaps;
    pOpenData->pAdapterFuncs->pfnCreateDevice = uXenD3DCreateDevice;
    pOpenData->pAdapterFuncs->pfnCloseAdapter = uXenD3DCloseAdapter;
    pOpenData->DriverVersion = D3D_UMD_INTERFACE_VERSION;

    return S_OK;
}

BOOL WINAPI
DllMain(HINSTANCE hModule, DWORD Reason, LPVOID pReserved)
{
    UNREFERENCED_PARAMETER(pReserved);

    switch (Reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        break;
    default:
        break;
    }

    return TRUE;
}
