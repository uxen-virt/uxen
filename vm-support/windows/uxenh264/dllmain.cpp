/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "uxenh264.h"
#include <mfidl.h>
#include <d3d11.h>
#include <dxgi1_2.h>

typedef HRESULT (*DllGetClassObjectType)(REFCLSID, REFIID, void**);

EXTERN_GUID(BR_CLSID_VideoProcessorMFT, 0x88753b26, 0x5b24, 0x49bd, 0xb2, 0xe7, 0x0c, 0x44, 0x5c, 0x78, 0xc9, 0x82);

UINT_PTR g_originalProcessOutput;
UINT_PTR g_originalProcessInput;
UINT_PTR g_originalPresent;
bool g_getReal;

class ClassFactory : public IClassFactory
{
protected:
            volatile ULONG  m_ulRefCount; // Reference count.
    static  volatile ULONG  m_ulServerLocks; // Number of server locks

public:
    ClassFactory(void)
    {
        m_ulRefCount = 1;
    }

    static bool IsLocked(void)
    {
        return (m_ulServerLocks != 0);
    }

    // IUnknown methods
    ULONG __stdcall AddRef(void)
    {
        return InterlockedIncrement(&m_ulRefCount);
    }

    ULONG __stdcall Release(void)
    {
        ULONG ulRef = 0;
        if (m_ulRefCount > 0)
            ulRef = InterlockedDecrement(&m_ulRefCount);
        if (ulRef == 0)
            delete this;
        return ulRef;
    }

    HRESULT __stdcall QueryInterface(
        REFIID riid,
        void** ppvObject)
    {
        HRESULT hr = S_OK;
        if (ppvObject == NULL)
            return E_POINTER;

        if (riid == IID_IUnknown)
            *ppvObject = (IUnknown*)this;
        else if (riid == IID_IClassFactory)
            *ppvObject = (IClassFactory*)this;
        else 
        {
            *ppvObject = NULL;
            return E_NOINTERFACE;
        }

        AddRef();
        return hr;
    }

    HRESULT __stdcall CreateInstance(
        IUnknown *pUnkOuter, REFIID riid, void** ppv)
    {
        HRESULT         hr      = S_OK;
        IMFTransform*   pHWMFT  = NULL;

        if (pUnkOuter != NULL)
            return CLASS_E_NOAGGREGATION;

        hr = uxenh264::CreateInstance(&pHWMFT);
        if (FAILED(hr))
            return hr;

        hr = pHWMFT->QueryInterface(riid, ppv);
        if (FAILED(hr))
            return hr;

        SAFERELEASE(pHWMFT);

        return hr;
    }

    HRESULT __stdcall LockServer(
        BOOL bLock)
    {
        HRESULT hr = S_OK;
        if (bLock != FALSE)
            InterlockedIncrement(&m_ulServerLocks);
        else
            InterlockedDecrement(&m_ulServerLocks);
        return hr;
    }
};

volatile ULONG  uxenh264::m_ulNumObjects = 0;       // Number of active COM objects
volatile ULONG ClassFactory::m_ulServerLocks = 0; // Number of server locks

BOOL APIENTRY DllMain(HANDLE, DWORD, LPVOID)
{
    return TRUE;
}

HRESULT __stdcall DllCanUnloadNow(void)
{
    return S_FALSE;
}

HRESULT __stdcall DllRegisterServer(void)
{
    return S_OK;
}

HRESULT __stdcall DllUnregisterServer(void)
{
    return S_OK;
}

static HRESULT SVRProc(void)
{
    HRESULT result = S_OK;
    WNDCLASSEX wc = {};

    wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
    wc.lpfnWndProc = DefWindowProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hIcon = LoadIcon(NULL, IDI_WINLOGO);
    wc.hIconSm = wc.hIcon;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszMenuName = NULL;
    wc.lpszClassName = TEXT("uxenh264_fullscreen");
    wc.cbSize = sizeof(WNDCLASSEX);

    if (!RegisterClassEx(&wc)) {
        uxen_err("Call to RegisterClass has failed.\n");
        result = E_FAIL;
        goto exit;
    }

    HWND hwnd = CreateWindowEx(WS_EX_APPWINDOW, TEXT("uxenh264_fullscreen"),
        TEXT("uxenh264_fullscreen"),
        WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
        0, 0,
        GetSystemMetrics(SM_CXSCREEN),
        GetSystemMetrics(SM_CYSCREEN),
        NULL,
        NULL,
        GetModuleHandle(NULL),
        NULL);
    if (!hwnd) {
        uxen_err("Call to CreateWindowEx has failed.\n");
        result = E_FAIL;
        goto exit;
    }

    DXGI_SWAP_CHAIN_DESC1 desc;
    ZeroMemory(&desc, sizeof(desc));
    desc.BufferCount = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.SampleDesc.Count = 1;
    desc.Flags = 0;
    desc.Width = GetSystemMetrics(SM_CXSCREEN);
    desc.Height = GetSystemMetrics(SM_CYSCREEN);
    
    D3D_FEATURE_LEVEL featureLevel = D3D_FEATURE_LEVEL_11_0;
    ID3D11Device *pd3dDevice = NULL;
    result = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, &featureLevel, 1, D3D11_SDK_VERSION,
        NULL, NULL, &pd3dDevice, NULL, NULL);
    if (FAILED(result)) {
        uxen_err("Call to D3D11CreateDeviceAndSwapChain has failed 0x%x", result);
        goto exit;
    }

    IDXGIDevice2 *pDXGIDevice = NULL;
    result = pd3dDevice->QueryInterface(__uuidof(IDXGIDevice2), (void **)&pDXGIDevice);
    if (FAILED(result)) {
        uxen_err("Call to QueryInterface(__uuidof(IDXGIDevice2)) has failed 0x%x", result);
        goto exit;
    }

    IDXGIAdapter *pDXGIAdapter = NULL;
    result = pDXGIDevice->GetParent(__uuidof(IDXGIAdapter), (void **)&pDXGIAdapter);
    if (FAILED(result)) {
        uxen_err("Call to GetParent(__uuidof(IDXGIAdapter)) has failed 0x%x", result);
        goto exit;
    }

    IDXGIFactory2 *pIDXGIFactory = NULL;
    result = pDXGIAdapter->GetParent(__uuidof(IDXGIFactory2), (void **)&pIDXGIFactory);
    if (FAILED(result)) {
        uxen_err("Call to GetParent(__uuidof(IDXGIFactory2)) has failed 0x%x", result);
        goto exit;
    }

    IDXGISwapChain1 *pSwapChain = NULL;
    result = pIDXGIFactory->CreateSwapChainForHwnd(pd3dDevice, hwnd, &desc, NULL, NULL, &pSwapChain);
    if (FAILED(result)) {
        uxen_err("Call to CreateSwapChainForHwnd has failed 0x%x", result);
        goto exit;
    }

    if (SUCCEEDED(result)) {
        void** vtable = *(void***)pSwapChain;
        DWORD old_protect = 0;
        if (VirtualProtect(vtable, USN_PAGE_SIZE, PAGE_READWRITE, &old_protect)) {
            g_originalPresent = (UINT_PTR)vtable[8];
            vtable[8] = VideoPresent;
            VirtualProtect(vtable, USN_PAGE_SIZE, old_protect, &old_protect);
            FlushInstructionCache(GetCurrentProcess(), vtable, USN_PAGE_SIZE);

            uxen_msg("dxgi.dll patched!");
        }
        else {
            uxen_err("VirtualProtect(vtable, USN_PAGE_SIZE, PAGE_READWRITE, &old_protect) failed");
        }
    }

exit:
    return result;
}

static HRESULT PatchProc(void)
{
    static bool patched = false;
    HRESULT result = S_OK;
    IMFTransform *trans = NULL;
    IUnknown *procUnk = NULL; // never released to keep DLL loaded

    if (patched) {
        uxen_debug("Already patched, skipping");
        goto exit;
    }

    SVRProc();

    result = CoCreateInstance(BR_CLSID_VideoProcessorMFT, NULL, CLSCTX_INPROC_SERVER, IID_IUnknown, (void**)&procUnk);
    if (FAILED(result)) {
        uxen_err("CoCreateInstance CLSID_VideoProcessorMFT failed");
        goto exit;
    }

    result = procUnk->QueryInterface<IMFTransform>(&trans);
    if (FAILED(result)) {
        uxen_err("proc_unk->QueryInterface<IMFTransform>(&trans); failed");
        goto exit;
    }

    if (SUCCEEDED(result)) {
        void** vtable = *(void***)trans;
        DWORD old_protect = 0;
        if (VirtualProtect(vtable, USN_PAGE_SIZE, PAGE_READWRITE, &old_protect)) {
            g_originalProcessInput = (UINT_PTR)vtable[24];
            vtable[24] = VideoProcessInput;
            g_originalProcessOutput = (UINT_PTR)vtable[25];
            vtable[25] = VideoProcessOutput;
            VirtualProtect(vtable, USN_PAGE_SIZE, old_protect, &old_protect);
            FlushInstructionCache(GetCurrentProcess(), vtable, USN_PAGE_SIZE);
            patched = true;
            uxen_msg("Video Processor patched");
        }
        else {
            uxen_msg("VirtualProtect(vtable, USN_PAGE_SIZE, PAGE_READWRITE, &old_protect) failed");
        }
        trans->Release();
    }

exit:
    if (!patched && procUnk) {
        procUnk->Release();
    }
    return result;
}

HRESULT __stdcall DllGetClassObject(
    REFCLSID rcid, REFIID riid, void** ppv)
{
    static HMODULE module = NULL;
    static DllGetClassObjectType proc = NULL;
    static HMODULE stay_loaded = NULL;
    HRESULT         hr       = S_OK;
    ClassFactory*   pFactory = NULL;

    uxen_ud_set_progname("uxenh264_guest");

    if (g_getReal) {
        uxen_msg("Creating real instance of _msmpeg2vdec.dll");
        if (!module) {
            module = LoadLibraryA("_msmpeg2vdec.dll");
            if (!module) {
                uxen_err("LoadLibraryA(_msmpeg2vdec.dll) failed");
            }
        }
        if (module && !proc) {
            proc = (DllGetClassObjectType)GetProcAddress(module, "DllGetClassObject");
            if (!proc) {
                uxen_err("GetProcAddress(module, DllGetClassObject) failed");
            }
        }
        if (proc) {
            uxen_msg("Calling real DllGetClassObject");
            return proc(rcid, riid, ppv);
        }
    }

    if (!stay_loaded) {
        stay_loaded = LoadLibraryA("msmpeg2vdec.dll");
    }

    PatchProc();

    pFactory = new ClassFactory();
    if (!pFactory) {
        uxen_err("new ClassFactory failed");
        return E_OUTOFMEMORY;
    }

    hr = pFactory->QueryInterface(riid, ppv);
    SAFERELEASE(pFactory);

    return hr;
}
