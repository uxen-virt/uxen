#ifndef _D3DKMTHK_X_H_
#define _D3DKMTHK_X_H_

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)

/*** some d3dkmthk.h typedefs ***/

typedef UINT D3DDDI_VIDEO_PRESENT_SOURCE_ID;
typedef UINT D3DKMT_HANDLE;

typedef struct _D3DKMT_CLOSEADAPTER
{
    D3DKMT_HANDLE   hAdapter;   // in: adapter handle
} D3DKMT_CLOSEADAPTER;

typedef struct _D3DKMT_OPENADAPTERFROMHDC {
    HDC                            hDc;
    D3DKMT_HANDLE                  hAdapter;
    LUID                           AdapterLuid;
    D3DDDI_VIDEO_PRESENT_SOURCE_ID VidPnSourceId;
} D3DKMT_OPENADAPTERFROMHDC;

typedef enum _D3DKMT_ESCAPETYPE
{
    D3DKMT_ESCAPE_DRIVERPRIVATE           = 0,
    D3DKMT_ESCAPE_VIDMM                   = 1,
    D3DKMT_ESCAPE_TDRDBGCTRL              = 2,
    D3DKMT_ESCAPE_VIDSCH                  = 3,
    D3DKMT_ESCAPE_DEVICE                  = 4,
    D3DKMT_ESCAPE_DMM                     = 5,
    D3DKMT_ESCAPE_DEBUG_SNAPSHOT          = 6,
    D3DKMT_ESCAPE_SETDRIVERUPDATESTATUS   = 7,
    D3DKMT_ESCAPE_DRT_TEST                = 8,
    D3DKMT_ESCAPE_DIAGNOSTICS             = 9
} D3DKMT_ESCAPETYPE;

typedef struct _D3DDDI_ESCAPEFLAGS
{
    union
    {
        struct
        {
            UINT    HardwareAccess      : 1;    // 0x00000001
            UINT    Reserved            :31;    // 0xFFFFFFFE
        };
        UINT        Value;
    };
} D3DDDI_ESCAPEFLAGS;

typedef struct _D3DKMT_ESCAPE
{
    D3DKMT_HANDLE       hAdapter;               // in: adapter handle
    D3DKMT_HANDLE       hDevice;                // in: device handle [Optional]
    D3DKMT_ESCAPETYPE   Type;                   // in: escape type.
    D3DDDI_ESCAPEFLAGS  Flags;                  // in: flags
    VOID*               pPrivateDriverData;     // in/out: escape data
    UINT                PrivateDriverDataSize;  // in: size of escape data
    D3DKMT_HANDLE       hContext;               // in: context handle [Optional]
} D3DKMT_ESCAPE;

/*** d3dkmthk dynamic API loading ***/

#define DEF_D3DKMT_FUNC(fn, arg)                                              \
    typedef NTSTATUS WINAPI (*PFN_ ## fn)(arg);                               \
    NTSTATUS fn(arg p)                                                        \
    {                                                                         \
        static PFN_ ## fn d3dkmt_ ## fn = NULL;                               \
        if (!(d3dkmt_ ## fn)) {                                               \
            (d3dkmt_ ## fn) = (PFN_ ## fn)                                    \
                GetProcAddress(GetModuleHandleA("gdi32.dll"), # fn);          \
            if (!(d3dkmt_ ## fn)) {                                           \
                uxen_err("Failed to get [%s] address: %d",                    \
                      # fn, (int)GetLastError());                             \
                return STATUS_NOT_IMPLEMENTED;                                \
            }                                                                 \
        }                                                                     \
        return (d3dkmt_ ## fn)(p);                                            \
    }

DEF_D3DKMT_FUNC(D3DKMTOpenAdapterFromHdc, D3DKMT_OPENADAPTERFROMHDC *)
DEF_D3DKMT_FUNC(D3DKMTEscape, D3DKMT_ESCAPE *)
DEF_D3DKMT_FUNC(D3DKMTCloseAdapter, D3DKMT_CLOSEADAPTER *)

#endif	/* _D3DKMTHK_X_H_ */
