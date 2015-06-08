/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/win32.h>

#include <dm/ioh.h>
#include <dm/os.h>
#include <dm/lib.h>
#include <dm/debug.h>

#include <mmsystem.h>
#include <mmdeviceapi.h>
#include <avrt.h>
#include <audioclient.h>

#include "wasapi.h"

#define WASAPI_BUF_LEN_MS 60
#define MAX_VOICES 4

struct wasapi_voice {
    int index;
    IAudioClient *client;
    IAudioRenderClient *render;
    IAudioClock *clock;
    HANDLE ev;
    HANDLE task;
    HANDLE thread;
    WAVEFORMATEXTENSIBLE fmt;
    wasapi_data_cb_t cb;
    void *cb_opaque;
    uint64_t pos;
    int quit_thread;
    int silence;
    int frames;
    int lost;
};

const IID IID_IADs = {0xFD8256D0, 0xFD15, 0x11CE,
  {0xAB,0xC4,0x02,0x60,0x8C,0x9E,0x75,0x53}
};
const IID IID_IADsContainer = {0xFD8256D0, 0xFD15, 0x11CE,
  {0xAB,0xC4,0x02,0x60,0x8C,0x9E,0x75,0x53}
};
const CLSID CLSID_MMDeviceEnumerator = { 0xbcde0395, 0xe52f, 0x467c,
  {0x8e, 0x3d, 0xc4, 0x57, 0x92, 0x91, 0x69, 0x2e}
};
const IID IID_IMMDeviceEnumerator = { 0xa95664d2, 0x9614, 0x4f35,
  {0xa7, 0x46, 0xde, 0x8d, 0xb6, 0x36, 0x17, 0xe6}
};
const IID IID_IAudioClient = { 0x1cb9ad4c, 0xdbfa, 0x4c32,
  {0xb1, 0x78, 0xc2, 0xf5, 0x68, 0xa7, 0x03, 0xb2}
};
const IID IID_IAudioClock = { 0xcd63314f, 0x3fba, 0x4a1b,
  {0x81, 0x2c, 0xef, 0x96, 0x35, 0x87, 0x28, 0xe7}
};
const IID IID_IAudioCaptureClient = { 0xc8adbd64, 0xe71e, 0x48a0,
  {0xa4, 0xde, 0x18, 0x5c, 0x39, 0x5c, 0xd3, 0x17}
};
const IID IID_IAudioRenderClient = { 0xf294acfc, 0x3146, 0x4483,
  {0xa7, 0xbf, 0xad, 0xdc, 0xa7, 0xc2, 0x60, 0xe2}
};
const IID IID_IMMNotificationClient = { 0x7991EEC9, 0x7E89, 0x4D85,
  {0x83, 0x90, 0x6C, 0x70, 0x3C, 0xEC, 0x60, 0xC0}
};
const IID IID_IUnknown = { 0x00000000, 0x0000, 0x0000,
  {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};
const static GUID GUID_KSDATAFORMAT_SUBTYPE_PCM = {0x00000001,0x0000,0x0010,
  {0x80,0x00,0x00,0xaa,0x00,0x38,0x9b,0x71}
};

#define WASAPI_FAIL(hr)                                                 \
    warnx("%s:%d: WASAPI call failed hr=0x%08lx", __FUNCTION__, __LINE__, hr)

HANDLE WINAPI (*_AvSetMmThreadCharacteristics)(LPCSTR, LPDWORD)=0;
BOOL WINAPI (*_AvRevertMmThreadCharacteristics)(HANDLE)=0;
BOOL WINAPI (*_AvSetMmThreadPriority)(HANDLE, AVRT_PRIORITY)=0;

static HANDLE mm_task;
static HANDLE mm_prioritize_ev;
static HANDLE devchange_ev;
static uint32_t num_voices;
static uint32_t num_nonsilent_voices;
static IMMDeviceEnumerator *enumerator;
static IMMNotificationClient *notification;
static critical_section lock;
static wasapi_voice_t voices[MAX_VOICES];

static void prioritize_cb(void*);

/* Notification client implementation */

static WINAPI ULONG NC_AddRef(IMMNotificationClient *c)
{
    return 1;
}

static WINAPI ULONG NC_Release(IMMNotificationClient *c)
{
    return 1;
}

static WINAPI HRESULT NC_QueryInterface(IMMNotificationClient *c, REFIID iid, VOID **ppvI)
{
    if (!memcmp(iid, &IID_IUnknown, sizeof(IID))) {
        *ppvI = (IUnknown*)c;
    } else if (!memcmp(iid, &IID_IMMNotificationClient, sizeof(IID))) {
        *ppvI = (IMMNotificationClient*)c;
    } else {
        *ppvI = NULL;
        return E_NOINTERFACE;
    }
    return S_OK;
}

static WINAPI HRESULT NC_OnDefaultDeviceChanged(
    IMMNotificationClient *c,
    EDataFlow flow, ERole role,
    LPCWSTR pwstrDeviceId)
{
    if (flow == eRender && role == eMultimedia)
        SetEvent(devchange_ev);
    return S_OK;
}

static WINAPI HRESULT NC_OnDeviceAdded(
    IMMNotificationClient *c,
    LPCWSTR pwstrDeviceId)
{
    return S_OK;
}

static WINAPI HRESULT NC_OnDeviceRemoved(
    IMMNotificationClient *c,
    LPCWSTR pwstrDeviceId)
{
    return S_OK;
}

static WINAPI HRESULT NC_OnDeviceStateChanged(
    IMMNotificationClient *c,
    LPCWSTR pwstrDeviceId,
    DWORD dwNewState)
{
    return S_OK;
}

static WINAPI HRESULT NC_OnPropertyValueChanged(
    IMMNotificationClient *c,
    LPCWSTR pwstrDeviceId,
    const PROPERTYKEY key)
{
    return S_OK;
}

static HRESULT notification_create(IMMNotificationClient **ppClient)
{
    HRESULT ret = E_FAIL;
    IMMNotificationClient *c;

    *ppClient = NULL;
    c = calloc(1, sizeof(IMMNotificationClient));
    if (!c)
        goto err;
    c->lpVtbl = calloc(1, sizeof(IMMNotificationClientVtbl));
    if (!c->lpVtbl)
        goto err;
    c->lpVtbl->AddRef = NC_AddRef;
    c->lpVtbl->Release = NC_Release;
    c->lpVtbl->QueryInterface = NC_QueryInterface;
    c->lpVtbl->OnDefaultDeviceChanged = NC_OnDefaultDeviceChanged;
    c->lpVtbl->OnDeviceAdded = NC_OnDeviceAdded;
    c->lpVtbl->OnDeviceRemoved = NC_OnDeviceRemoved;
    c->lpVtbl->OnDeviceStateChanged = NC_OnDeviceStateChanged;
    c->lpVtbl->OnPropertyValueChanged = NC_OnPropertyValueChanged;
    *ppClient = c;
    ret = S_OK;
    goto out;

err:
    if (c) {
        free(c->lpVtbl);
        free(c);
    }
out:
    return ret;
}

static void notification_free(IMMNotificationClient *c)
{
    if (c) {
        free(c->lpVtbl);
        free(c);
    }
}

static HRESULT get_mm_device(IMMDevice **ppMMDevice)
{
    HRESULT hr = S_OK;

    critical_section_enter(&lock);
    if (!enumerator) {
        IMMDeviceEnumerator *pMMDeviceEnumerator;
        // activate a device enumerator
        hr = CoCreateInstance(
            &CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL,
            &IID_IMMDeviceEnumerator,
            (void**)&pMMDeviceEnumerator
            );
        if ( FAILED(hr) ) {
            WASAPI_FAIL(hr);
            critical_section_leave(&lock);
            return hr;
        }
        hr = notification_create(&notification);
        if ( FAILED(hr) ) {
            WASAPI_FAIL(hr);
            critical_section_leave(&lock);
            return hr;
        }
        hr = pMMDeviceEnumerator->lpVtbl->RegisterEndpointNotificationCallback(
            pMMDeviceEnumerator, notification);
        if ( FAILED(hr) ) {
            WASAPI_FAIL(hr);
            notification_free(notification);
            critical_section_leave(&lock);
            return hr;
        }
        enumerator = pMMDeviceEnumerator;
    }
    critical_section_leave(&lock);

    // get the default render endpoint
    hr = enumerator->lpVtbl->GetDefaultAudioEndpoint(enumerator,
           eRender, eMultimedia, ppMMDevice);

    if ( FAILED(hr) ) {
        WASAPI_FAIL(hr);
        return hr;
    }

    return S_OK;
}

static int is_format_supported(IAudioClient* client,
                               const WAVEFORMATEX* format)
{
    PWAVEFORMATEX pmatch;
    HRESULT hr;

    pmatch = CoTaskMemAlloc(sizeof(WAVEFORMATEX));
    hr = client->lpVtbl->IsFormatSupported(client, AUDCLNT_SHAREMODE_SHARED, format, &pmatch);

    if (FAILED(hr))
        WASAPI_FAIL(hr);

    if (pmatch)
        CoTaskMemFree(pmatch);

    return hr == S_OK;
}

static void
dump_format(const char *str, WAVEFORMATEX *f)
{
    debug_printf("%s: tag=%d channels=%d rate=%d bps=%d align=%d bits=%d size=%d",
                 str,
                 (int)f->wFormatTag, (int)f->nChannels, (int)f->nSamplesPerSec,
                 (int)f->nAvgBytesPerSec,
                 (int)f->nBlockAlign, (int)f->wBitsPerSample, (int)f->cbSize);
    if (f->cbSize >= sizeof(WAVEFORMATEXTENSIBLE) - sizeof(WAVEFORMATEX)) {
        WAVEFORMATEXTENSIBLE *ex = (WAVEFORMATEXTENSIBLE*)f;
        debug_printf(" validbits=%d channelmask=%d", (int)ex->Samples.wValidBitsPerSample,
                     (int)ex->dwChannelMask);
    }
    debug_printf("\n");
}

static HRESULT
create_audio_client(wasapi_voice_t v, IMMDevice *pMMDevice,
                    WAVEFORMATEX* datafmt, IAudioClient **ppClient)
{
    HRESULT hr;
    IAudioClient *client = NULL;
    REFERENCE_TIME engperiod, devperiod;
    uint32_t sz = 0;
    WAVEFORMATEX *mixfmt = NULL;
    int channels;
    static int announce = 1;

    hr = pMMDevice->lpVtbl->Activate(pMMDevice,
        &IID_IAudioClient,
        CLSCTX_ALL, NULL,
        (void**)&client);

    if ( FAILED(hr) ) {
        WASAPI_FAIL(hr);
        return hr;
    }

    hr = client->lpVtbl->GetMixFormat(client, &mixfmt);
    if ( FAILED(hr) ) {
        client->lpVtbl->Release(client);
        WASAPI_FAIL(hr);
        return hr;
    }

    channels = mixfmt->nChannels;
    if (channels > 2)
        channels = 2;

    /* use mixer sampler rate and channels */
    memset(&v->fmt, 0, sizeof(WAVEFORMATEXTENSIBLE));
    v->fmt.Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
    v->fmt.Format.cbSize = sizeof(WAVEFORMATEXTENSIBLE) - sizeof(WAVEFORMATEX);
    v->fmt.Format.nChannels = channels;
    v->fmt.Format.nSamplesPerSec = mixfmt->nSamplesPerSec;
    v->fmt.Format.wBitsPerSample = datafmt->wBitsPerSample;
    v->fmt.Format.nBlockAlign = v->fmt.Format.nChannels * v->fmt.Format.wBitsPerSample / 8;
    v->fmt.Format.nAvgBytesPerSec = v->fmt.Format.nSamplesPerSec * v->fmt.Format.nBlockAlign;
    v->fmt.Samples.wValidBitsPerSample = v->fmt.Format.wBitsPerSample;
    v->fmt.SubFormat = GUID_KSDATAFORMAT_SUBTYPE_PCM;
    if (channels == 1)
        v->fmt.dwChannelMask = SPEAKER_FRONT_CENTER;
    else
        v->fmt.dwChannelMask = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT;

    if (!is_format_supported(client, (WAVEFORMATEX*)&v->fmt)) {
        debug_printf("audio format not supported\n");
        dump_format("mix format", mixfmt);
        dump_format("playback format", (WAVEFORMATEX*)&v->fmt);
        CoTaskMemFree(mixfmt);
        client->lpVtbl->Release(client);
        return E_FAIL;
    }

    hr = client->lpVtbl->GetDevicePeriod(client, &engperiod, &devperiod);
    if ( FAILED(hr) ) {
        CoTaskMemFree(mixfmt);
        client->lpVtbl->Release(client);
        WASAPI_FAIL(hr);
        return hr;
    }
    hr = client->lpVtbl->Initialize(
        client, AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
        WASAPI_BUF_LEN_MS * 10000, 0, (WAVEFORMATEX*)&v->fmt, NULL);
    if ( FAILED(hr) ) {
        dump_format("mix format", mixfmt);
        dump_format("playback format", (WAVEFORMATEX*)&v->fmt);
        CoTaskMemFree(mixfmt);
        client->lpVtbl->Release(client);
        WASAPI_FAIL(hr);
        return hr;
    }

    client->lpVtbl->GetBufferSize(client, &sz);
    if (announce) {
        announce = 0;
        debug_printf("audio device period: %dus %dus\n",
                     (int)engperiod/10, (int)devperiod/10);
        debug_printf("audio buffer size: %d frames = %d bytes\n",
                     sz, sz * datafmt->nBlockAlign);
        dump_format("mix format", mixfmt);
        dump_format("data format", datafmt);
        dump_format("playback format", (WAVEFORMATEX*)&v->fmt);
    }
    CoTaskMemFree(mixfmt);
    *ppClient = client;
    return S_OK;
}

/* set current thread characteristics to "pro audio" */
void __mm_prioritize(HANDLE *ptask, int on)
{
    DWORD task_index = 0;
    if (on) {
        if (*ptask)
            return;
        *ptask = _AvSetMmThreadCharacteristics("Pro Audio", &task_index);
        if (!*ptask) {
            debug_printf("audio: failed to set mm thread characteristics\n");
        } else {
#if 0
            if (!_AvSetMmThreadPriority(*ptask, AVRT_PRIORITY_CRITICAL)) {
                debug_printf("audio: failed to set mm thread pri\n");
            }
#endif
        }
    } else {
        if (!*ptask)
            return;
        _AvRevertMmThreadCharacteristics(*ptask);
        *ptask = NULL;
    }
}

static void prioritize(wasapi_voice_t v, int on)
{
    __mm_prioritize(&v->task, on);
}

static void prioritize_cb(void *opaque)
{
    __mm_prioritize(&mm_task, num_nonsilent_voices > 0);
}

static DWORD WINAPI voice_thread_run(void *opaque)
{
    wasapi_voice_t v = (wasapi_voice_t)opaque;
    int silence = 0;
    HRESULT hr;
    prioritize(v, 1);

    if (!v->quit_thread) {
        hr = v->client->lpVtbl->Start(v->client);
        if ( FAILED(hr) ) {
            WASAPI_FAIL(hr);
            return 0;
        }
    }

    while (!v->quit_thread) {
        WaitForSingleObject(v->ev, INFINITE);
        if (v->quit_thread)
            break;
        if (v->cb) {
            v->cb(v, v->cb_opaque);
        }
        if (v->silence != silence) {
            silence = v->silence;
            if (silence)
                atomic_dec(&num_nonsilent_voices);
            else
                atomic_inc(&num_nonsilent_voices);
            prioritize(v, !silence);
            SetEvent(mm_prioritize_ev);
        }
    }
    if (silence)
        atomic_inc(&num_nonsilent_voices);

    prioritize(v, 0);
    return 0;
}

void wasapi_mute_voice(wasapi_voice_t v, int silence)
{
    if (v->silence != silence) {
        v->silence = silence;
        debug_printf("audio: set mute %d\n", v->silence);
    }
}

int wasapi_play(wasapi_voice_t v)
{
    if (v->thread) {
        debug_printf("wasapi_play: already playing\n");
        return -1;
    }
    v->quit_thread = 0;
    v->pos = 0;
    create_thread(&v->thread, voice_thread_run, v);
    atomic_inc(&num_voices);
    atomic_inc(&num_nonsilent_voices);
    SetEvent(mm_prioritize_ev);
    debug_printf("audio: started playback\n");
    return 0;
}

int wasapi_stop(wasapi_voice_t v)
{
    HRESULT hr;

    if (!v->thread) {
        return -1;
    }
    hr = v->client->lpVtbl->Stop(v->client);
    if ( FAILED(hr) ) {
        WASAPI_FAIL(hr);
        return -1;
    }
    v->quit_thread = 1;
    SetEvent(v->ev);
    wait_thread(v->thread);
    close_thread_handle(v->thread);
    v->thread = NULL;
    atomic_dec(&num_voices);
    atomic_dec(&num_nonsilent_voices);
    SetEvent(mm_prioritize_ev);
    debug_printf("audio: stopped playback\n");
    return 0;
}

int wasapi_get_position(wasapi_voice_t v, uint64_t *p)
{
    uint64_t freq;
    HRESULT hr;

    hr = v->clock->lpVtbl->GetFrequency(v->clock, &freq);
    if ( FAILED(hr) ) {
        WASAPI_FAIL(hr);
        *p = v->pos; /* last valid pos */
        return -1;
    }

    hr = v->clock->lpVtbl->GetPosition(v->clock, p, NULL);
    if ( FAILED(hr) ) {
        WASAPI_FAIL(hr);
        *p = v->pos; /* last valid pos */
        return -1;
    }
    *p = *p * 1000000000 / freq;
    v->pos = *p;
    return 0;
}

int wasapi_get_buffer_space(wasapi_voice_t v, int *frames)
{
    uint32_t padding, sz;
    HRESULT hr;

    hr = v->client->lpVtbl->GetBufferSize(v->client, &sz);
    if ( FAILED(hr) ) {
        WASAPI_FAIL(hr);
        return -1;
    }
    hr = v->client->lpVtbl->GetCurrentPadding(v->client, &padding);
    if ( FAILED(hr) ) {
        WASAPI_FAIL(hr);
        return -1;
    }
    *frames = sz - padding;
    if (*frames < 0) *frames = 0;

    return 0;
}

int wasapi_get_play_fmt(wasapi_voice_t v, WAVEFORMATEX **pf)
{
    *pf = (WAVEFORMATEX*)&v->fmt;
    return 0;
}

int wasapi_lock_buffer(wasapi_voice_t v, int *frames, void **buffer)
{
    HRESULT hr;

    *buffer = 0;
    if (wasapi_get_buffer_space(v, frames))
        return -1;

    hr = v->render->lpVtbl->GetBuffer(v->render, *frames, (BYTE**)buffer);
    if ( FAILED(hr) ) {
        WASAPI_FAIL(hr);
        return -1;
    }

    return 0;
}

int wasapi_unlock_buffer(wasapi_voice_t v, int frames)
{
    HRESULT hr;

    hr = v->render->lpVtbl->ReleaseBuffer(v->render, frames, 0);
    if ( FAILED(hr) ) {
        WASAPI_FAIL(hr);
        return -1;
    }
    v->frames += frames;

    return 0;
}

void wasapi_set_data_cb(wasapi_voice_t v, wasapi_data_cb_t cb, void *opaque)
{
    v->cb = cb;
    v->cb_opaque = opaque;
}

static int voice_register(wasapi_voice_t v)
{
    int i;

    critical_section_enter(&lock);
    for (i = 0; i < MAX_VOICES; ++i) {
        if (!voices[i]) {
            v->index = i;
            voices[i] = v;
            critical_section_leave(&lock);
            return i;
        }
    }
    critical_section_leave(&lock);
    return -1;
}

static void voice_unregister(wasapi_voice_t v)
{
    int i;

    critical_section_enter(&lock);
    v->index = 0;
    for (i = 0; i < MAX_VOICES; ++i) {
        if (voices[i] == v) {
            voices[i] = NULL;
        }
    }
    critical_section_leave(&lock);
}

static int voice_init_internal(wasapi_voice_t v, WAVEFORMATEX *fmt)
{
    IMMDevice *dev = NULL;
    HRESULT hr;
    int rv;

    debug_printf("initialising audio voice\n");
    memset(v, 0, sizeof(*v));
    v->ev = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!v->ev)
        goto err;
    get_mm_device(&dev);
    if (!dev) {
        debug_printf("no audio device\n");
        goto err;
    }
    if ( FAILED(create_audio_client(v, dev, fmt, &v->client)) )
        goto err;
    hr = v->client->lpVtbl->SetEventHandle(v->client, v->ev);
    if ( FAILED(hr) ) {
        WASAPI_FAIL(hr);
        goto err;
    }
    hr = v->client->lpVtbl->GetService(v->client, &IID_IAudioRenderClient, (void**)&v->render);
    if ( FAILED(hr) ) {
        WASAPI_FAIL(hr);
        goto err;
    }
    hr = v->client->lpVtbl->GetService(v->client, &IID_IAudioClock, (void**)&v->clock);
    if ( FAILED(hr) ) {
        WASAPI_FAIL(hr);
        goto err;
    }
    if (voice_register(v) < 0) {
        debug_printf("not enough free voices\n");
        goto err;
    }
    rv = 0;
    goto out;

err:
    rv = -1;
    debug_printf("voice_init_internal failed\n");
    if (v->ev) CloseHandle(v->ev);
out:
    return rv;
}

static void voice_release_internal(wasapi_voice_t v)
{
    if (v) {
        wasapi_stop(v);
        v->clock->lpVtbl->Release(v->clock);
        v->render->lpVtbl->Release(v->render);
        v->client->lpVtbl->Release(v->client);
        CloseHandle(v->ev);
        voice_unregister(v);
        memset(v, 0, sizeof(*v));
    }
}

int wasapi_init_voice(wasapi_voice_t* out_v, WAVEFORMATEX *fmt)
{
    wasapi_voice_t v;
    int rv;

    *out_v = NULL;
    v = calloc(1, sizeof(struct wasapi_voice));
    if (!v)
        return -1;
    rv = voice_init_internal(v, fmt);
    if (rv) {
        free(v);
        return rv;
    }
    *out_v = v;
    return 0;
}

void wasapi_release_voice(wasapi_voice_t v)
{
    if (v) {
        voice_release_internal(v);
        free(v);
    }
}

int wasapi_lost_voice(wasapi_voice_t v)
{
    return v->lost;
}

static void devchange_cb(void *opaque)
{
    int i;

    critical_section_enter(&lock);
    for (i = 0; i < MAX_VOICES; ++i) {
        if (voices[i])
            voices[i]->lost = 1;
    }
    critical_section_leave(&lock);
}

static void load_avrt()
{
    HANDLE h;

    if (_AvSetMmThreadCharacteristics)
        return;
    h = LoadLibrary("avrt.dll");
    assert(h);
    _AvSetMmThreadCharacteristics =
        (HANDLE WINAPI (*)(LPCSTR, LPDWORD))
        GetProcAddress(h, "AvSetMmThreadCharacteristicsA");
    _AvRevertMmThreadCharacteristics =
        (BOOL WINAPI (*)(HANDLE))
        GetProcAddress(h, "AvRevertMmThreadCharacteristics");
    _AvSetMmThreadPriority =
        (BOOL WINAPI (*)(HANDLE, AVRT_PRIORITY))
        GetProcAddress(h, "AvSetMmThreadPriority");
}

void wasapi_init(void)
{
    mm_prioritize_ev = CreateEvent(NULL, TRUE, FALSE, NULL);
    ioh_add_wait_object(&mm_prioritize_ev, prioritize_cb, NULL, NULL);
    devchange_ev = CreateEvent(NULL, TRUE, FALSE, NULL);
    ioh_add_wait_object(&devchange_ev, devchange_cb, NULL, NULL);
}

void wasapi_exit(void)
{
    CloseHandle(mm_prioritize_ev);
    CloseHandle(devchange_ev);
    if (enumerator) {
        if (notification)
            enumerator->lpVtbl->UnregisterEndpointNotificationCallback(
                enumerator, notification);
        enumerator->lpVtbl->Release(enumerator);
        enumerator = NULL;
    }
    if (notification) {
        notification_free(notification);
        notification = NULL;
    }
}

static void __attribute__((constructor)) wasapi_construct(void)
{
    CoInitialize(NULL);
    critical_section_init(&lock);
    load_avrt();
}

