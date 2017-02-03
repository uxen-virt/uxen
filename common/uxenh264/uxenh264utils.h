/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#pragma once

#include <Propvarutil.h>

// {2E651004-01A4-4946-AA4D-2C7C584B399B}
EXTERN_GUID(BR_MF_SAMPLE_TIME, 0x2e651004, 0x1a4, 0x4946, 0xaa, 0x4d, 0x2c, 0x7c, 0x58, 0x4b, 0x39, 0x9b);
// {AE651004-01A4-4946-AA4D-2C7C584B390B}
EXTERN_GUID(BR_MF_SAMPLE_DURATION, 0xae651004, 0x1a4, 0x4946, 0xaa, 0x4d, 0x2c, 0x7c, 0x58, 0x4b, 0x39, 0x0b);

static void brh264_serialize_attributes(
    IMFAttributes* pAttr, BYTE** buff, PUINT32 size)
{
    LPSTREAM str = NULL;
    HGLOBAL hg = NULL;
    LPVOID ser = NULL;
    LARGE_INTEGER li = {0};

    CreateStreamOnHGlobal(NULL, TRUE, &str);
    MFSerializeAttributesToStream(pAttr, 0, str);
    str->Seek(li, STREAM_SEEK_SET, NULL);
    GetHGlobalFromStream(str, &hg);
    *size = (unsigned int)GlobalSize(hg);
    *buff = (PBYTE)malloc(*size);
    ser = GlobalLock(hg);
    memcpy(*buff, ser, *size);
    GlobalUnlock(hg);
    str->Release();
}

static void brh264_deserialize_attributes(
    IMFAttributes* pAttr, BYTE* buff, UINT32 size)
{
    LPSTREAM str = NULL;
    HRESULT hr = S_OK;
    LARGE_INTEGER li = {0};
    str = SHCreateMemStream(buff, size);
    str->Seek(li, STREAM_SEEK_SET, NULL);
    hr = MFDeserializeAttributesFromStream(pAttr, 0, str);
    str->Release();
}

static IMFSample *
create_media_sample(DWORD size)
{
    IMFSample *sample = NULL;
    IMFMediaBuffer *buff = NULL;
    HRESULT result = S_OK;

    result = MFCreateSample(&sample);
    if (FAILED(result))
        goto error;

    result = MFCreateMemoryBuffer(size, &buff);
    if (FAILED(result))
        goto error;

    result = sample->AddBuffer(buff);
    if (FAILED(result))
        goto error;

    result = buff->SetCurrentLength(size);
    if (FAILED(result))
        goto error;

    if (buff)
        buff->Release();

    return sample;

error:
    if (buff)
        buff->Release();
    if (sample)
        sample->Release();
    return NULL;
}

static HRESULT
fill_media_sample(IMFSample *sample, struct brh264_data *data)
{
    IMFMediaBuffer *buff = NULL;
    HRESULT result = S_OK;
    BYTE *bytes = NULL;
    DWORD curr_len = 0;
    DWORD max_len = 0;

    brh264_deserialize_attributes(sample, data->params, data->params_size);

    result = sample->SetSampleTime(MFGetAttributeUINT64(sample, BR_MF_SAMPLE_TIME, 0));
    if (FAILED(result))
        goto error;

    result = sample->SetSampleDuration(MFGetAttributeUINT64(sample, BR_MF_SAMPLE_DURATION, 0));
    if (FAILED(result))
        goto error;

    result = sample->ConvertToContiguousBuffer(&buff);
    if (FAILED(result))
        goto error;

    result = buff->Lock(&bytes, &max_len, &curr_len);
    if (FAILED(result))
        goto error;

    memcpy(bytes, data->data, data->data_size);

    result = buff->Unlock();
    if (FAILED(result))
        goto error;

    result = buff->SetCurrentLength(data->data_size);
    if (FAILED(result))
        goto error;

error:
    if (buff)
        buff->Release();

    return S_OK;
}

static HRESULT
send_media_sample(brh264_ctx ctx, UINT32 fullscreen, PBYTE new_frame, IMFSample *sample)
{
    HRESULT result = S_OK;
    PBYTE mem;
    DWORD max_len;
    DWORD curr_len;
    LONGLONG time = 0;
    LONGLONG duration = 0;
    IMFMediaBuffer* buff = NULL;
    struct brh264_data dec = {};

    if (!sample) {
       goto exit;
    }

    result = sample->GetSampleDuration(&duration);
    if (FAILED(result))
        duration = 0;
    sample->SetUINT64(BR_MF_SAMPLE_DURATION, duration);

    result = sample->GetSampleTime(&time);
    if (FAILED(result))
        time = 0;
    sample->SetUINT64(BR_MF_SAMPLE_TIME, time);

    brh264_serialize_attributes(sample, &dec.params, &dec.params_size);

    result = sample->ConvertToContiguousBuffer(&buff);
    if (FAILED(result))
        goto exit;

    if (!fullscreen) {
        result = buff->Lock(&mem, &max_len, &curr_len);
        if (FAILED(result))
            goto exit;
        CopyMemory(new_frame, mem, curr_len);
        buff->Unlock();
    }
    brh264_send_dec(ctx, &dec);

exit:
    if (dec.params)
        free(dec.params);
    if (buff)
        buff->Release();

    return result;
}
