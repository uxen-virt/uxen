/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#define COBJMACROS 1 
#include <windows.h>
//#include <objbase.h>
#include <objidl.h>
#include <gdiplus/gdiplus.h>
#include <gdiplus/gdiplustypes.h>
#include <gdiplus/gdiplusflat.h>
#include <ole2.h>
#include <stdio.h>
#include "hdrop.h"

#define MAX_FILE_SZ (256*1024*1024)

static int GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
{
   UINT  j, num = 0;          // number of image encoders
   UINT  size = 0;         // size of the image encoder array in bytes

   ImageCodecInfo* pImageCodecInfo = NULL;

   GetImageEncodersSize(&num, &size);
   if(size == 0)
      return -1;  // Failure

   pImageCodecInfo = (ImageCodecInfo*)(malloc(size));
   if(pImageCodecInfo == NULL)
      return -1;  // Failure

   GetImageEncoders(num, size, pImageCodecInfo);

   for(j = 0; j < num; ++j)
   {
      if( wcscmp(pImageCodecInfo[j].MimeType, format) == 0 )
      {
         *pClsid = pImageCodecInfo[j].Clsid;
         free(pImageCodecInfo);
         return j;  // Success
      }    
   }

   free(pImageCodecInfo);
   return -1;  // Failure
}

static HRESULT get_istream_from_bytes(char* input, unsigned int input_size,
    IStream** stream)
{
    HRESULT hr;
    ULONG nwritten = 0, total = 0;

    hr = CreateStreamOnHGlobal(NULL, TRUE, stream);
    if (hr)
        return hr;
    while (total < input_size) {
        hr = IStream_Write(*stream, input + total, input_size - total, 
            &nwritten);
        if (hr)
            return hr;
        total += nwritten;
    }
    return 0;
}

static HRESULT get_bytes_from_istream(IStream* stream, char** output,
    unsigned int* output_size)
{
    LARGE_INTEGER zero;
    ULARGE_INTEGER position;
    HRESULT hr;
    ULONG nread = 0, total = 0;

    zero.QuadPart = 0;
    position.QuadPart = 0;
    hr = IStream_Seek (stream, zero, STREAM_SEEK_END, &position);
    if (hr)
        return hr;
    *output_size = position.QuadPart;
    *output = malloc(*output_size);
    if (!*output)
        return E_OUTOFMEMORY;
    hr = IStream_Seek (stream, zero, STREAM_SEEK_SET, NULL);
    if (hr)
        return hr;
    while (total < *output_size) {
        hr = IStream_Read(stream, *output + total, *output_size - total,
            &nread);
        if (hr)
            return hr;
        total += nread;
    }

    return 0;
}

int uxenclipboard_convert_to_bmp(char* input, unsigned int input_size, char** output,
    unsigned int* output_size)
{
    HRESULT hr;
    IStream *input_stream = NULL, *output_stream = NULL;
    CLSID encoderClsid = {0,};
    GpImage* image = NULL;

    hr = get_istream_from_bytes(input, input_size, &input_stream);
    if (hr)
        goto out_release_none;
    hr = CreateStreamOnHGlobal(NULL, TRUE, &output_stream);
    if (hr)
        goto out_release_istream;
    GetEncoderClsid(L"image/bmp", &encoderClsid);
    hr = GdipLoadImageFromStream(input_stream, &image);
    if (hr)
        goto out_release_ostream;
    hr = GdipSaveImageToStream(image, output_stream, &encoderClsid, NULL);
    if (hr)
        goto out_release_image;
    hr = get_bytes_from_istream(output_stream, output, output_size);
out_release_image:
    GdipDisposeImage(image);
out_release_ostream:
    IStream_Release(output_stream);
out_release_istream:
    IStream_Release(input_stream);
out_release_none:
    return hr;
}

static GdiplusStartupOutput gdiplusStartupOutput;
static ULONG_PTR gdiplusNotificationToken;
static ULONG_PTR gdiplusToken;

int 
uxenclipboard_gdi_startup()
{
    GdiplusStartupInput inp = {1, NULL, TRUE, FALSE};

    GdiplusStartup(&gdiplusToken, &inp, &gdiplusStartupOutput);
    if (gdiplusStartupOutput.NotificationHook)
        gdiplusStartupOutput.NotificationHook(&gdiplusNotificationToken);
    return 0;
}

void uxenclipboard_gdi_shutdown()
{
    if (gdiplusStartupOutput.NotificationUnhook)
        gdiplusStartupOutput.NotificationUnhook(gdiplusNotificationToken);
   GdiplusShutdown(gdiplusToken);
}

void uxenclipboard_gdi_startup_with_atexit()
{
    uxenclipboard_gdi_startup();
    atexit(uxenclipboard_gdi_shutdown);
}

static int getclipboarddata_real(unsigned int fmt, char** output,
    unsigned int* output_size)
{
    HANDLE hclip;
    LPVOID lp;
    unsigned int size;

    hclip = GetClipboardData(fmt);
    if (!hclip)
        return -1;
    lp = GlobalLock(hclip);
    if (!lp)
        return -1;
    size = GlobalSize(hclip);
    if (!size) {
        GlobalUnlock(hclip);
        return -1;
    }
    /* It is somewhat unfortunate that we have to malloc here instead of
    just "*output = lp", but in try_convert, we might have to skip
    bmp file header and malloc. So, mallocing in both cases, to make the
    interface less horrible. */
    *output = malloc(size);
    if (!*output) {
        GlobalUnlock(hclip);
        return E_OUTOFMEMORY;
    }
    memcpy(*output, lp, size);
    *output_size = size;
    GlobalUnlock(hclip);
    return 0;
}

static int try_convert(char* alt_data, unsigned int alt_size, char** output,
    unsigned int* output_size)
{
    char* converted_data;
    unsigned int converted_size, dib_size;
    int ret;

    ret = uxenclipboard_convert_to_bmp(alt_data, alt_size, &converted_data,
        &converted_size);
    if (ret)
        return ret;
    if (converted_size <= sizeof(BITMAPFILEHEADER)) {
        free(converted_data);
        return -1;
    }
    dib_size = converted_size - sizeof(BITMAPFILEHEADER);
    *output = malloc(dib_size);
    if (!*output) {
        free(converted_data);
        return E_OUTOFMEMORY;
    }
    memcpy(*output, converted_data + sizeof(BITMAPFILEHEADER), dib_size);
    *output_size = dib_size;
    free(converted_data);
    return 0;
}

static
wchar_t* uxen_recognized_graphics_formats[] = {L"PNG", L"JFIF", L"GIF",
    L"JPG", L"TIFF", NULL};

int uxenclipboard_is_supported_graphics_format(wchar_t* fmt)
{
    int i;
    for (i = 0; uxen_recognized_graphics_formats[i]; i++)
        if (!wcscmp(fmt, uxen_recognized_graphics_formats[i]))
            return 1;
    return 0;
}

static int slurp_file_in(wchar_t* filename, char** output,
    unsigned int* output_size)
{
    FILE* f;
    int rv;

    f = _wfopen(filename, L"rb");
    if (!f)
        return -1;
    rv = fseek(f, 0, SEEK_END);
    if (rv) {
        fclose(f);
        return -1;
    }
    *output_size = ftell(f);
    if (*output_size > MAX_FILE_SZ) {
        fclose(f);
        return -1;
    }
    rewind(f);
    *output = malloc(*output_size);
    if (!*output) {
        fclose(f);
        return -1;
    }
    if (fread(*output, 1, *output_size, f) != *output_size) {
        free(*output);
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int get_content_from_hdrop_for_fmt(int expected_fmt, char** output,
    unsigned int* output_size)
{
    wchar_t* filename;
    wchar_t* guessed_fmtname;
    int ret;

    if (!IsClipboardFormatAvailable(CF_HDROP))
        return -1;
    guessed_fmtname = uxenclipboard_get_format_from_hdrop(TRUE, &filename);
    if (!guessed_fmtname)
        return -1;
    if (expected_fmt &&
        RegisterClipboardFormatW(guessed_fmtname) != expected_fmt) {
        free(filename);
        return -1;
    }
    ret = slurp_file_in(filename, output, output_size);
    free(filename);
    return ret;
}

int uxenclipboard_getdata(int format, char** output, unsigned int* output_size) 
{
    int i, ret;
    wchar_t* fmtname;
    char* data;
    unsigned int datalen;

    ret = getclipboarddata_real(format, output, output_size);
    if (!ret)
        return 0;
    if (format != CF_DIB)
        return get_content_from_hdrop_for_fmt(format, output, output_size);

    for (i = 0; (fmtname = uxen_recognized_graphics_formats[i]); i++) {
        ret = getclipboarddata_real(RegisterClipboardFormatW(fmtname),
            &data, &datalen);
        if (ret)
            continue;
        ret = try_convert(data, datalen, output, output_size);
        free(data);
        if (!ret)
            return 0;
    }
    /* No luck with clipboard format conversion to CF_DIB. So, check
    whether the contents of CF_HDROP is usable.*/
    #define ANY_GRAPHICS_FORMAT 0
    if (get_content_from_hdrop_for_fmt(ANY_GRAPHICS_FORMAT, &data, &datalen))
        return -1;
    ret = try_convert(data, datalen, output, output_size);
    free(data);
    return ret;
}

