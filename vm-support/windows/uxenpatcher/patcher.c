/*
 * Copyright 2016, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#define __CRT_STRSAFE_IMPL
#undef WINVER
#define WINVER 0x0601
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <winnt.h>
#include <intrin.h>
#include <Dbghelp.h>
#include <strsafe.h>
#include <dm-features.h>
#include "logging.h"

#define DXGKRNL "c:\\Windows\\System32\\drivers\\dxgkrnl.sys"
#define PVK_PART "c:\\uXenGuest\\uxenpatcher\\pvk.pvk"
#define CER_PART "c:\\uXenGuest\\uxenpatcher\\cer.cer"
#define PFX_PART "c:\\uXenGuest\\uxenpatcher\\pfx.pfx"

struct file_map
{
    HANDLE file;
    HANDLE mapping;
    LPVOID view;
};

enum tools
{
    TAKEOWN,
    ICACLS,
    MAKECERT,
    PVK2PFX,
    SIGNTOOL,
    CERTUTIL,
    BCDEDIT
};

static const char* tools[][3] = {
    {"c:\\windows\\system32\\takeown.exe",
     "%s /f " DXGKRNL,
     "Taking ownership of " DXGKRNL},
    {"c:\\windows\\system32\\icacls.exe",
     "%s " DXGKRNL " /grant Everyone:F",
     "Granting access rights to " DXGKRNL},
    {"c:\\uXenGuest\\uxenpatcher\\makecert.exe",
     "%s -sv " PVK_PART " -n \"CN=_\" " CER_PART " -b 08/01/2010 -e 08/01/2199 -r",
     "Making temporary certificate"},
    {"c:\\uXenGuest\\uxenpatcher\\PVK2PFX.exe",
     "%s -f /pvk " PVK_PART " /spc " CER_PART " /pfx " PFX_PART,
     "Converting temporary certificate to pfx"},
    {"c:\\uXenGuest\\uxenpatcher\\signtool.exe",
     "%s sign /f " PFX_PART " " DXGKRNL,
     "Signing " DXGKRNL " with temporary certificate"},
    {"c:\\windows\\system32\\certutil.exe",
     "%s -f -p \"\" -importpfx \"Root\" " PFX_PART,
     "Add temporary certificate to root store"},
    {"c:\\windows\\system32\\bcdedit.exe",
     "%s -set TESTSIGNING ON",
     "Enable test signing"}
};

static struct file_map* create_file_map(LPCSTR filepath)
{
    struct file_map* file = NULL;
    DWORD attr = GENERIC_READ | GENERIC_WRITE;
    DWORD share = FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE;
    DWORD protect = PAGE_READWRITE;
    DWORD access = FILE_MAP_ALL_ACCESS;

    file = (struct file_map*)malloc(sizeof(*file));
    if (file == NULL)
    {
        debug_log("malloc failed");
        return NULL;
    }

    file->file = CreateFileA(filepath, attr, share, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file->file == INVALID_HANDLE_VALUE)
    {
        debug_log("CreateFile failed with error %ld", GetLastError());
        free(file);
        return NULL;
    }

    file->mapping = CreateFileMapping(file->file, NULL, protect, 0, 0, NULL);
    if (file->mapping == NULL)
    {
        CloseHandle(file->file);
        free(file);
        debug_log("CreateFileMapping failed with error %ld", GetLastError());
        return NULL;
    }

    file->view = MapViewOfFile(file->mapping, access, 0, 0, 0);
    if (file->view == NULL)
    {
        CloseHandle(file->mapping);
        CloseHandle(file->file);
        free(file);
        debug_log("MapViewOfFile failed with error %ld", GetLastError());
        return NULL;
    }

    return file;
}

static void destroy_file_map(struct file_map** file)
{
    if ((file != NULL) && (*file != NULL))
    {
        UnmapViewOfFile((*file)->view);
        CloseHandle((*file)->mapping);
        CloseHandle((*file)->file);
        free(*file);
        *file = NULL;
    }
}

static void pre_kmp(int *pi, char *pattern, int psize)
{
    int k = -1;
    int i = 1;

    pi[0] = k;
    for (i = 1; i < psize; i++)
    {
        while (k > -1 && pattern[k + 1] != pattern[i])
            k = pi[k];
        if (pattern[i] == pattern[k + 1])
            k++;
        pi[i] = k;
    }
}

static int kmp(int *pi, char *target, int tsize, char *pattern, int psize)
{
    int i;
    int k = -1;

    pre_kmp(pi, pattern, psize);
    for (i = 0; i < tsize; i++)
    {
        while (k > -1 && pattern[k + 1] != target[i])
            k = pi[k];
        if (target[i] == pattern[k + 1])
            k++;
        if (k == psize - 1)
            return i - k;
    }
    return -1;
}

// We try to locate ProcessVSyncTdrWorker function which we expect to find in PAGE section
// and which we expect to use a magic constant within 64 bytes of its end. Should there be
// more then one function with such properties we expect our function to be the last one.
// What could possibly go wrong...
static PVOID find_function(PVOID view, PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY rt, ULONG rt_size)
{
    PIMAGE_NT_HEADERS headers = NULL;
    PIMAGE_SECTION_HEADER section = NULL;
    PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY rt_next = rt;
    int magic = 10000000; // 1s in 100ns units
    int kmp_next[sizeof (magic)];
    int offset = 0;
    DWORD func_size = 0;
    PVOID func = NULL;
    PVOID func_next = NULL;
    DWORD begin_offset;
    DWORD end_offset;

    headers = ImageNtHeader(view);
    if (headers == NULL)
    {
        DWORD err = GetLastError();
        debug_log("ImageNtHeader failed %ld", err);
        goto exit;
    }

    while ((UINT_PTR)rt_next < (UINT_PTR)rt + rt_size)
    {
        func_next = ImageRvaToVa(headers, view, rt_next->BeginAddress, &section);
        func_size = rt_next->EndAddress - rt_next->BeginAddress;
        begin_offset = rt_next->BeginAddress;
        end_offset = rt_next->EndAddress;
        ++rt_next;

        if (!func_next)
            continue;
        if (_strcmpi((PCHAR)section->Name, "PAGE"))
            continue;
        offset = kmp(kmp_next, (PCHAR)func_next, func_size, (PCHAR)&magic, sizeof (magic));
        if (offset < 0)
            continue;
        if (func_size - offset > 64)
            continue;

        func = func_next;
        debug_log("Found matching function with begin/end offset: 0x%lx/0x%lx", begin_offset, end_offset);
    }

exit:
    return func;
}

static int run_cmd(const char* app, const char* cmd_line, const char* desc)
{
    int ret = 0;
    HRESULT hres = S_OK;
    BOOL res = FALSE;
    DWORD exit_code = 0;
    size_t app_len = 0;
    size_t cmd_len = 0;
    LPSTR cmd = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    debug_log("%s", desc);

    hres = StringCbLengthA(app, STRSAFE_MAX_CCH, &app_len);
    if (FAILED(hres))
    {
        ret = -1;
        debug_log("StringCbLengthA app_name failed 0x%lx", hres);
        goto exit;
    }

    hres = StringCbLengthA(cmd_line, STRSAFE_MAX_CCH, &cmd_len);
    if (FAILED(hres))
    {
        ret = -2;
        debug_log("StringCbLengthA cmd_line failed 0x%lx", hres);
        goto exit;
    }

    cmd = (LPSTR)malloc(app_len + cmd_len);
    if (FAILED(hres))
    {
        ret = -3;
        debug_log("malloc failed %d", (int)(app_len + cmd_len));
        goto exit;
    }

    hres = StringCbPrintfA(cmd, app_len + cmd_len, cmd_line, app);
    if (FAILED(hres))
    {
        ret = -4;
        debug_log("StringCbPrintf failed 0x%lx", hres);
        goto exit;
    }

    ZeroMemory(&pi, sizeof (pi));
    ZeroMemory(&si, sizeof (si));
    si.cb = sizeof (si);

    res = CreateProcessA(app, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    if (!res)
    {
        ret = -5;
        debug_log("CreateProcessA failed %ld", GetLastError());
        goto exit;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    res = GetExitCodeProcess(pi.hProcess, &exit_code);
    if (!res || (exit_code != 0))
    {
        ret = -6;
        debug_log("GetExitCodeProcess failed %ld", GetLastError());
        goto exit;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

exit:
    if (cmd)
        free(cmd);

    return ret;
}

static int backup_driver(LPCSTR file)
{
    BOOL res = FALSE;
    int ret = 0;
    int tool_idx = 0;
    const char **tool = NULL;

    for (tool_idx = TAKEOWN; tool_idx <= ICACLS; ++tool_idx)
    {
        tool = tools[tool_idx];
        ret = run_cmd(tool[0], tool[1], tool[2]);
        if (ret < 0)
        {
            debug_log("%s failed %d", tool[0], ret);
            goto exit;
        }
    }

    debug_log("Making a backup of %s", DXGKRNL);
    res = MoveFileA(DXGKRNL, DXGKRNL ".uxen_bak");
    if (!res)
        debug_log("MoveFileA failed %ld - continuing", GetLastError());

    res = CopyFileA(DXGKRNL ".uxen_bak", DXGKRNL, TRUE);
    if (!res)
        debug_log("CopyFileA failed %ld - continuing", GetLastError());

exit:
    return ret;
}

static void log_file_info(LPCSTR file)
{
    DWORD ver_data_size;
    UINT info_size;
    LPVOID ver_data = NULL;
    VS_FIXEDFILEINFO *info;
    BOOL err;

    ver_data_size = GetFileVersionInfoSizeA(file, NULL);
    if (ver_data_size == 0)
    {
        debug_log("GetFileVersionInfoSize failed %ld", GetLastError());
        goto exit;
    }

    ver_data = malloc(ver_data_size);
    if (!ver_data)
    {
        debug_log("malloc failed %ld", ver_data_size);
        goto exit;
    }

    err = GetFileVersionInfoA(file, 0, ver_data_size, ver_data);
    if (!err)
    {
        debug_log("GetFileVersionInfo failed %ld", GetLastError());
        goto exit;
    }

    err = VerQueryValueA(ver_data, "\\", (LPVOID*)&info, &info_size);
    if (!err)
    {
        debug_log("VerQueryValueA failed %ld", GetLastError());
        goto exit;
    }

    debug_log("File info for: %s", file);
    debug_log("  File    Version: %ld.%ld.%ld.%ld", (info->dwFileVersionMS >> 16) & 0xffff, info->dwFileVersionMS & 0xffff,
                                                    (info->dwFileVersionLS >> 16) & 0xffff, info->dwFileVersionLS & 0xffff);
    debug_log("  Product Version: %ld.%ld.%ld.%ld", (info->dwProductVersionMS >> 16) & 0xffff, info->dwProductVersionMS & 0xffff,
                                                    (info->dwProductVersionLS >> 16) & 0xffff, info->dwProductVersionLS & 0xffff);

exit:
    if (ver_data)
        free(ver_data);
}

static int patch_driver(LPCSTR path)
{
    int ret = 0;
    struct file_map* file;
    ULONG except_size = 0;
    PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY except = NULL;
    PVOID func;
    int patch = 0x909090C3;

    file = create_file_map(path);
    if (file == NULL)
    {
        debug_log("create_file_map file failed");
        ret = -1;
        goto exit;
    }

    except = (PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY)
        ImageDirectoryEntryToDataEx(file->view, FALSE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &except_size, NULL);
    if (except == NULL)
    {
        DWORD err = GetLastError();
        debug_log("ImageDirectoryEntryToDataEx IMAGE_DIRECTORY_ENTRY_EXCEPTION failed %ld", err);
        ret = -2;
        goto exit;
    }

    func = find_function(file->view, except, except_size);
    if (func == NULL)
    {
        debug_log("Unable to find ProcessVSyncTdrWorker");
        ret = -3;
        goto exit;
    }

    debug_log("Replacing 0x%x with 0x%x", *(int*)func, patch);
    memcpy(func, &patch, sizeof (patch));

exit:
    UnmapViewOfFile(except);
    destroy_file_map(&file);
    return ret;
}

static int create_pvk(LPCSTR name)
{
    DWORD err = 0;
    int ret = 0;
    BOOL res = FALSE;
    HCRYPTPROV crypt_prov = 0;
    HCRYPTKEY key = 0;
    DWORD key_len = 0;
    PBYTE key_blob = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD bytes_written = 0;
    BYTE header[] = {0x1e, 0xf1, 0xb5, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    res = CryptAcquireContextA(&crypt_prov, NULL, NULL, PROV_RSA_FULL, 0);
    err = GetLastError();
    if (!res && (err == NTE_BAD_KEYSET)) {
        res = CryptAcquireContextA(&crypt_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);
        err = GetLastError();
    }
    if (!res)
    {
        debug_log("CryptAcquireContextA failed 0x%lx", err);
        ret = -1;
        goto exit;
    }

    res = CryptAcquireContextA(&crypt_prov, NULL, NULL, PROV_RSA_FULL, 0);
    if (!res)
    {
        err = GetLastError();
        debug_log("CryptAcquireContextA failed 0x%lx", err);
        ret = -1;
        goto exit;
    }

    res = CryptGenKey(crypt_prov, AT_SIGNATURE, CRYPT_NO_SALT | CRYPT_ARCHIVABLE, &key);
    if (!res)
    {
        err = GetLastError();
        debug_log("CryptGenKey failed 0x%lx", err);
        ret = -2;
        goto exit;
    }

    res = CryptExportKey(key, 0, PRIVATEKEYBLOB, 0, NULL, &key_len);
    if (!res)
    {
        err = GetLastError();
        debug_log("CryptExportKey failed 0x%lx", err);
        ret = -3;
        goto exit;
    }

    key_blob = (PBYTE)malloc(key_len);
    if (!key_blob)
    {
        debug_log("malloc failed %ld", key_len);
        ret = -4;
        goto exit;
    }

    res = CryptExportKey(key, 0, PRIVATEKEYBLOB, 0, key_blob, &key_len);
    if (!res)
    {
        err = GetLastError();
        debug_log("CryptExportKey failed 0x%lx", err);
        ret = -5;
        goto exit;
    }

    file = CreateFileA(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        err = GetLastError();
        debug_log("CreateFileA failed 0x%lx", err);
        ret = -6;
        goto exit;
    }

    res = WriteFile(file, header, sizeof (header), &bytes_written, NULL);
    if (!res)
    {
        err = GetLastError();
        debug_log("WriteFile header failed 0x%lx", err);
        ret = -7;
        goto exit;
    }

    res = WriteFile(file, &key_len, sizeof (key_len), &bytes_written, NULL);
    if (!res)
    {
        err = GetLastError();
        debug_log("WriteFile key length failed 0x%lx", err);
        ret = -8;
        goto exit;
    }

    res = WriteFile(file, key_blob, key_len, &bytes_written, NULL);
    if (!res)
    {
        err = GetLastError();
        debug_log("WriteFile key failed 0x%lx", err);
        ret = -8;
        goto exit;
    }

exit:
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);

    if (key_blob)
        free(key_blob);

    if (key)
        CryptDestroyKey(key);

    if (crypt_prov)
        CryptReleaseContext(crypt_prov, 0);

    return ret;
}

static int sign_driver(LPCSTR file)
{
    int ret = 0;
    int tool_idx = 0;
    const char **tool = NULL;

    ret = create_pvk(PVK_PART);
    if (ret < 0)
    {
        debug_log("create_pvk failed %d", ret);
        goto exit;
    }

    for (tool_idx = MAKECERT; tool_idx <= BCDEDIT; ++tool_idx)
    {
        tool = tools[tool_idx];
        ret = run_cmd(tool[0], tool[1], tool[2]);
        if (ret < 0)
        {
            debug_log("%s failed %d", tool[0], ret);
            break;
        }
    }

    DeleteFileA(PVK_PART);
    DeleteFileA(CER_PART);
    DeleteFileA(PFX_PART);

exit:
    return ret;
}

static void enable_vsync(void)
{
    LONG res = 0;
    HKEY kmdod = 0;
    LPCSTR path = "SYSTEM\\CurrentControlSet\\Services\\uxenkmdod\\vsync";

    res = RegCreateKeyExA(HKEY_LOCAL_MACHINE, path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &kmdod, NULL);
    if (res != ERROR_SUCCESS)
    {
        debug_log("RegOpenKeyEx failed %ld", res);
        goto exit;
    }

exit:
    if (kmdod != 0)
        RegCloseKey(kmdod);
}


static int get_base_leaf(void)
{
    int leaf;
    union {
        struct {
            int eax;
            char signature[13];
        };
        int blob[4];
    } cpu_info;

    memset(&cpu_info, 0, sizeof cpu_info);
    for (leaf = 0x40000000; leaf < 0x40010000; leaf += 0x100) {
        __cpuid(cpu_info.blob, leaf);
        cpu_info.signature[12] = 0;

        if (!strcmp(cpu_info.signature, "uXenisnotXen"))
            break;
    }

    if (leaf >= 0x40010000 || (cpu_info.eax - leaf) < 2)
        return 0;

    return leaf;
}

int main()
{
    int ret = 0;
    PVOID old_value;
    union dm_features features;
    int cpuid_base_leaf = 0;
    int blob[4] = {0};

    Wow64DisableWow64FsRedirection(&old_value);

    logging_init();

    features.blob = 0;
    cpuid_base_leaf = get_base_leaf();
    if (cpuid_base_leaf) {
        __cpuid(blob, cpuid_base_leaf + 193);
        features.blob = blob[0];
        debug_log("patcher cpuid_base_leaf %d. dm-features: 0x%0I64x", cpuid_base_leaf, features.blob);
    }

    if (!features.bits.run_patcher)
    {
        debug_log("patcher disabled in dm-features");
        return 0;
    }

    debug_log("Backing up %s", DXGKRNL);
    ret = backup_driver(DXGKRNL);
    if (ret < 0)
    {
        debug_log("backup_driver failed %d", ret);
        goto exit;
    }

    log_file_info(DXGKRNL);

    debug_log("Patching %s", DXGKRNL);
    ret = patch_driver(DXGKRNL);
    if (ret < 0)
    {
        debug_log("patch_driver failed %d", ret);
        goto exit;
    }

    debug_log("Signing %s", DXGKRNL);
    ret = sign_driver(DXGKRNL);
    if (ret < 0)
    {
        debug_log("sign_driver failed %d", ret);
        goto exit;
    }

    enable_vsync();

exit:
    if (ret != 0)
        debug_log("Patching %s has failed with error %d", DXGKRNL, ret);
    else
        debug_log("Patching %s succeeded", DXGKRNL);
    return 0;
}
