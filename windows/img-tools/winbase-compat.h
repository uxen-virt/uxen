#include <windows.h>
#include <winioctl.h>
#include <ntdef.h>
/* definitions missing from mingw's winbase.h. Present in a newer version
 * I found online at http://sourceforge.net/p/mingw, so we should upgrade. */

/* http://msdn.microsoft.com/en-us/library/aa364226%28v=VS.85%29.aspx */
typedef struct _FILE_ID_BOTH_DIR_INFO {
    DWORD    NextEntryOffset;
    DWORD    FileIndex;
    LARGE_INTEGER    CreationTime;
    LARGE_INTEGER    LastAccessTime;
    LARGE_INTEGER    LastWriteTime;
    LARGE_INTEGER    ChangeTime;
    LARGE_INTEGER    EndOfFile;
    LARGE_INTEGER    AllocationSize;
    DWORD    FileAttributes;
    DWORD    FileNameLength;
    DWORD    EaSize;
    CCHAR    ShortNameLength;
    WCHAR    ShortName[12];
    LARGE_INTEGER    FileId;
    WCHAR    FileName[1];
} FILE_ID_BOTH_DIR_INFO,*PFILE_ID_BOTH_DIR_INFO,*LPFILE_ID_BOTH_DIR_INFO;

typedef enum _FILE_INFO_BY_HANDLE_CLASS {
    FileBasicInfo,
    FileStandardInfo,
    FileNameInfo,
    FileRenameInfo,
    FileDispositionInfo,
    FileAllocationInfo,
    FileEndOfFileInfo,
    FileStreamInfo,
    FileCompressionInfo,
    FileAttributeTagInfo,
    FileIdBothDirectoryInfo,
    FileIdBothDirectoryRestartInfo,
    FileIoPriorityHintInfo,
    FileRemoteProtocolInfo,
    MaximumFileInfoByHandlesClass
} FILE_INFO_BY_HANDLE_CLASS,*PFILE_INFO_BY_HANDLE_CLASS;

/* https://msdn.microsoft.com/en-us/library/windows/desktop/aa364401(v=vs.85).aspx */
typedef struct _FILE_STANDARD_INFO {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    DWORD         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} FILE_STANDARD_INFO, *PFILE_STANDARD_INFO;

#define CreateSymbolicLink __AW(CreateSymbolicLink)
WINBASEAPI BOOL WINAPI CreateSymbolicLinkA(LPCSTR,LPCSTR,DWORD);
WINBASEAPI BOOL WINAPI CreateSymbolicLinkW(LPCWSTR,LPCWSTR,DWORD);
/* http://msdn.microsoft.com/en-us/library/aa364953%28VS.85%29.aspx */
WINBASEAPI BOOL WINAPI GetFileInformationByHandleEx(HANDLE,FILE_INFO_BY_HANDLE_CLASS,LPVOID,DWORD);

HANDLE WINAPI FindFirstFileNameW(
LPCWSTR lpFileName,
DWORD dwFlags,
LPDWORD StringLength,
PWCHAR LinkName
);

BOOL WINAPI FindNextFileNameW(
HANDLE hFindStream,
LPDWORD StringLength,
PWCHAR LinkName
);

typedef struct IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS stat;
        PVOID pointer;
    };
    ULONG_PTR info;
} IO_STATUS_BLOCK;

typedef ULONG (__stdcall *pNtCreateFile)(
        PHANDLE FileHandle,
        ULONG DesiredAccess,
        PVOID ObjectAttributes,
        PVOID IoStatusBlock,
        PLARGE_INTEGER AllocationSize,
        ULONG FileAttributes,
        ULONG ShareAccess,
        ULONG CreateDisposition,
        ULONG CreateOptions,
        PVOID EaBuffer,
        ULONG EaLength
        );

typedef ULONG (__stdcall *pNtClose)(
        HANDLE Handle
        );

typedef ULONG (__stdcall *pNtReadFile)(
        HANDLE FileHandle,
        HANDLE Event,
        PVOID ApcRoutine,
        PVOID ApcContext,
        IO_STATUS_BLOCK *IoStatusBlock,
        PVOID Buffer,
        ULONG Length,
        PLARGE_INTEGER ByteOffset,
        PULONG Key
        );

typedef HRESULT (__stdcall *pFilterConnectCommunicationPort)(
    LPCWSTR lpPortName,
    DWORD dwOptions,
    LPCVOID lpContext,
    WORD dwSizeOfContext,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    HANDLE *hPort
    );

typedef HRESULT (__stdcall *pFilterSendMessage) (
    HANDLE hPort,
    LPVOID lpInBuffer,
    DWORD dwInBufferSize,
    LPVOID lpOutBuffer,
    DWORD dwOutBufferSize,
    LPDWORD lpBytesReturned
    );

typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS (NTAPI *pNtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );

typedef NTSTATUS (NTAPI *pNtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;


typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG  Attributes;
    ACCESS_MASK  GrantedAccess;
    ULONG  HandleCount;
    ULONG  PointerCount;
    ULONG  PagedPoolUsage;
    ULONG  NonPagedPoolUsage;
    ULONG  Reserved[3];
    ULONG  NameInformationLength;
    ULONG  TypeInformationLength;
    ULONG  SecurityDescriptorLength;
    LARGE_INTEGER  CreateTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

#define FILE_OPEN                           0x00000001
#define FILE_OPEN_BY_FILE_ID                0x00002000
#define FILE_NON_DIRECTORY_FILE             0x00000040
#define FILE_SEQUENTIAL_ONLY                0x00000004
#define FILE_OPEN_FOR_BACKUP_INTENT         0x00004000

#define SystemHandleInformation             16
#define ObjectBasicInformation              0
#define ObjectNameInformation               1
#define ObjectTypeInformation               2
#define ObjectHandleInformation             3

