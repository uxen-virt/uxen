RTR3DECL(int) RTPathQueryInfoExUcs(const wchar_t *pszPath, PRTFSOBJINFO pObjInfo
, RTFSOBJATTRADD enmAdditionalAttribs, uint32_t fFlags);
RTR3DECL(int) RTFileOpenUcs(PRTFILE pFile, const wchar_t *pszFilename, uint64_t fOpen,
                            int *pfAlreadyExists, int *pfCreated, int *pfTruncated);
RTDECL(int) RTDirCreateUcs(const wchar_t *pszPath, RTFMODE fMode, uint32_t fCreate);
RTDECL(int) RTDirOpenFilteredUcs(PRTDIR *ppDir, const wchar_t *pszPath, RTDIRFILTER enmFilter, uint32_t fOpen);
int rtDirNativeOpenUcs(PRTDIR pDir, wchar_t *pszPathBuf);
RTR3DECL(int)  RTFileDeleteUcs(const wchar_t *pszFilename);
RTDECL(int) RTDirRemoveUcs(const wchar_t *pszPath);
RTDECL(int) RTFileRenameUcs(const wchar_t *pszSrc, const wchar_t *pszDst, 
    unsigned fRename);
RTDECL(int) RTDirRenameUcs(const wchar_t *pszSrc, const wchar_t *pszDst, 
    unsigned fRename);
RTDECL(int) RTFileMoveUcs(const wchar_t *pszSrc, const wchar_t *pszDst, 
    unsigned fMove);
RTDECL(int) RTDirReadExUcs(PRTDIR pDir, PRTDIRENTRYEX pDirEntry, 
    size_t *pcbDirEntry, RTFSOBJATTRADD enmAdditionalAttribs, uint32_t fFlags);
RTR3DECL(int) RTFsQuerySizesUnc(const wchar_t *pszFsPath, RTFOFF *pcbTotal, 
    RTFOFF *pcbFree, uint32_t *pcbBlock, uint32_t *pcbSector);
RTR3DECL(int) RTFsQueryPropertiesUnc(const wchar_t *pszFsPath, 
    PRTFSPROPERTIES pProperties);
wchar_t* RTwcsdup(wchar_t* s);
RTR3DECL(int) RTPathSetTimesUcs(const wchar_t *pszPath, 
    PCRTTIMESPEC pAccessTime,
    PCRTTIMESPEC pModificationTime, PCRTTIMESPEC pChangeTime,
    PCRTTIMESPEC pBirthTime);
DECLHIDDEN(int) rtPathWin32MoveRenameUcs(const wchar_t *pwszSrc, 
    const wchar_t *pwszDst, uint32_t fFlags, RTFMODE fFileType);






