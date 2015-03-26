#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <windows.h>
#include <tchar.h>
#include <dbghelp.h>

int winsym_init(void *winsymid,
                char *modname, uint32_t timestamp, uint32_t imagesize,
                char *symsrvpath, uint64_t vabase)
{
    int rc;
    char path[MAX_PATH];

    if (symsrvpath == NULL)
        symsrvpath = "srv*http://msdl.microsoft.com/download/symbols";

    rc = SymInitialize(winsymid, 
                       "srv*http://msdl.microsoft.com/download/symbols", 0);
    if (!rc) {
        perror("SymInitialize");
        return 0;
    }

    rc = SymFindFileInPath(winsymid, NULL, 
                           modname, &timestamp, imagesize,
                           0, SSRVOPT_DWORDPTR, path, NULL, NULL);
    if (!rc) {
        perror("SymFindFileInPath");
        SymCleanup(winsymid);
        return 0;
    }
    fprintf(stderr, "PATH: %s, vabase = %"PRIx64"\n", path, vabase);
    rc = SymLoadModule64(winsymid, NULL, path, NULL, vabase, 0);
    if (!rc) {
        perror("SymLoadModule64");
        SymCleanup(winsymid);
        return 0;
    }

    return 1;
}

int winsym_fin(void *winsymid)
{

    return SymCleanup(winsymid);
}

int winsym_resolve(void *winsymid, char *sym, uint64_t *addr)
{
    int rc;
    TCHAR szSymbolName[MAX_SYM_NAME];
    ULONG64 buffer[(sizeof(SYMBOL_INFO) +
                    MAX_SYM_NAME * sizeof(TCHAR) +
                    sizeof(ULONG64) - 1) /
                   sizeof(ULONG64)] = {0, };
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;
    _tcscpy(szSymbolName, sym);

    rc = SymFromName(GetCurrentProcess(), szSymbolName, pSymbol);
    if (!rc) {
        perror("SymFromName");
        return 0;
    }

    *addr = pSymbol->Address;
    return 1;
}
