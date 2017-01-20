!include ../makefile.inc

$(OBJ_PATH)\$(O)\dbghelp.dll: 
    copy $(PUBLIC_ROOT)\Debuggers\dbghelp.dll $@

$(OBJ_PATH)\$(O)\symsrv.dll: 
    copy $(PUBLIC_ROOT)\Debuggers\symsrv.dll $@

$(OBJ_PATH)\$(O)\symsrv.yes: 
    copy $(PUBLIC_ROOT)\Debuggers\symsrv.yes $@

COPY: $(OBJ_PATH)\$(O)\dbghelp.dll
COPY: $(OBJ_PATH)\$(O)\symsrv.dll
COPY: $(OBJ_PATH)\$(O)\symsrv.yes
