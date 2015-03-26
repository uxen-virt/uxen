!include ../makefile.inc

$(OBJ_PATH)\$(O)\install.bat:
  copy $(OBJ_PATH)\..\uxenzeroshareconsole\$(O)\uxenzeroshareconsole.exe $@

$(OBJ_PATH)\$(O)\uxenzeroshareconsole.exe: 
  copy $(OBJ_PATH)\..\uxenzeroshareconsole\$(O)\uxenzeroshareconsole.exe $@

$(OBJ_PATH)\$(O)\uxenzeroshareconsole.pdb: 
  copy $(OBJ_PATH)\..\uxenzeroshareconsole\$(O)\uxenzeroshareconsole.pdb $@

$(OBJ_PATH)\$(O)\dbghelp.dll: 
  copy $(OBJ_PATH)\..\uxenzeroshareconsole\$(O)\dbghelp.dll $@

$(OBJ_PATH)\$(O)\symsrv.dll: 
  copy $(OBJ_PATH)\..\uxenzeroshareconsole\$(O)\symsrv.dll $@

$(OBJ_PATH)\$(O)\symsrv.yes: 
  copy $(OBJ_PATH)\..\uxenzeroshareconsole\$(O)\symsrv.yes $@

COPY: $(OBJ_PATH)\$(O)\uxenzeroshareconsole.exe
COPY: $(OBJ_PATH)\$(O)\uxenzeroshareconsole.pdb
COPY: $(OBJ_PATH)\$(O)\install.bat
COPY: $(OBJ_PATH)\$(O)\dbghelp.dll
COPY: $(OBJ_PATH)\$(O)\symsrv.dll
COPY: $(OBJ_PATH)\$(O)\symsrv.yes

POST: $(OBJ_PATH)\$(O)\$(INF_NAME).inf
  $(SIGNCMD) $(OBJ_PATH)\$(O)\$(TARGETNAME).$(TARGETEXT)
  $(INF2CAT)
  $(SIGNCMD) $(OBJ_PATH)\$(O)\$(TARGETNAME).cat

