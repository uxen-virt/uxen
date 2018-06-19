!include ../../common/makefile.inc

$(OBJ_PATH)\$(O)\$(INF_NAME).inf: $(_INX)\$(INF_NAME).inx
    copy $(_INX)\$(@B).inx $@
    $(STAMP)

$(OBJ_PATH)\$(O)\uxenMRXNP.dll:
    copy $(OBJ_PATH)\..\dll\$(O)\uxenMRXNP.dll $@

$(OBJ_PATH)\$(O)\install.bat: install.bat
    copy install.bat $@

COPY: $(OBJ_PATH)\$(O)\uxenMRXNP.dll $(OBJ_PATH)\$(O)\install.bat

POST:
