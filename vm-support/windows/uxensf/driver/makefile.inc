!include ../../common/makefile.inc

$(OBJ_PATH)\$(O)\$(INF_NAME).inf: $(_INX)\$(INF_NAME).inx
    copy $(_INX)\$(@B).inx $@
    $(STAMP)

$(OBJ_PATH)\$(O)\VBoxMRXNP.dll:
    copy $(OBJ_PATH)\..\dll\$(O)\VBoxMRXNP.dll $@

$(OBJ_PATH)\$(O)\install.bat: install.bat
    copy install.bat $@

COPY: $(OBJ_PATH)\$(O)\VBoxMRXNP.dll $(OBJ_PATH)\$(O)\install.bat

POST:
