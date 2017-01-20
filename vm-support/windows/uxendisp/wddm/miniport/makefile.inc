!include ../../../common/makefile.inc

$(OBJ_PATH)\$(O)\$(INF_NAME).inf: $(_INX)\$(INF_NAME).inx
    copy $(_INX)\$(@B).inx $@
    $(STAMP)

$(OBJ_PATH)\$(O)\uxend3d.dll:
    copy $(OBJ_PATH)\..\display\$(O)\uxend3d.dll $@
$(OBJ_PATH)\$(O)\uxend3d.pdb:
    copy $(OBJ_PATH)\..\display\$(O)\uxend3d.pdb $@

COPY: $(OBJ_PATH)\$(O)\uxend3d.dll $(OBJ_PATH)\$(O)\uxend3d.pdb

$(OBJ_PATH)\$(O)\install.bat: install.bat
    copy install.bat $@

COPY: $(COPY_DEVCON)
COPY: $(OBJ_PATH)\$(O)\install.bat

POST: $(OBJ_PATH)\$(O)\$(INF_NAME).inf
    $(INF2CAT)
