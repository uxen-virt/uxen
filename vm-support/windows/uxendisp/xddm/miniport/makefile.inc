!include ../../../common/makefile.inc

$(OBJ_PATH)\$(O)\$(INF_NAME).inf: $(_INX)\$(INF_NAME).inx 
    copy $(_INX)\$(@B).inx $@
    $(STAMP)

# A bit dodgy, but I guess it's fine for now
$(OBJ_PATH)\$(O)\uxendispdd.dll:
    copy $(OBJ_PATH)\..\display\$(O)\uxendispdd.dll $@
$(OBJ_PATH)\$(O)\uxendispdd.pdb:
    copy $(OBJ_PATH)\..\display\$(O)\uxendispdd.pdb $@

COPY: $(OBJ_PATH)\$(O)\uxendispdd.dll $(OBJ_PATH)\$(O)\uxendispdd.pdb

$(OBJ_PATH)\$(O)\install.bat: install.bat
    copy install.bat $@

COPY: $(COPY_DEVCON)
COPY: $(OBJ_PATH)\$(O)\install.bat

POST: $(OBJ_PATH)\$(O)\$(INF_NAME).inf
    $(INF2CAT)
