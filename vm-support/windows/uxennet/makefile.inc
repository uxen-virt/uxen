!include ../common/makefile.inc

$(OBJ_PATH)\$(O)\$(INF_NAME).inf: $(_INX)\$(INF_NAME).inx 
    copy $(_INX)\$(@B).inx $@
    $(STAMP)

$(OBJ_PATH)\$(O)\install.bat: install.bat
    copy install.bat $@

$(OBJ_PATH)\$(O)\uxenv4vlib.sys:
    copy $(UXENV4VLIB_SYS) $@
    copy $(UXENV4VLIB_PDB) $(@D)

COPY: $(COPY_DEVCON)
COPY: $(OBJ_PATH)\$(O)\install.bat
COPY: $(OBJ_PATH)\$(O)\uxenv4vlib.sys

POST: $(OBJ_PATH)\$(O)\$(INF_NAME).inf
    $(INF2CAT)

