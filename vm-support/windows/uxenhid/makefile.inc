!include ../common/makefile.inc

$(OBJ_PATH)\$(O)\$(INF_NAME).inf: $(_INX)\$(INF_NAME).inx 
    copy $(_INX)\$(@B).inx $@
    $(STAMP)

$(OBJ_PATH)\$(O)\uxenvmlib.sys:
    copy $(UXENVMLIB_SYS) $@
    copy $(UXENVMLIB_PDB) $(@D)

COPY: $(OBJ_PATH)\$(O)\uxenvmlib.sys

POST: $(OBJ_PATH)\$(O)\$(INF_NAME).inf
    $(INF2CAT)
