!include ../common/makefile.inc

$(OBJ_PATH)\$(O)\$(INF_NAME).inf: $(_INX)\$(INF_NAME).inx 
    copy $(_INX)\$(@B).inx $@
    $(STAMP)

$(OBJ_PATH)\$(O)\install.bat: install.bat
    copy install.bat $@

COPY: $(COPY_DEVCON)
COPY: $(OBJ_PATH)\$(O)\install.bat

POST: $(OBJ_PATH)\$(O)\$(INF_NAME).inf
    $(INF2CAT)

