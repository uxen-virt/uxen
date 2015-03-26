!include ../common/makefile.inc

$(OBJ_PATH)\$(O)\$(INF_NAME).inf: $(_INX)\$(INF_NAME).inx 
    copy $(_INX)\$(@B).inx $@
    $(STAMP)

POST: $(OBJ_PATH)\$(O)\$(INF_NAME).inf
    $(SIGNCMD) $(OBJ_PATH)\$(O)\$(TARGETNAME).sys
    $(INF2CAT)
    $(SIGNCMD) $(OBJ_PATH)\$(O)\$(TARGETNAME).cat
