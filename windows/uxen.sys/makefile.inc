
!if defined(UXEN_WINDOWS_SIGN)
SIGNCMD=$(UXEN_WINDOWS_SIGN)
!else
SIGNCMD=rem build not signed since UXEN_WINDOWS_SIGN not defined
!endif

POST: $(OBJ_PATH)\$(O)\$(TARGETNAME).sys
    $(SIGNCMD) $(OBJ_PATH)\$(O)\$(TARGETNAME).sys

$(OBJ_PATH)\$(O)\uxen-core.obj: $(BUILDDIR_XEN)\uxen.obj
	copy $(BUILDDIR_XEN)\uxen.obj $(OBJ_PATH)\$(O)\uxen-core.obj
	echo $(OBJ_PATH)\$(O)\uxen-core.obj

$(OBJ_PATH)\$(O)\uxen-xpdata.obj: $(BUILDDIR_XEN)\uxen-xpdata.obj
	copy $(BUILDDIR_XEN)\uxen-xpdata.obj $(OBJ_PATH)\$(O)\uxen-xpdata.obj

$(OBJ_PATH)\$(O)\uxenv4vlib.sys:
    copy $(UXENV4VLIB_SYS) $@
    copy $(UXENV4VLIB_PDB) $(@D)

COPY: $(OBJ_PATH)\$(O)\uxenv4vlib.sys



