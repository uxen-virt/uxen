!include ../../common/makefile.inc

.SUFFIXES: .inx

STAMP=stampinf

.inx{$(OBJ_PATH)\$(O)}.inf:
    copy $(@B).inx $@
    $(STAMP) -f $@ -a $(_BUILDARCH) -k $(KMDF_VERSION_MAJOR).$(KMDF_VERSION_MINOR) -u $(UMDF_VERSION_MAJOR).$(UMDF_VERSION_MINOR).0

!if defined(UXEN_WINDOWS_SIGN)
SIGNCMD=$(UXEN_WINDOWS_SIGN)
!else
SIGNCMD=rem build not signed since UXEN_WINDOWS_SIGN not defined
!endif

POST:
    $(SIGNCMD) $(OBJ_PATH)\$(O)\VBoxMRXNP.dll
