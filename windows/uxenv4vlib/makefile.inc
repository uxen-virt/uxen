# even if you're not using kmdf, you can still use this as is, without issue

_LNG=$(LANGUAGE)
_INX=.
STAMP=stampinf -f $@ -a $(_BUILDARCH) -k $(KMDF_VERSION_MAJOR).$(KMDF_VERSION_MINOR)

!if ("$(_BUILDARCH)" == "AMD64")
DEVCON_ARCH_SUBDIR=$(_BUILDARCH)
INF2CAT_OS=7_X64
!else
DEVCON_ARCH_SUBDIR=i386
INF2CAT_OS=7_X86
!endif

!if defined(UXEN_WINDOWS_SIGN)
SIGNCMD=$(UXEN_WINDOWS_SIGN)
!else
SIGNCMD=rem build not signed since UXEN_WINDOWS_SIGN not defined
!endif
INF2CAT=inf2cat /driver:$(OBJ_PATH)\$(O)\ /os:$(INF2CAT_OS)

COPY_DEVCON = $(OBJ_PATH)\$(O)\devcon.exe

$(COPY_DEVCON): $(PUBLIC_ROOT)\tools\devcon\$(DEVCON_ARCH_SUBDIR)\devcon.exe
    copy $(PUBLIC_ROOT)\tools\devcon\$(DEVCON_ARCH_SUBDIR)\devcon.exe $@

POST: 
    $(SIGNCMD) $(OBJ_PATH)\$(O)\$(TARGETNAME).sys

