
# even if you're not using kmdf, you can still use this as is, without issue

_LNG=$(LANGUAGE)
_INX=.
!if defined(KMDF_VERSION_MAJOR)
STAMP=stampinf -f $@ -a $(_BUILDARCH) -k $(KMDF_VERSION_MAJOR).$(KMDF_VERSION_MINOR)
!else
STAMP=stampinf -f $@ -a $(_BUILDARCH)
!endif

!if ("$(_BUILDARCH)" == "AMD64")
DEVCON_ARCH_SUBDIR=$(_BUILDARCH)
INF2CAT_OS=7_X64
!else
DEVCON_ARCH_SUBDIR=i386
INF2CAT_OS=7_X86
!endif

INF2CAT=inf2cat /driver:$(OBJ_PATH)\$(O)\ /os:$(INF2CAT_OS)

COPY_DEVCON = $(OBJ_PATH)\$(O)\devcon.exe

$(COPY_DEVCON): $(PUBLIC_ROOT)\tools\devcon\$(DEVCON_ARCH_SUBDIR)\devcon.exe
    copy $(PUBLIC_ROOT)\tools\devcon\$(DEVCON_ARCH_SUBDIR)\devcon.exe $@

COPY_WDFCOINSTALLER = $(OBJ_PATH)\$(O)\WdfCoInstaller01009.dll

$(COPY_WDFCOINSTALLER): $(PUBLIC_ROOT)\redist\wdf\$(_BUILDARCH)\WdfCoInstaller01009.dll
    copy $(PUBLIC_ROOT)\redist\wdf\$(_BUILDARCH)\WdfCoInstaller01009.dll $@
