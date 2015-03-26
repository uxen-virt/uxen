_NT_TARGET_VERSION= $(_NT_TARGET_VERSION_WIN7)

!IF (("$(TARGETTYPE)" == "DRIVER_LIBRARY") || ("$(TARGETTYPE)" == "DRIVER"))
USER_C_FLAGS=$(USER_C_FLAGS) /DUXENZEROSHARE_KERNEL_MODE
LIBINTERNALS_LIB=$(OBJ_PATH)\..\libinternals\sys\$(O)\libinternals.lib
!ELSE
USER_C_FLAGS=$(USER_C_FLAGS) /DUXENZEROSHARE_USER_MODE
LIBINTERNALS_LIB=$(OBJ_PATH)\..\libinternals\usr\$(O)\libinternals.lib

! IF "$(NTDEBUG)" == "retail" || "$(NTDEBUG)" == "" || "$(NTDEBUG)" == "ntsdnodbg"
CFLAGS=$(CFLAGS) /MT
! ELSE
CFLAGS=$(CFLAGS) /MTd
! ENDIF

! IF ("$(TARGETTYPE)" == "PROGRAM")
UMTYPE=console
UMBASE=0x0400000
USE_MSVCRT=1
! ENDIF
!ENDIF

!include $(COMMON_DIR)\sources.inc

UXENVMLIB_BUILD_DIR   = \
  $(OBJECT_ROOT)\..\uxenvmlib\$(WDK_ALTERNATE_MAKEDIR)\..\..\uxenvmlib\$(O)

UXENVMLIB_LIB         = \
  $(UXENVMLIB_BUILD_DIR)\uxenvmlib.lib


