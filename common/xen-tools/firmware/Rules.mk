#
override XEN_TARGET_ARCH = x86_64
XEN_TARGET_ARCH = x86_64

# User-supplied CFLAGS are not useful here.
CFLAGS = -D__UXEN__

include $(XEN_TOOLS_ROOT)/Rules.mk

ifneq ($(debug),y)
CFLAGS += -DNDEBUG
endif

CFLAGS += -Werror

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))

# Extra CFLAGS suitable for an embedded type of environment.
CFLAGS += -fno-builtin -msoft-float
