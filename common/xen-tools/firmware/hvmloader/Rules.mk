
# force -O0 since hvmloader is broken with anything but -O0
CFLAGS_debug := $(subst -O2,-O0,$(CFLAGS_debug))

XEN_INCLUDE        = $(abspath $(TOPDIR))/common/include/xen-public
CFLAGS_xeninclude = -I$(XEN_INCLUDE)
CFLAGS += -D__XEN_TOOLS__ -DNDEBUG
CFLAGS += -fno-strict-aliasing
CFLAGS += -std=gnu99
CFLAGS += -Wstrict-prototypes
CFLAGS += -Wno-unused-value
CFLAGS += -Wdeclaration-after-statement
CFLAGS += -fno-builtin -msoft-float

$(REL_ONLY)LDFLAGS_DIRECT += -s
