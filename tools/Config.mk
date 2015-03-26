
UXEN_TOOLS_TARGETS ?= $(TARGET_HOST)

BUILD_WINDOWS_TOOLS := $(if $(filter windows,$(UXEN_TOOLS_TARGETS)),,n-)
BUILD_OSX_TOOLS := $(if $(filter osx,$(UXEN_TOOLS_TARGETS)),,n-)
