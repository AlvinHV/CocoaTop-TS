ARCHS = arm64
TARGET = iphone:clang:18.4:12.0
APPLICATION_NAME = CocoaTop
ADDITIONAL_OBJCFLAGS = -fobjc-arc # -Wno-deprecated-declarations

#DEBUG = 0
#FINALPACKAGE = 1
#PACKAGE_VERSION = $(THEOS_PACKAGE_BASE_VERSION)

include $(THEOS)/makefiles/common.mk
SUBPROJECTS += src/CocoaTop
include $(THEOS_MAKE_PATH)/aggregate.mk
