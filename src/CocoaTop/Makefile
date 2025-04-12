ARCHS = arm64
include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = CocoaTop

ADDITIONAL_OBJCFLAGS = -fobjc-arc # -Wno-deprecated-declarations
XCODEPROJ_NAME = CocoaTop

CocoaTop_FRAMEWORKS = UIKit IOKit CoreGraphics
CocoaTop_CODESIGN_FLAGS = -Sentitlements.xml
CocoaTop_XCODE_SCHEME = CocoaTop

include $(THEOS_MAKE_PATH)/xcodeproj.mk
