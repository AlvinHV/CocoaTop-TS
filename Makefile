ARCHS = arm64
TARGET = iphone:clang:18.4:12.0
APPLICATION_NAME = CocoaTop

#DEBUG = 0
#FINALPACKAGE = 1
#PACKAGE_VERSION = $(THEOS_PACKAGE_BASE_VERSION)

include $(THEOS)/makefiles/common.mk
SUBPROJECTS += src/CocoaTop
include $(THEOS_MAKE_PATH)/aggregate.mk

ipa: package
	@mkdir -p .theos/_tmp/build/Payload
	@cp -r .theos/_/Applications/* .theos/_tmp/build/Payload
	@cd .theos/_tmp/build/ && zip -r ../../../packages/$(APPLICATION_NAME).tipa Payload
	@cd ../../../..
	@echo "[+] Done! IPA created"
