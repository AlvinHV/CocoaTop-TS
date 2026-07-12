ARCHS = arm64
TARGET = iphone:clang:16.5:12.0
APPLICATION_NAME = CocoaTop
DEBUG ?= 0

.PHONY: build-subprojects

#FINALPACKAGE = 1
#PACKAGE_VERSION = $(THEOS_PACKAGE_BASE_VERSION)

include $(THEOS)/makefiles/common.mk
SUBPROJECTS += src/CocoaTop
include $(THEOS_MAKE_PATH)/aggregate.mk

build-subprojects:
	@$(MAKE) -C src/CocoaTop-helper DEBUG=$(DEBUG) all

ipa: build-subprojects package
	@rm -rf .theos/_tmp/build packages/$(APPLICATION_NAME).app.dSYM
	@mkdir -p .theos/_tmp/build/Payload
	@cp -r .theos/_/Applications/* .theos/_tmp/build/Payload
	@xcrun dsymutil .theos/_/Applications/$(APPLICATION_NAME).app/$(APPLICATION_NAME) -o packages/$(APPLICATION_NAME).app.dSYM
	@rm -f packages/$(APPLICATION_NAME).tipa
	@cd .theos/_tmp/build/ && zip -r ../../../packages/$(APPLICATION_NAME).tipa Payload
	@cd ../../../..
	@echo "[+] Done! IPA created"
