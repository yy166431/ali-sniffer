# Makefile for KNBypass (酷牛设备黑名单/签名/越狱检测 Bypass)
# 编译环境: macOS + Xcode Command Line Tools
# 目标: arm64 dylib，轻松签注入

IOS_SDK := $(shell xcrun --sdk iphoneos --show-sdk-path)
CC := clang

CFLAGS := \
	-arch arm64 \
	-isysroot $(IOS_SDK) \
	-fobjc-arc \
	-fmodules \
	-miphoneos-version-min=11.0 \
	-O2

LDFLAGS := \
	-dynamiclib \
	-framework UIKit \
	-framework Foundation \
	-framework CoreFoundation \
	-framework CFNetwork \
	-framework WebKit \
	-framework AVFoundation \
	-framework AVKit \
	-framework CoreMedia

TARGET := KNBypass.dylib
SRCS   := AliSniffer.m fishhook.c

all: $(TARGET)

$(TARGET): $(SRCS) fishhook.h
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)
	@echo "[*] Build OK: $(TARGET)"

clean:
	rm -f $(TARGET)
