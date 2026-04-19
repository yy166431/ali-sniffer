# Makefile for KNBypass v6.0
IOS_SDK := $(shell xcrun --sdk iphoneos --show-sdk-path)
CC := clang

CFLAGS := \
	-arch arm64 \
	-isysroot $(IOS_SDK) \
	-fobjc-arc \
	-fmodules \
	-miphoneos-version-min=13.0 \
	-O2

LDFLAGS := \
	-dynamiclib \
	-framework UIKit \
	-framework Foundation \
	-framework Security

TARGET := KNBypass.dylib
SRCS   := AliSniffer.m

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)
	@echo "[*] Build OK: $(TARGET)"

clean:
	rm -f $(TARGET)
