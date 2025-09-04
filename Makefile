# Makefile for LiveHelper (non-jailbreak friendly)
IOS_SDK := $(shell xcrun --sdk iphoneos --show-sdk-path)
CC      := clang

CFLAGS  := -arch arm64 -isysroot $(IOS_SDK) -fobjc-arc -miphoneos-version-min=11.0
LDFLAGS := -dynamiclib \
           -framework UIKit \
           -framework Foundation \
           -framework CFNetwork \
           -framework WebKit

all: AliSniffer.dylib

AliSniffer.dylib: AliSniffer.m fishhook.c fishhook.h
	$(CC) $(CFLAGS) AliSniffer.m fishhook.c -o $@ $(LDFLAGS)

clean:
	rm -f AliSniffer.dylib
