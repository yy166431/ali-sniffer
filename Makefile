# Makefile for AliSniffer
IOS_SDK := $(shell xcrun --sdk iphoneos --show-sdk-path)
CC := clang
CFLAGS := -arch arm64 -isysroot $(IOS_SDK) -fobjc-arc -miphoneos-version-min=11.0
LDFLAGS := -dynamiclib -framework AVFoundation -framework UIKit -framework Foundation

all: AliSniffer.dylib

AliSniffer.dylib: AliSniffer.m
    $(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
    rm -f AliSniffer.dylib