# ========= AliSniffer Makefile =========
# 目录结构：
#   AliSniffer.m  fishhook.c  fishhook.h  Makefile
#
# 用法：
#   make        # 生成 AliSniffer.dylib
#   make clean  # 清理

# iOS SDK 路径
IOS_SDK := $(shell xcrun --sdk iphoneos --show-sdk-path)

# 架构（TrollStore/非越狱环境 arm64 足够；要兼容 A12+ 可加 arm64e）
ARCHS  ?= -arch arm64
# ARCHS  ?= -arch arm64 -arch arm64e

CC     := clang
OBJS   := AliSniffer.o fishhook.o
TARGET := AliSniffer.dylib

# 编译参数
CFLAGS := $(ARCHS) -isysroot $(IOS_SDK) -fobjc-arc -fvisibility=hidden \
          -miphoneos-version-min=12.0 -Wall -Wextra

# 链接参数（注意 dynamiclib + 框架）
LDFLAGS := $(ARCHS) -isysroot $(IOS_SDK) -dynamiclib \
           -framework UIKit -framework Foundation -framework CFNetwork -framework WebKit \
           -lobjc

# 某些环境需要取消未定义符号检查（通常不需要）
# LDFLAGS += -Wl,-undefined,dynamic_lookup

# -------- 目标 --------
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

# -------- 规则 --------
AliSniffer.o: AliSniffer.m fishhook.h
	$(CC) $(CFLAGS) -c $< -o $@

fishhook.o: fishhook.c fishhook.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
# ========= end =========
