ROOT_DIR ?= .
BUILD_TYPE ?= debug
API_LEVEL ?= 25
ARCHS ?= arm64-v8a armeabi-v7a
ARCH ?= arm64-v8a

VER_NAME ?= v2.1.2
# VER_CODE = commit count + 36: 36 commits were squashed away on 2026-09-01,
# the last pre-squash build was 578, so the sequence continues from there.
GIT_COUNT ?= $(shell git -C "$(ROOT_DIR)" rev-list HEAD --count 2>/dev/null || echo 542)
VER_CODE ?= $(shell expr $(GIT_COUNT) + 36)
COMMIT_HASH ?= $(shell git -C "$(ROOT_DIR)" rev-parse --verify --short HEAD 2>/dev/null || echo unknown)

MIN_KSU_VERSION ?= 10940
MIN_KSUD_VERSION ?= 11425

MODULE_ID ?= rezygisk
MODULE_NAME ?= VexZygisk

NDK_VERSION ?= 29.0.13113456
ANDROID_HOME ?= $(HOME)/Android/Sdk
NDK_PATH ?= $(ANDROID_HOME)/ndk/$(NDK_VERSION)
TOOLCHAIN = $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64
SYSROOT = $(TOOLCHAIN)/sysroot

ifeq ($(TERMUX_VERSION),)
	CC = $(TOOLCHAIN)/bin/clang
	AR = $(TOOLCHAIN)/bin/llvm-ar
	STRIP = $(TOOLCHAIN)/bin/llvm-strip
else
	CC = clang
	AR = llvm-ar
	STRIP = llvm-strip
endif

BUILD_DIR ?= $(ROOT_DIR)/build

TARGET_arm64-v8a = aarch64-linux-android$(API_LEVEL)
TARGET_armeabi-v7a = armv7a-linux-androideabi$(API_LEVEL)

CC_ARCH = $(CC) --target=$(TARGET_$(ARCH)) --sysroot=$(SYSROOT)

NDK_CFLAGS = -DANDROID -fdata-sections -ffunction-sections -funwind-tables \
	-fstack-protector-strong -no-canonical-prefixes -D_FORTIFY_SOURCE=2 \
	-Wformat -Werror=format-security
