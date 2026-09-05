ROOT_DIR := ..
include ../common.mk

BUILD_DIR ?= $(ROOT_DIR)/build

OBJ_ROOT = $(BUILD_DIR)/obj/$(BUILD_TYPE)/zygiskd
OBJ_DIR = $(OBJ_ROOT)/$(ARCH)

ZKSU_VERSION ?= $(VER_NAME)

ifeq ($(BUILD_TYPE),release)
	TYPE_CFLAGS = -O3 -flto
	TYPE_LDFLAGS = -Wl,--strip-all -flto
else
	TYPE_CFLAGS = -g -O0 -DDEBUG
	TYPE_LDFLAGS =
endif

ZYGISKD_CFLAGS = -D_GNU_SOURCE -std=c99 -Wpedantic -Wall -Wextra -Werror  \
			 	 -Wformat -Wuninitialized -Wshadow -Wno-zero-length-array \
			 	 -Wno-unknown-warning-option -Wconversion                 \
			 	 $(ROOT_IMPL_DEF)                                         \
			 	 '-DZKSU_VERSION="$(ZKSU_VERSION)"'

ROOT_IMPL_SRC = $(if $(filter apatch,$(ROOT_IMPL)),src/root_impl/apatch.c,src/root_impl/kernelsu.c)

SRCS = src/root_impl/common.c $(ROOT_IMPL_SRC) \
	   src/companion.c src/main.c src/utils.c src/zygiskd.c src/zn_companion.c

OBJS = $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRCS))
BIN = $(OBJ_DIR)/zygiskd

# INFO: The Zygisk Next module contract lives with the loader, the daemon hosts
#       the companion side of it and must follow the very same layout.
INCLUDES = -Isrc -Isrc/root_impl -I../loader/src/include

.PHONY: all arch clean

all:
	@for arch in $(ARCHS); do                                                                                  \
		$(MAKE) BUILD_TYPE=$(BUILD_TYPE) BUILD_DIR=$(BUILD_DIR) ARCH=$$arch ZKSU_VERSION=$(ZKSU_VERSION) arch; \
	done

	@mkdir -p $(OBJ_ROOT)
	@touch $(OBJ_ROOT)/.done

arch: $(BIN)

clean:
	rm -rf $(BUILD_DIR)/obj/$(BUILD_TYPE)/zygiskd

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(ZYGISKD_CFLAGS) $(TYPE_CFLAGS) $(INCLUDES) -c $< -o $@

$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(TYPE_LDFLAGS) $(OBJS) -llog -o $@
