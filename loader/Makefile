ROOT_DIR := ..
include ../common.mk

BUILD_DIR ?= $(ROOT_DIR)/build

OBJ_ROOT = $(BUILD_DIR)/obj/$(BUILD_TYPE)/loader
OBJ_DIR = $(OBJ_ROOT)/$(ARCH)

ZKSU_VERSION ?= $(VER_NAME)-$(VER_CODE)-$(COMMIT_HASH)-$(BUILD_TYPE)

ifeq ($(BUILD_TYPE),release)
	TYPE_CFLAGS = -O3 -ffast-math -flto -Wno-unused -Wno-unused-parameter       \
				  -fvisibility=hidden -fvisibility-inlines-hidden -fno-unwind-tables \
				  -fno-asynchronous-unwind-tables -DNDEBUG
	TYPE_LDFLAGS = -Wl,--exclude-libs,ALL -Wl,--strip-all -flto
else
	TYPE_CFLAGS = -g -O0
	TYPE_LDFLAGS =
endif

LOADER_CFLAGS = -std=c18 -D_GNU_SOURCE -Wall -Wextra -fno-rtti -fno-exceptions         \
				-fno-stack-protector -fomit-frame-pointer -Wno-builtin-macro-redefined \
				'-D__FILE__=__FILE_NAME__' -DZKSU_VERSION=\"$(ZKSU_VERSION)\"

COMMON_LDFLAGS = -static-libstdc++ -Wl,--build-id=sha1 -Wl,--no-rosegment           \
				 -Wl,--no-undefined-version -Wl,--fatal-warnings -Wl,--no-undefined \
				 -Qunused-arguments -Wl,--gc-sections

COMMON_SRCS = src/common/daemon.c src/common/elf_util.c   \
			  src/common/misc.c src/common/socket_utils.c
INJECTOR_SRCS = src/injector/cpp_strings.c src/injector/entry.c \
				src/injector/hook.c src/injector/ptrace_clear.c \
				src/injector/zn_api.c src/injector/zn_loader.c
PTRACER_SRCS = src/ptracer/main.c src/ptracer/monitor.c src/ptracer/ptracer.c \
			   src/ptracer/remote_csoloader.c src/ptracer/utils.c

COMMON_OBJS = $(patsubst src/common/%.c,$(OBJ_DIR)/common/%.o,$(COMMON_SRCS))
INJECTOR_OBJS = $(patsubst src/injector/%.c,$(OBJ_DIR)/injector/%.o,$(INJECTOR_SRCS))
PTRACER_OBJS = $(patsubst src/ptracer/%.c,$(OBJ_DIR)/ptracer/%.o,$(PTRACER_SRCS))

PLTI_LIB = $(BUILD_DIR)/obj/$(BUILD_TYPE)/plti/$(ARCH)/libplti.a
CSOLOADER_LIB = $(BUILD_DIR)/obj/$(BUILD_TYPE)/csoloader/$(ARCH)/libcsoloader.a
DOBBY_LIB = $(BUILD_DIR)/obj/$(BUILD_TYPE)/dobby/$(ARCH)/libdobby.a

LIBCOMMON = $(OBJ_DIR)/libcommon.a
LIBZYGISK = $(OBJ_DIR)/libzygisk.so
LIBPTRACE = $(OBJ_DIR)/libzygisk_ptrace.so
LIBZYGISK_STRIPPED = $(OBJ_DIR)/stripped/libzygisk.so
LIBPTRACE_STRIPPED = $(OBJ_DIR)/stripped/libzygisk_ptrace.so

PLTI_DIR = src/external/plti
CSOLOADER_DIR = src/external/csoloader
DOBBY_DIR = src/external/dobby

COMMON_INCLUDES = -Isrc/include
INJECTOR_INCLUDES = -Isrc/include -I$(PLTI_DIR)/src -I$(CSOLOADER_DIR)/include -I$(DOBBY_DIR)/include

# INFO: Dobby is C++ and ships no Makefile, so its sources are compiled here
#       instead of being delegated to a submake like PLTI and CSOLoader. The
#       list mirrors Dobby's own CMakeLists for Linux/Android on ARM: the
#       x86/ia32 and Darwin/Windows backends are left out, and the symbol
#       resolver plugin is skipped because nothing in the hook path uses it.
DOBBY_SRCS = \
	source/core/arch/CpuFeature.cc \
	source/core/arch/CpuRegister.cc \
	source/core/assembler/assembler.cc \
	source/core/assembler/assembler-arm.cc \
	source/core/assembler/assembler-arm64.cc \
	source/core/codegen/codegen-arm.cc \
	source/core/codegen/codegen-arm64.cc \
	source/MemoryAllocator/CodeBuffer/CodeBufferBase.cc \
	source/MemoryAllocator/AssemblyCodeBuilder.cc \
	source/MemoryAllocator/MemoryAllocator.cc \
	source/MemoryAllocator/NearMemoryAllocator.cc \
	source/InstructionRelocation/arm/InstructionRelocationARM.cc \
	source/InstructionRelocation/arm64/InstructionRelocationARM64.cc \
	source/InterceptRouting/InterceptRouting.cpp \
	source/InterceptRouting/Routing/FunctionInlineHook/FunctionInlineHook.cc \
	source/InterceptRouting/Routing/FunctionInlineHook/RoutingImpl.cc \
	source/InterceptRouting/Routing/InstructionInstrument/InstructionInstrument.cc \
	source/InterceptRouting/Routing/InstructionInstrument/RoutingImpl.cc \
	source/InterceptRouting/Routing/InstructionInstrument/instrument_routing_handler.cc \
	source/InterceptRouting/RoutingPlugin/RoutingPlugin.cc \
	source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/NearBranchTrampoline.cc \
	source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/near_trampoline_arm64.cc \
	source/TrampolineBridge/Trampoline/arm/trampoline_arm.cc \
	source/TrampolineBridge/Trampoline/arm64/trampoline_arm64.cc \
	source/TrampolineBridge/ClosureTrampolineBridge/common_bridge_handler.cc \
	source/TrampolineBridge/ClosureTrampolineBridge/arm/helper_arm.cc \
	source/TrampolineBridge/ClosureTrampolineBridge/arm/closure_bridge_arm.cc \
	source/TrampolineBridge/ClosureTrampolineBridge/arm/ClosureTrampolineARM.cc \
	source/TrampolineBridge/ClosureTrampolineBridge/arm64/helper_arm64.cc \
	source/TrampolineBridge/ClosureTrampolineBridge/arm64/closure_bridge_arm64.cc \
	source/TrampolineBridge/ClosureTrampolineBridge/arm64/ClosureTrampolineARM64.cc \
	source/Backend/UserMode/PlatformUtil/Linux/ProcessRuntimeUtility.cc \
	source/Backend/UserMode/UnifiedInterface/platform-posix.cc \
	source/Backend/UserMode/ExecMemory/code-patch-tool-posix.cc \
	source/Backend/UserMode/ExecMemory/clear-cache-tool-all.c \
	source/dobby.cpp source/Interceptor.cpp source/InterceptEntry.cpp \
	external/logging/logging.c external/logging/cxxlogging.cc

DOBBY_OBJ_DIR = $(BUILD_DIR)/obj/$(BUILD_TYPE)/dobby/$(ARCH)
DOBBY_OBJS = $(addsuffix .o,$(addprefix $(DOBBY_OBJ_DIR)/,$(DOBBY_SRCS)))

DOBBY_CXXFLAGS = -std=c++14 -D_GNU_SOURCE -fno-rtti -fno-exceptions -fno-stack-protector \
				 -fomit-frame-pointer -fno-unwind-tables -fno-asynchronous-unwind-tables \
				 -Wno-deprecated-register -Wno-unused -Wno-unused-parameter \
				 -D__DOBBY_BUILD_VERSION__='"Dobby"' -DLOGGING_DISABLE -DNDEBUG
DOBBY_INCLUDES = -I$(DOBBY_DIR)/include -I$(DOBBY_DIR)/source -I$(DOBBY_DIR)/source/include \
				 -I$(DOBBY_DIR)/external -I$(DOBBY_DIR)/external/logging \
				 -I$(DOBBY_DIR)/source/Backend/UserMode

.PHONY: all arch clean

all:
	@for arch in $(ARCHS); do                                                                                  \
		$(MAKE) BUILD_TYPE=$(BUILD_TYPE) BUILD_DIR=$(BUILD_DIR) ARCH=$$arch ZKSU_VERSION=$(ZKSU_VERSION) arch; \
	done

	@mkdir -p $(OBJ_ROOT)
	@touch $(OBJ_ROOT)/.done

arch: $(LIBZYGISK_STRIPPED) $(LIBPTRACE_STRIPPED)

clean:
	rm -rf $(BUILD_DIR)/obj/$(BUILD_TYPE)/loader
	rm -rf $(BUILD_DIR)/obj/$(BUILD_TYPE)/plti
	rm -rf $(BUILD_DIR)/obj/$(BUILD_TYPE)/csoloader
	rm -rf $(BUILD_DIR)/obj/$(BUILD_TYPE)/dobby

$(PLTI_LIB):
	@mkdir -p $(dir $@)
	$(MAKE) -C $(PLTI_DIR) BUILD_TYPE=$(BUILD_TYPE) ARCH=$(ARCH) \
		NDK_PATH=$(NDK_PATH) API_LEVEL=$(API_LEVEL)              \
		out=$(BUILD_DIR)/obj/$(BUILD_TYPE)/plti/$(ARCH)

$(CSOLOADER_LIB):
	@mkdir -p $(dir $@)
	$(MAKE) -C $(CSOLOADER_DIR) BUILD_TYPE=$(BUILD_TYPE) ARCH=$(ARCH) \
		NDK_PATH=$(NDK_PATH) API_LEVEL=$(API_LEVEL)                   \
		out=$(BUILD_DIR)/obj/$(BUILD_TYPE)/csoloader/$(ARCH)

$(DOBBY_OBJ_DIR)/%.c.o: $(DOBBY_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(NDK_CFLAGS) -D_GNU_SOURCE -std=c11 -fno-stack-protector  \
		-fomit-frame-pointer -Wno-unused -Wno-unused-parameter -DNDEBUG   \
		$(DOBBY_INCLUDES) -fPIC -c $< -o $@

$(DOBBY_OBJ_DIR)/%.cc.o: $(DOBBY_DIR)/%.cc
	@mkdir -p $(dir $@)
	$(CXX_ARCH) $(NDK_CFLAGS) $(DOBBY_CXXFLAGS) $(TYPE_CFLAGS) \
		$(DOBBY_INCLUDES) -fPIC -c $< -o $@

$(DOBBY_OBJ_DIR)/%.cpp.o: $(DOBBY_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX_ARCH) $(NDK_CFLAGS) $(DOBBY_CXXFLAGS) $(TYPE_CFLAGS) \
		$(DOBBY_INCLUDES) -fPIC -c $< -o $@

$(DOBBY_LIB): $(DOBBY_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(OBJ_DIR)/common/%.o: src/common/%.c
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(NDK_CFLAGS) $(LOADER_CFLAGS) $(TYPE_CFLAGS) \
		$(COMMON_INCLUDES) -fPIC -c $< -o $@

$(OBJ_DIR)/injector/%.o: src/injector/%.c
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(NDK_CFLAGS) $(LOADER_CFLAGS) $(TYPE_CFLAGS) \
		$(INJECTOR_INCLUDES) -Dzygisk_EXPORTS -fPIC -c $< -o $@

$(OBJ_DIR)/ptracer/%.o: src/ptracer/%.c
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(NDK_CFLAGS) $(LOADER_CFLAGS) $(TYPE_CFLAGS) \
		$(COMMON_INCLUDES) -fPIE -c $< -o $@

$(LIBCOMMON): $(COMMON_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(LIBZYGISK): $(INJECTOR_OBJS) $(LIBCOMMON) $(PLTI_LIB) $(CSOLOADER_LIB) $(DOBBY_LIB)
	@mkdir -p $(dir $@)
	$(CXX_ARCH) -fPIC -shared -Wl,-soname,libzygisk.so                    \
		$(COMMON_LDFLAGS) $(TYPE_LDFLAGS) -nostartfiles                   \
		$(INJECTOR_OBJS) $(LIBCOMMON) $(PLTI_LIB) $(CSOLOADER_LIB)        \
		$(DOBBY_LIB) -llog -lm -o $@

$(LIBPTRACE): $(PTRACER_OBJS) $(LIBCOMMON)
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(COMMON_LDFLAGS) $(TYPE_LDFLAGS) \
		$(PTRACER_OBJS) $(LIBCOMMON) -llog -lm -o $@

$(LIBZYGISK_STRIPPED): $(LIBZYGISK)
	@mkdir -p $(dir $@)
	cp $< $@
	$(STRIP) --strip-all $@

$(LIBPTRACE_STRIPPED): $(LIBPTRACE)
	@mkdir -p $(dir $@)
	cp $< $@
	$(STRIP) --strip-all $@
