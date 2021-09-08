CROSS_DLL ?= 0
TARGET = libsecp256k1
ifeq ($(CROSS_DLL),1)
PLATFORM = windows
ARCH = amd64
else ifeq ($(OS),Windows_NT)
PLATFORM = windows
ARCH = amd64
else
PLATFORM = $(shell uname -s | tr A-Z a-z)
ARCH = $(shell uname -m)
endif

# Paths
LIB_DIR = secp256k1-zkp
BUILD_DIR = build

# Tools
ifeq ($(PLATFORM),windows)
TOOLCHAIN_PREFIX ?= x86_64-w64-mingw32-
else
TOOLCHAIN_PREFIX ?= 
endif

CC := $(TOOLCHAIN_PREFIX)gcc
ifeq ($(OS),Windows_NT)
MKDIR_P = mkdir
RM_R = rmdir /s /q
else
MKDIR_P = mkdir -p
RM_R = rm -r
endif

# C sources
C_SOURCES = $(addprefix $(LIB_DIR)/src/,\
	secp256k1.c \
	)

# C includes
C_INCLUDES =  \
	$(LIB_DIR) \
	$(LIB_DIR)/src \
	config

# C defines
C_DEFS =  \
	HAVE_CONFIG_H

ifeq ($(PLATFORM),windows)
C_DEFS += _WIN32
endif

OBJS := $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))

DEPS := $(OBJS:.o=.d)

ifeq ($(PLATFORM),windows)
CFLAGS = -O2 -std=c99 -MMD -MP -Werror -Wno-unused-function \
	$(addprefix -I,$(C_INCLUDES)) $(addprefix -D,$(C_DEFS))
else
CFLAGS = -fPIC -O2 -Werror -Wno-unused-function \
	$(addprefix -I,$(C_INCLUDES)) $(addprefix -D,$(C_DEFS))
endif

ifeq ($(PLATFORM),windows)
LDFLAGS = -shared -s \
	-Wl,--subsystem,windows,--out-implib,$(BUILD_DIR)/$(TARGET).a
EXT = .dll
else ifeq ($(PLATFORM),darwin)
LDFLAGS = -dynamiclib
EXT = .dylib
else
LDFLAGS = -shared
EXT = .so
endif

$(BUILD_DIR)/$(TARGET)_$(PLATFORM)_$(ARCH)$(EXT): $(OBJS) Makefile
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c Makefile
	$(MKDIR_P) "$(dir $@)"
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean

clean:
	$(RM_R) "$(BUILD_DIR)"

-include $(DEPS)
