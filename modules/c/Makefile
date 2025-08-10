# Compiler settings
CC_LINUX = gcc
CC_WINDOWS = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -O2
LDFLAGS = -ljansson

# Output directories
BUILD_DIR = build
LINUX_DIR = $(BUILD_DIR)/linux
WINDOWS_DIR = $(BUILD_DIR)/windows

# Source files
SOURCES = recon.c
TARGETS_LINUX = $(SOURCES:%.c=$(LINUX_DIR)/%)
TARGETS_WINDOWS = $(SOURCES:%.c=$(WINDOWS_DIR)/%.exe)

# Default target
all: linux windows

# Create build directories
$(BUILD_DIR):
	mkdir -p $(LINUX_DIR) $(WINDOWS_DIR)

# Linux builds
linux: $(BUILD_DIR) $(TARGETS_LINUX)

$(LINUX_DIR)/%: %.c
	$(CC_LINUX) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Windows builds
windows: $(BUILD_DIR) $(TARGETS_WINDOWS)

$(WINDOWS_DIR)/%.exe: %.c
	$(CC_WINDOWS) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all linux windows clean
