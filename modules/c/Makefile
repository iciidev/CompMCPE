# Compiler settings
CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -ljansson

# Output directory
BUILD_DIR = build

# Source files
SOURCES = recon.c vuln.c
TARGETS = $(SOURCES:%.c=$(BUILD_DIR)/%)

# Default target
all: $(BUILD_DIR) $(TARGETS)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build targets
$(BUILD_DIR)/%: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
