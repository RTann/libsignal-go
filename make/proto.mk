BASE_DIR ?= $(CURDIR)

# Protocol Buffers

PROTOC_VERSION := 22.2
PROTOC_DIR := $(BASE_DIR)/bin

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
PROTOC_OS = linux
endif
ifeq ($(UNAME_S),Darwin)
PROTOC_OS = osx
endif
PROTOC_ARCH=$(shell case $$(uname -m) in (arm64) echo aarch_64 ;; (*) uname -m ;; esac)

DOWNLOAD_DIR := $(PROTOC_DIR)/.downloads
$(DOWNLOAD_DIR):
	mkdir -p "$@"

PROTOC_ZIP := protoc-$(PROTOC_VERSION)-$(PROTOC_OS)-$(PROTOC_ARCH).zip
PROTOC_FILE := $(DOWNLOAD_DIR)/$(PROTOC_ZIP)

.PRECIOUS: $(PROTOC_FILE)
$(PROTOC_FILE): $(DOWNLOAD_DIR)
	curl --output-dir $(DOWNLOAD_DIR) -LO "https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/$(PROTOC_ZIP)"

PROTOC := $(PROTOC_DIR)/bin/protoc

$(PROTOC): $(PROTOC_FILE)
	@mkdir -p "$(PROTOC_DIR)"
	@unzip -q -o -d "$(PROTOC_DIR)" "$(PROTOC_FILE)"
	@test -x "$@"
	@rm -rf $(DOWNLOAD_DIR)

.PHONY: protoc-install
protoc-install: $(PROTOC)
