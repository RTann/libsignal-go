BASE_DIR := ..

# Code generation

include ../make/proto.mk

.PHONY: proto-gen
proto-gen: $(PROTOC)
	mkdir -p generated/v1
	$(PROTOC) -I=proto/v1/ --go_out=generated/ proto/v1/*

.PHONY: go-gen
go-gen:
	go generate ./...

# Tests

.PHONY: unit-tests
unit-tests: proto-gen
	go test -race -v ./...

# Style

.PHONY: style
style:
	go fmt ./...
