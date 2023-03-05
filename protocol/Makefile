# Code generation

.PHONY: proto-gen
proto-gen:
	mkdir -p generated/v1
	protoc -I=proto/v1/ --go_out=generated/ proto/v1/*

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
