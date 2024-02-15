.PHONY: all fmt tidy lint test
all: fmt tidy lint test

fmt:
	go fmt ./...

tidy:
	go mod tidy -v

lint:
	golangci-lint run

test:
	go clean -testcache
	go test -v ./...

