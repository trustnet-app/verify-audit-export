GO ?= go

.PHONY: all build test vet fmt check clean

all: check

build:
	$(GO) build ./cmd/trustnet-verify

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l .

check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt'd:"; echo "$$unformatted"; exit 1; \
	fi
	$(GO) vet ./...
	$(GO) test -race ./...
	$(GO) build ./cmd/trustnet-verify

clean:
	rm -f trustnet-verify
