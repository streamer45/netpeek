dist/netpeek:
	mkdir -p dist/
	go build -o dist/netpeek ./...

clean:
	rm -f netpeek

.PHONY: lint
lint: 
	@if ! [ -x "$$(command -v golangci-lint)" ]; then \
		echo "golangci-lint is not installed. Please see https://github.com/golangci/golangci-lint#install for installation instructions."; \
		exit 1; \
	fi; \

	@echo Running golangci-lint
	golangci-lint run ./...
