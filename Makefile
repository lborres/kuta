.PHONY: test test-verbose test-coverage test-race test-integration clean

# Run all tests
test:
	go test ./...

# Run tests with verbose output
test-verbose:
	go test -v ./...

# Run tests with coverage report
test-coverage:
	go test -v -cover ./...

# Run tests with detailed coverage
test-coverage-detail:
	go test -coverprofile=.tmp/coverage.out ./...
	go tool cover -func=.tmp/coverage.out

# Run tests with coverage HTML report
test-coverage-html:
	go test -coverprofile=.tmp/coverage.out ./...
	go tool cover -html=.tmp/coverage.out

# Run tests with race detector
test-race:
	go test -v -race ./...

# Run all quality checks (recommended before commit)
test-all: test-race test-coverage

test-integration:
	go test ./... -v -tags=integration

# Clean test cache and coverage files
clean:
	go clean -testcache
	rm -f coverage.out

# Help command
help:
	@echo "Available commands:"
	@echo "  make test                 - Run all tests"
	@echo "  make test-verbose         - Run tests with verbose output"
	@echo "  make test-coverage        - Run tests with coverage report"
	@echo "  make test-coverage-detail - Detailed coverage by function"
	@echo "  make test-coverage-html   - Open coverage in browser"
	@echo "  make test-race            - Run tests with race detector"
	@echo "  make test-all             - Run all quality checks"
	@echo "  make clean                - Clean test cache and coverage files"
