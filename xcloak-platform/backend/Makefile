.PHONY: test test-unit test-integration swagger lint build

## Run unit tests (no DB required)
test-unit:
	go test ./... -count=1 -timeout 60s

## Run all tests including integration (requires docker-compose.test.yml)
test-integration:
	../scripts/test-integration.sh

## Alias: unit tests
test: test-unit

## Generate OpenAPI docs from swag annotations.
## Requires: go install github.com/swaggo/swag/cmd/swag@latest
swagger:
	swag init \
		--generalInfo docs/swagger.go \
		--dir . \
		--output docs/generated \
		--parseDependency \
		--parseInternal

## Build the backend binary
build:
	go build -o bin/xcloak-api ./

## Vet + staticcheck
lint:
	go vet ./...
	@which staticcheck >/dev/null 2>&1 && staticcheck ./... || true
