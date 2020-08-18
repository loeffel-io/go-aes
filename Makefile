install:
	go get

test-coverage:
	go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...

test-coverage-report:
	go test -v -race -coverprofile=coverage.out ./... && go tool cover -html=coverage.out

linter:
	golangci-lint run

test:
	make test-coverage
	make linter