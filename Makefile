default: build

.PHONY: build
build:
	go install

.PHONY: test
test:
	go test ./... -timeout=60s -parallel=4

.PHONY: testacc
testacc:
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 5m

.PHONY: lint
lint:
	golangci-lint run
