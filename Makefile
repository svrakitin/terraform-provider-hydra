default: build

.PHONY: build
build:
	go install

.PHONY: test
test:
	go test ./... -timeout=120s -parallel=4

.PHONY: testacc
testacc:
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m

.PHONY: lint
lint:
	golangci-lint run
