.PHONY: build test testacc fmt

build:
	go build -o terraform-provider-openwarp .

test:
	go test ./...

# Requires OPENWARP_HOST, OPENWARP_TOKEN and OPENWARP_TEST_ORG_ID plus a
# terraform binary on PATH.
testacc:
	TF_ACC=1 go test ./internal/provider -v -timeout 20m

fmt:
	gofmt -w .
