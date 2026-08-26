# Makefile — codegen, build, and demo targets for fqdn-network-policy.
#
# The long-term fix for hand-maintaining zz_generated.deepcopy.go is here:
# `make generate` regenerates it from the +kubebuilder markers already in
# api/v1alpha1/fqdnnetworkpolicy_types.go. `make manifests` regenerates the
# CRD YAML the same way, so config/crd/bases stops being hand-written too.

SHELL := /usr/bin/env bash

# ---- Tool versions (pinned; bump deliberately, not accidentally) ----------
CONTROLLER_GEN_VERSION ?= v0.14.0

# ---- Paths ------------------------------------------------------------
LOCALBIN ?= $(shell pwd)/bin
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen

# ---- Image ------------------------------------------------------------
IMG ?= fqdn-network-policy:demo

.PHONY: all
all: generate manifests build

## ---- Codegen -----------------------------------------------------------

.PHONY: controller-gen
controller-gen: $(LOCALBIN) ## Download controller-gen locally if not present, pinned to CONTROLLER_GEN_VERSION.
	@test -s $(CONTROLLER_GEN) && $(CONTROLLER_GEN) --version | grep -q $(CONTROLLER_GEN_VERSION) || \
		GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

.PHONY: generate
generate: controller-gen ## Regenerate zz_generated.deepcopy.go from +kubebuilder markers.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./api/..."

.PHONY: manifests
manifests: controller-gen ## Regenerate CRD YAML and RBAC from +kubebuilder markers.
	$(CONTROLLER_GEN) crd paths="./api/..." output:crd:artifacts:config=config/crd/bases
	$(CONTROLLER_GEN) rbac:roleName=fqdn-network-policy-controller paths="./internal/..." output:rbac:artifacts:config=config/rbac

## ---- Build --------------------------------------------------------------

.PHONY: build
build: generate ## Build the manager binary.
	go build -o bin/manager ./cmd

.PHONY: test
test: generate ## Run unit tests.
	go test ./... -v

.PHONY: docker-build
docker-build: generate manifests ## Build the controller image.
	docker build -t $(IMG) .

## ---- Demo -----------------------------------------------------------

.PHONY: demo
demo: docker-build ## Run the full kind+Calico demo end to end.
	./demo.sh

.PHONY: demo-clean
demo-clean: ## Tear down the demo kind cluster.
	kind delete cluster --name fqdn-demo

## ---- Housekeeping ---------------------------------------------------

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: help
help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'
