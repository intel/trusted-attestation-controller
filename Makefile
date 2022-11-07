REGISTRY ?= docker.io
IMG_NAME ?= intel/trusted-attestation-controller
IMG_TAG ?= latest
# Image URL to use all building/pushing image targets
IMG ?= $(REGISTRY)/$(IMG_NAME):$(IMG_TAG)
# List of in-tree plugins
PLUGINS ?= kmra isecl null

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

all: build $(PLUGINS)

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

manifests: vendor controller-gen ## Generate ClusterRole objects.
	$(CONTROLLER_GEN) rbac:roleName=role webhook paths="./..."

generate: vendor controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

 # latest protoc releae as of 03.03.2020
PROTOC_VERSION=3.19.4
generate-proto: bin/protoc-v${PROTOC_VERSION}
	$< --go_out=plugins=grpc,paths=source_relative:. ./pkg/api/v1alpha1/pluginapi.proto

bin/protoc-v${PROTOC_VERSION}: bin/protoc-${PROTOC_VERSION}-linux-x86_64.zip
	unzip -p $< bin/protoc > $@ && chmod +x $@

bin/protoc-${PROTOC_VERSION}-linux-x86_64.zip:
	wget https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip -P bin/

vendor:
	go mod tidy
	go mod vendor

fmt: ## Run go fmt against code.
	go fmt ./...

vet: ## Run go vet against code.
	go vet ./...

ENVTEST_ASSETS_DIR=$(shell pwd)/testbin
test: manifests generate fmt vet ## Run tests.
	mkdir -p ${ENVTEST_ASSETS_DIR}
	test -f ${ENVTEST_ASSETS_DIR}/setup-envtest.sh || curl -sSLo ${ENVTEST_ASSETS_DIR}/setup-envtest.sh https://raw.githubusercontent.com/kubernetes-sigs/controller-runtime/v0.8.3/hack/setup-envtest.sh
	source ${ENVTEST_ASSETS_DIR}/setup-envtest.sh; fetch_envtest_tools $(ENVTEST_ASSETS_DIR); setup_envtest_env $(ENVTEST_ASSETS_DIR); go test ./... -coverprofile cover.out

##@ Build

build: vendor generate fmt vet ## Build manager binary.
	go build -o bin/manager main.go

$(PLUGINS): generate-proto fmt vet ## Build plugin binaries.
	go build -o bin/$@-plugin ./plugins/$@/main.go


# additional arguments to pass to 'docker build'
DOCKER_BUILD_ARGS ?=
docker-build: test ## Build docker image with the manager.
	@docker build ${DOCKER_BUILD_ARGS} -t ${IMG} -f Dockerfile .

docker-push: ## Push docker image with the manager.
	docker push ${IMG}

##@ Deployment

## Deploy controller to the K8s cluster specified in ~/.kube/config.
## If provided OUTFILE instead it writes the deployment to the given
## file.
deploy-%: kustomize ./config/plugins/%
	$(eval TMP := $(shell mktemp -d -p ./config/))
	echo -e "bases:\n- ../plugins/$*" > $(TMP)/kustomization.yaml
	@cd $(TMP) && $(KUSTOMIZE) edit set image controller=${IMG} $*-plugin=${IMG}
ifneq ("$(OUTFILE)", "")
	$(KUSTOMIZE) build $(TMP) -o $(OUTFILE)
else
	$(KUSTOMIZE) build $(TMP) | kubectl apply -f -
endif
	rm -rf $(TMP)

undeploy-%: #ensure-plugin ## Undeploy controller from the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/plugins/$* | kubectl delete -f -

deploy-manifest-%: kustomize
	@echo "Generating manifest for plugin: $*"
	mkdir -p deployment
	$(MAKE) deploy-$* OUTFILE=deployment/tac-with-$*.yaml

deploy-manifests: $(patsubst %, deploy-manifest-%, $(PLUGINS))
	@echo "Complete!"


VERSION=
release-branch:
ifeq ("$(VERSION)", "")
	$(error "Set release version using VERSION make variable. Example: `make release VERSION=0.1.0` ")
endif
	./hack/prepare-release-branch.sh --version $(VERSION)

CONTROLLER_GEN = $(shell pwd)/bin/controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-get-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.8.0)

KUSTOMIZE = $(shell pwd)/bin/kustomize
kustomize: ## Download kustomize locally if necessary.
	$(call go-get-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v4@v4.5.4)

# go-get-tool will 'go get' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-get-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(PROJECT_DIR)/bin go install $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef

.PHONY : .deploy
