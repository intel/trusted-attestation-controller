# trusted-attestation-controller
<!-- Table of contents is auto generated using 
[Auto Markdown TOC](https://marketplace.visualstudio.com/items?itemName=huntertran.auto-markdown-toc) extension -->
<!-- TOC depthfrom:2 depthto:3 -->

- [Overview](#overview)
- [Getting started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installing with source code](#installing-with-source-code)
    - [Provision TCS issuer root certificate and private key](#provision-tcs-issuer-root-certificate-and-private-key)
- [Attestation Plugins](#attestation-plugins)
- [Limitations](#limitations)

<!-- /TOC -->

## Overview

The Trusted Attestation Controller is a Kubernetes controller for reconciling the [QuoteAttestation](https://github.com/intel/trusted-certificate-issuer/blob/main/api/v1alpha1/quoteattestation_types.go) requests initiated by the [Trusted Certificate Service (TCS)](https://github.com/intel/trusted-certificate-issuer). It mediates between the TCS and the key server(s) which supports attestation services. The key servers could plugin to the controller by implementing the API provided by the controller.

## Getting started

This section covers how to getting started with the Trusted Attestation Controller. That includes how to build and deploy the controller to a Kubernetes cluster.

### Prerequisites

Prerequisites for building and running Trusted Attestation Controller:

- Kubernetes cluster with running [Trusted Certificate Service](https://github.com/intel/trusted-certificate-issuer)
- [Key Management Reference Application (KMRA) AppHSM Server](https://01.org/key-management-reference-application-kmra)
- git, or similar tool, to obtain the source code
- Docker, or similar tool, to build container images
- Container registry ([local](https://docs.docker.com/registry/deploying/) or remote)

### Installing with source code

This section covers how to obtain the source code, build and install it.

1. Getting the source code

```sh
git clone https://github.com/intel/trusted-attestation-controller.git
```
2. Build and push the container image

Choose a container registry to push the generated image using `REGISTRY` make variable.
The registry should be reachable from the Kubernetes cluster.

```sh
$ cd trusted-attestation-controller
$ export REGISTRY="localhost:5000" # docker registry to push the container image
$ make docker-build docker-push
```

3. Deploy QuoteAttestation CRD

```sh
# set the KUBECONFIG based on your configuration
export KUBECONFIG="$HOME/.kube/config"
kubectl apply -f https://raw.githubusercontent.com/intel/trusted-certificate-issuer/main/deployment/crds/quoteattestations.tcs.intel.com.yaml
```

4. Setup a key server

[Download the KMRA v2.0](https://01.org/key-management-reference-application-kmra/downloads/key-management-reference-application-kmra-v2.0) source code and refer to its instructions
for setting up the key server on a host that is securely accessible from your Kubernetes cluster.

4. Configure the key server url and credentials

```sh
export SERVER_URL=<<https://server-address:port>>
sed -ie "s;^KEY_SERVER=\(.*\);$SERVER_URL;g" ./config/manager/.kmra-server.conf
sed -e "s;^\(ca.crt=\).*;\1$(base64 -w 0 /ca/certificate/file);g" \
     -e "s;^\(client.crt=\).*;\1$(base64 -w 0 /client/certificate/file);g" \
     -e "s;^\(client.key=\).*;\1$(base64 -w 0 /client/privatekey/file);g" ./config/manager/.ca.secrets
```

5. Deploy the controller

```sh
make deploy
```

### Provision TCS issuer root certificate and private key

Once the deployment is up and running, it is ready to accept `QuoteAttestation` custom resources.

Create a `TCSIssuer` with `spec.selfSign` set to `false`. This results in a `QuoteAttestation` object
gets created by the TCS with its SGX enclave quote and a public key. 

```sh
kubectl create ns sandbox
cat <<EOF |kubectl create -f -
apiVersion: tcs.intel.com/v1alpha1
kind: TCSIssuer
metadata:
    name: my-ca
    namespace: sandbox
spec:
    secretName: my-ca-cert
    selfSign: false
EOF

kubectl get quoteattestation,tcsissuer -n sandbox
NAME                                                           AGE
quoteattestation.tcs.intel.com/my-ca.tcsissuer.tcs.intel.com   0s

NAME                            AGE   READY   REASON      MESSAGE
tcsissuer.tcs.intel.com/my-ca   10s   False   Reconcile   Signer is not ready
```

And, the Trusted Attestation Controller reconciles this request and forwards the attestation request to the
configured key server plugin, in this case the KMRA. The server validates the provided SGX quote. Only
if the validation success, the controller requests the server to fetch the encrypted CA private key 
and certificate and it updates the `QuoteAttestation` object status with the results. Then the TCS
enclave decrypts the key, and TCS deletes the `QuoteAttestation` object silently.

```sh
kubectl get quoteattestation,tcsissuer -n sandbox
NAME                            AGE   READY   REASON      MESSAGE
tcsissuer.tcs.intel.com/my-ca   1m    True    Reconcile   Success
```

## Attestation Plugins 

To integrate the external key management servers with TCS, the attestation controller provides
a GRPC based plugin API. Refer to [developer documentation](docs/Developer.md#overview) for writing
attestation plugins.

## Limitations

- This version of the software is pre-production release and is meant for evaluation and trial purposes only.