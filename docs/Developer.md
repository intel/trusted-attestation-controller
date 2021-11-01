<!-- Table of contents is auto generated using 
[Auto Markdown TOC](https://marketplace.visualstudio.com/items?itemName=huntertran.auto-markdown-toc) extension -->
<!-- TOC depthfrom:2 depthto:3 -->

- [Overview](#overview)
- [Attestation API](#attestation-api)
    - [Registry service](#registry-service)
    - [Plugin service](#plugin-service)
- [Plugin deployment](#plugin-deployment)

<!-- /TOC -->
## Overview

The Trusted Attestation Controller provides a gRPC based API for integrating the external key management servers to the [Trusted Certificate Service (TCS)](https://github.com/intel/trusted-certificate-issuer). The key server is expected to run outside to the cluster and the plugin should access the server securely. This document covers a brief about API and deploy the plugins.

## Attestation API

There two parts of the API, the `Registry` and the `Plugin` service. The `Registry` service is exposed by the attestation controller on an UNIX domain socket. The plugins must expose the `Plugin` service over the UNIX domain socket and register themselves using the API call(s) provided by the `Registry` service. The controller forwards the attestation requests to the appropriate plugin over the socket that was registered with it. 

### Registry service

The `Registry` service offered by the controller. The plugin can use `Registry.RegisterPlugin()` method to register the with its details such as, plugin name and socket address to use to communicate with the plugin.

```protobuf
service Registry {
    rpc RegisterPlugin (RegisterPluginRequest) returns (RegisterKeyServerReply) {}
} 

message RegisterPluginRequest{
    // Name of the plugin
    string name = 1;
    // Plugin socket address to register; where it offers Plugin functionality
    // at this socket.
    string address = 2;
}
```

### Plugin service

The `Plugin` service API allows to write out-of-tree attestation plugins. Each plugin has to implement the API defined in the`Plugin` service which consists of two methods, `ValidateQuote` and `GetCAKeyAndCertificate`. These methods are used by the attestation controller to validate the SGX quote provided by the TCS and provision the secrets securely. 

```protobuf
service Plugin {
    // ValidateQuote validates the given SGX quote
    rpc ValidateQuote(ValidateQuoteRequest) returns (ValidateQuoteReply) {}
    // GetCAKeyCertificate retrieves the stored CA key and certificate at the key-manager
	// for given signer signerName.
	// On success, returns the key and certificate. 
	// Otherwise, appropriate error gets returned.
    rpc GetCAKeyAndCertificate(GetCAKeyAndCertificateRequest) returns (GetCAKeyAndCertificateReply) {}
}
```
- `ValidateQuote` 

The plugin must implement this RPC all. This RPC is called by the attestation controller to validate the SGX enclave quote provided by the TCS. The key server has to validate the provided SGX enclave `quote` using the Intel(R) SGX ECDSA Quote Verification Library. The server also should validate if the SHA256 hash of the provided `publicKey` matches with the hash embedded in the `quote`. The plugin shall return the results of the quote validation with appropriate message in case of failure.

```protobuf
message ValidateQuoteRequest {
    // CA signer name
    string signerName = 1;
    // base64 encoded public key used for generating the quote
    bytes publicKey = 2;
    // base64 encoded SGX Quote
    bytes quote = 3;
}

message ValidateQuoteReply {
    bool result = 1;
    // Failure message in case of provided quote is invalid
    string message = 2;
}

```

- `GetCAKeyAndCertificateRequest`

The plugin must implement this RPC all. This RPC is called by the attestation controller to provision th CA secrets securely on behalf of the TCS. The key server has to validate the provided SGX enclave `quote` using the Intel(R) SGX ECDSA Quote Verification Library. Only if the provided quote is valid the server shall share the CA secret for the given `signerName`. The secret must be wrap<sup>[1]</sup> the CA private key using provided `publicKey`in the request.

<sup>>1</sup> 


```protobuf
message GetCAKeyAndCertificateRequest {
    // CA signer name
    string signerName = 1;
    // base64 encoded public key used for generating the quote
    bytes publicKey = 2;
    // base64 encoded SGX Quote
    bytes quote = 3;
}

message GetCAKeyAndCertificateReply {
    // The CA private key(PWK) is wrapped with a symmetric key(SWK)
    // that was wrapped with the given publicKey. Both the SWK and
    // PWK are concatenated and returned as single base64 encoded block. 
    bytes wrappedKey = 1;
    // base64 encoded PEM certificate
    bytes certificate = 2;
}
```

## Plugin deployment

The plugin must run in its own container image in the same pod beside the controller. And both the controller and the plugin communicates over the UNIX domain sockets. Define the Kubernetes YAML such that deploys plugin as a sidecar to the controller.

Below is an example plugin deployment:
```yaml
...
spec:
    containers:
    ...
    - name: manager
        command:
        - /manager
        args:
        - --leader-elect
        - --registration-path=/registration/controller.sock
        ....
        volumeMounts:
        - name: my-plugin-socket-dir
          mountPath: /my-plugin
        - name: registry-socket-dir
          mountPath: /registration
      - name: my-plugin
        command:
        - /my-plugin
        args:
        # plugin name
        - --plugin-name=my-plugin
        # Plugin socket path to be registered by the plugin with the controller
        - --plugin-socket-path=/my-plugin/socket.sock
        # Controller's registry service socket path
        - --registry-socket-path=/registration/controller.sock
        # Plugin container image
        image: custom-plugin:latest
        volumeMounts:
        - name: my-plugin-socket-dir
          mountPath: /my-plugin
        # mount the registration socket directory to access the registration API
        - name: registry-socket-dir
          mountPath: /registration
    ...
    - volumes:
      # Location of the socket where to plugin exposes its service
      # and registers with the controller
      - name: my-plugin-socket-dir
        hostPath:
          path: /var/lib/trusted-attestation-controller/plugins/my-plugin
          type: DirectoryOrCreate
      # Location of the socket where to controller exposes its registry service
      # for the plugins
      - name: registry-socket-dir
        hostPath:
          path: /var/lib/trusted-attestation-controller/registry/
          type: DirectoryOrCreate
          
```

