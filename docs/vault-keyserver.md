# Securing TCS signer key using HashiCorp Vault KMIP secrets manager

## Introduction

This document describes how to use [HashCorp Vault](https://www.vaultproject.io/)
as a key server for provisioning the [TCS](https://github.com/intel/trusted-certificate-issuer)
issuer's signing key securely using the trusted-attestation-controller (TAC).

## Prerequisites

- Kubernetes cluster
- [Trusted-certificate-issuer](https://github.com/intel/trusted-certificate-issuer)
- [Trusted-attestation-controller with iSecL plugin](../plugins/isecl/README.md)
- [Intel Secure Libraries v4.2.0-Beta](https://github.com/intel-secl/intel-secl/tree/v4.2.0-Beta):
  - Key Broker Service (KBS)
  - Certificate Manager Service (CMS)
  - Authentication Service (AAS)
  - SGX Quote Verification Service (SQVS)
- [HashCorp Vault Enterprise v1.13.0](https://developer.hashicorp.com/vault/docs/release-notes/1.13.0)
- Yaml processor tool such as ['yq'](https://github.com/mikefarah/yq)

## Setup Vault secrets engine

The Vault key server shall be installed and configured to act as backend KMIP key
server for the iSecL key broker service (KBS) for storing and retrieving the signing keys.
The Vault server must be accessible from the machine where the KBS is running.

The Key Management Interoperability Protocol (KMIP) secrets engine requires
[Vault Enterprise Advanced Data Protection (ADP)](https://www.hashicorp.com/products/vault/pricing/)
license.

- Download and install Vault enterprise version 1.13.0

```sh
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault
```
The above instructions are to install Vault on Ubuntu/Debian OS. Follow the [Vault documentation](https://developer.hashicorp.com/vault/downloads) for details to install on a different operating system.

- Enable the Vault KMIP secrets engine
```sh
vault secrets enable kmip
vault write kmip/config listen_addrs=0.0.0.0:5696
```

- Create a scope and roles
In order to generate client certificates for KBS to interact with Vault's KMIP
server, we must first create a scope and role and specify the desired set of
allowed operations for it.
```sh
# Create a scope for TCS
vault write -f kmip/scope/tcs
# Create a admin role with in the scope with all KMIP operations
vault write kmip/scope/tcs/role/admin operation_all=true
```
- Generate client certificates

Generate client certificates for the `tcs` role with the `admin` scope we prepared
in the previous step:
```sh
# Generate the client credentials
vault write -f kmip/scope/tcs/role/admin/credential/generate --format=yaml format=pem > credential.yaml
# Extract the private key and certificates to files
sudo mkdir -p /opt/kbs/kmip-certs
yq '.data.certificate' credential.yaml | sudo tee /opt/kbs/kmip-certs/cert.pem
yq '.data.private_key' credential.yaml | sudo tee /opt/kbs/kmip-certs/key.pem
yq '.data.ca_chain' credential.yaml | grep -v '^-' | sudo tee /opt/kbs/kmip-certs/ca.pem
```

## Setup iSecL Key Broker Service

Modify the installed KBS configuration (/etc/kbs/config.yml) with the Vault
KMIP server information as below:

```sh
# Vault KMIP implementation supports 1.4 specification
sudo yq -i '.kmip.version |= "1.4"' /etc/kbs/config.yml
# Port number used while setting the Vault KMIP server
sudo yq -i '.kmip.server-port |= "5696"' /etc/kbs/config.yml
# Hostname or IP address where the the Vault key server is 
sudo yq -i '.kmip.server |= "'$VAULT_SERVER_HOST'"' /etc/kbs/config.yml
# Set the client TLS certificate details generated above
sudo yq -i '.kmip.client-key-path |= "/opt/kbs/kmip-certs/key.pem"' /etc/kbs/config.yml
sudo yq -i '.kmip.client-cert-path |= "/opt/kbs/kmip-certs/cert.pem"' /etc/kbs/config.yml
sudo yq -i '.kmip.root-cert-path |= "/opt/kbs/kmip-certs/ca.pem"' /etc/kbs/config.yml
# restart KBS
sudo systemctl restart kbs
```

## Usage

### Create a new signing key


Below steps create a new RSA key pair in the Vault KMIP server using
KBS API. The key is supposed to be used as toot signing key by the TCS
cluster issuer named `sgx-ca`:

```sh
export TCS_ISSUER=tcsclusterissuer.tcs.intel.com/sgx-ca
export TAC_TOKEN=$(curl --noproxy "*" -k -X POST https://$AAS_HOST:8444/aas/v1/token -d '{"username": "'$TAC_USERNAME'", "password": "'$TAC_PASSWORD'"}')

# Create a RSA key pair in the key server 
cat > key-info.json << EOF
{
    "key_information":{
        "algorithm":"RSA",
        "key_length":3072
    },
    "label": "$TCS_ISSUER"
}
EOF
curl --noproxy "*" -k -X POST https://$KBS_HOST:9443/kbs/v1/keys \
    -H "Accept: application/json" -H "Content-Type: application/json" -H "Authorization: Bearer $TAC_TOKEN" \
    -d "@./key-info.json"
```

### Create a new TCS issuer whose key should be provisioned

Create a `TCSClusterIssuer` named `sgx-ca` by setting `selfSigned` to `false`.
This initiates a `QuoteAttestation` request by the TCI (trusted-certificate-issuer).
The request is handled by the TAC (trusted-attestation-controller) for validating the
provided SGX quote and fetching the signing key stored at the KBS/Vault KMIP server.

```sh
cat <<EOF |kubectl create -f -
apiVersion: tcs.intel.com/v1alpha1
kind: TCSClusterIssuer
metadata:
    name: sgx-ca
spec:
    secretName: my-ca-cert
    selfSign: false
EOF
# Check the issuer if it is ready
kubectl get tcsclusterissuer sgx-ca
```