# iSecL 

## Overview

[Intel® SecL-DC](https://intel-secl.github.io/docs/4.2/) is an open-source
remote attestation implementation comprising of a set of building blocks
that utilize Intel Security features to discover, attest, and enable critical
foundation security and confidential computing use-cases. It applies the 
remote attestation fundamentals and standard specifications to maintain a 
platform data collection service and an efficient verification engine to
perform comprehensive trust evaluations.

This plugin uses Intel(R) SecL Key Broker Service (KBS) to securely transfer CA
private keys to the [trusted-certificate-issuer (TCI)](https://github.com/intel/trusted-certificate-issuer) SGX Enclave from a KMIP-compliant key management server such as [HashiCorp Vault secrets engine](https://www.vaultproject.io/docs/secrets/kmip).

## Setup

### Install iSecL components

Below are the minimum required Intel(R) SecL-DC components that are supposed to
deploy in a tenant's enterprise environment and shall be accessible from the
Kubernetes cluster where the `trusted-attestation-controller (TAC)` with iSecL
plugin is running in a CSP environment:

* Certificate Management Server ([CMS](https://github.com/intel-secl/intel-secl/tree/v4.2.0-Beta/pkg/cms))
* Authentication and Authorization Service ([AAS](https://github.com/intel-secl/intel-secl/tree/v4.2.0-Beta/pkg/aas))
* Key Broker Service ([KBS](https://github.com/intel-secl/intel-secl/tree/v4.2.0-Beta/pkg/kbs))
* SGX Caching Service ([SCS](https://github.com/intel-secl/sgx-caching-service/tree/v4.1.2))
* SGX Quote Verification Service ([SQVS](https://github.com/intel-secl/sgx-verification-service/tree/v4.1.2))

Other dependencies:
* [Postgres SQL](https://pypi.org/project/pgdb/)
* A [KMIP](https://en.wikipedia.org/wiki/Key_Management_Interoperability_Protocol)-compliant
key management service, such as [PyKMIP](https://pykmip.readthedocs.io/en/latest/server.html) or,
[HashiCorp Vault](https://www.vaultproject.io/docs/secrets/kmip)

You can use [setup_isecl.sh](./tools/setup-isecl.sh) script to setup the above
components on a linux machine or on a VM. [Intel(R) SecL utils](https://github.com/intel-secl/utils)
repo has instructions to deploy them in different environments.

### Configure the client TLS certificates

In order the `trusted-attestation-controller` to access KBS API, it shall be
configured with the appropriate permissions. And also with valid private key
and a TLS client certificate that was signed by the CMS CA. Check
[plugin configuration](#plugin-configuration) section for additional details.

- Configure TAC plugin with appropriate permissions:
```sh
# Set appropriate hostname/IP address where the iSecL services are running
export AAS_HOST="$(hostname)" # Hostname (or IP address of the host) where AuthService is running
export CMS_HOST="$(hostname)" # Hostname (or IP address of the host) where CMS is running
export KBS_HOST="$(hostname)" # Hostname (or IP address of the host) where KBS is running
# Get AuthService token for creating role with permissions
export AAS_ADMIN_USERNAME="adminaas" # AuthService admin username, defined in setup-isecl.sh
export AAS_ADMIN_PASSWORD="admin" # AuthService password, defined in setup-isecl.sh
export ADMIN_TOKEN=$(curl --noproxy "*" -k -X POST https://$AAS_HOST:8444/aas/v1/token -d '{"username": "'$AAS_ADMIN_USERNAME'", "password": "'$AAS_ADMIN_PASSWORD'"}')
cat <<EOF > /tmp/tac-role.json
{
  "name": "KeyManager",
  "service": "KBS",
  "permissions": ["keys:*:*"]
}
EOF
# Add key manager role
KM_ROLE_ID=$(curl --noproxy "*" -k -H "Authorization: Bearer $ADMIN_TOKEN" -X POST https://$AAS_HOST:8444/aas/v1/roles -d @/tmp/tac-role.json | jq '.role_id' -r)
# Add quote verification role
SQVS_ROLE_ID=$(curl --noproxy "*" -k -H "Authorization: Bearer $ADMIN_TOKEN" -X POST https://$AAS_HOST:8444/aas/v1/roles -d '{"name": "QuoteVerifier", "service": "SQVS" }' | jq '.role_id' -r)
# Update TAC_USER roles
TAC_USER_ID=$(curl --noproxy "*" -k -H "Authorization: Bearer $ADMIN_TOKEN" -X GET  https://$AAS_HOST:8444/aas/v1/users?name=tacuser | jq '.[0].user_id' -r)
curl --noproxy "*" -k -H "Authorization: Bearer $ADMIN_TOKEN" -X POST https://$AAS_HOST:8444/aas/v1/users/$TAC_USER_ID/roles -d '{"role_ids": [ "'$KM_ROLE_ID'","'$SQVS_ROLE_ID'" ] }'
```

- Fetch the CMS Certificate Authority root certificate:

```sh
export ADMIN_USER="admin" # install admin username, defined in setup-isecl.sh
export ADMIN_PASSWORD="admin" #install admin password, defined in setup-isecl.sh
export ADMIN_TOKEN=$(curl --noproxy "*" -k -X POST https://$AAS_HOST:8444/aas/v1/token -d '{"username": "'$ADMIN_USER'", "password": "'$ADMIN_PASSWORD'"}')
# Get CMS CA file
curl --noproxy "*" -k https://$CMSS_HOST:8445/cms/v1/ca-certificates -H "Authorization: Bearer $ADMIN_TOKEN" -H "Accept: application/x-pem-file" > cmsca.pem
```

-  Get a client TLS certificate signed by the CMS CA

```sh
# Generate a CSR
# NOTE: the CN should match with the TAC_CN in ./setup-isecl.sh
openssl req -newkey rsa:3072 -keyout tac-key.pem -out request.csr -subj /CN=trusted-attestation-controller -nodes -sha384
curl --noproxy "*" -k https://$CMS_HOST:8445/cms/v1/certificates?certType=TLS-Client -H "Authorization: Bearer $ADMIN_TOKEN" -H "Accept: application/x-pem-file" -H "Content-Type: application/x-pem-file" -d "$(cat request.csr)" -o tac-client.crt
```

### Initialize the key transfer policy

To control which enclave(s) can access a private key, one has to define the
transfer policies with appropriate enclave information. Below example illustrate
how to define a policy that allows to transferring of a key to the
`trusted-certificate-issuer` enclave:

```sh
export ENCLAVE_MRSINGER="<<MrSigner value of the TCI enclave>>"
export ENCLAVE_PROD_ID="<<TCI enclave production id>>"
export ENCLAVE_MEASUREMENT="<<MrEnclave value of the TCI enclave>>"

cat > key-transfer-policy.json << EOF
{
    "sgx_enclave_issuer_anyof": ["'$ENCLAVE_MRSIGNER'"],
    "sgx_enclave_issuer_product_id": '$ENCLAVE_PROD_ID',
    "sgx_enclave_measurement_anyof":["'$ENCLAVE_MEASUREMENT'"],
    "sgx_enclave_svn_minimum":1,
    "tls_client_certificate_issuer_cn_anyof": ["CMSCA", "CMS TLS Client CA"],
    "attestation_type_anyof":["SGX"]
}
EOF
curl --noproxy "*" -k -X POST https://$KBS_HOST:9443/kbs/v1/key-transfer-policies \
   -d @key-transfer-policy.json
```

The above curl command returns an ID, which could be as `transfer_policy_id` 
while creating a key in the KBS.

### Create signer keys and certificates.

Store the CA private key and certificate in the key server that needs to be
securely transfer to the TCI enclave. Those key and certificate are used by a
`TCSIssuer` or a `TCSClusterIssuer` for singing certificate requests inside
the Kubernetes cluster.

You can use the [`kmiptool`](./tools/kmiptool/kmiptool.go) utility for storing
key/certificate into the the key server. 

- Build `kmiptool` from source
```sh
git clone https://github.com/intel/trusted-attestation-controller.git && cd trusted-attestation-controller
go build -o ./kmiptool ./plugins/isecl/tools/kmiptool/kmiptool.go
```
Assumptions for the below example:
- The key and certificate is consumed by a `TCSClusterIssuer` named `sgx-ca`.
- The KMIP server uses Username and Password credential type for client authentication.

```sh
export TCS_ISSUER=tcsclusterissuer.tcs.intel.com/sgx-ca
export TPID="<<key transfer policy id returned in the earlier step>>"
export SGX_CA_PRIVATE_KEY=sgx-ca-key.pem
export SGX_CA_CERTIFICATE=sgx-ca-cert.pem
export TAC_USERNAME=tacuser # username (SKC_LIBRARY_USERNAME) used in the setup-isech.sh script
export TAC_USERNAME=tacpasswd # password (SKC_LIBRARY_PASSWORD) used in the setup-isech.sh script
export TAC_TOKEN=$(curl --noproxy "*" -k -X POST https://$AAS_HOST:8444/aas/v1/token -d '{"username": "'$TAC_USERNAME'", "password": "'$TAC_PASSWORD'"}')
# Create a RSA key pair in the key server 
cat > key-info.json << EOF
{
    "key_information":{
        "algorithm":"RSA", "key_length":3072
    },
    "label": "$TCS_ISSUER",
    "transfer_policy_id":"$TPID"
}
EOF
# Capture the associated KMIP key-id for the key
KEY_ID=$(curl --noproxy "*" -k -X POST https://$KBS_HOST:9443/kbs/v1/keys \
    -H "Accept: application/json" -H "Content-Type: application/json" -H "Authorization: Bearer $TAC_TOKEN" \
    -d "@./key-info.json" | jq '.key_information.kmip_key_id')

# KMIP server client configuration
export KMIP_USERNAME="username" # base64 encoded string
export KMIP_PASSWORD="password" # base64 encoded string
export KMIP_ROOT_CERT=/location/of/root/ca-cert.pem
export KMIP_CLENT_CERT=/location/of/client/cert.pem
export KMIP_CLENT_KEY=/location/of/client/key.pem
export KMIP_SERVER_IP="127.0.0.1" # server ip address

# fetch the newly created private key from the server
./kmiptool -cmd get-key -kmip-server-ip $KMIP_SERVER_IP \
   -kmip-ca-cert $KMIP_ROOT_CERT -kmip-client-key $KMIP_CLIENT_KEY \
   -kmip-client-cert $KMIP_CLIENT_CERT -id $KEY_ID > $(SGX_CA_PRIVATE_KEY)

# Sign a certificate for using private key with a root CA and save 
# the certificate into $SGX_CA_CERTIFICATE.

# store certificate into the key server
./kmiptool -cmd store-cert -kmip-server-ip $KMIP_SERVER_IP \
   -kmip-ca-cert $KMIP_ROOT_CERT -kmip-client-key $KMIP_CLIENT_KEY \
   -kmip-client-cert $KMIP_CLIENT_CERT -cert "$(<SGX_CA_CERTIFICATE)" -label "$TCS_ISSUER"
```

## Plugin Configuration

The plugin supports below configuration fields which must be provided in an
YAML file.

- Main configuration fields

| Field | Type | Description |
|------- | -----| -----------|
| kbs | KBSConfig | Key Broker Service client configuration |
| sqvs | SQVSConfig | SGX Quote Verification Service client configuration |
| kmip | KMIPConfig | KMIP client configuration |

- KBS configuration fields

| field | type | description | default value |
|------- | -----| -----------| --- |
| host | string | IP address or hostname of the KBS server | |
| port | string | KBS server port number | "9443" |
| prefix | string | KBS API prefix | "/kbs/v1" |
| caCert | string | PEM-encoded Root CA certificate file path | |
| clientCert | string | PEM-encoded client TLS certificate file path | |
| clientKey | string | PEM-encoded private key file path | |
| token | string | Bearer token to access KBS API | |

- SQVS configuration fields

| field | type | description | default value |
|------- | -----| -----------| --- |
| host | string | IP address or hostname of the SQVS server | |
| port | string | KBS server port number | "9447" |
| prefix | string | SQVS API prefix | "/svs/v2" |

- KMIP configuration fields

| field | type | description | default value |
|------- | -----| -----------| --- |
| hostname | string | hostname of the KMIP server | |
| ip | string | ip address of the KMIP server | |
| port | string | KBS server port number | "5696" |
| username | string | Base64-encoded username | |
| password | string | Base64-encoded password | |
| caCert | string | PEM-encoded Root CA certificate file path | |
| clientCert | string | PEM-encoded client TLS certificate file path | |
| clientKey | string | PEM-encoded private key file path | |
