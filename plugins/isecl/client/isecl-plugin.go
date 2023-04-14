/*
Copyright 2021-2022.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package client

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/gemalto/kmip-go/kmip14"
	"github.com/go-logr/logr"
	"github.com/intel/trusted-attestation-controller/pkg/httpclient"
	"github.com/intel/trusted-attestation-controller/pkg/plugin"
	"github.com/intel/trusted-attestation-controller/plugins/isecl/config"
	"github.com/intel/trusted-attestation-controller/plugins/isecl/kmip"
	"golang.org/x/mod/semver"
	"k8s.io/klog/v2/klogr"

	"github.com/intel-secl/intel-secl/v4/pkg/model/kbs"
)

const (
	KBS_API_VERSION = "v4" // this should match with the import path version
)

type quoteData struct {
	// QuoteBlob is base64 encoded quote excluding it's length
	QuoteBlob string `json:"quote"`
	// UserData is base64 encoded of publickey+nonce
	UserData string `json:"userData"`
}

type iSeclPlugin struct {
	config     *config.Config
	log        logr.Logger
	client     httpclient.HttpClient
	kmipClient *kmip.Client // KMIP client for fetching CA certificate(s)
}

var _ plugin.KeyManagerPlugin = &iSeclPlugin{}

func NewISecLPlugin(cfg *config.Config) (plugin.KeyManagerPlugin, error) {
	if cfg == nil {
		// create new empty config
		cfg = &config.Config{}
	}

	// Create new http client to send requests to keys server
	client, err := httpclient.NewHttpClient(&httpclient.Config{
		CACertFile:     cfg.Kbs.CaCert,
		ClientCertFile: cfg.Kbs.ClientCert,
		KeyFile:        cfg.Kbs.ClientKey,
		RequestTimeout: cfg.Timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KBS client: %v", err)
	}

	kmipClient, err := kmip.NewClient(cfg.Kmip)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KMIP client: %v", err)
	}
	km := &iSeclPlugin{
		log:        klogr.New().WithName("isecl"),
		config:     cfg,
		client:     client,
		kmipClient: kmipClient,
	}
	if err := km.initialize(); err != nil {
		return nil, err
	}
	return km, nil
}

func (km *iSeclPlugin) initialize() error {
	if km == nil {
		return errors.New("kmStore is nil")
	}

	// Get the server API version
	version, err := km.getApiVersion()
	if err != nil {
		return err
	}
	km.log.Info("server version response", "KBS Version", version)
	// Check if api version meets criteria
	err = validateApiVersion(version)
	if err != nil {
		return fmt.Errorf("server api version validation failed: %v", err)
	}

	return nil
}

// AttestQuote uses post request to attest the quote match the key for a given signer
func (km *iSeclPlugin) AttestQuote(ctx context.Context, signerName string, quote []byte, publicKey []byte, nonce []byte) (bool, error) {
	if km.client == nil {
		return false, errors.New("http client is not initialized")
	}

	rsaPublicKey, err := parseRSAPublicKey(publicKey)
	if err != nil {
		return false, err
	}
	exponent := big.NewInt(int64(rsaPublicKey.E))
	modulus := rsaPublicKey.N

	// UserData format: base-64(pubKey+nonce)
	userData := []byte{}
	userData = append(userData, exponent.Bytes()...)
	userData = append(userData, modulus.Bytes()...)
	userData = append(userData, []byte(nonce)...)

	quoteInfo := quoteData{
		QuoteBlob: string(quote),
		UserData:  base64.StdEncoding.EncodeToString(userData),
	}

	request, err := json.Marshal(quoteInfo)
	if err != nil {
		return false, fmt.Errorf("unable to prepare quote verification request: %v", err)
	}

	qvUrl := km.config.Sqvs.URL() + "/sgx_qv_verify_quote"
	header := map[string]string{
		"Accept":        "application/json",
		"Authorization": "Bearer " + km.config.Kbs.BearerToken,
	}

	km.log.Info("Initiating quote verification", "url", qvUrl, "header", header)
	resp, status, err := km.client.Post(qvUrl, request, header)
	if err != nil {
		return false, fmt.Errorf("failed to initiate request: %v", err)
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("quote verification returned unexpected status: %v", status)
	}
	type quoteVerifyResponse struct {
		Attributes kbs.QuoteVerifyAttributes `json:"quoteData"`
	}
	verificationResponse := &quoteVerifyResponse{}
	if err := json.Unmarshal(resp, verificationResponse); err != nil {
		return false, fmt.Errorf("unable to parse quote verification response: %v", err)
	}

	if verificationResponse.Attributes.Message == "SGX_QL_QV_RESULT_OK" {
		return true, nil
	}

	return false, fmt.Errorf("quote verification failed with message: %s", verificationResponse.Attributes.Message)
}

func (km *iSeclPlugin) GetCAKeyCertificate(ctx context.Context, signerName string, encodedQuote []byte, publicKey []byte, nonce []byte) ([]byte, []byte, error) {
	if km == nil {
		return nil, nil, errors.New("kmStore is nil")
	}
	if km.client == nil {
		return nil, nil, errors.New("http client is not initialized")
	}
	decodedQuote, err := base64.StdEncoding.DecodeString(string(encodedQuote))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid quote: %v", err)
	}

	signerInfo, ok := km.config.Signers[signerName]
	if !ok {
		signerInfo = config.CAInfo{}
		km.config.Signers[signerName] = signerInfo
	}
	if signerInfo.KeyID == "" {
		// Not found in the configuration, determine the key id
		keys, err := km.fetchKeys()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get existing key info: %v", err)
		}
		for _, key := range keys {
			if key.Label == signerName {
				signerInfo.KeyID = key.KeyInformation.ID.String()
				break
			}
		}
		if signerInfo.KeyID == "" {
			return nil, nil, fmt.Errorf("no key found for the signer %q", signerName)
		}
	}

	wrappedSwk, wrappedKey, err := km.getWrappedKey(signerInfo.KeyID, decodedQuote, publicKey, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch key: %v", err)
	}
	km.log.Info("WrappedKey", "len", len(wrappedKey))
	keyData := append(wrappedSwk, wrappedKey...)
	encodedKey := []byte(base64.StdEncoding.EncodeToString(keyData))

	if km.kmipClient == nil {
		// if no KMIP client, just ignore certificate fetching
		return encodedKey, nil, nil
	}

	if signerInfo.CertID == "" {
		// No configuration entry found for the signer certificate
		certs, err := km.kmipClient.GetObjects(kmip14.ObjectTypeCertificate, signerName)
		if err != nil {
			//return fmt.Errorf("failed to get existing certificate info: %v", err)
			km.log.Error(err, "failed to get existing certificate info")
			return encodedKey, nil, nil
		}
		if len(certs) > 1 {
			km.log.Info("found multiple certificate objects", "signer", signerName)
		}
		signerInfo.CertID = certs[0].ID
	}

	cert, err := km.kmipClient.GetCertificate(signerInfo.CertID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch certificate: %v", err)
	}

	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return encodedKey, []byte(base64.StdEncoding.EncodeToString(pemCert)), nil
}

func (km *iSeclPlugin) initiateKeyTransfer(keyID string, sessionID string) ([]byte, int, error) {
	keyTransferUrl := km.config.Kbs.URL() + "/keys/" + keyID + "/dhsm2-transfer"
	headers := map[string]string{
		"Accept":           "application/json",
		"Accept-Challenge": "SGX",
		"Authorization":    "Bearer " + km.config.Kbs.BearerToken,
	}
	if len(sessionID) != 0 {
		headers["Session-Id"] = sessionID
	}

	km.log.Info("Sending key transfer request", "url", keyTransferUrl, "session", sessionID)
	return km.client.Get(keyTransferUrl, headers)
}

func (km *iSeclPlugin) openSessionForKeyTransfer(keyID string, quote []byte, publicKey []byte, nonce []byte) (string, []byte, error) {
	response, status, err := km.initiateKeyTransfer(keyID, "")
	if err != nil {
		return "", nil, fmt.Errorf("post request for keys failed: %v", err)
	}
	if status != http.StatusUnauthorized {
		// Expected an unauthorized access as no session
		// key transfer still exists
		return "", nil, fmt.Errorf("unexpected response (code %d) from key server: %v", status, string(response))
	}
	challenge := kbs.ChallengeRequest{}
	if err := json.Unmarshal(response, &challenge); err != nil {
		return "", nil, fmt.Errorf("failed to parse response: %v", err)
	}
	km.log.Info("Key transfer response", "challenge", challenge)
	// If session creation successful, use decoded challenge as sessionID
	id, err := base64.StdEncoding.DecodeString(challenge.Challenge)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode session id from challenge: %v", err)
	}
	// NOTE(avalluri): For KBS session, there is no way to pass the 'nonce'.
	// It only expects quote and the public key.
	swk, err := km.createSession(quote, publicKey, challenge.Challenge)
	if err != nil {
		return "", nil, err
	}
	session := challenge.ChallengeType + ":" + string(id)

	return session, swk, nil
}

// getWrappedKey fetches wrapped SWK and Private key from the KBS server
func (km *iSeclPlugin) getWrappedKey(keyID string, quote []byte, publicKey []byte, nonce []byte) ([]byte, []byte, error) {
	sessionID, swk, err := km.openSessionForKeyTransfer(keyID, quote, publicKey, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initiate key transfer: %v", err)
	}

	response, status, err := km.initiateKeyTransfer(keyID, sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to re-initiate key transfer: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected response (code %d) from the server: %s", status, string(response))
	}
	result := kbs.KeyTransferResponse{}
	if err := json.Unmarshal(response, &result); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal key transfer response: %v", err)
	}

	wrappedKey, err := base64.StdEncoding.DecodeString(result.KeyInfo.KeyData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to base64 decode the wrapped key returned by the server: %v", err)
	}
	truncate := 12 // first 12 bytes are the keyMetaDataSize
	return swk, wrappedKey[truncate:], nil
}

func (km *iSeclPlugin) createSession(quote []byte, publicKey []byte, challenge string) ([]byte, error) {
	if len(quote) == 0 || len(publicKey) == 0 || len(challenge) == 0 {
		return nil, fmt.Errorf("invalid quote or public key")
	}
	rsaPublicKey, err := parseRSAPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	fullQuote := bytes.NewBuffer(nil)
	exponent := big.NewInt(int64(rsaPublicKey.E))
	modulus := rsaPublicKey.N

	// Full quote data format (in base64 encoding) expected by the KBS:
	// |4-byte|4-byte|4-byte  |len(exponent)|len(modulus)|len(quote)
	// |------|------|--------|-------------|------------|---------|
	// |expLen|modLen|quoteLen|  exponent   |  modulus   |  quote  |
	// ////////////////////////////////////////////////////////////////
	binary.Write(fullQuote, binary.LittleEndian, uint32(len(exponent.Bytes())))
	binary.Write(fullQuote, binary.LittleEndian, uint32(len(modulus.Bytes())))
	binary.Write(fullQuote, binary.LittleEndian, uint32(len(quote)))
	binary.Write(fullQuote, binary.LittleEndian, exponent.Bytes())
	binary.Write(fullQuote, binary.LittleEndian, modulus.Bytes())
	binary.Write(fullQuote, binary.LittleEndian, quote)

	encodedQuote := base64.StdEncoding.EncodeToString(fullQuote.Bytes())
	sessionAttrs, err := json.Marshal(&kbs.SessionManagementAttributes{
		ChallengeType: "SGX",
		Challenge:     challenge,
		Quote:         encodedQuote,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to prepare session attributes: %v", err)
	}

	sessionUrl := km.config.Kbs.URL() + "/session"
	header := map[string]string{
		"Authorization": "Bearer " + km.config.Kbs.BearerToken,
		"Accept":        "application/json",
	}
	km.log.Info("Initiating create session", "url", sessionUrl, "header", header)
	resp, status, err := km.client.Post(sessionUrl, sessionAttrs, header)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate request: %v", err)
	}
	if status != http.StatusCreated {
		return nil, fmt.Errorf("create session returned unexpected status: %v", status)
	}

	sessionResponse := kbs.SessionResponseAttributes{}
	if err := json.Unmarshal(resp, &sessionResponse); err != nil {
		return nil, fmt.Errorf("failed to parse session response: %v", err)
	}
	if sessionResponse.Status != "success" {
		return nil, fmt.Errorf("unexpected session response '%v'", sessionResponse)
	}
	km.log.Info("Session", "response", sessionResponse)

	return sessionResponse.SessionData.SWK, nil
}

// getApiVersion uses get request to get the server version and api version.
// On success only the api version is returned.
func (km *iSeclPlugin) getApiVersion() (string, error) {
	if km.client == nil {
		return "", errors.New("http client is not initialized")
	}
	versionUrl := km.config.Kbs.URL() + "/version"
	km.log.Info("Sending get request", "url", versionUrl)
	response, status, err := km.client.Get(versionUrl, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get sys version from server: %v", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", status)
	}

	for _, line := range strings.Split(string(response), "\n") {
		if strings.HasPrefix(line, "Version: ") {
			if fields := strings.Fields(line); len(fields) == 2 {
				version := fields[1]
				return version, nil
			}
		}
	}

	return "", fmt.Errorf("missing version details in server response: %s", response)
}

// validateApiVersion checks that provided server version is
// supported with the current plugin implementation.
func validateApiVersion(version string) error {
	// Expected format is major.minor
	if semver.Major(version) != KBS_API_VERSION {
		return fmt.Errorf("Unsupported KBS server version '%s'. Current implementation only supports '%s'", version, KBS_API_VERSION)
	}
	return nil
}

func parseRSAPublicKey(publicKey []byte) (*rsa.PublicKey, error) {
	decodedKey, _ := pem.Decode(publicKey)
	if decodedKey == nil {
		return nil, errors.New("publicKey is not a correct PEM data")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(decodedKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	rsaPublicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to assert type of publicKey, invalid format")
	}

	return rsaPublicKey, nil
}

func (km *iSeclPlugin) fetchKeys() ([]kbs.KeyResponse, error) {
	keysURL := km.config.Kbs.URL() + "/keys" //+ "?algorithm=RSA"
	headers := map[string]string{
		"Authorization": "Bearer " + km.config.Kbs.BearerToken,
		"Accept":        "application/json",
	}
	response, status, err := km.client.Get(keysURL, headers)
	if err != nil {
		return nil, fmt.Errorf("post request for keys failed: %v", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status received from server: %v", status)
	}
	keys := []kbs.KeyResponse{}
	if err := json.Unmarshal(response, &keys); err != nil {
		return nil, fmt.Errorf("failed to parse server response: %v", err)
	}
	return keys, nil
}
