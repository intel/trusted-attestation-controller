/*
Copyright 2022.

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
package registryserver

import (
	"context"
	"fmt"

	pluginapi "github.com/intel/trusted-attestation-controller/pkg/api/v1alpha1"
	"google.golang.org/grpc"
)

type KeyServer interface {
	// GetName returns the name of the key server
	GetName() string

	// IsReady return if the connection the key server is ready
	IsReady() bool

	// AttestQuote attests the given quote is valid. Both quote and
	// publicKey are base64 encoded. The publickey hash part of the quote
	// must match with the given publicKey.
	//
	// Returns true if given quote is valid.
	// Returns false if verification failed.
	// In case of other problems, appropriate error gets returned.
	AttestQuote(ctx context.Context, signerName string, quote []byte, publicKey []byte) (bool, error)

	// GetCAKeyCertificate retrieves the stored CA key and certificate at the key-manager
	// for given signer signerName. Both quote and publicKey are base64 encoded.
	// First the given SGX quote is validated is valid by using quote validation library.
	// The publickey hash part of the quote must match with the given publicKey.
	//
	// On success, returns the key and certificate. The CA private key(PWK) is wrapped
	// with a symmetric key(SWK) that was wrapped with the given publicKey. Both the
	// SWK and PWK are concatenated and returned as single base64 encoded block. Certificate
	// is base64 encoded.
	// Otherwise, appropriate error gets returned.
	GetCAKeyCertificate(ctx context.Context, signerName string, quote []byte, publicKey []byte) ([]byte, []byte, error)
}

type keyServer struct {
	name       string
	socketPath string
	cc         *grpc.ClientConn
}

func (ks *keyServer) GetName() string {
	if ks == nil {
		return ""
	}
	return ks.name
}

func (ks *keyServer) IsReady() bool {
	return ks != nil && ks.cc != nil
}

func (ks *keyServer) AttestQuote(ctx context.Context, signerName string, quote []byte, publicKey []byte) (bool, error) {
	if !ks.IsReady() {
		return false, fmt.Errorf("%s: server is not ready", ks.name)
	}

	client := pluginapi.NewPluginClient(ks.cc)
	res, err := client.ValidateQuote(ctx, &pluginapi.ValidateQuoteRequest{
		SignerName: signerName,
		Quote:      quote,
		PublicKey:  publicKey,
	})
	if err != nil {
		return false, err
	}

	return res.Result, nil
}

func (ks *keyServer) GetCAKeyCertificate(ctx context.Context, signerName string, quote []byte, publicKey []byte) ([]byte, []byte, error) {
	if !ks.IsReady() {
		return nil, nil, fmt.Errorf("%s: server is not ready", ks.name)
	}

	client := pluginapi.NewPluginClient(ks.cc)
	res, err := client.GetCAKeyAndCertificate(ctx, &pluginapi.GetCAKeyAndCertificateRequest{
		SignerName: signerName,
		Quote:      quote,
		PublicKey:  publicKey,
	})
	if err != nil {
		return nil, nil, err
	}

	return res.WrappedKey, res.Certificate, nil
}
