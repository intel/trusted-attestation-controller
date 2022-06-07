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
	"github.com/intel/trusted-attestation-controller/pkg/plugin"
	"google.golang.org/grpc"
)

type KeyServer interface {
	plugin.KeyManagerPlugin
	// GetName returns the name of the key server
	GetName() string

	// IsReady return if the connection the key server is ready
	IsReady() bool
}

type keyServer struct {
	name       string
	socketPath string
	cc         *grpc.ClientConn
}

var _ KeyServer = &keyServer{}

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
