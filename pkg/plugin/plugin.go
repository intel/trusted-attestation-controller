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

package plugin

import (
	"context"
	"sync"
	"time"

	"github.com/go-logr/logr"
	pluginapi "github.com/intel/trusted-attestation-controller/pkg/api/v1alpha1"
	grpcserver "github.com/intel/trusted-attestation-controller/pkg/grpc-server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"k8s.io/klog/v2/klogr"
)

type KeyManagerPlugin interface {
	// AttestQuote attests the given quote is valid. Both quote and
	// publicKey are base64 encoded. The publickey hash part of the quote
	// must match with the given publicKey.
	//
	// Returns true if given quote is valid.
	// Returns false if verification failed.
	// In case of other problems, appropriate error gets returned.
	AttestQuote(ctx context.Context, signerName string, quote []byte, publicKey []byte, nonce []byte) (bool, error)

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
	GetCAKeyCertificate(ctx context.Context, signerName string, quote []byte, publicKey []byte, nonce []byte) ([]byte, []byte, error)
}

type plugin struct {
	*grpcserver.GrpcServer
	pluginapi.UnimplementedPluginServer
	log        logr.Logger
	name       string
	socketPath string
	kmStore    KeyManagerPlugin
	lock       sync.Mutex
}

func NewPlugin(name, socketPath string, client KeyManagerPlugin) (*plugin, error) {
	p := &plugin{
		log:        klogr.New().WithName(name),
		name:       name,
		socketPath: socketPath,
	}
	p.log.Info("Starting plugin server...", "socketPath", socketPath)
	s, err := grpcserver.NewServer(socketPath, p)
	if err != nil {
		return nil, err
	}
	p.GrpcServer = s
	p.kmStore = client

	return p, nil
}

func (p *plugin) RegisterService(server *grpc.Server) {
	pluginapi.RegisterPluginServer(server, p)
}

func (p *plugin) ValidateQuote(ctx context.Context, req *pluginapi.ValidateQuoteRequest) (*pluginapi.ValidateQuoteReply, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.log.Info("Validating quote", "req", req)

	res, err := p.kmStore.AttestQuote(ctx, req.SignerName, req.Quote, req.PublicKey, req.Nonce)
	if err != nil {
		return nil, err
	}
	return &pluginapi.ValidateQuoteReply{
		Result: res,
	}, nil
}

func (p *plugin) GetCAKeyAndCertificate(ctx context.Context, req *pluginapi.GetCAKeyAndCertificateRequest) (*pluginapi.GetCAKeyAndCertificateReply, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.log.Info("fetching CA key and certificate", "req", req)
	key, cert, err := p.kmStore.GetCAKeyCertificate(ctx, req.SignerName, req.Quote, req.PublicKey, req.Nonce)
	if err != nil {
		return nil, err
	}
	return &pluginapi.GetCAKeyAndCertificateReply{
		WrappedKey:  key,
		Certificate: cert,
	}, nil
}

func (p *plugin) RegisterWithController(ctx context.Context, controllerSocketPath string) {
	success := false
	retryTimeout := time.Minute
	var conn *grpc.ClientConn
	for {
		var err error
		if conn != nil && conn.GetState() == connectivity.Ready {
			break
		}
		p.log.Info("Connecting to registry server...", "at", controllerSocketPath)
		conn, err = grpc.DialContext(ctx, "unix://"+controllerSocketPath, grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			p.log.V(4).Error(err, "failed to connect controller socket, will retry", "after", retryTimeout)
			time.Sleep(retryTimeout)
			continue
		}
	}
	defer conn.Close()

	client := pluginapi.NewRegistryClient(conn)
	for {
		if success {
			return
		}
		p.log.Info("Registering the plugin...", "name", p.name, "socket", p.socketPath)
		_, err := client.RegisterPlugin(ctx, &pluginapi.RegisterPluginRequest{
			Name:    p.name,
			Address: p.socketPath,
		})
		if err != nil {
			p.log.V(3).Error(err, "Failed to register plugin socket, will retry", "after", retryTimeout)
			time.Sleep(retryTimeout)
			continue
		}
		p.log.Info("Registration success!!!")
		success = true
	}
}
