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

	"github.com/go-logr/logr"
	pluginapi "github.com/intel/trusted-attestation-controller/pkg/api/v1alpha1"
	grpcserver "github.com/intel/trusted-attestation-controller/pkg/grpc-server"
	"github.com/intel/trusted-attestation-controller/plugins/kmra/client"
	"google.golang.org/grpc"
	"k8s.io/klog/v2/klogr"
)

type plugin struct {
	*grpcserver.GrpcServer
	log     logr.Logger
	kmStore *client.KmStore
}

func NewPlugin(name, socketPath string, cfg *client.Config) (*plugin, error) {
	p := &plugin{
		log: klogr.New().WithName(name),
	}
	km, err := client.NewKmStore(cfg)
	if err != nil {
		return nil, err
	}
	p.log.Info("Starting plugin server...", "socketPath", socketPath)
	s, err := grpcserver.NewServer(socketPath, p)
	if err != nil {
		return nil, err
	}
	p.GrpcServer = s
	p.kmStore = km

	return p, nil
}

func (p *plugin) RegisterService(server *grpc.Server) {
	pluginapi.RegisterPluginServer(server, p)
}

func (p *plugin) ValidateQuote(ctx context.Context, req *pluginapi.ValidateQuoteRequest) (*pluginapi.ValidateQuoteReply, error) {
	p.log.Info("Validating quote", "req", req)
	res, err := p.kmStore.ValidateQuote(req.SignerName, req.Quote, req.PublicKey)
	if err != nil {
		return nil, err
	}
	return &pluginapi.ValidateQuoteReply{
		Result: res,
	}, nil
}

func (p *plugin) GetCAKeyAndCertificate(ctx context.Context, req *pluginapi.GetCAKeyAndCertificateRequest) (*pluginapi.GetCAKeyAndCertificateReply, error) {
	p.log.Info("fetching CA key and certificate", "req", req)
	key, cert, err := p.kmStore.GetCAKeyAndCertificate(req.SignerName, req.Quote, req.PublicKey)
	if err != nil {
		return nil, err
	}
	return &pluginapi.GetCAKeyAndCertificateReply{
		WrappedKey:  key,
		Certificate: cert,
	}, nil
}
