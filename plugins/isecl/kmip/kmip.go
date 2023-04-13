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

package kmip

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/creasty/defaults"
	"github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/kmip20"
	"github.com/gemalto/kmip-go/ttlv"
	"github.com/go-logr/logr"
	"github.com/intel-secl/intel-secl/v4/pkg/kbs/constants"
	"github.com/intel-secl/intel-secl/v4/pkg/kbs/domain/models"
	"github.com/intel-secl/intel-secl/v4/pkg/kbs/kmipclient"
	commonLog "github.com/intel-secl/intel-secl/v4/pkg/lib/common/log"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2/klogr"
)

type ClientConfig struct {
	KmipVersion    string `default:"2.0" yaml:"kmipVersion"`
	ServerIP       string `yaml:"ip"`
	Port           string `default:"5696" yaml:"port"`
	Hostname       string `yaml:"hostname"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	CACertFile     string `yaml:"caCert"`
	KeyFile        string `yaml:"clientKey"`
	ClientCertFile string `yaml:"clientCert"`
	LogLevel       string `default:"warn" yaml:"logLevel"`
}

func NewClientConfig() *ClientConfig {
	cfg := &ClientConfig{}
	defaults.Set(cfg)
	return cfg
}

type Client struct {
	kmipclient.KmipClient
	log logr.Logger
}

func NewClient(config *ClientConfig) (*Client, error) {
	c := &Client{
		log:        klogr.New().WithName("kmip"),
		KmipClient: kmipclient.NewKmipClient(),
	}
	username, err := base64.StdEncoding.DecodeString(config.Username)
	if err != nil {
		return nil, fmt.Errorf("invalid username: %v", err)
	}
	password, err := base64.StdEncoding.DecodeString(config.Password)
	if err != nil {
		return nil, fmt.Errorf("invalid password: %v", err)
	}
	lv, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		c.log.V(3).Error(err, "invalid config", "logLevel", config.LogLevel)
		lv = logrus.WarnLevel
	}
	commonLog.GetDefaultLogger().Logger.SetLevel(lv)

	if err := c.InitializeClient(
		config.KmipVersion,
		config.ServerIP,
		config.Port,
		config.Hostname,
		string(username),
		string(password),
		config.KeyFile,
		config.ClientCertFile,
		config.CACertFile,
	); err != nil {
		return nil, err
	}
	return c, nil
}

func ParseConfig(confFile string) (*ClientConfig, error) {
	data, err := ioutil.ReadFile(confFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read kmip client configuration '%s': %v", confFile, err)
	}
	cfg := NewClientConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse kmip configuration: %v", err)
	}
	return cfg, nil
}

func (c *Client) RegisterCertificate(pemCert string, label string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("nil client")
	}
	if len(pemCert) == 0 {
		return "", fmt.Errorf("invalid argument")
	}
	blk, _ := pem.Decode([]byte(pemCert))
	if blk.Type != "CERTIFICATE" {
		return "", fmt.Errorf("invalid PEM coded cert")
	}

	payload := &RegisterRequestPayload{
		ObjectType: kmip20.ObjectTypeCertificate,
		Certificate: &kmip.Certificate{
			CertificateType:  kmip14.CertificateTypeX_509,
			CertificateValue: blk.Bytes,
		},
		Attributes: ttlv.NewStruct(kmip20.TagAttributes,
			ttlv.NewValue(kmip14.TagName, kmip.Name{NameType: kmip14.NameTypeUninterpretedTextString, NameValue: label})),
	}
	batchItem, decoder, err := c.SendRequest(payload, kmip14.OperationRegister)
	if err != nil {
		return "", fmt.Errorf("failed to perform register certificate: %v", err)
	}

	resp := kmip.RegisterResponsePayload{}
	err = decoder.DecodeValue(&resp, batchItem.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return "", fmt.Errorf("failed to decode response payload: %v", err)
	}

	return resp.UniqueIdentifier, nil
}

func (c *Client) GetCertificate(id string) (*x509.Certificate, error) {
	getRequestPayLoad := models.GetRequestPayload{
		UniqueIdentifier: kmip20.UniqueIdentifierValue{Text: id},
	}

	batchItem, decoder, err := c.SendRequest(getRequestPayLoad, kmip14.OperationGet)
	if err != nil {
		return nil, errors.Wrap(err, "failed to perform get certificate operation")
	}

	var respPayload GetResponsePayload
	err = decoder.DecodeValue(&respPayload, batchItem.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode get certificate response payload")
	}
	cert, err := x509.ParseCertificate(respPayload.Certificate.CertificateValue)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode certificate block")
	}
	return cert, nil
}

func (c *Client) GetCertificateName(id string) (string, error) {
	requestPayLoad := GetAttributesRequestPayload{
		UniqueIdentifier: kmip20.UniqueIdentifierValue{Text: id},
		Attributes: ttlv.Values{
			ttlv.NewValue(kmip20.TagAttributeReference, "Name"),
			ttlv.NewValue(kmip20.TagAttributeReference, "Object Type"),
		},
	}

	batchItem, decoder, err := c.SendRequest(requestPayLoad, kmip14.OperationGetAttributes)
	if err != nil {
		return "", errors.Wrap(err, "failed to perform get attributes operation")
	}

	respPayload := GetAttributesResponsePayload{}
	if err := decoder.DecodeValue(&respPayload, batchItem.ResponsePayload.(ttlv.TTLV)); err != nil {
		return "", errors.Wrap(err, "failed to decode get attributes response payload")
	}

	if respPayload.Attributes.ObjectType != kmip20.ObjectTypeCertificate {
		return "", fmt.Errorf("unexpected object type: %v", respPayload.Attributes.ObjectType)
	}
	return respPayload.Attributes.Name.NameValue, nil
}

func (c *Client) LocateCertificateIDs() ([]string, error) {
	requestPayLoad := LocateRequestPayload{
		Attributes: ttlv.NewValue(kmip20.TagAttributes, Attribute{
			ObjectType: "Certificate",
		}),
	}

	batchItem, decoder, err := c.SendRequest(requestPayLoad, kmip14.OperationLocate)
	if err != nil {
		return nil, errors.Wrap(err, "failed to perform locate operation")
	}

	respPayload := LocateResponsePayload{}
	if err := decoder.DecodeValue(&respPayload, batchItem.ResponsePayload.(ttlv.TTLV)); err != nil {
		return nil, errors.Wrap(err, "failed to decode locate response payload")
	}

	return respPayload.UniqueIdentifier, nil
}

func (c *Client) GetCertificateNameAndIDs() ([]CertInfo, error) {
	ids, err := c.LocateCertificateIDs()
	if err != nil {
		return nil, err
	}
	certs := []CertInfo{}
	for _, id := range ids {
		name, err := c.GetCertificateName(id)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificate name for '%s': %v", id, err)
		}
		certs = append(certs, CertInfo{ID: id, Label: name})
	}
	return certs, nil
}

func (c *Client) DeleteCertificate(id string) error {
	if _, _, err := c.SendRequest(&DeleteRequestPayload{
		UniqueIdentifier: kmip20.UniqueIdentifierValue{Text: id},
	}, kmip14.OperationDestroy); err != nil {
		return errors.Wrap(err, "failed to perform destroy operation")
	}
	return nil
}

func (c *Client) GetKey(keyID string) ([]byte, error) {
	getRequestPayLoad := models.GetRequestPayload{
		UniqueIdentifier: kmip20.UniqueIdentifierValue{
			Text: keyID,
		},
	}

	batchItem, decoder, err := c.SendRequest(getRequestPayLoad, kmip14.OperationGet)
	if err != nil {
		return nil, errors.Wrap(err, "failed to perform get key operation")
	}

	var respPayload GetResponsePayload
	err = decoder.DecodeValue(&respPayload, batchItem.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode get key response payload")
	}

	var encodeStr string
	if respPayload.ObjectType == kmip20.ObjectTypePublicKey {
		encodeStr = "PUBLIC KEY"
	} else if respPayload.ObjectType == kmip20.ObjectTypePrivateKey {
		encodeStr = "PRIVATE KEY"
	} else {
		return nil, fmt.Errorf("Unknown key type: %v", respPayload.ObjectType)
	}

	var keyValue models.KeyValue
	if err = decoder.DecodeValue(&keyValue, respPayload.PrivateKey.KeyBlock.KeyValue.(ttlv.TTLV)); err != nil {
		return nil, errors.Wrap(err, "failed to decode key block")
	}

	block := &pem.Block{
		Type:  encodeStr, /*"PUBLIC KEY"*/
		Bytes: keyValue.KeyMaterial,
	}
	return pem.EncodeToMemory(block), nil
}

func (c *Client) RegisterKey(pemKey string, algorithm string, keyLen int, label string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("nil client")
	}
	if len(pemKey) == 0 {
		return "", fmt.Errorf("invalid argument")
	}
	blk, _ := pem.Decode([]byte(pemKey))
	if blk.Type != "PRIVATE KEY" {
		return "", fmt.Errorf("invalid private key. Expected a PEM-encoded private key")
	}
	var cryptoAlgo kmip14.CryptographicAlgorithm
	switch algorithm {
	case "RSA", "rsa":
		cryptoAlgo = kmip14.CryptographicAlgorithmRSA
	default:
		return "", fmt.Errorf("unsupported key type: %q", algorithm)
	}

	payload := &RegisterRequestPayload{
		ObjectType: kmip20.ObjectTypePrivateKey,
		PrivateKey: &kmip.PrivateKey{
			KeyBlock: kmip.KeyBlock{
				KeyValue:               blk.Bytes,
				KeyFormatType:          kmip14.KeyFormatTypeRaw,
				CryptographicAlgorithm: cryptoAlgo,
				CryptographicLength:    keyLen,
			},
		},
		Attributes: ttlv.NewStruct(kmip20.TagAttributes,
			ttlv.NewValue(kmip14.TagName, kmip.Name{NameType: kmip14.NameTypeUninterpretedTextString, NameValue: label})),
	}
	batchItem, decoder, err := c.SendRequest(payload, kmip14.OperationRegister)
	if err != nil {
		return "", fmt.Errorf("failed to perform register the key: %v", err)
	}

	resp := kmip.RegisterResponsePayload{}
	err = decoder.DecodeValue(&resp, batchItem.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return "", fmt.Errorf("failed to decode response payload: %v", err)
	}

	return resp.UniqueIdentifier, nil
}
