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
package httpclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type HttpClient interface {
	Get(url string, headers map[string]string) ([]byte, int, error)
	Post(url string, request []byte, headers map[string]string) ([]byte, int, error)
}

type kmClient struct {
	client *http.Client
}

func NewHttpClient(caCertPath, clientCertPath, clientKeyPath string, timeout time.Duration) (HttpClient, error) {
	cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed creating x509 key pair: %v", err)
	}
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed opening ca cert `%s`, error: %v", caCert, err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		},
	}

	return &kmClient{&http.Client{Transport: transport, Timeout: timeout}}, nil
}

func (c *kmClient) Get(url string, headers map[string]string) ([]byte, int, error) {
	return c.doRequest(url, "GET", nil, headers)
}

func (c *kmClient) Post(url string, request []byte, headers map[string]string) ([]byte, int, error) {
	return c.doRequest(url, "POST", request, headers)
}

func (c *kmClient) doRequest(url, method string, body []byte, headers map[string]string) ([]byte, int, error) {
	var requestBuffer io.Reader
	if body == nil {
		requestBuffer = strings.NewReader("")
	} else {
		requestBuffer = bytes.NewBuffer(body)
	}
	req, err := http.NewRequest(method, url, requestBuffer)
	if err != nil {
		return nil, 0, fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	response, err := c.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("error received on http post request: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read http post response: %v", err)
	}
	return responseBody, response.StatusCode, nil
}
