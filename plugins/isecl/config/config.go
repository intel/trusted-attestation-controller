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

package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/creasty/defaults"
	"github.com/intel/trusted-attestation-controller/plugins/isecl/kmip"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Kbs         KbsConfig          `yaml:"kbs"`
	Sqvs        Service            `yaml:"sqvs"`
	AuthService *Service           `yaml:"aas"`
	Kmip        *kmip.ClientConfig `yaml:"kmip"`
	Signers     map[string]CAInfo  `yaml:"signers"`
	Timeout     time.Duration      `default:"60s" yaml:"timeout"`
}

func (cfg *Config) EnsureDefaults() {
	// These default values cannot be set via go tags.
	// Hence we are setting them explicitly.
	cfg.Kbs.EnsureDefaults()
	if cfg.Sqvs.Port == "" {
		cfg.Sqvs.Port = "9447"
	}
	if cfg.Sqvs.Prefix == "" {
		cfg.Sqvs.Prefix = "/svs/v2"
	}
	if cfg.AuthService != nil && cfg.AuthService.Port == "" {
		cfg.AuthService.Port = "8444"
	}
	if cfg.AuthService != nil && cfg.AuthService.Prefix == "" {
		cfg.AuthService.Prefix = "/aas/v1"
	}
}

type KbsConfig struct {
	Service     `yaml:",inline"`
	CaCert      string `yaml:"caCert"`
	ClientCert  string `yaml:"clientCert"`
	ClientKey   string `yaml:"clientKey"`
	BearerToken string `yaml:"token"`
}

func (kc *KbsConfig) EnsureDefaults() {
	if kc.Proto == "" {
		kc.Proto = "https"
	}
	if kc.Port == "" {
		kc.Port = "9443"
	}
	if kc.Prefix == "" {
		kc.Prefix = "/kbs/v1"
	}
}

type Service struct {
	Proto  string `default:"https" yaml:"proto"`
	Host   string `yaml:"host"`
	Port   string `yaml:"port"`
	Prefix string `yaml:"prefix"`
}

func (s Service) URL() string {
	prefix := s.Prefix
	if !strings.HasPrefix(s.Prefix, "/") {
		prefix = "/" + s.Prefix
	}
	return fmt.Sprintf("%s://%s:%s%s", s.Proto, s.Host, s.Port, prefix)
}

type CAInfo struct {
	CertID string `yaml:"certId"`
	KeyID  string `yaml:"keyId"`
}

func ParseConfigFile(filePath string) (*Config, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return ParseConfig(content)
}

func ParseConfig(data []byte) (*Config, error) {
	cfg := &Config{
		Signers: make(map[string]CAInfo),
	}
	defaults.Set(cfg)

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %v", err)
	}
	// Ensure default values which are not set earlier
	cfg.EnsureDefaults()
	return cfg, nil
}
