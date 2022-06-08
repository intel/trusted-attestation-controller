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

package main

import (
	"context"
	"flag"
	"os"

	"github.com/intel/trusted-attestation-controller/pkg/plugin"
	"github.com/intel/trusted-attestation-controller/plugins/isecl/client"
	"github.com/intel/trusted-attestation-controller/plugins/isecl/config"
	"k8s.io/klog/v2/klogr"
)

func main() {
	var pluginName string
	var socketPath string
	var controllerEndpoint string
	var configFile string
	flag.StringVar(&pluginName, "plugin-name", "isecl", "Name of the plugin.")
	flag.StringVar(&socketPath, "plugin-socket-path", "/isecl.sock", "The address the key server endpoint binds to.")
	flag.StringVar(&controllerEndpoint, "registry-socket-path", "/registration/controller.sock", "Plugin registration server socket path.")
	flag.StringVar(&configFile, "config-file", "/etc/tac/config.yaml", "Location of the configuration file that holds the signers key mapping(json format).")
	flag.Parse()

	l := klogr.New().WithName("setup")
	cfg, err := config.ParseConfigFile(configFile)
	if err != nil {
		l.Error(err, "Config failure")
		os.Exit(-1)
	}
	p, err := client.NewISecLPlugin(cfg)
	if err != nil {
		l.Error(err, "Failed to initialize iSecL plugin")
		os.Exit(-1)
	}
	plugin, err := plugin.NewPlugin(pluginName, socketPath, p)
	if err != nil {
		l.Error(err, "Failed to initialize plugin", "socketPath", socketPath)
		os.Exit(-1)
	}
	plugin.Start()

	ctx, cancelRegistration := context.WithCancel(context.TODO())
	defer cancelRegistration()
	go plugin.RegisterWithController(ctx, controllerEndpoint)
	plugin.Wait()
	plugin.Stop()
}
