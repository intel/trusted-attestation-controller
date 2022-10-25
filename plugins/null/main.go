package main

import (
	"context"
	"flag"
	"time"

	"github.com/go-logr/logr"
	pluginapi "github.com/intel/trusted-attestation-controller/pkg/api/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"k8s.io/klog/v2/klogr"
)

func main() {
	var pluginName string
	var socketPath string
	// var registrationPath string
	var controllerEndpoint string
	flag.StringVar(&pluginName, "plugin-name", "null", "Name of the plugin.")
	flag.StringVar(&socketPath, "plugin-socket-path", "/null.sock", "The address the key server binds to.")
	flag.StringVar(&controllerEndpoint, "registry-socket-path", "/registration/controller.sock", "Plugin registration server socket path.")
	flag.Parse()

	l := klogr.New().WithName("setup")

	l.Info("Initializing the null plugin...")

	ctx, cancelRegistration := context.WithCancel(context.TODO())
	success := registerPlugin(ctx, l, pluginName, socketPath, controllerEndpoint)
	if success {
		// Keep the container running and do nothing
		for {
			l.Info("Infinite looping...")
			time.Sleep(time.Minute)
		}
	}

	cancelRegistration()
}

func registerPlugin(ctx context.Context, l logr.Logger, pluginName, socketPath, controllerSocketPath string) bool {
	success := false
	retryTimeout := time.Minute
	var conn *grpc.ClientConn
	for {
		var err error
		if conn != nil && conn.GetState() == connectivity.Ready {
			break
		}
		l.Info("Connecting to registry server...", "at", controllerSocketPath)
		conn, err = grpc.DialContext(ctx, "unix://"+controllerSocketPath, grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			l.V(4).Error(err, "Failed to connect controller socket, will retry", "after", retryTimeout)
			time.Sleep(retryTimeout)
			continue
		}
	}
	defer conn.Close()
	client := pluginapi.NewRegistryClient(conn)
	for {
		if success {
			return true
		}
		l.Info("Registering the plugin...", "name", pluginName, "socket", socketPath)
		_, err := client.RegisterPlugin(ctx, &pluginapi.RegisterPluginRequest{
			Name:    pluginName,
			Address: socketPath,
		})
		if err != nil {
			l.V(3).Error(err, "Failed to register plugin socket, will retry", "after", retryTimeout)
			time.Sleep(retryTimeout)
			continue
		}
		l.Info("Registration success")
		success = true
	}
}
