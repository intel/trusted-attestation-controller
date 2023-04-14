package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"os"

	"github.com/gemalto/kmip-go/kmip14"
	"github.com/intel/trusted-attestation-controller/plugins/isecl/kmip"
)

func main() {
	cmdList := []string{
		"store-key",
		"delete-key",
		"get-key",
		"store-cert",
		"get-cert",
		"list-certs",
		"list-keys",
		"delete-cert",
	}
	var configFile string
	var cmd string
	var id string
	var label string
	var certBytes string
	var keyBytes string
	var keyAlgorithm string
	var keyLength int
	var keyType string
	var err error
	var client *kmip.Client

	kmipCfg := &kmip.ClientConfig{
		KmipVersion: "1.4", // Could be configure using kmip config file
	}
	flag.StringVar(&configFile, "config-file", "", "kmip client configuration file")
	flag.StringVar(&cmd, "cmd", "", fmt.Sprintf("command to execute. Supported commands: %v", cmdList))
	flag.StringVar(&label, "label", "", "Key/Certificate label to use to list/create.")
	flag.StringVar(&id, "id", "", "Key/Certificate ID")
	flag.StringVar(&kmipCfg.ServerIP, "kmip-server-ip", "127.0.0.1", "IP address of the KMIP server.")
	flag.StringVar(&kmipCfg.Port, "kmip-server-port", "5696", "KMIP server port.")
	flag.StringVar(&kmipCfg.Hostname, "kmip-server-hostname", "localhost", "Hostname of the KMIP server.")
	flag.StringVar(&kmipCfg.CACertFile, "kmip-ca-cert", "", "CA certificate file to access KMIP server.")
	flag.StringVar(&kmipCfg.ClientCertFile, "kmip-client-cert", "", "Client certificate file to access KMIP server.")
	flag.StringVar(&kmipCfg.KeyFile, "kmip-client-key", "", "Private key file to access KMIP server.")
	flag.StringVar(&certBytes, "cert", "", "certificate bytes to store as KMIP object")
	flag.StringVar(&keyBytes, "key", "", "PEM encoded PKCS8 private key bytes to store as KMIP object")
	flag.StringVar(&keyAlgorithm, "algo", "RSA", "private key type. Supported types: RSA, ECDSA etc.,")
	flag.IntVar(&keyLength, "length", 3072, "private key length")
	flag.StringVar(&keyType, "type", "private", fmt.Sprintf("key type to list, one of: %v", getKeyTypeNames()))
	flag.Parse()

	if cmd == "" {
		flag.CommandLine.Usage()
		os.Exit(1)
	}

	if configFile != "" {
		cfg, err := kmip.ParseConfig(configFile)
		if err != nil {
			fmt.Printf("ERR: Failed to read configuration from '%s': %v\n", configFile, err)
			return
		}
		kmipCfg = cfg
	}

	kmipCfg.Username = os.Getenv("KMIP_USERNAME")
	kmipCfg.Password = os.Getenv("KMIP_PASSWORD")
	client, err = kmip.NewClient(kmipCfg)
	if err != nil {
		fmt.Printf("ERR: Failed to initialize the KMIP client: %v", err)
		os.Exit(1)
	}

	switch cmd {
	case "store-key":
		if label == "" {
			fmt.Println("nil key label")
			os.Exit(1)
		}
		if keyBytes == "" {
			fmt.Printf("ERR: missing key bytes to store.")
			os.Exit(1)
		}
		id, err = client.RegisterKey(keyBytes, keyAlgorithm, keyLength, label)
		if id != "" {
			fmt.Printf("Created key with id '%s'", id)
		}
	case "delete-key":
		if id == "" {
			fmt.Println("nil key id")
			os.Exit(1)
		}
		err = client.DeleteKey(id)
	case "get-key":
		if id == "" {
			fmt.Println("ERR: nil key id")
			os.Exit(1)
		}
		var keyBytes []byte
		keyBytes, err = client.GetKey(id)
		if keyBytes != nil {
			fmt.Println(string(keyBytes))
		}
	case "store-cert":
		if label == "" {
			fmt.Println("ERR: nil certificate label")
			os.Exit(1)
		}
		if certBytes == "" {
			fmt.Printf("ERR: missing certificate bytes to store.")
			os.Exit(1)
		}
		id, err = client.RegisterCertificate(certBytes, label)
		if id != "" {
			fmt.Printf("Unique ID of the registered certificate: %s", id)
		}
	case "get-cert":
		if id == "" {
			fmt.Println("nil certificate id")
			os.Exit(1)
		}
		var cert *x509.Certificate
		cert, err = client.GetCertificate(id)
		if cert != nil {
			fmt.Printf("Certificate Issuer: %v\n", cert.Issuer)
		}
	case "list-certs":
		var certs []kmip.ObjectInfo
		certs, err = client.GetObjects(kmip14.ObjectTypeCertificate, label)
		if len(certs) != 0 {
			fmt.Printf("Got Certificates: %+v\n", certs)
		} else {
			fmt.Printf("No certificates found with label %q!\n", label)
		}
	case "list-keys":
		objType, err := keyTypeToObjectType(keyType)
		if err != nil {
			break
		}
		var keys []kmip.ObjectInfo
		keys, err = client.GetObjects(objType, label)
		if len(keys) != 0 {
			fmt.Printf("Got Keys: %+v\n", keys)
		} else if err == nil {
			fmt.Printf("No %s key found with label %q!\n", keyType, label)
		}
	case "delete-cert":
		if id == "" {
			fmt.Printf("ERR: nil certificate id")
			os.Exit(1)
		}
		err = client.DeleteCertificate(id)
	default:
		err = fmt.Errorf("unrecognized command: %s", cmd)
	}

	if err != nil {
		fmt.Printf("ERR: Failed to execute command '%v': %v\n", cmd, err)
	}
}

var kmipKeyTypes = map[string]kmip14.ObjectType{
	"private":   kmip14.ObjectTypePrivateKey,
	"public":    kmip14.ObjectTypePublicKey,
	"symmetric": kmip14.ObjectTypeSymmetricKey,
	"split":     kmip14.ObjectTypeSymmetricKey,
	"pgp":       kmip14.ObjectTypePGPKey,
}

func getKeyTypeNames() []string {
	names := []string{}
	for key := range kmipKeyTypes {
		names = append(names, key)
	}
	return names
}

func keyTypeToObjectType(typeStr string) (kmip14.ObjectType, error) {
	objectType, ok := kmipKeyTypes[typeStr]
	if !ok {
		return 0, fmt.Errorf("unknown key type %q", typeStr)
	}
	return objectType, nil
}
