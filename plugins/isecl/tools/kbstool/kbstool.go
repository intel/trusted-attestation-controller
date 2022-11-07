package main

import (
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/setup"
	"github.com/intel-secl/intel-secl/v4/pkg/model/kbs"
	"github.com/intel/trusted-attestation-controller/pkg/httpclient"
	"github.com/intel/trusted-attestation-controller/plugins/isecl/config"
)

type runFunc func(args []string) error

func newKbsFlags(name string, kbsCfg *config.KbsConfig) *flag.FlagSet {
	flags := flag.NewFlagSet(os.Args[0]+" "+name, flag.ExitOnError)
	flags.StringVar(&kbsCfg.Host, "kbs-host", "localhost", "Hostname of the KBS server to connect")
	flags.StringVar(&kbsCfg.Port, "kbs-port", "9443", "Port number of the KBS server")
	flags.StringVar(&kbsCfg.CaCert, "ca-cert", "", "CA root certificate")
	flags.StringVar(&kbsCfg.ClientCert, "cert-file", "", "Location of the KBC client certificate to store/load. Used by 'download-cert'")
	flags.StringVar(&kbsCfg.ClientCert, "key-file", "", "Location of the client private key to load for signing")
	return flags
}

func newCmsFlags(name string, cmsCfg *config.Service) *flag.FlagSet {
	cmsCfg.Prefix = "/cms/v1"
	flags := flag.NewFlagSet(os.Args[0]+" "+name, flag.ExitOnError)
	flags.StringVar(&cmsCfg.Host, "cms-host", "localhost", "Hostname of the CMS server to fetch certificates")
	flags.StringVar(&cmsCfg.Port, "cms-port", "8445", "Port number of the CMS server")
	return flags
}

func main() {
	commands := map[string]runFunc{
		"list-all": func(args []string) error {
			commandList := []string{
				"list-all",
				"download-cms-ca-cert",
				"download-cert",
				"create-key",
				"list-keys",
				"delete-key",
				"get-pub-key",
				"hsm-transfer",
			}
			fmt.Printf("Available commands: %v\n", commandList)
			return nil
		},
		"download-cms-ca-cert": func(args []string) error {
			var caDir string
			cmsCfg := &config.Service{}
			flags := newCmsFlags("download-cms-ca-cert", cmsCfg)
			flags.StringVar(&caDir, "ca-dir", "/etc/tac/", "Directory location to save the downloaded CMS CA certificate.")
			flags.Parse(args)

			hash := os.Getenv("CMS_CERT_HASH")
			if hash == "" {
				return errors.New("missing CMS CA certificate hash. Provide it via CMS_CERT_HASH environment. You can get it by running 'cms tlscertsha384'.")
			}
			return downloadCaCert(cmsCfg.URL(), hash, caDir)
		},
		"download-cert": func(args []string) error {
			var caDir, cn, sanList, clientKey, clientCert string
			cmsCfg := &config.Service{}
			flags := newCmsFlags("download-cms-ca-cert", cmsCfg)
			flags.StringVar(&caDir, "ca-dir", "/etc/tac/", "Directory location to save the signed client certificate by CMS")
			flags.StringVar(&clientCert, "cert-file", "", "File path to save the client certificate.")
			flags.StringVar(&clientKey, "key-file", "", "File path to save the client private key used for signing request.")
			flags.StringVar(&cn, "common-name", "localhost", "CommonName to use for the signing a client certificate.")
			flags.StringVar(&sanList, "san-list", "localhost,127.0.0.1", "Subject alternative names to use for the signing a client certificate.")
			flags.Parse(args)

			token := os.Getenv("BEARER_TOKEN")
			if token == "" {
				return errors.New("missing KBS token. Provide it via BEARER_TOKEN environment!")
			}
			hash := os.Getenv("CMS_CERT_HASH")
			if hash == "" {
				return errors.New("missing CMS CA certificate hash. Provide it via CMS_CERT_HASH environment. You can get it by running 'cms tlscertsha384'.")
			}
			return downloadCert(cmsCfg.URL(), token, cn, sanList, caDir, clientKey, clientCert)
		},
		"create-key": func(args []string) error {
			kbsCfg := &config.KbsConfig{}
			var label string
			var keyType string
			var keyLength int
			var keyTransferPolicy string
			flags := newKbsFlags("create-key", kbsCfg)
			flags.StringVar(&label, "label", "", "Label to use for newly created key")
			flags.StringVar(&keyType, "key-type", "RSA", "Key algorithm: RSA or ECDSA. Needed for 'create-key")
			flags.IntVar(&keyLength, "key-len", 3072, "Key length")
			flags.StringVar(&keyTransferPolicy, "ktp-id", "", "Key transfer policy ID, to use for newly created key. Needed for 'create-key")
			flags.Parse(args)
			kbsCfg.EnsureDefaults()

			if label == "" {
				return errors.New("nil key label")
			}
			kbsCfg.BearerToken = os.Getenv("BEARER_TOKEN")
			if kbsCfg.BearerToken == "" {
				return errors.New("missing KBS token. Provide it via BEARER_TOKEN environment!")
			}
			return createKey(kbsCfg, keyType, keyLength, keyTransferPolicy, label)
		},
		"list-keys": func(args []string) error {
			kbsCfg := &config.KbsConfig{}
			flags := newKbsFlags("list-keys", kbsCfg)
			flags.Parse(args)
			kbsCfg.EnsureDefaults()

			kbsCfg.BearerToken = os.Getenv("BEARER_TOKEN")
			if kbsCfg.BearerToken == "" {
				return errors.New("missing KBS token. Provide it via BEARER_TOKEN environment!")
			}
			return listKeys(kbsCfg)
		},
		"delete-key": func(args []string) error {
			kbsCfg := &config.KbsConfig{}
			var id string
			flags := newKbsFlags("delete-key", kbsCfg)
			flags.StringVar(&id, "id", "", "Key ID to delete")
			flags.Parse(args)
			kbsCfg.EnsureDefaults()
			if id == "" {
				return errors.New("nil key id")
			}
			kbsCfg.BearerToken = os.Getenv("BEARER_TOKEN")
			if kbsCfg.BearerToken == "" {
				return errors.New("missing KBS token. Provide it via BEARER_TOKEN environment!")
			}
			return deleteKey(kbsCfg, id)
		},
		"hsm-transfer": func(args []string) error {
			kbsCfg := &config.KbsConfig{}
			var id string
			flags := newKbsFlags("list-keys", kbsCfg)
			flags.StringVar(&id, "id", "", "Key ID to retrieve")
			flags.Parse(args)
			kbsCfg.EnsureDefaults()
			kbsCfg.BearerToken = os.Getenv("BEARER_TOKEN")
			if kbsCfg.BearerToken == "" {
				return errors.New("missing KBS token. Provide it via BEARER_TOKEN environment!")
			}
			return transferKey(kbsCfg, id)
		},
	}

	if len(os.Args) < 2 {
		os.Args = append(os.Args, "list-all")
	}

	run, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "ERR: Unknown command '%s'", os.Args[1])
		return
	}
	if err := run(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "ERR: failed to execute: %v", err)
	}
}

// transferKey initiates the key transfer for given keyID
func transferKey(kbsCfg *config.KbsConfig, keyID string) error {
	quote := os.Getenv("QUOTE")
	if len(quote) == 0 {
		return fmt.Errorf("nil quote, provide a valid SGX quote via QUOTE environment variable")
	}

	client, err := httpclient.NewHttpClient(&httpclient.Config{
		CACertFile:     kbsCfg.CaCert,
		KeyFile:        kbsCfg.ClientKey,
		ClientCertFile: kbsCfg.ClientCert,
		RequestTimeout: 2 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("failed to prepare http client: %v", err)
	}
	return hsmTransfer(client, kbsCfg, keyID, quote, "")
}

// hsmTransfer initiates key transfer request to KBS for given keyID.
// If the passed sessionID is empty then it created a new session by
// initiating a new session request wit the given SGX quote. And then
// re-initiates the key transfer request.
//
// Full quote data format (in base64 encoding) expected by the KBS:
// |      metadata        |      public key          |  quote  |
// |4-byte|4-byte| 4-byte |len(exponent)|len(modulus)|len(quote)
// |------|------|--------|-------------|------------|---------|
// |expLen|modLen|quoteLen|  exponent   |  modulus   |  quote  |
// |-----------------------------------------------------------|
// Arguments:
//
//	client: An HTTP client
//	kbs: KBS client configuration
//	keyID: Identifier of the private key to be transferred
//	quote: SGX Quote prefixed with an RSA public key
//	sessionID: KBS session identifier
func hsmTransfer(client httpclient.HttpClient, kbsCfg *config.KbsConfig, keyID, quote, sessionID string) error {
	url := kbsCfg.URL() + "/keys/" + keyID + "/dhsm2-transfer"

	header := map[string]string{
		"Authorization":    "Bearer " + kbsCfg.BearerToken,
		"Accept":           "application/json",
		"Accept-Challenge": "SGX",
	}
	if len(sessionID) != 0 {
		header["Session-Id"] = sessionID
	}

	resp, status, err := client.Get(url, header)
	if err != nil {
		return fmt.Errorf("failed to initiate request: %v", err)
	}

	switch status {
	case http.StatusUnauthorized:
		fmt.Println("DBG: No active session")
		challenge := kbs.ChallengeRequest{}
		if err := json.Unmarshal(resp, &challenge); err != nil {
			return fmt.Errorf("failed to parse response: %v", err)
		}

		sessionAttrs := &kbs.SessionManagementAttributes{
			ChallengeType: "SGX",
			Challenge:     challenge.Challenge,
			Quote:         quote,
		}
		data, err := json.Marshal(sessionAttrs)
		if err != nil {
			return err
		}
		fmt.Println("DBG: Create new session...")
		sessionResp, status, err := client.Post(kbsCfg.URL()+"/session", data, map[string]string{
			"Authorization": "Bearer " + kbsCfg.BearerToken,
			"Accept":        "application/json",
		})
		if err != nil {
			return fmt.Errorf("Failed to initiate request: %v", err)
		}
		if status != http.StatusCreated {
			return fmt.Errorf("create session returned unexpected status: %v", status)
		}
		fmt.Println("DBG: Session Response: " + string(sessionResp))
		sessionID, err := base64.StdEncoding.DecodeString(challenge.Challenge)
		if err != nil {
			return fmt.Errorf("failed to decode session id from challenge: %v", err)
		}
		session := sessionAttrs.ChallengeType + ":" + string(sessionID)

		fmt.Println("DBG: Re-initiating key-transfer with session")
		if err := hsmTransfer(client, kbsCfg, keyID, quote, session); err != nil {
			return err
		}

	case http.StatusOK:
		fmt.Println(string(resp))
		return nil

	default:
		return fmt.Errorf("Unexpected status code: %v", status)
	}

	return nil
}

// createKey creates a new private key with the given type and length in the key server
// Arguments:
//
//	kbs: KBS client configuration
//	keyType: Key type to create: RSA or ECDSA
//	keyLength: Key length in bits
//	label: Label attached to the newly crated key
func createKey(kbs *config.KbsConfig, keyType string, keyLength int, keyTransferPolicy, label string) error {
	url := kbs.URL() + "/keys"
	request := fmt.Sprintf(`
"key_information": {
		"algorithm": "%s",
		"key_length": %d
}`, keyType, keyLength)
	if label != "" {
		request += fmt.Sprintf(`,"label": "%s"`, label)
	}
	if keyTransferPolicy != "" {
		request += fmt.Sprintf(`,"transfer_policy_ID": "%s"`, keyTransferPolicy)
	}
	request = "{" + request + "}"

	client, err := httpclient.NewHttpClient(nil)
	if err != nil {
		return fmt.Errorf("Failed to prepare the request: %v", err)
	}
	header := map[string]string{
		"Authorization": "Bearer " + kbs.BearerToken,
		"Accept":        "application/json",
	}

	resp, status, err := client.Post(url, []byte(request), header)
	if err != nil {
		return fmt.Errorf("failed to initiate request: %v", err)
	}
	if status != http.StatusCreated {
		return fmt.Errorf("unexpected status code from server: %d (resp: %s)", status, string(resp))
	}

	fmt.Println(string(resp))
	return nil
}

// deleteKey deletes the key information registered with the KBS
// Arguments:
//
//	kbs: KBS client configuration
//	keyID: Identifier of the key to remove
func deleteKey(kbs *config.KbsConfig, keyID string) error {
	if keyID == "" {
		return fmt.Errorf("no key ID provided")
	}
	url := kbs.URL() + "/keys/" + keyID

	client, err := httpclient.NewHttpClient(nil)
	if err != nil {
		return err
	}

	header := map[string]string{
		"Authorization": "Bearer " + kbs.BearerToken,
		"Accept":        "application/json",
	}

	resp, status, err := client.Delete(url, header)
	if err != nil {
		return fmt.Errorf("failed to initiate the request: %v", err)
	}
	if status >= 300 {
		return fmt.Errorf("unexpected status return by the server '%d' (resp: %s)", status, string(resp))
	}

	fmt.Println(string(resp))
	return nil
}

// listKeys retrieves the key information registered with the KBS
// Arguments:
//
//	kbs: KBS client configuration
func listKeys(kbs *config.KbsConfig) error {
	url := kbs.URL() + "/keys" //?algorithm=RSA"

	client, err := httpclient.NewHttpClient(nil)
	if err != nil {
		return err
	}

	header := map[string]string{
		"Authorization": "Bearer " + kbs.BearerToken,
		"Accept":        "application/json",
	}
	resp, status, err := client.Get(url, header)
	if err != nil {
		return fmt.Errorf("Failed to execute request: %v", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("Server returned error status: %d (resp: %s)", status, string(resp))
	}

	fmt.Println(string(resp))
	return nil
}

// downloadCaCert Downloads the CA root certificate from the CMS.
// Arguments:
//
//	cmsUrl: CSM server url
//	cmsCertDigest: SHA-256 hash of the root certificate
//	outCaCertDir: Directory path to save the downloaded CMS CA certificate
func downloadCaCert(cmsURL, cmsCertDigest, outCaCertDir string) error {
	task := &setup.DownloadCMSCert{
		CaCertDirPath: outCaCertDir,
		ConsoleWriter: os.Stdout,
		CmsBaseURL:    cmsURL,
		TlsCertDigest: cmsCertDigest,
	}
	return task.Run()
}

// downloadCert Create a new RSA private key and requests CMS CA for signing a
// TLS client certificate.
// Arguments:
//
//	cmsURL: CSM server url
//	token: Bearer token to access CMS API
//	cn: Client common name to use for the certificate
//	sanList: Subject alternative names of the client used for the certificate
//	caCertDir: Directory path of the CMS ca certificate
//	outKeyFile: File path to save the newly created private key
//	outCertFile: File path to save the signed certificate
func downloadCert(cmsURL, token, cn, sanList, caCertDir, outKeyFile, outCertFile string) error {
	task := &setup.DownloadCert{
		CaCertDirPath: caCertDir,
		ConsoleWriter: os.Stdout,
		CmsBaseURL:    cmsURL,
		KeyFile:       outKeyFile,
		CertFile:      outCertFile,
		KeyAlgorithm:  "rsa",
		KeyLength:     3072,
		Subject: pkix.Name{
			CommonName: cn, //"skcuser",
		},
		SanList:     sanList,
		CertType:    "TLS-Client",
		BearerToken: token,
	}

	task.SetName("download-cert-tls", "TLS-Client")

	return task.Run()
}
