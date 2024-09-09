package utils

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/helpers"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
	log "github.com/sirupsen/logrus"
)

// SaveAttestation saves the attestations retrieved from Guac
func SaveAttestation(attestations map[string]*dsse.Envelope) error {
	dir := "attestations"
	log.Infof("Creating Directory %s...", dir)

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		reader := bufio.NewReader(os.Stdin)

		log.Printf("Directory %s already exists. Do you want to proceed? (y/n): ", dir)
		answer, _ := reader.ReadString('\n')

		answer = strings.TrimSpace(answer)
		answer = strings.ToLower(answer)

		if answer != "y" && answer != "yes" {
			log.Info("Operation aborted by the user.")
			return nil
		}

		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return err
	}

	for name, attestation := range attestations {
		fPath := filepath.Join(dir, name+".json")
		jsonData, err := json.MarshalIndent(attestation, "", "  ")
		if err != nil {
			return err
		}
		err = os.WriteFile(fPath, jsonData, os.ModePerm)
		if err != nil {
			return err
		}
		log.Infof("%s saved to %s\n", name, fPath)
	}

	return nil
}

// ParseSubjectName parses subject name from purl
func ParseSubjectName(subject string) string {
	genericPrefix := "pkg:guac/generic/"
	if strings.HasPrefix(subject, genericPrefix) {
		return strings.TrimPrefix(subject, genericPrefix)
	}
	if pkg, err := helpers.PurlToPkg(subject); err == nil {
		return pkg.Name
	}
	return subject
}

// WrapEnvelope wrap the dsse envelopse on attestations
func WrapEnvelope(statements map[string]*attestationv1.Statement, key *in_toto.Key) (map[string]*dsse.Envelope, error) {
	attestations := map[string]*dsse.Envelope{}
	for stepName, statement := range statements {
		env := &dsse.Envelope{}
		encodedBytes, err := cjson.EncodeCanonical(statement)
		if err != nil {
			return nil, err
		}

		env = &dsse.Envelope{
			Payload:     base64.StdEncoding.EncodeToString(encodedBytes),
			PayloadType: in_toto.PayloadType,
		}

		if !reflect.ValueOf(key).IsZero() {
			signer, err := getSignerVerifierFromKey(*key)
			if err != nil {
				return nil, err
			}

			es, err := dsse.NewEnvelopeSigner(signer)
			if err != nil {
				return nil, err
			}

			payload, err := env.DecodeB64Payload()
			if err != nil {
				return nil, err
			}

			env, err = es.SignPayload(context.Background(), env.PayloadType, payload)
			if err != nil {
				return nil, err
			}
		}
		predicateFormat := "%s.%.8s"
		stepName = fmt.Sprintf(predicateFormat, stepName, key.KeyID)
		attestations[stepName] = env
	}
	return attestations, nil
}

func getSignerVerifierFromKey(key in_toto.Key) (dsse.SignerVerifier, error) {
	sslibKey := signerverifier.SSLibKey{
		KeyType:             key.KeyType,
		KeyIDHashAlgorithms: key.KeyIDHashAlgorithms,
		KeyID:               key.KeyID,
		Scheme:              key.Scheme,
		KeyVal: signerverifier.KeyVal{
			Public:      key.KeyVal.Public,
			Private:     key.KeyVal.Private,
			Certificate: key.KeyVal.Certificate,
		},
	}

	switch sslibKey.KeyType {
	case signerverifier.RSAKeyType:
		return signerverifier.NewRSAPSSSignerVerifierFromSSLibKey(&sslibKey)
	case signerverifier.ED25519KeyType:
		return signerverifier.NewED25519SignerVerifierFromSSLibKey(&sslibKey)
	case signerverifier.ECDSAKeyType:
		return signerverifier.NewECDSASignerVerifierFromSSLibKey(&sslibKey)
	}

	return nil, fmt.Errorf("unsupported key type")
}

// Load private key from path or generate one if path is not provided
func LoadPrivateKey(keyPath string) (*in_toto.Key, error) {
	key := &in_toto.Key{}
	if len(keyPath) > 0 {
		if _, err := os.Stat(keyPath); err == nil {
			if err := key.LoadKeyDefaults(keyPath); err != nil {
				return nil, fmt.Errorf("invalid key at %s: %w", keyPath, err)
			}
		} else {
			return nil, fmt.Errorf("key not found at %s: %w", keyPath, err)
		}
		return key, nil
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("Error generating ECDSA private key:", err)
		return nil, err
	}
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		fmt.Println("Error marshaling ECDSA private key:", err)
		return nil, err
	}
	privateKeyPem := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privateKeyPemBytes := pem.EncodeToMemory(privateKeyPem)
	tempFile, err := os.CreateTemp("", "ecdsa_private_key_*.pem")
	if err != nil {
		fmt.Println("Error creating temporary file:", err)
		return nil, err
	}
	defer os.Remove(tempFile.Name())
	if _, err := tempFile.Write(privateKeyPemBytes); err != nil {
		fmt.Println("Error writing to temporary file:", err)
		return nil, err
	}
	key.LoadKeyDefaults(tempFile.Name())

	return key, nil
}
