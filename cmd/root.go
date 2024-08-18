package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/in-toto/attestation-verifier/parsers"
	"github.com/in-toto/attestation-verifier/utils"
	"github.com/in-toto/attestation-verifier/verifier"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:  "ite-10-verifier",
	RunE: verify,
}

var (
	layoutPath      string
	attestationsDir string
	parametersPath  string
	graphqlEndpoint string
	purl            string
	hash            string
	keyPath         string
	saveAttestation bool
)

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(
		&layoutPath,
		"layout",
		"l",
		"",
		"Layout to use for verification",
	)

	rootCmd.Flags().StringVarP(
		&attestationsDir,
		"attestations-directory",
		"a",
		"",
		"Directory to load attestations from",
	)

	rootCmd.Flags().StringVar(
		&parametersPath,
		"substitute-parameters",
		"",
		"Path to JSON file containing key-value string pairs for parameter substitution in the layout",
	)

	rootCmd.Flags().StringVarP(
		&purl,
		"purl",
		"p",
		"",
		"PURL for package",
	)

	rootCmd.Flags().StringVarP(
		&hash,
		"hash",
		"d",
		"",
		"Hash of the artifact <alg>:<digest>",
	)

	rootCmd.Flags().StringVarP(
		&graphqlEndpoint,
		"attestations-from",
		"g",
		"http://localhost:8080/query",
		"endpoint used to connect to GUAC server (default: http://localhost:8080/query)",
	)

	rootCmd.Flags().StringVarP(
		&keyPath,
		"key",
		"k",
		"",
		"Path to a PEM formatted private key file",
	)

	rootCmd.Flags().BoolVarP(
		&saveAttestation,
		"save-attestation",
		"s",
		false,
		"flag to save the retrieved attestation from GUAC server",
	)

	rootCmd.MarkFlagsMutuallyExclusive("purl", "hash")
}

func verify(cmd *cobra.Command, args []string) error {

	key := &in_toto.Key{}
	var err error
	if len(keyPath) != 0 || len(purl) != 0 || len(hash) != 0 {
		key, err = utils.LoadPrivateKey(keyPath)
		if err != nil {
			return err
		}
	}

	layout := &verifier.Layout{}
	if len(layoutPath) > 0 {
		if layout, err = verifier.LoadLayout(layoutPath); err != nil {
			return err
		}
		if key.KeyID != "" {
			// adding functionary for attestations retrieved from GUAC
			a := verifier.Functionary{}
			a.KeyID = key.KeyID
			a.KeyIDHashAlgorithms = key.KeyIDHashAlgorithms
			a.KeyType = key.KeyType
			a.KeyVal = verifier.KeyVal{
				Public: key.KeyVal.Public,
			}
			a.Scheme = key.Scheme

			layout.Functionaries[key.KeyID] = a

			for _, step := range layout.Steps {
				if step.FromGUAC {
					for i, expectedPredicate := range step.ExpectedPredicates {
						functionaries := append(expectedPredicate.Functionaries, key.KeyID)
						step.ExpectedPredicates[i].Functionaries = functionaries
					}
				}
			}
		}
	}

	parameters := map[string]string{}
	if len(parametersPath) > 0 {
		contents, err := os.ReadFile(parametersPath)
		if err != nil {
			return err
		}

		if err := json.Unmarshal(contents, &parameters); err != nil {
			return err
		}
	}

	attestations := map[string]*dsse.Envelope{}
	if purl != "" || hash != "" {
		statements := parsers.GetAttestationFromPURL(purl, hash, graphqlEndpoint)
		aa, err := utils.WrapEnvelope(statements, key)
		if err != nil {
			return err
		}

		if saveAttestation {
			return utils.SaveAttestation(aa)
		}

		for name, attestation := range aa {
			attestations[name] = attestation
		}
	}
	if attestationsDir != "" {
		dirEntries, err := os.ReadDir(attestationsDir)
		if err != nil {
			return err
		}

		for _, e := range dirEntries {
			name := e.Name()
			ab, err := os.ReadFile(filepath.Join(attestationsDir, name))
			if err != nil {
				return err
			}
			// attestation := &attestationv1.Statement{}
			// if err := json.Unmarshal(ab, attestation); err != nil {
			// 	return err
			// }
			// encodedBytes, err := cjson.EncodeCanonical(attestation)
			// if err != nil {
			// 	return err
			// }
			// envelope := &dsse.Envelope{
			// 	Payload:     base64.StdEncoding.EncodeToString(encodedBytes),
			// 	PayloadType: "application/vnd.in-toto+json",
			// }
			envelope := &dsse.Envelope{}
			if err := json.Unmarshal(ab, envelope); err != nil {
				return err
			}

			attestations[strings.TrimSuffix(name, ".json")] = envelope
		}
	}

	return verifier.Verify(layout, attestations, parameters)
}
