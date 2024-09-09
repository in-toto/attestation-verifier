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
	subject         string
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
		&subject,
		"subject",
		"s",
		"",
		"subject can either be purl for package or <alg>:<digest> for an artifact",
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

	rootCmd.Flags().BoolVar(
		&saveAttestation,
		"save-attestation",
		false,
		"flag to save the retrieved attestation from GUAC server",
	)
}

func verify(cmd *cobra.Command, args []string) error {

	key := &in_toto.Key{}
	var err error

	// maps stepname with subject
	subjectStepMap := make(map[string]string, 0)
	if subject != "" {
		subjectStepMap[""] = subject
	}

	layout := &verifier.Layout{}
	if len(layoutPath) > 0 {
		if layout, err = verifier.LoadLayout(layoutPath); err != nil {
			return err
		}	

		// getting subjects from layout
		for _, step := range layout.Steps {
			if step.FromGUAC {
				if len(step.Subject) > 0 {
					subjectStepMap[step.Name] = step.Subject
				}
			}
		}
	}

	// loading private key if available else creating one
	if len(keyPath) != 0 || len(subjectStepMap) != 0 {
		key, err = utils.LoadPrivateKey(keyPath)
		if err != nil {
			return err
		}

		// adding key as functionary for attestation that are being retrieved from guac
		if len(layout.Steps) != 0 {
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
						step.ExpectedPredicates[i].Functionaries = append(expectedPredicate.Functionaries, key.KeyID)
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
	if len(subjectStepMap) != 0 {
		statements := parsers.GetAttestationFromPURL(subjectStepMap, graphqlEndpoint)
		retrievedAttestation, err := utils.WrapEnvelope(statements, key)
		if err != nil {
			return err
		}

		if saveAttestation {
			return utils.SaveAttestation(retrievedAttestation)
		}

		for name, attestation := range retrievedAttestation {
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
