package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/in-toto/attestation-verifier/utils"
	"github.com/in-toto/attestation-verifier/verifier"
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
		"attestation-for",
		"p",
		"",
		"PURL for package",
	)

	rootCmd.Flags().StringVarP(
		&graphqlEndpoint,
		"attestations-from",
		"g",
		"http://localhost:8080/query",
		"endpoint used to connect to GUAC server (default: http://localhost:8080/query)",
	)

	rootCmd.MarkFlagRequired("layout")
}

func verify(cmd *cobra.Command, args []string) error {
	layout, err := verifier.LoadLayout(layoutPath)
	if err != nil {
		return err
	}

	if purl != "" {
		utils.GetAttestationFromPURL(purl, graphqlEndpoint)
	} else if attestationsDir != "" {
		dirEntries, err := os.ReadDir(attestationsDir)
		if err != nil {
			return err
		}
	
		attestations := map[string]*dsse.Envelope{}
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

		return verifier.Verify(layout, attestations, parameters)
	}

	return fmt.Errorf("either purl[-p] or attestation-directory[-a] required for verification")
}
