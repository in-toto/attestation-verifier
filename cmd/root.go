package cmd

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/adityasaky/ite-10-verifier/verifier"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
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

	rootCmd.MarkFlagRequired("layout")
	rootCmd.MarkFlagRequired("attestations-directory")
}

func verify(cmd *cobra.Command, args []string) error {
	layout, err := verifier.LoadLayout(layoutPath)
	if err != nil {
		return err
	}

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
		attestation := &attestationv1.Statement{}
		if err := json.Unmarshal(ab, attestation); err != nil {
			return err
		}
		encodedBytes, err := cjson.EncodeCanonical(attestation)
		if err != nil {
			return err
		}
		envelope := &dsse.Envelope{
			Payload:     base64.StdEncoding.EncodeToString(encodedBytes),
			PayloadType: "application/vnd.in-toto+json",
		}

		attestations[strings.TrimSuffix(name, ".json")] = envelope
	}

	return verifier.Verify(layout, attestations)
}
