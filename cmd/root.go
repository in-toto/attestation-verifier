package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/adityasaky/ite-10-verifier/verifier"
	attestationv1 "github.com/in-toto/attestation/go/v1"
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

	attestations := []*attestationv1.Statement{}
	for _, e := range dirEntries {
		ab, err := os.ReadFile(filepath.Join(attestationsDir, e.Name()))
		if err != nil {
			return err
		}
		attestation := &attestationv1.Statement{}
		if err := json.Unmarshal(ab, attestation); err != nil {
			return err
		}
		attestations = append(attestations, attestation)
	}

	return verifier.Verify(layout, attestations)
}
