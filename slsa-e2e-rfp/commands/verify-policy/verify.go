package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/in-toto/attestation-verifier/verifier"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func verify(layoutPath, attestationsDir, parametersPath string) (map[string]string, error) {
	hashes := make(map[string]string)

	layout, err := verifier.LoadLayout(layoutPath)
	if err != nil {
		return nil, err
	}

	// FIXME: Silly to read the files agai just to hash it; do it instead when loading the layout.
	layoutPathHash, err := sha256Hash(layoutPath)
	if err != nil {
		return nil, err
	}
	hashes[layoutPath] = layoutPathHash

	dirEntries, err := os.ReadDir(attestationsDir)
	if err != nil {
		return nil, err
	}

	attestations := map[string]*dsse.Envelope{}
	for _, dirEntry := range dirEntries {
		filename := dirEntry.Name()
		filePath := filepath.Join(attestationsDir, filename)

		envelopeBytes, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}

		envelope := &dsse.Envelope{}
		if err := json.Unmarshal(envelopeBytes, envelope); err != nil {
			return nil, err
		}
		attestations[strings.TrimSuffix(filename, ".json")] = envelope

		attestationHash, err := sha256Hash(filePath)
		if err != nil {
			return nil, err
		}
		hashes[filePath] = attestationHash
	}

	parameters := map[string]string{}
	parametersBytes, err := os.ReadFile(parametersPath)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(parametersBytes, &parameters); err != nil {
		return nil, err
	}

	parametersHash, err := sha256Hash(parametersPath)
	if err != nil {
		return nil, err
	}
	hashes[parametersPath] = parametersHash

	return hashes, verifier.Verify(layout, attestations, parameters)
}
