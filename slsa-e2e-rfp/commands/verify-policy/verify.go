package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/in-toto/attestation-verifier/verifier"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func sha256Hash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

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

	attestationsDirEntries, err := os.ReadDir(attestationsDir)
	if err != nil {
		return nil, err
	}

	attestations := map[string]*dsse.Envelope{}
	for _, attestationDirEntry := range attestationsDirEntries {
		filename := attestationDirEntry.Name()
		// FIXME: Terrible hack to skip the policy VSA, but whatever, it works for now.
		if strings.HasPrefix(filename, "policy.") && strings.HasSuffix(filename, ".json") {
			continue
		}
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
