// Package main implements the verify-policy command.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"os"

	"github.com/in-toto/attestation-verifier/slsa-e2e-rfp/probes"
	att "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/proto"
)

const (
	attestationsDir  = "slsa-e2e-rfp/attestations"
	prngSeed         = 42
	vsaPredicateType = "https://slsa.dev/verification_summary/v1"
)

func attestWithProbe(ctx context.Context, prng io.Reader, fileStore *probes.FileStore, stepName, predicateType string, predicate proto.Message, subject *att.ResourceDescriptor) error {
	probe, err := probes.NewProbeWithSigner(prng, fileStore)
	if err != nil {
		return err
	}
	return probe.Attest(ctx, stepName, predicateType, predicate, subject)
}

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

// TODO:
// - Attestations are not all linked right now (e.g., build has nothing to do with source).
func main() {
	ctx := context.Background()
	prng := rand.New(rand.NewSource(prngSeed))
	fileStore := probes.NewFileStore(attestationsDir)

	fmt.Println("Generating the Source Verification Summary Attestation (VSA)...")
	if err := source(ctx, prng, fileStore); err != nil {
		panic(err)
	}
	fmt.Print("...done.\n\n")

	fmt.Println("Generating the Build Provenance Attestation...")
	if err := build(ctx, prng, fileStore); err != nil {
		panic(err)
	}
	fmt.Print("...done.\n\n")

	fmt.Println("Generating the Release Attestation...")
	if err := release(ctx, prng, fileStore); err != nil {
		panic(err)
	}
	fmt.Print("...done.\n\n")
}
