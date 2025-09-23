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
	attestationsDir = "slsa-e2e-rfp/attestations"
	parametersPath  = "slsa-e2e-rfp/parameters/source-build-release.json"
	policyPath      = "slsa-e2e-rfp/policies/source-build-release.yaml"
	// Fixed seed for reproducibility of attestation signing keys.
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
	subject, err := release(ctx, prng, fileStore)
	if err != nil {
		panic(err)
	}
	fmt.Print("...done.\n\n")

	fmt.Println("Verifying Attestations against Policy...")
	// FIXME: Get policy, attestations, and parameters from user instead of harcoding them.
	hashes, err := verify(policyPath, attestationsDir, parametersPath)
	fmt.Print("...done.\n\n")

	fmt.Println("Generating the Policy VSA...")
	err = summarize(ctx, prng, fileStore, policyPath, hashes, subject, err)
	if err != nil {
		panic(err)
	}
	fmt.Print("...done.\n")
}
