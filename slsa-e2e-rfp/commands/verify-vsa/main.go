// Package main implements the verify-vsa command.
package main

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	vsa "github.com/in-toto/attestation/go/predicates/vsa/v1"
	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
	"google.golang.org/protobuf/encoding/protojson"
)

// Inputs:
// 1. The final output artifact name on disk
// 2. The public key to verify the Policy VSA
// 3. The Policy VSA itself

const (
	// FIXME(trishankkarthik): Get these from user instead of hardcoding them.
	artifactPath     = "slsa-e2e-rfp/artifacts/sigstore-3.0.0.tgz"
	policyVSA        = "slsa-e2e-rfp/attestations/policy.64b5e39b.json"
	vsaPredicateType = "https://slsa.dev/verification_summary/v1"
)

// FIMXE(trishankkarthik): Read the public key from disk instead of hardcoding it.
var (
	policyVSAPubKey = &signerverifier.SSLibKey{
		KeyIDHashAlgorithms: []string{"sha256", "sha512"},
		KeyType:             "ed25519",
		KeyVal: signerverifier.KeyVal{
			Public: "1f81c9eedcb9325243706a10cd24cf672e5b6f31cd419a4976ea7b6c166181f9",
		},
		Scheme: "ed25519",
		KeyID:  "64b5e39bbf527b383a758f40501005c470df4d5463c3183486da1a04a0cce755",
	}
)

// TODO:
// [x] Verify the Policy VSA using the public key
// [x] Check that the artifact name and digest in the Policy VSA matches the artifact on disk
// [x] Check that the verification passed
// [x] Check that the verification time is not too long ago in the past
func main() {
	verifier, err := signerverifier.NewED25519SignerVerifierFromSSLibKey(policyVSAPubKey)
	if err != nil {
		panic(err)
	}

	envelopeVerifier, err := dsse.NewEnvelopeVerifier(verifier)
	if err != nil {
		panic(err)
	}

	envelopeBytes, err := os.ReadFile(policyVSA)
	if err != nil {
		panic(err)
	}

	envelope := &dsse.Envelope{}
	if err := json.Unmarshal(envelopeBytes, envelope); err != nil {
		panic(err)
	}

	acceptedKeys, err := envelopeVerifier.Verify(context.Background(), envelope)
	if err != nil {
		panic(err)
	}
	if len(acceptedKeys) != 1 {
		panic("expected exactly one accepted key")
	}
	fmt.Printf("Policy VSA verified by public key with ID %s\n", acceptedKeys[0].KeyID)

	payloadBytes, err := envelope.DecodeB64Payload()
	if err != nil {
		panic(err)
	}

	statement := &v1.Statement{}
	if err := protojson.Unmarshal(payloadBytes, statement); err != nil {
		panic(err)
	}
	if statement.PredicateType != vsaPredicateType {
		panic(fmt.Sprintf("expected predicate type %s, got %s", vsaPredicateType, statement.PredicateType))
	}

	artifactFile, err := os.Open(artifactPath)
	if err != nil {
		panic(err)
	}
	defer artifactFile.Close()

	hasher := sha512.New()
	if _, err := io.Copy(hasher, artifactFile); err != nil {
		panic(err)
	}
	artifactHash := hex.EncodeToString(hasher.Sum(nil))

	artifactBase := filepath.Base(artifactPath)
	found := false
	for _, subject := range statement.Subject {
		// If we have an artifact with the same name, we want the same digest.
		subjectHash := subject.Digest["sha2-512"]
		if subject.Name == artifactBase {
			if subjectHash != artifactHash {
				panic(fmt.Sprintf("artifact hash mismatch: expected %s, got %s", artifactHash, subject.Digest["sha2-512"]))
			}
			found = true
		}
		// And if we have an artifact with the same hash, we want the same name.
		if subjectHash == artifactHash {
			if subject.Name != artifactBase {
				panic(fmt.Sprintf("artifact name mismatch: expected %s, got %s", artifactBase, subject.Name))
			}
			found = true
		}
	}
	// So basically, we guarantee there is only one subject with the same name and digest.
	if !found {
		panic("artifact hash not found in statement subjects")
	}
	fmt.Println("Artifact name", artifactBase, "and hash", artifactHash, "is one of the subjects of the Policy VSA")

	predicateBytes, err := protojson.Marshal(statement.Predicate)
	if err != nil {
		panic(err)
	}

	vsaPredicate := &vsa.VerificationSummary{}
	if err := protojson.Unmarshal(predicateBytes, vsaPredicate); err != nil {
		panic(err)
	}

	if vsaPredicate.VerificationResult != "PASSED" {
		panic("policy vsa verification did not pass: " + vsaPredicate.VerificationResult)
	}
	fmt.Println("Policy VSA verification: PASSED")

	verificationTime := vsaPredicate.TimeVerified.AsTime()
	maxAge := 24 * time.Hour
	if time.Since(verificationTime) > maxAge {
		panic(fmt.Sprintf("Policy VSA is too old: verified at %s", verificationTime))
	}
	fmt.Println("Policy VSA is timely: less than a day old")
}
