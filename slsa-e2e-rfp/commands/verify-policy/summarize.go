package main

import (
	"context"
	"io"
	"strings"

	"github.com/in-toto/attestation-verifier/slsa-e2e-rfp/probes"
	vsa "github.com/in-toto/attestation/go/predicates/vsa/v1"
	att "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func summarize(ctx context.Context, prng io.Reader, fileStore *probes.FileStore, layoutPath string, hashes map[string]string, subject *att.ResourceDescriptor, verificationErr error) error {
	var verificationResult string
	if verificationErr != nil {
		verificationResult = "FAILED"
	} else {
		verificationResult = "PASSED"
	}

	inputAttestations := []*vsa.VerificationSummary_InputAttestation{}
	for filename, hash := range hashes {
		// FIXME: Terrible hack to skip adding parameters and policies as attestations, but whatever, it works.
		if strings.Contains(filename, "/parameters/") || strings.Contains(filename, "/policies/") {
			continue
		}
		inputAttestations = append(inputAttestations, &vsa.VerificationSummary_InputAttestation{
			Uri: filename,
			Digest: map[string]string{
				"sha2-256": hash,
			},
		})
	}

	predicate := &vsa.VerificationSummary{
		Verifier: &vsa.VerificationSummary_Verifier{
			Id: "https://github.com/in-toto/attestation-verifier",
		},
		TimeVerified: timestamppb.Now(),
		// FIXME(trishankkarthik): Add the parameters here under policy.
		Policy: &vsa.VerificationSummary_Policy{
			Uri: layoutPath,
			Digest: map[string]string{
				"sha2-256": hashes[layoutPath],
			},
		},
		InputAttestations:  inputAttestations,
		VerificationResult: verificationResult,
		VerifiedLevels:     []string{
			"SLSA_SOURCE_LEVEL_3",
			"SLSA_BUILD_LEVEL_3",
		},
	}

	// FIXME(trishankkarthik): Write the pubkey to disk also so we can verify the Policy VSA.
	return attestWithProbe(ctx, prng, fileStore, "policy", vsaPredicateType, predicate, subject)
}
