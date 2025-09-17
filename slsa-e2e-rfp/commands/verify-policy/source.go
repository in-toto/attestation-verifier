package main

import (
	"context"
	"io"

	"github.com/in-toto/attestation-verifier/slsa-e2e-rfp/probes"
	vsa "github.com/in-toto/attestation/go/predicates/vsa/v1"
	att "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// https://slsa.dev/spec/v1.2-rc1/source-requirements#source-verification-summary-attestation
func source(ctx context.Context, prng io.Reader, fileStore *probes.FileStore) error {
	predicate := &vsa.VerificationSummary{
		Verifier: &vsa.VerificationSummary_Verifier{
			Id: "https://example.com/source_verifier",
		},
		TimeVerified: &timestamppb.Timestamp{
			Seconds: 482196050,
			Nanos:   520000000,
		},
		ResourceUri: "git+https://github.com/foo/hello-world",
		Policy: &vsa.VerificationSummary_Policy{
			Uri: "https://example.com/slsa_source.policy",
		},
		VerificationResult: "PASSED",
		VerifiedLevels:     []string{"SLSA_SOURCE_LEVEL_3"},
	}

	annnotations, err := structpb.NewStruct(map[string]any{
		"source_refs": []any{"refs/heads/main", "refs/heads/release_1.0"},
	})
	if err != nil {
		return err
	}
	subject := &att.ResourceDescriptor{
		Uri: "https://github.com/foo/hello-world/commit/9a04d1ee393b5be2773b1ce204f61fe0fd02366a",
		Digest: map[string]string{
			"gitCommit": "9a04d1ee393b5be2773b1ce204f61fe0fd02366a",
		},
		Annotations: annnotations,
	}

	return attestWithProbe(ctx, prng, fileStore, "source", vsaPredicateType, predicate, subject)
}
