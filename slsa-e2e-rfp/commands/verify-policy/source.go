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
			Id: "https://github.com/gittuf/gittuf",
		},
		TimeVerified: &timestamppb.Timestamp{
			Seconds: 482196050,
			Nanos:   520000000,
		},
		ResourceUri: "git+https://github.com/sigstore/sigstore-js",
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
		Uri: "https://github.com/sigstore/sigstore-js/commit/3a57a741bfb9f7c3bca69b63e170fc28e9432e69",
		Digest: map[string]string{
			"gitCommit": "3a57a741bfb9f7c3bca69b63e170fc28e9432e69",
		},
		Annotations: annnotations,
	}

	return attestWithProbe(ctx, prng, fileStore, "source", vsaPredicateType, predicate, subject)
}
