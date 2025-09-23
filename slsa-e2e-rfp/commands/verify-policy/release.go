package main

import (
	"context"
	"io"

	"github.com/in-toto/attestation-verifier/slsa-e2e-rfp/probes"
	rel "github.com/in-toto/attestation/go/predicates/release/v0"
	att "github.com/in-toto/attestation/go/v1"
)

func release(ctx context.Context, prng io.Reader, fileStore *probes.FileStore) (*att.ResourceDescriptor, error) {
	predicateType := "https://in-toto.io/attestation/release/v0.1"
	releaseID := "1234567890"
	predicate := &rel.Release{
		//Purl:      "pkg:npm/sigstore@3.0.0",
		ReleaseId: &releaseID,
	}

	subject := &att.ResourceDescriptor{
		// FIXME: What should be the artifact name in build and release? The filenames or the PURL?
		//Name: "sigstore-3.0.0.tgz",
		Name: "pkg:npm/sigstore@3.0.0",
		Digest: map[string]string{
			"sha512": "3c73227e187710de25a0c7070b3ea5deffe5bb3813df36bef5ff2cb9b1a078c3636c98f31f8223fd8a17dc6beefa46a8b894489557531c70911000d87fe66d78",
		},
	}

	err := attestWithProbe(ctx, prng, fileStore, "release", predicateType, predicate, subject)
	if err != nil {
		return nil, err
	}
	return subject, nil
}
