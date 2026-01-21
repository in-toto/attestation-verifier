package main

import (
	"context"
	"io"

	"github.com/in-toto/attestation-verifier/slsa-e2e-rfp/probes"
	prv "github.com/in-toto/attestation/go/predicates/provenance/v1"
	att "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// Mocked after: https://search.sigstore.dev/?logIndex=139985224
func build(ctx context.Context, prng io.Reader, fileStore *probes.FileStore) error {
	externalParameters, err := structpb.NewStruct(map[string]any{
		"workflow": map[string]any{
			"ref":        "refs/heads/main",
			"repository": "https://github.com/sigstore/sigstore-js",
			"path":       ".github/workflows/release.yml",
		},
	})
	if err != nil {
		return err
	}

	internalParameters, err := structpb.NewStruct(map[string]any{
		"github": map[string]any{
			"event_name":          "push",
			"repository_id":       "495574555",
			"repository_owner_id": "71096353",
		},
	})
	if err != nil {
		return err
	}

	resolvedDependencies := []*att.ResourceDescriptor{
		{
			Uri: "git+https://github.com/sigstore/sigstore-js/commit/3a57a741bfb9f7c3bca69b63e170fc28e9432e69",
			Digest: map[string]string{
				"gitCommit": "3a57a741bfb9f7c3bca69b63e170fc28e9432e69",
			},
		},
	}

	buildDefinition := prv.BuildDefinition{
		BuildType:            "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
		ExternalParameters:   externalParameters,
		InternalParameters:   internalParameters,
		ResolvedDependencies: resolvedDependencies,
	}

	runDetails := prv.RunDetails{
		Builder: &prv.Builder{
			Id: "https://github.com/actions/runner/github-hosted",
		},
		Metadata: &prv.BuildMetadata{
			InvocationId: "https://github.com/sigstore/sigstore-js/actions/runs/11331290387/attempts/1",
		},
	}

	predicateType := "https://slsa.dev/provenance/v1"
	predicate := &prv.Provenance{
		BuildDefinition: &buildDefinition,
		RunDetails:      &runDetails,
	}

	subject := &att.ResourceDescriptor{
		Name: "sigstore-3.0.0.tgz",
		// TODO: Actually, this raises the question: should MATCH compare URIs for equality, too?
		Digest: map[string]string{
			"sha2-512": "3c73227e187710de25a0c7070b3ea5deffe5bb3813df36bef5ff2cb9b1a078c3636c98f31f8223fd8a17dc6beefa46a8b894489557531c70911000d87fe66d78",
		},
	}

	return attestWithProbe(ctx, prng, fileStore, "build", predicateType, predicate, subject)
}
