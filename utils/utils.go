package utils

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/cli"
	attestationv1 "github.com/in-toto/attestation/go/v1"
)

type neighbors struct {
	occurrences []*model.NeighborsNeighborsIsOccurrence
	hasSLSAs    []*model.NeighborsNeighborsHasSLSA
	hasSBOMs    []*model.NeighborsNeighborsHasSBOM
}

func GetAttestationFromPURL(purl, graphqlEndpoint string) []*attestationv1.Statement {
	ctx := context.Background()
	httpClient := http.Client{Transport: cli.HTTPHeaderTransport(ctx, "", http.DefaultTransport)}
	gqlclient := graphql.NewClient(graphqlEndpoint, &httpClient)

	pkgInput, err := helpers.PurlToPkg(purl)
	if err != nil {
		log.Fatalf("failed to parse PURL: %v", err)
	}

	pkgQualifierFilter := []model.PackageQualifierSpec{}
	for _, qualifier := range pkgInput.Qualifiers {
		qualifier := qualifier
		pkgQualifierFilter = append(pkgQualifierFilter, model.PackageQualifierSpec{
			Key:   qualifier.Key,
			Value: &qualifier.Value,
		})
	}

	pkgFilter := &model.PkgSpec{
		Type:       &pkgInput.Type,
		Namespace:  pkgInput.Namespace,
		Name:       &pkgInput.Name,
		Version:    pkgInput.Version,
		Subpath:    pkgInput.Subpath,
		Qualifiers: pkgQualifierFilter,
	}
	pkgResponse, err := model.Packages(ctx, gqlclient, *pkgFilter)
	if err != nil {
		log.Fatalf("error querying for package: %v", err)
	}
	if len(pkgResponse.Packages) != 1 {
		log.Fatalf("failed to locate the package based on purl")
	}

	pkgNameNeighbors, err := queryKnownNeighbors(ctx, gqlclient, pkgResponse.Packages[0].Namespaces[0].Names[0].Id)
	if err != nil {
		log.Fatalf("error querying for package name neighbors: %v", err)
	}

	statements := make([]*attestationv1.Statement, 0)

	sta, err := getAttestation(ctx, gqlclient, pkgNameNeighbors)
	if err != nil {
		log.Fatalf("error occured while collecting attestations, %+v", err)
	}
	statements = append(statements, sta...)

	pkgVersionNeighbors, err := queryKnownNeighbors(ctx, gqlclient, pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id)
	if err != nil {
		log.Fatalf("error querying for package version neighbors: %v", err)
	}

	sta, err = getAttestation(ctx, gqlclient, pkgVersionNeighbors)
	if err != nil {
		log.Fatalf("Error occured while collecting attestations, %+v", err)
	}
	statements = append(statements, sta...)

	for i := range statements {
		log.Printf("\nAttestaion: %+v\n", statements[i])
	}

	return statements
}

func queryKnownNeighbors(ctx context.Context, gqlclient graphql.Client, subjectQueryID string) (*neighbors, error) {
	collectedNeighbors := &neighbors{}
	neighborResponse, err := model.Neighbors(ctx, gqlclient, subjectQueryID, []model.Edge{})
	if err != nil {
		return nil, fmt.Errorf("error querying neighbors: %v", err)
	}
	for _, neighbor := range neighborResponse.Neighbors {
		switch v := neighbor.(type) {
		case *model.NeighborsNeighborsHasSLSA:
			collectedNeighbors.hasSLSAs = append(collectedNeighbors.hasSLSAs, v)
		case *model.NeighborsNeighborsIsOccurrence:
			collectedNeighbors.occurrences = append(collectedNeighbors.occurrences, v)
		case *model.NeighborsNeighborsHasSBOM:
			collectedNeighbors.hasSBOMs = append(collectedNeighbors.hasSBOMs, v)
		default:
			continue
		}
	}
	return collectedNeighbors, nil
}

func getAttestation(ctx context.Context, gqlclient graphql.Client, collectedNeighbors *neighbors) ([]*attestationv1.Statement, error) {
	statements := make([]*attestationv1.Statement, 0)

	for _, sbom := range collectedNeighbors.hasSBOMs {
		sta, err := ParseSbomAttestation(sbom)
		if err != nil {
			return nil, err
		}
		statements = append(statements, sta)
	}

	if len(collectedNeighbors.hasSLSAs) > 0 {
		for _, slsa := range collectedNeighbors.hasSLSAs {
			sta, err := ParseSlsaAttestation(slsa)
			if err != nil {
				return nil, err
			}
			statements = append(statements, sta)
		}
	} else {
		for _, occurrence := range collectedNeighbors.occurrences {
			artifactFilter := &model.ArtifactSpec{
				Algorithm: &occurrence.Artifact.Algorithm,
				Digest:    &occurrence.Artifact.Digest,
			}
			artifactResponse, err := model.Artifacts(ctx, gqlclient, *artifactFilter)
			if err != nil {
				log.Printf("error querying for artifacts: %v", err)
				return nil, err
			}
			if len(artifactResponse.Artifacts) != 1 {
				log.Printf("failed to located artifacts based on (algorithm:digest)")
				return nil, err
			}
			neighborResponseHasSLSA, err := model.Neighbors(ctx, gqlclient, artifactResponse.Artifacts[0].Id, []model.Edge{model.EdgeArtifactHasSlsa})
			if err != nil {
				log.Printf("error querying neighbors: %v", err)
				return nil, err
			}

			for _, neighborHasSLSA := range neighborResponseHasSLSA.Neighbors {
				if hasSLSA, ok := neighborHasSLSA.(*model.NeighborsNeighborsHasSLSA); ok {
					sta, err := ParseSlsaAttestation(hasSLSA)
					if err != nil {
						return nil, err
					}
					statements = append(statements, sta)
				}
			}
		}
	}
	return statements, nil
}
