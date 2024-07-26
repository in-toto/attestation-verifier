package parsers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/cli"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
)

type neighbors struct {
	occurrences []*model.NeighborsNeighborsIsOccurrence
	hasSLSAs    []*model.NeighborsNeighborsHasSLSA
	hasSBOMs    []*model.NeighborsNeighborsHasSBOM
	vexLinks    []*model.NeighborsNeighborsCertifyVEXStatement
}

func GetAttestationFromPURL(purl, graphqlEndpoint string) map[string]*attestationv1.Statement {
	log.Info("Retrieving attestations from GUAC graphql endpoint.")
	statements := make(map[string]*attestationv1.Statement, 0)

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

	sta, err := getAttestation(ctx, gqlclient, pkgNameNeighbors)
	if err != nil {
		log.Fatalf("error occured while collecting attestations, %+v", err)
	}
	for k, v := range sta {
		statements[k] = v
	}

	pkgVersionNeighbors, err := queryKnownNeighbors(ctx, gqlclient, pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[0].Id)
	if err != nil {
		log.Fatalf("error querying for package version neighbors: %v", err)
	}

	sta, err = getAttestation(ctx, gqlclient, pkgVersionNeighbors)
	if err != nil {
		log.Fatalf("Error occured while collecting attestations, %+v", err)
	}
	for k, v := range sta {
		statements[k] = v
	}

	log.Info("Done.")
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
		case *model.NeighborsNeighborsCertifyVEXStatement:
			collectedNeighbors.vexLinks = append(collectedNeighbors.vexLinks, v)
		default:
			continue
		}
	}
	return collectedNeighbors, nil
}

func getAttestation(ctx context.Context, gqlclient graphql.Client, collectedNeighbors *neighbors) (map[string]*attestationv1.Statement, error) {
	statements := make(map[string]*attestationv1.Statement)
	statementSet := make(map[string]*attestationv1.Statement)
	if len(collectedNeighbors.hasSBOMs) > 0 {
		for _, sbom := range collectedNeighbors.hasSBOMs {
			sbomName := getAttestationName(sbom.Origin)
			sta, err := ParseSbomAttestation(ctx, gqlclient, sbom, collectedNeighbors.vexLinks)
			if err != nil {
				return nil, err
			}
			dup, err := checkRepeatedAttestations(statementSet, sta)
			if err != nil {
				return nil, err
			}
			if !dup {
				statements[sbomName] = sta
			}
		}
	} else {
		// if there is an isOccurrence, check to see if there are sbom associated with it
		for _, occurrence := range collectedNeighbors.occurrences {
			neighborResponseHasSBOM, err := getAssociatedArtifact(ctx, gqlclient, occurrence, model.EdgeArtifactHasSbom)
			if err != nil {
				log.Fatalf("error querying neighbors: %v", err)
			} else {
				for _, neighborHasSBOM := range neighborResponseHasSBOM.Neighbors {
					if hasSBOM, ok := neighborHasSBOM.(*model.NeighborsNeighborsHasSBOM); ok {
						sbomName := getAttestationName(hasSBOM.Origin)
						sta, err := ParseSbomAttestation(ctx, gqlclient, hasSBOM, collectedNeighbors.vexLinks)
						if err != nil {
							return nil, err
						}
						dup, err := checkRepeatedAttestations(statementSet, sta)
						if err != nil {
							return nil, err
						}
						if !dup {
							statements[sbomName] = sta
						}
					}
				}
			}
		}
	}

	if len(collectedNeighbors.hasSLSAs) > 0 {
		for _, slsa := range collectedNeighbors.hasSLSAs {
			slsaName := getAttestationName(slsa.Slsa.Origin)
			sta, err := ParseSlsaAttestation(slsa)
			if err != nil {
				return nil, err
			}
			dup, err := checkRepeatedAttestations(statementSet, sta)
			if err != nil {
				return nil, err
			}
			if !dup {
				statements[slsaName] = sta
			}
		}
	} else {
		for _, occurrence := range collectedNeighbors.occurrences {
			neighborResponseHasSLSA, err := getAssociatedArtifact(ctx, gqlclient, occurrence, model.EdgeArtifactHasSlsa)
			if err != nil {
				log.Fatalf("error querying neighbors: %v", err)
				return nil, err
			}

			for _, neighborHasSLSA := range neighborResponseHasSLSA.Neighbors {
				if hasSLSA, ok := neighborHasSLSA.(*model.NeighborsNeighborsHasSLSA); ok {
					slsaName := getAttestationName(hasSLSA.Slsa.Origin)
					sta, err := ParseSlsaAttestation(hasSLSA)
					if err != nil {
						return nil, err
					}
					dup, err := checkRepeatedAttestations(statementSet, sta)
					if err != nil {
						return nil, err
					}
					if !dup {
						statements[slsaName] = sta
					}
				}
			}
		}
	}
	return statements, nil
}

func getAssociatedArtifact(ctx context.Context, gqlclient graphql.Client, occurrence *model.NeighborsNeighborsIsOccurrence, edge model.Edge) (*model.NeighborsResponse, error) {
	artifactFilter := &model.ArtifactSpec{
		Algorithm: &occurrence.Artifact.Algorithm,
		Digest:    &occurrence.Artifact.Digest,
	}
	artifactResponse, err := model.Artifacts(ctx, gqlclient, *artifactFilter)
	if err != nil {
		log.Fatalf("error querying for artifacts: %v", err)
	}
	if len(artifactResponse.Artifacts) != 1 {
		log.Fatalf("failed to located artifacts based on (algorithm:digest)")
	}
	return model.Neighbors(ctx, gqlclient, artifactResponse.Artifacts[0].Id, []model.Edge{edge})
}

func getAttestationName(origin string) string {
	originSplit := strings.Split(origin, "/")
	stepName := originSplit[len(originSplit)-1]
	dotIndex := strings.LastIndex(stepName, ".")
	if dotIndex != -1 && dotIndex > 0 {
		stepName = stepName[:dotIndex]
	}
	return stepName
}

func checkRepeatedAttestations(statementSet map[string]*attestationv1.Statement, statement *attestationv1.Statement) (bool, error) {
	predBytes, err := protojson.Marshal(statement.Predicate)
	if err != nil {
		return false, err
	}
	if existedStatement, ok := statementSet[string(predBytes)]; ok {
		if len(existedStatement.Subject) > 0 && len(statement.Subject) > 0 {
			for k, v := range statement.Subject[0].Digest {
				existedStatement.Subject[0].Digest[k] = v
			}
		}
		return true, nil
	}
	statementSet[string(predBytes)] = statement
	return false, nil
}
