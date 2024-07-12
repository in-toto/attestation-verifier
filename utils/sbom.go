package utils

import (
	"encoding/json"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	spdx "github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	spdx_v2_3 "github.com/spdx/tools-golang/spdx/v2/v2_3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

type SbomSubject struct {
	Typename   *string                                      `json:"__typename"`
	Id         string                                       `json:"id"`
	Type       string                                       `json:"type"`
	Algorithm  string                                       `json:"algorithm"`
	Digest     string                                       `json:"digest"`
	Namespaces []model.AllPkgTreeNamespacesPackageNamespace `json:"namespaces"`
}

func ParseSbomAttestation(sbom *model.NeighborsNeighborsHasSBOM) (*attestationv1.Statement, error) {
	s := &attestationv1.Statement{}

	subject, err := getPkgSubject(sbom.Subject)
	if err != nil {
		return nil, err
	}

	s.Type = in_toto.StatementInTotoV01

	// sbom uri is serial number in case of cycloneDX which starts with "urn:uuid"
	if strings.HasPrefix(sbom.Uri, "urn:uuid:") {
		s.PredicateType = in_toto.PredicateCycloneDX
	} else {
		s.PredicateType = in_toto.PredicateSPDX
	}

	subName := ""
	if *sbom.Subject.GetTypename() == "Package" {
		subName = subject.Namespaces[0].Names[0].Name
	}
	s.Subject = []*attestationv1.ResourceDescriptor{
		{
			Name: subName,
			Uri:  sbom.Uri,
		},
	}

	if s.PredicateType == in_toto.PredicateCycloneDX {
		s.Predicate, err = getCdxPredicate(sbom, subject)
		if err != nil {
			return nil, err
		}
	} else {
		s.Predicate, err = getSpdxPredicate(sbom, subject)
		if err != nil {
			return nil, err
		}
	}

	return s, nil
}

func getSpdxPredicate(sbom *model.NeighborsNeighborsHasSBOM, subject *SbomSubject) (*structpb.Struct, error) {
	var spdxDoc spdx.Document
	spdxDoc.SPDXIdentifier = common.ElementID("DOCUMENT")
	spdxDoc.SPDXVersion = spdx_v2_3.Version
	spdxDoc.DataLicense = spdx_v2_3.DataLicense
	spdxDoc.DocumentName = subject.Namespaces[0].Names[0].Name
	spdxDoc.DocumentNamespace = sbom.Uri
	spdxDoc.CreationInfo = &spdx.CreationInfo{}
	spdxDoc.CreationInfo.Created = sbom.KnownSince.Format("2006-01-02T15:04:05.000Z")

	// packages are listed in the sbom.IncludedSoftware array, but their checksums are found in sbom.IncludedOccurrences.
	// packageMap maps package node IDs to *spdx.Package. It updates the checksum of each package while traversing through sbom.IncludedOccurrences.
	packages := make([]*spdx.Package, 0)
	packageMap := make(map[string]*spdx.Package)
	for _, pkg := range sbom.IncludedSoftware {
		if *pkg.GetTypename() != "Package" {
			continue
		}
		sub, err := getPkgSubject(pkg)
		if err != nil {
			return nil, err
		}
		pkgPurl := sub.Namespaces[0].Names[0].Versions[0].Purl
		if pkgPurl == subject.Namespaces[0].Names[0].Versions[0].Purl || sub.Namespaces[0].Namespace == "files" {
			continue
		}
		var p spdx.Package
		p.PackageSPDXIdentifier = common.ElementID(sub.Namespaces[0].Names[0].Versions[0].Id)
		p.PackageName = sub.Namespaces[0].Names[0].Name
		p.PackageExternalReferences = append(p.PackageExternalReferences, &spdx.PackageExternalReference{
			Category: spdx.CategoryPackageManager,
			Locator:  pkgPurl,
			RefType:  spdx.PackageManagerPURL,
		})
		p.PackageVersion = sub.Namespaces[0].Names[0].Versions[0].Version
		packageMap[sub.Namespaces[0].Names[0].Versions[0].Id] = &p
		packages = append(packages, &p)
	}

	// fileMap maps "name:filename" to *spdx.File. This is required because the same file node with multiple checksums will have different artifacts.
	// Additionally, spdx.Files with the same name and checksum might be different nodes due to different filenames. Therefore, "name:filename" is mapped to *spdx.File.
	files := make([]*spdx.File, 0)
	fileMap := make(map[string]*spdx.File)
	for _, pkg := range sbom.IncludedOccurrences {
		sub, err := getPkgSubject(pkg.Subject)
		if err != nil {
			return nil, err
		}
		if sub.Namespaces[0].Namespace == "files" {
			fileName := ""
			for _, q := range sub.Namespaces[0].Names[0].Versions[0].Qualifiers {
				if q.Key == "filename" {
					fileName = q.Value
				}
			}
			if f, ok := fileMap[sub.Namespaces[0].Names[0].Name+":"+fileName]; ok {
				if f == nil {
					continue
				}
				f.Checksums = append(f.Checksums, common.Checksum{
					Algorithm: common.ChecksumAlgorithm(pkg.Artifact.Algorithm),
					Value:     pkg.Artifact.Digest,
				},
				)
				depFileName := pkg.Artifact.Algorithm + ":" + pkg.Artifact.Digest
				fileMap[depFileName] = nil
				continue
			}
			var f spdx.File
			f.FileSPDXIdentifier = common.ElementID(sub.Namespaces[0].Names[0].Versions[0].Id)
			f.FileName = sub.Namespaces[0].Names[0].Name
			f.Checksums = append(f.Checksums, common.Checksum{
				Algorithm: common.ChecksumAlgorithm(pkg.Artifact.Algorithm),
				Value:     pkg.Artifact.Digest,
			},
			)
			for _, q := range sub.Namespaces[0].Names[0].Versions[0].Qualifiers {
				if q.Key == "filename" {
					f.FileName = q.Value
				}
			}
			fileMap[sub.Namespaces[0].Names[0].Name+":"+f.FileName] = &f
			files = append(files, &f)
		} else {
			if occPkg, ok := packageMap[sub.Namespaces[0].Names[0].Versions[0].Id]; ok {
				occPkg.PackageChecksums = append(occPkg.PackageChecksums, common.Checksum{
					Algorithm: common.ChecksumAlgorithm(pkg.Artifact.Algorithm),
					Value:     pkg.Artifact.Digest,
				})
			}
		}
	}
	spdxDoc.Packages = packages
	spdxDoc.Files = files

	relationships := make([]*spdx.Relationship, 0)
	for _, rel := range sbom.IncludedDependencies {
		if subject.Namespaces[0].Names[0].Versions[0].Purl != rel.Package.Namespaces[0].Names[0].Versions[0].Purl {
			var r spdx.Relationship
			r.RefA = common.DocElementID{
				ElementRefID: common.ElementID(rel.Package.Namespaces[0].Names[0].Versions[0].Id),
			}
			r.RefB = common.DocElementID{
				ElementRefID: common.ElementID(rel.DependencyPackage.Namespaces[0].Names[0].Versions[0].Id),
			}
			r.Relationship = common.TypeRelationshipOther
			relationships = append(relationships, &r)
		}
	}
	spdxDoc.Relationships = relationships

	docBytes, err := json.Marshal(spdxDoc)
	if err != nil {
		return nil, err
	}

	var pred structpb.Struct
	if err := protojson.Unmarshal(docBytes, &pred); err != nil {
		return nil, err
	}

	return &pred, nil
}

func getCdxPredicate(sbom *model.NeighborsNeighborsHasSBOM, subject *SbomSubject) (*structpb.Struct, error) {
	var bom cdx.BOM
	bom.BOMFormat = cdx.BOMFormat
	bom.SpecVersion = cdx.SpecVersion(5)
	bom.Version = 1
	bom.SerialNumber = sbom.Uri
	bom.Metadata = &cdx.Metadata{}
	bom.Metadata.Component = &cdx.Component{}
	bom.Metadata.Component.Type = cdx.ComponentTypeLibrary
	subjectNodeId := subject.Id
	if *subject.Typename == "Package" {
		bom.Metadata.Component.Name = subject.Namespaces[0].Names[0].Name
		bom.Metadata.Component.Version = subject.Namespaces[0].Names[0].Versions[0].Version
		bom.Metadata.Component.BOMRef = subject.Namespaces[0].Names[0].Versions[0].Purl
		bom.Metadata.Component.PackageURL = subject.Namespaces[0].Names[0].Versions[0].Purl
	} else if *subject.Typename == "Artifact" {
		bom.Metadata.Component.Hashes = &[]cdx.Hash{
			{
				Algorithm: cdx.HashAlgorithm(subject.Algorithm),
				Value:     subject.Digest,
			},
		}
	}
	bom.Metadata.Timestamp = sbom.KnownSince.Format("2006-01-02T15:04:05.000Z")

	// componentMap maps component node IDs to *cdx.Component. It updates the checksum of each package while traversing through sbom.IncludedOccurrences.
	components := make([]*cdx.Component, 0)
	componentMap := make(map[string]*cdx.Component)
	for _, pkg := range sbom.IncludedSoftware {
		if *pkg.GetTypename() != "Package" {
			continue
		}
		sub, err := getPkgSubject(pkg)
		if err != nil {
			return nil, err
		}
		pkgPurl := sub.Namespaces[0].Names[0].Versions[0].GetPurl()
		var comp cdx.Component
		comp.Type = cdx.ComponentTypeLibrary
		comp.BOMRef = pkgPurl
		comp.PackageURL = pkgPurl
		comp.Name = sub.Namespaces[0].Names[0].Name
		comp.Version = sub.Namespaces[0].Names[0].Versions[0].Version
		componentMap[sub.Namespaces[0].Names[0].Versions[0].Id] = &comp
		components = append(components, &comp)
	}

	hashesMap := make(map[string][]cdx.Hash)
	for _, pkg := range sbom.IncludedOccurrences {
		sub, err := getPkgSubject(pkg.Subject)
		if err != nil {
			return nil, err
		}
		if bom.Metadata.Component.Name == "" && subjectNodeId == pkg.Artifact.Id {
			bom.Metadata.Component.Name = sub.Namespaces[0].Names[0].Name
			bom.Metadata.Component.Version = sub.Namespaces[0].Names[0].Versions[0].Version
			bom.Metadata.Component.BOMRef = sub.Namespaces[0].Names[0].Versions[0].Purl
			bom.Metadata.Component.PackageURL = sub.Namespaces[0].Names[0].Versions[0].Purl
		}
		hashesMap[sub.Namespaces[0].Names[0].Versions[0].Id] = append(hashesMap[sub.Namespaces[0].Names[0].Versions[0].Id], cdx.Hash{
			Algorithm: cdx.HashAlgorithm(pkg.Artifact.Algorithm),
			Value:     pkg.Artifact.Digest,
		})
	}
	for k, v := range hashesMap {
		v := v
		if occPkg, ok := componentMap[k]; ok {
			occPkg.Hashes = &v
		}
	}

	tempComponent := make([]cdx.Component, len(components))
	for i, c := range components {
		tempComponent[i] = *c
	}
	bom.Components = &tempComponent

	dependencies := make([]cdx.Dependency, 0)
	dependencyMap := make(map[string][]string, 0)
	for _, dep := range sbom.IncludedDependencies {
		if dep.DependencyType == "DIRECT" {
			dependencyMap[dep.Package.Namespaces[0].Names[0].Versions[0].Purl] = append(dependencyMap[dep.Package.Namespaces[0].Names[0].Versions[0].Purl], dep.DependencyPackage.Namespaces[0].Names[0].Versions[0].Purl)
		}
	}
	for k, v := range dependencyMap {
		v := v
		dependencies = append(dependencies, cdx.Dependency{
			Ref:          k,
			Dependencies: &v,
		})
	}
	bom.Dependencies = &dependencies

	bomBytes, err := json.Marshal(bom)
	if err != nil {
		return nil, err
	}

	var pred structpb.Struct
	if err := protojson.Unmarshal(bomBytes, &pred); err != nil {
		return nil, err
	}

	return &pred, nil
}

func getPkgSubject(sub any) (*SbomSubject, error) {
	var subject SbomSubject
	subjectbytes, err := json.Marshal(sub)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(subjectbytes, &subject); err != nil {
		return nil, err
	}
	return &subject, nil
}
