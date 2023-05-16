package verifier

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	linkPredicatev0 "github.com/in-toto/attestation/go/predicates/link/v0"
	attestationv1 "github.com/in-toto/attestation/go/v1"
)

type Functionary struct {
	Type      string `yaml:"type"`
	Scheme    string `yaml:"scheme"`
	PublicKey string `yaml:"publicKey"`
}

type ExpectedStepPredicates struct {
	PredicateTypes     []string `yaml:"predicateTypes"`
	ExpectedMaterials  []string `yaml:"expectedMaterials"`
	ExpectedProducts   []string `yaml:"expectedProducts"`
	ExpectedAttributes []string `yaml:"expectedAttributes"`
	Functionaries      []string `yaml:"functionaries"`
	Threshold          int      `yaml:"threshold"`
}

type Step struct {
	Name               string                   `yaml:"name"`
	Command            string                   `yaml:"command"`
	ExpectedPredicates []ExpectedStepPredicates `yaml:"expectedPredicates"`
}

type ExpectedSubjectPredicates struct {
	PredicateTypes     []string `yaml:"predicateTypes"`
	ExpectedAttributes []string `yaml:"expectedAttributes"`
	Functionaries      []string `yaml:"functionaries"`
	Threshold          int      `yaml:"threshold"`
}

type Subject struct {
	Subject            []string                    `yaml:"subject"`
	ExpectedPredicates []ExpectedSubjectPredicates `yaml:"expectedPredicates"`
}

type Inspection struct {
	Name               string   `yaml:"name"`
	Command            string   `yaml:"command"`
	Predicates         []string `yaml:"predicates"`
	ExpectedMaterials  []string `yaml:"expectedMaterials"`
	ExpectedProducts   []string `yaml:"expectedProducts"`
	ExpectedAttributes []string `yaml:"expectedAttributes"`
}

type Layout struct {
	Expires       string                 `yaml:"expires"`
	Functionaries map[string]Functionary `yaml:"functionaries"`
	Steps         []*Step                `yaml:"steps"`
	Subjects      []*Subject             `yaml:"subjects"`
	Inspections   []*Inspection          `yaml:"inspections"`
}

func LoadLayout(path string) (*Layout, error) {
	layoutBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	layout := &Layout{}
	if err := yaml.Unmarshal(layoutBytes, layout); err != nil {
		return nil, err
	}

	return layout, nil
}

func Verify(layout *Layout, attestations map[string]*attestationv1.Statement) error {
	expiry, err := time.Parse(time.RFC3339, layout.Expires)
	if err != nil {
		return err
	}

	if compare := expiry.Compare(time.Now()); compare == -1 {
		return fmt.Errorf("layout has expired")
	}

	if layout.Steps == nil && layout.Subjects == nil && layout.Inspections == nil {
		return fmt.Errorf("empty layout, one of steps, subjects, and inspections must be specified")
	}

	for _, step := range layout.Steps {
		stepAttestation, ok := attestations[step.Name]
		if !ok {
			return fmt.Errorf("no attestation found for step %s", step.Name)
		}

		stepMaterials, stepProducts, stepAttributes, err := getMaterialsProductsAttributes(stepAttestation)
		if err != nil {
			return err
		}

		for _, expectedPredicate := range step.ExpectedPredicates {
			// TODO: only one predicate type?
			if expectedPredicate.PredicateTypes[0] != stepAttestation.PredicateType {
				return fmt.Errorf("expected predicate of type %s for step %s, received %s instead", expectedPredicate.PredicateTypes[0], step.Name, stepAttestation.PredicateType)
			}

			if err := applyMaterialRules(stepMaterials, expectedPredicate.ExpectedMaterials); err != nil {
				return err
			}

			if err := applyProductRules(stepProducts, expectedPredicate.ExpectedProducts); err != nil {
				return err
			}

			if err := applyAttributeRules(stepAttributes, expectedPredicate.ExpectedAttributes); err != nil {
				return err
			}
		}
	}

	for _, subject := range layout.Subjects {
		subjectAttestations := getAttestationsForSubject(subject.Subject, attestations)

		for _, expectedPredicate := range subject.ExpectedPredicates {
			matchedAttestations := getAttestationsForPredicateType(expectedPredicate.PredicateTypes, subjectAttestations)

			if len(matchedAttestations) == 0 {
				return fmt.Errorf("no attestation found for predicate %s for subject %s", strings.Join(expectedPredicate.PredicateTypes, ", "), strings.Join(subject.Subject, ", "))
			}

			for _, attestation := range matchedAttestations {
				_, _, attributes, err := getMaterialsProductsAttributes(attestation)
				if err != nil {
					return err
				}
				if err := applyAttributeRules(attributes, expectedPredicate.ExpectedAttributes); err != nil {
					return err
				}
			}
		}
	}

	for _, inspection := range layout.Inspections {
		// TODO executeInspection shouldn't perform the checks as well to be consistent, or we need helpers for steps, subjects
		if err := executeInspection(inspection); err != nil {
			return err
		}
	}

	return nil
}

func getMaterialsProductsAttributes(statement *attestationv1.Statement) ([]*attestationv1.ResourceDescriptor, []*attestationv1.ResourceDescriptor, map[string]string, error) {
	switch statement.PredicateType {
	case "https://in-toto.io/attestation/link/v0.3":
		linkBytes, err := json.Marshal(statement.Predicate)
		if err != nil {
			return nil, nil, nil, err
		}

		link := &linkPredicatev0.Link{}
		if err := json.Unmarshal(linkBytes, link); err != nil {
			return nil, nil, nil, err
		}

		attributes := map[string]string{}
		attributes["name"] = link.Name
		attributes["command"] = strings.Join(link.Command, " ")
		for k, v := range link.Byproducts.AsMap() {
			key := fmt.Sprintf("byproducts.%s", k)
			switch value := v.(type) {
			case string:
				attributes[key] = value
			case int:
				attributes[key] = string(value)
			}
		}
		for k, v := range link.Environment.AsMap() {
			key := fmt.Sprintf("environment.%s", k)
			switch value := v.(type) {
			case string:
				attributes[key] = value
			case int:
				attributes[key] = string(value)
			}
		}

		return link.Materials, statement.Subject, attributes, nil
	}

	return nil, nil, nil, fmt.Errorf("unknown predicate type")
}

func applyMaterialRules(materials []*attestationv1.ResourceDescriptor, rules []string) error

func applyProductRules(products []*attestationv1.ResourceDescriptor, rules []string) error

func applyAttributeRules(attributes map[string]string, rules []string) error

func getAttestationsForSubject(patterns []string, attestations map[string]*attestationv1.Statement) []*attestationv1.Statement

func getAttestationsForPredicateType(predicateTypes []string, attestations []*attestationv1.Statement) []*attestationv1.Statement

func executeInspection(inspection *Inspection) error
