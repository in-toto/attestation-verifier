package verifier

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	linkPredicatev0 "github.com/in-toto/attestation/go/predicates/link/v0"
	attestationv1 "github.com/in-toto/attestation/go/v1"
)

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
				attributes[key] = fmt.Sprint(value)
			}
		}
		for k, v := range link.Environment.AsMap() {
			key := fmt.Sprintf("environment.%s", k)
			switch value := v.(type) {
			case string:
				attributes[key] = value
			case int:
				attributes[key] = fmt.Sprint(value)
			}
		}

		return link.Materials, statement.Subject, attributes, nil
	default:
		attributes := map[string]string{}
		for k, v := range statement.Predicate.AsMap() {
			switch value := v.(type) {
			case string:
				attributes[k] = value
			case int:
				attributes[k] = fmt.Sprint(value) // DRY
			}
		}

		return statement.Subject, nil, attributes, nil
	}
}

func getAttestationsForSubject(patterns []string, attestations map[string]*attestationv1.Statement) []*attestationv1.Statement

func getAttestationsForPredicateType(predicateTypes []string, attestations []*attestationv1.Statement) []*attestationv1.Statement

func executeInspection(inspection *Inspection) error
