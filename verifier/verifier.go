package verifier

import (
	"encoding/json"
	"fmt"
	"time"

	linkPredicatev0 "github.com/in-toto/attestation/go/predicates/link/v0"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func Verify(layout *Layout, attestations map[string]*dsse.Envelope) error {
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
		attestationBytes, err := stepAttestation.DecodeB64Payload()
		if err != nil {
			return err
		}
		statement := &attestationv1.Statement{}
		if err := json.Unmarshal(attestationBytes, statement); err != nil {
			return err
		}

		// stepMaterials, stepProducts, err := getMaterialsAndProducts(statement)
		// if err != nil {
		// 	return err
		// }

		for _, expectedPredicate := range step.ExpectedPredicates {
			// TODO: only one predicate type?
			if expectedPredicate.PredicateType != statement.PredicateType {
				return fmt.Errorf("expected predicate of type %s for step %s, received %s instead", expectedPredicate.PredicateType, step.Name, statement.PredicateType)
			}
			// if err := applyMaterialRules(stepMaterials, step.ExpectedMaterials); err != nil {
			// 	return err
			// }
			// if err := applyProductRules(stepProducts, expectedPredicate.ExpectedProducts); err != nil {
			// 	return err
			// }
			if err := applyAttributeRules(statement.PredicateType, statement.Predicate.AsMap(), expectedPredicate.ExpectedAttributes); err != nil {
				return err
			}
		}
	}
	///
	// for _, subject := range layout.Subjects {
	// 	subjectAttestations := getAttestationsForSubject(subject.Subject, attestations)
	///
	// 	fmt.Printf("Found %d attestations for subjects %s\n", len(subjectAttestations), subject.Subject)
	///
	// 	for _, expectedPredicate := range subject.ExpectedPredicates {
	// 		matchedAttestations := getAttestationsForPredicateType(expectedPredicate.PredicateType, subjectAttestations)
	///
	// 		fmt.Printf("Found %d attestations for predicate type %s\n", len(matchedAttestations), expectedPredicate.PredicateType)
	///
	// 		if len(matchedAttestations) == 0 {
	// 			return fmt.Errorf("no attestation found for predicate %s for subject %s", expectedPredicate.PredicateType, strings.Join(subject.Subject, ", "))
	// 		}
	///
	// 		for _, attestation := range matchedAttestations {
	// 			if err := applyAttributeRules(attestation.PredicateType, attestation.Predicate.AsMap(), expectedPredicate.ExpectedAttributes); err != nil {
	// 				return err
	// 			}
	// 		}
	// 	}
	// }

	// for _, inspection := range layout.Inspections {
	// 	// TODO executeInspection shouldn't perform the checks as well to be consistent, or we need helpers for steps, subjects
	// 	if err := executeInspection(inspection); err != nil {
	// 		return err
	// 	}
	// }

	return nil
}

func getMaterialsAndProducts(statement *attestationv1.Statement) ([]*attestationv1.ResourceDescriptor, []*attestationv1.ResourceDescriptor, error) {
	switch statement.PredicateType {
	case "https://in-toto.io/attestation/link/v0.3":
		linkBytes, err := json.Marshal(statement.Predicate)
		if err != nil {
			return nil, nil, err
		}

		link := &linkPredicatev0.Link{}
		if err := json.Unmarshal(linkBytes, link); err != nil {
			return nil, nil, err
		}

		return link.Materials, statement.Subject, nil

	case "https://slsa.dev/provenance/v1":
		// FIXME: no slsa proto yet for materials
		return nil, statement.Subject, nil

	default:
		attributes := map[string]any{}
		for k, v := range statement.Predicate.AsMap() {
			switch value := v.(type) {
			case string:
				attributes[k] = value
			case int:
				attributes[k] = fmt.Sprint(value) // DRY
			}
		}

		return statement.Subject, nil, nil
	}
}

func getAttestationsForSubject(patterns []string, attestations []*attestationv1.Statement) []*attestationv1.Statement {
	matchedAttestations := []*attestationv1.Statement{}
	for _, attestation := range attestations {
		matched := false
		for _, subject := range attestation.Subject {
			for _, pattern := range patterns {
				if subject.Name == pattern {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if matched {
			attestation := attestation
			matchedAttestations = append(matchedAttestations, attestation)
		}
	}

	return matchedAttestations
}

func getAttestationsForPredicateType(predicateType string, attestations []*attestationv1.Statement) []*attestationv1.Statement {
	matchedAttestations := []*attestationv1.Statement{}
	for _, attestation := range attestations {
		if attestation.PredicateType == predicateType {
			attestation := attestation
			matchedAttestations = append(matchedAttestations, attestation)
		}
	}

	return matchedAttestations
}

// func executeInspection(inspection *Inspection) error
