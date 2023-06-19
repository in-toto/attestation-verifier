package verifier

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	linkPredicatev0 "github.com/in-toto/attestation/go/predicates/link/v0"
	provenancePredicatev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	log "github.com/sirupsen/logrus"
)

// func applyMaterialRules(statement *attestationv1.Statement, rules []string, claims map[string]map[AttestationIdentifier]*attestationv1.Statement) error

// func applyProductRules(statement *attestationv1.Statement, rules []string, claims map[string]map[AttestationIdentifier]*attestationv1.Statement) error

func applyAttributeRules(predicateType string, predicate map[string]any, rules []Constraint) error {
	env, err := getCELEnvForPredicateType(predicateType)
	if err != nil {
		return err
	}

	for _, r := range rules {
		log.Infof("Evaluating rule %s", r.Rule)
		ast, issues := env.Compile(r.Rule)
		if issues != nil && issues.Err() != nil {
			return issues.Err()
		}

		prog, err := env.Program(ast)
		if err != nil {
			return err
		}

		out, _, err := prog.Eval(predicate)
		if err != nil {
			if strings.Contains(err.Error(), "no such attribute") && r.AllowIfNoClaim {
				continue
			}
		}
		if result, ok := out.Value().(bool); !ok {
			return fmt.Errorf("unexpected result from CEL")
		} else if !result {
			return fmt.Errorf("verification failed for rule '%s'", r.Rule)
		}
	}

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
		provenanceBytes, err := json.Marshal(statement.Predicate)
		if err != nil {
			return nil, nil, err
		}

		provenance := &provenancePredicatev1.Provenance{}
		if err := json.Unmarshal(provenanceBytes, provenance); err != nil {
			return nil, nil, err
		}

		return provenance.BuildDefinition.ResolvedDependencies, statement.Subject, nil

	default:
		return statement.Subject, nil, nil
	}
}

func getCELEnvForPredicateType(predicateType string) (*cel.Env, error) {
	switch predicateType {
	case "https://in-toto.io/attestation/link/v0.3":
		return cel.NewEnv(
			cel.Variable("name", cel.StringType),
			cel.Variable("command", cel.ListType(cel.StringType)),
			cel.Variable("materials", cel.ListType(cel.ObjectType("in_toto_attestation.v1.ResourceDescriptor"))),
			cel.Variable("byproducts", cel.ObjectType("google.protobuf.Struct")),
			cel.Variable("environment", cel.ObjectType("google.protobuf.Struct")),
		)
	case "https://in-toto.io/attestation/test-result/v0.1":
		return cel.NewEnv(
			cel.Variable("result", cel.StringType),
			cel.Variable("configuration", cel.ListType(cel.ObjectType("in_toto_attestation.v1.ResourceDescriptor"))),
			cel.Variable("passedTests", cel.ListType(cel.StringType)),
			cel.Variable("warnedTests", cel.ListType(cel.StringType)),
			cel.Variable("failedTests", cel.ListType(cel.StringType)),
		)
	}

	return nil, fmt.Errorf("unknown predicate type")
}
