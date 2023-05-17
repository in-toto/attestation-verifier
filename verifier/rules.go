package verifier

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
)

// func applyMaterialRules(materials []*attestationv1.ResourceDescriptor, rules []string) error

// func applyProductRules(products []*attestationv1.ResourceDescriptor, rules []string) error

func applyAttributeRules(predicateType string, predicate map[string]any, rules []Constraint) error {
	env, err := getCELEnvForPredicateType(predicateType)
	if err != nil {
		return err
	}

	for _, r := range rules {
		fmt.Println("Evaluating rule", r.Rule)
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
