package verifier

import (
	"fmt"
	"strings"

	attestationv1 "github.com/in-toto/attestation/go/v1"
)

type ruleType int

const (
	is ruleType = iota
	isNot
	oneOf
	notOneOf
)

type rule struct {
	t ruleType
	l string
	r any
}

func parseRule(r string) (rule, error) {
	split := strings.Split(r, " ")
	operator := strings.ToLower(split[1])
	switch operator {
	case "is":
		return rule{t: is, l: split[0], r: split[2]}, nil
	case "isnot":
		return rule{t: isNot, l: split[0], r: split[2]}, nil
	case "oneof":
		rhs := split[2]
		if !strings.HasPrefix(rhs, "[") || !strings.HasSuffix(rhs, "]") {
			return rule{}, fmt.Errorf("invalid rule %s", r)
		}

		rhs = rhs[1 : len(rhs)-1]
		components := strings.Split(rhs, ",")
		r := []string{}
		for _, c := range components {
			r = append(r, strings.TrimSpace(c))
		}

		return rule{t: oneOf, l: split[0], r: components}, nil
	case "notoneof":
		rhs := split[2]
		if !strings.HasPrefix(rhs, "[") || !strings.HasSuffix(rhs, "]") {
			return rule{}, fmt.Errorf("invalid rule %s", r)
		}

		rhs = rhs[1 : len(rhs)-1]
		components := strings.Split(rhs, ",")
		r := []string{}
		for _, c := range components {
			r = append(r, strings.TrimSpace(c))
		}

		return rule{t: notOneOf, l: split[0], r: components}, nil
	}
	return rule{}, fmt.Errorf("unknown rule type in rule %s", r)
}

func applyIs(expected, actual string) bool {
	return expected == actual
}

func applyOneOf(expected []string, actual string) bool {
	matched := false
	for _, acceptedValue := range expected {
		if actual == acceptedValue {
			matched = true
			break
		}
	}

	return matched
}

func applyAttributeRules(attributes map[string]string, rules []string) error {
	for _, r := range rules {
		rule, err := parseRule(r)
		if err != nil {
			return err
		}
		actual, ok := attributes[rule.l]
		if !ok {
			return fmt.Errorf("no claim available for rule %s", r)
		}
		switch rule.t {
		case is:
			expected, ok := rule.r.(string)
			if !ok {
				return fmt.Errorf("invalid rule %s", r)
			}

			if !applyIs(expected, actual) {
				return fmt.Errorf("verification failed for rule %s", r)
			}
		case isNot:
			expected, ok := rule.r.(string)
			if !ok {
				return fmt.Errorf("invalid rule %s", r)
			}

			if applyIs(expected, actual) {
				return fmt.Errorf("verification failed for rule %s", r)
			}
		case oneOf:
			expected, ok := rule.r.([]string)
			if !ok {
				return fmt.Errorf("invalid rule %s", r)
			}

			if !applyOneOf(expected, actual) {
				return fmt.Errorf("verification failed for rule %s", r)
			}
		case notOneOf:
			expected, ok := rule.r.([]string)
			if !ok {
				return fmt.Errorf("invalid rule %s", r)
			}

			if applyOneOf(expected, actual) {
				return fmt.Errorf("verification failed for rule %s", r)
			}
		}
	}

	return nil
}

func applyMaterialRules(materials []*attestationv1.ResourceDescriptor, rules []string) error

func applyProductRules(products []*attestationv1.ResourceDescriptor, rules []string) error
