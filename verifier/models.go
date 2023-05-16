package verifier

import (
	"os"

	"gopkg.in/yaml.v3"
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
