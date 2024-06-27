package utils

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"

	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func ParseSlsaAttestation(slsa *model.NeighborsNeighborsHasSLSA) (*attestationv1.Statement, error) {
	s := &attestationv1.Statement{}
	resultPred := make(map[string]interface{})

	for _, item := range slsa.Slsa.SlsaPredicate {
		keys := strings.Split(item.Key, ".")
		value := item.Value
		currMap := resultPred

		for i, key := range keys {
			if i == len(keys)-1 {
				currMap[key] = value
			} else {
				if _, ok := currMap[key]; !ok {
					currMap[key] = make(map[string]interface{})
				}
				currMap = currMap[key].(map[string]interface{})
			}
		}
	}

	resultPred = ParseMap(resultPred)

	var slsaType string
	if slsa.Slsa.SlsaVersion == slsa1.PredicateSLSAProvenance {
		slsaType = attestationv1.StatementTypeUri
	} else {
		slsaType = in_toto.StatementInTotoV01
	}

	digest := make(map[string]string)
	digest[slsa.Subject.Algorithm] = slsa.Subject.Digest

	data := map[string]interface{}{
		"type": slsaType,
		"subject": []map[string]interface{}{
			{
				"digest": digest,
			},
		},
		"predicateType": slsa.Slsa.SlsaVersion,
		"predicate":     resultPred["slsa"],
	}

	jsonData, err := json.MarshalIndent(data, " ", "  ")
	if err != nil {
		return nil, err
	}

	// Replace "true" and "false" strings to boolean
	jsonData = bytes.ReplaceAll(jsonData, []byte(`"true"`), []byte(`true`))
	jsonData = bytes.ReplaceAll(jsonData, []byte(`"false"`), []byte(`false`))

	// Convert "<nil>" to null in json. Required for externalParameters field which currenty don't have `omitempty` tag
	jsonData = bytes.ReplaceAll(jsonData, []byte(`"\u003cnil\u003e"`), []byte(`null`))

	if err := protojson.Unmarshal(jsonData, s); err != nil {
		return nil, err
	}

	return s, nil
}

func ParseMap(input map[string]interface{}) map[string]interface{} {
	output := make(map[string]interface{})
	for key, value := range input {
		switch value := value.(type) {
		case map[string]interface{}:
			if slices.Contains([]string{"resolvedDependencies", "byproducts", "builderDependencies", "materials"}, key) {
				output[key] = convertSlice(value)
			} else {
				output[key] = ParseMap(value)
			}
		default:
			output[key] = value
		}
	}
	return output
}

func convertSlice(value map[string]interface{}) []interface{} {
	val := make([]interface{}, 0)
	for _, v := range value {
		val = append(val, v)
	}
	return val
}
