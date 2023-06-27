package verifier

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/interpreter"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
)

func Verify(layout *Layout, attestations map[string]*dsse.Envelope) error {
	log.Info("Verifying expiry...")
	expiry, err := time.Parse(time.RFC3339, layout.Expires)
	if err != nil {
		return err
	}

	if compare := expiry.Compare(time.Now()); compare == -1 {
		return fmt.Errorf("layout has expired")
	}
	log.Info("Done.")

	log.Info("Fetching verifiers...")
	verifiers, err := getVerifiers(layout.Functionaries)
	if err != nil {
		return err
	}
	envVerifier, err := dsse.NewEnvelopeVerifier(verifiers...)
	if err != nil {
		return err
	}
	log.Info("Done.")

	log.Info("Loading attestations as claims...")
	claims := map[string]map[AttestationIdentifier]*attestationv1.Statement{}
	for attestationName, env := range attestations {
		stepName := getStepName(attestationName)
		if claims[stepName] == nil {
			claims[stepName] = map[AttestationIdentifier]*attestationv1.Statement{}
		}

		acceptedKeys, err := envVerifier.Verify(context.Background(), env)
		if err != nil {
			return err
		}

		sb, err := env.DecodeB64Payload()
		if err != nil {
			return err
		}

		statement := &attestationv1.Statement{}
		if err := protojson.Unmarshal(sb, statement); err != nil {
			return err
		}

		for _, ak := range acceptedKeys {
			claims[stepName][AttestationIdentifier{Functionary: ak.KeyID, PredicateType: statement.PredicateType}] = statement
		}
	}
	log.Info("Done.")

	env, err := getCELEnv()
	if err != nil {
		return err
	}

	for _, step := range layout.Steps {
		stepStatements, ok := claims[step.Name]
		if !ok {
			return fmt.Errorf("no claims found for step %s", step.Name)
		}

		for _, expectedPredicate := range step.ExpectedPredicates {
			if expectedPredicate.Threshold == 0 {
				expectedPredicate.Threshold = 1
			}

			matchedPredicates := getPredicates(stepStatements, expectedPredicate.PredicateType, expectedPredicate.Functionaries)
			if len(matchedPredicates) < expectedPredicate.Threshold {
				return fmt.Errorf("threshold not met for step %s", step.Name)
			}

			failedChecks := []error{}
			acceptedPredicates := 0
			for functionary, statement := range matchedPredicates {
				log.Infof("Verifying claim for step %s of type %s by %s", step.Name, expectedPredicate.PredicateType, functionary)
				failed := false

				if err := applyArtifactRules(statement, step.ExpectedMaterials, expectedPredicate.ExpectedProducts, claims); err != nil {
					failed = true
					failedChecks = append(failedChecks, fmt.Errorf("for step %s, claim by %s failed artifact rules: %w", step.Name, functionary, err))
				}

				input, err := getActivation(statement)
				if err != nil {
					return err
				}

				if err := applyAttributeRules(env, input, expectedPredicate.ExpectedAttributes); err != nil {
					failed = true
					failedChecks = append(failedChecks, fmt.Errorf("for step %s, claim by %s failed attribute rules: %w", step.Name, functionary, err))
				}

				if failed {
					log.Infof("Claim for step %s of type %s by %s failed.", step.Name, expectedPredicate.PredicateType, functionary)
				} else {
					acceptedPredicates += 1
				}
			}
			if acceptedPredicates < expectedPredicate.Threshold {
				return errors.Join(failedChecks...)
			}
		}
	}

	log.Info("Verification successful!")

	return nil
}

func getVerifiers(publicKeys map[string]Functionary) ([]dsse.Verifier, error) {
	verifiers := []dsse.Verifier{}

	for _, key := range publicKeys {
		log.Infof("Creating verifier for key %s", key.KeyID)
		sslibKey := &signerverifier.SSLibKey{
			KeyIDHashAlgorithms: key.KeyIDHashAlgorithms,
			KeyType:             key.KeyType,
			KeyVal: signerverifier.KeyVal{
				Public: key.KeyVal.Public,
			},
			Scheme: key.Scheme,
			KeyID:  key.KeyID,
		}

		switch key.KeyType { // TODO: use scheme
		case "rsa":
			verifier, err := signerverifier.NewRSAPSSSignerVerifierFromSSLibKey(sslibKey)
			if err != nil {
				return nil, err
			}

			verifiers = append(verifiers, verifier)
		case "ecdsa":
			verifier, err := signerverifier.NewECDSASignerVerifierFromSSLibKey(sslibKey)
			if err != nil {
				return nil, err
			}

			verifiers = append(verifiers, verifier)
		case "ed25519":
			verifier, err := signerverifier.NewED25519SignerVerifierFromSSLibKey(sslibKey)
			if err != nil {
				return nil, err
			}

			verifiers = append(verifiers, verifier)
		}
	}

	return verifiers, nil
}

func getPredicates(statements map[AttestationIdentifier]*attestationv1.Statement, predicateType string, functionaries []string) map[string]*attestationv1.Statement {
	matchedPredicates := map[string]*attestationv1.Statement{}

	for _, keyID := range functionaries {
		statement, ok := statements[AttestationIdentifier{PredicateType: predicateType, Functionary: keyID}]
		if ok {
			matchedPredicates[keyID] = statement
		}
	}

	return matchedPredicates
}

func getCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Types(&attestationv1.Statement{}),
		cel.Variable("subject", cel.ListType(cel.ObjectType("in_toto_attestation.v1.ResourceDescriptor"))),
		cel.Variable("predicateType", cel.StringType),
		cel.Variable("predicate", cel.ObjectType("google.protobuf.Struct")),
	)
}

func getActivation(statement *attestationv1.Statement) (interpreter.Activation, error) {
	return interpreter.NewActivation(map[string]any{
		"type":          statement.Type,
		"subject":       statement.Subject,
		"predicateType": statement.PredicateType,
		"predicate":     statement.Predicate,
	})
}

func getStepName(name string) string {
	nameS := strings.Split(name, ".")
	nameS = nameS[:len(nameS)-1]
	return strings.Join(nameS, ".")
}
