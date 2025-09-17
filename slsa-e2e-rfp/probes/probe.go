// Package probes implements ways to sign and store attestations.
package probes

import (
	"context"
	"encoding/json"
	"io"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	PayloadType = "application/vnd.in-toto+json"
)

type Prober interface {
	Attest(ctx context.Context, stepName, predicateType string, predicate proto.Message, subjects ...*intoto.ResourceDescriptor) error
	KeyID() (string, error)
}

type Probe struct {
	signer Signer
	store  Store
}

func NewProbeWithSigner(rng io.Reader, store Store) (Prober, error) {
	signer, err := NewEd25519Signer(rng)
	if err != nil {
		return nil, err
	}
	return &Probe{
		signer: signer,
		store:  store,
	}, nil
}

func (pr *Probe) KeyID() (string, error) {
	return pr.signer.KeyID()
}

func (pr *Probe) Attest(ctx context.Context, stepName, predicateType string, predicate proto.Message, subjects ...*intoto.ResourceDescriptor) error {
	messageToStruct := func(m proto.Message) (*structpb.Struct, error) {
		predBytes, err := protojson.Marshal(m)
		if err != nil {
			return nil, err
		}
		predStruct := &structpb.Struct{}
		err = protojson.Unmarshal(predBytes, predStruct)
		if err != nil {
			return nil, err
		}
		return predStruct, nil
	}

	newStatement := func(predicateType string, predicateStruct *structpb.Struct, subjects []*intoto.ResourceDescriptor) *intoto.Statement {
		return &intoto.Statement{
			Type:          intoto.StatementTypeUri,
			PredicateType: predicateType,
			Predicate:     predicateStruct,
			Subject:       subjects,
		}
	}

	keyID, err := pr.signer.KeyID()
	if err != nil {
		return err
	}
	key := stepName + "." + keyID[:8] + ".json"
	predicateStruct, err := messageToStruct(predicate)
	if err != nil {
		return err
	}

	statement := newStatement(predicateType, predicateStruct, subjects)
	payload, err := protojson.Marshal(statement)
	if err != nil {
		return err
	}

	envelopeSigner, err := dsse.NewEnvelopeSigner(pr.signer)
	if err != nil {
		return err
	}

	env, err := envelopeSigner.SignPayload(ctx, PayloadType, payload)
	if err != nil {
		return err
	}

	envelopeBytes, err := json.Marshal(env)
	if err != nil {
		return err
	}

	err = pr.store.Put(ctx, key, envelopeBytes)
	if err != nil {
		return err
	}

	return nil
}
