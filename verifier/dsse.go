package verifier

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"golang.org/x/crypto/ssh"
)

// ErrNoSignature indicates that an envelope did not contain any signatures.
var errNoSignature = errors.New("no signature found")

type envelopeVerifier struct {
	providers []dsse.Verifier
	threshold int
}

type acceptedKey struct {
	Public crypto.PublicKey
	KeyID  string
	Sig    dsse.Signature
}

func (ev *envelopeVerifier) Verify(ctx context.Context, e *dsse.Envelope) ([]acceptedKey, error) {
	if e == nil {
		return nil, errors.New("cannot verify a nil envelope")
	}

	if len(e.Signatures) == 0 {
		return nil, errNoSignature
	}

	// Decode payload (i.e serialized body)
	body, err := e.DecodeB64Payload()
	if err != nil {
		return nil, err
	}
	// Generate PAE(payloadtype, serialized body)
	paeEnc := dsse.PAE(e.PayloadType, body)

	// If *any* signature is found to be incorrect, it is skipped
	var acceptedKeys []acceptedKey
	usedKeyids := make(map[string]string)
	unverified_providers := ev.providers
	for _, s := range e.Signatures {
		sig, err := b64Decode(s.Sig)
		if err != nil {
			return nil, err
		}

		// Loop over the providers.
		// If provider and signature include key IDs but do not match skip.
		// If a provider recognizes the key, we exit
		// the loop and use the result.
		providers := unverified_providers
		for i, v := range providers {
			keyID, err := v.KeyID()

			// Verifiers that do not provide a keyid will be generated one using public.
			if err != nil || keyID == "" {
				keyID, err = SHA256KeyID(v.Public())
				if err != nil {
					keyID = ""
				}
			}

			if s.KeyID != "" && keyID != "" && err == nil && s.KeyID != keyID {
				continue
			}

			err = v.Verify(ctx, paeEnc, sig)
			if err != nil {
				continue
			}

			acceptedKey := acceptedKey{
				Public: v.Public(),
				KeyID:  keyID,
				Sig:    s,
			}
			unverified_providers = removeIndex(providers, i)

			// See https://github.com/in-toto/in-toto/pull/251
			if _, ok := usedKeyids[keyID]; ok {
				fmt.Printf("Found envelope signed by different subkeys of the same main key, Only one of them is counted towards the step threshold, KeyID=%s\n", keyID)
				continue
			}

			usedKeyids[keyID] = ""
			acceptedKeys = append(acceptedKeys, acceptedKey)
			break
		}
	}

	// Sanity if with some reflect magic this happens.
	if ev.threshold <= 0 || ev.threshold > len(ev.providers) {
		return nil, errors.New("invalid threshold")
	}

	if len(usedKeyids) < ev.threshold {
		return acceptedKeys, fmt.Errorf("accepted signatures do not match threshold, Found: %d, Expected %d", len(acceptedKeys), ev.threshold)
	}

	return acceptedKeys, nil
}

func newEnvelopeVerifier(v ...dsse.Verifier) (*envelopeVerifier, error) {
	return newMultiEnvelopeVerifier(1, v...)
}

func newMultiEnvelopeVerifier(threshold int, p ...dsse.Verifier) (*envelopeVerifier, error) {
	if threshold <= 0 || threshold > len(p) {
		return nil, errors.New("invalid threshold")
	}

	ev := envelopeVerifier{
		providers: p,
		threshold: threshold,
	}

	return &ev, nil
}

func SHA256KeyID(pub crypto.PublicKey) (string, error) {
	// Generate public key fingerprint
	sshpk, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	fingerprint := ssh.FingerprintSHA256(sshpk)
	return fingerprint, nil
}

func removeIndex(v []dsse.Verifier, index int) []dsse.Verifier {
	return append(v[:index], v[index+1:]...)
}

/*
Both standard and url encoding are allowed:
https://github.com/secure-systems-lab/dsse/blob/master/envelope.md
*/
func b64Decode(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("unable to base64 decode payload (is payload in the right format?)")
		}
	}

	return b, nil
}
