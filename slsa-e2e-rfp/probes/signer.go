package probes

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
)

type Signer dsse.Signer

// Can't think of better than copying this right now:
// https://github.com/secure-systems-lab/go-securesystemslib/blob/v0.9.1/signerverifier/utils.go#L48
func calculateKeyID(k *signerverifier.SSLibKey) (string, error) {
	key := map[string]any{
		"keytype":               k.KeyType,
		"scheme":                k.Scheme,
		"keyid_hash_algorithms": k.KeyIDHashAlgorithms,
		"keyval": map[string]string{
			"public": k.KeyVal.Public,
		},
	}
	canonical, err := cjson.EncodeCanonical(key)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func newEd25519SSLibKey(rng io.Reader) (*signerverifier.SSLibKey, error) {
	public, private, err := ed25519.GenerateKey(rng)
	if err != nil {
		return nil, err
	}

	key := &signerverifier.SSLibKey{
		KeyType:             "ed25519",
		Scheme:              "ed25519",
		KeyIDHashAlgorithms: signerverifier.KeyIDHashAlgorithms,
		KeyVal: signerverifier.KeyVal{
			Private: hex.EncodeToString(private),
			Public:  hex.EncodeToString(public),
		},
	}

	keyID, err := calculateKeyID(key)
	if err != nil {
		return nil, err
	}
	key.KeyID = keyID
	fmt.Println("Key ID:", keyID, "/", "Public Key:", key.KeyVal.Public)

	return key, nil
}

func NewEd25519Signer(rng io.Reader) (dsse.Signer, error) {
	ssLibKey, err := newEd25519SSLibKey(rng)
	if err != nil {
		return nil, err
	}
	sv, err := signerverifier.NewED25519SignerVerifierFromSSLibKey(ssLibKey)
	if err != nil {
		return nil, err
	}
	return sv, nil
}
