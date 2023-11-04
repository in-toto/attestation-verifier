package verifier

import (
	"context"
	"crypto"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
	gitsignVerifier "github.com/sigstore/gitsign/pkg/git"
	gitsignRekor "github.com/sigstore/gitsign/pkg/rekor"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	sigstoreVerify "github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
)

const (
	rekorServer = "https://rekor.sigstore.dev"
)

var (
	errNotImplemented             = errors.New("not implemented")
	ErrIncorrectVerificationKey   = errors.New("incorrect key provided to verify signature")
	ErrVerifyingSigstoreSignature = errors.New("unable to verify sigstore signature")
)

//go:embed root/trusted-root.json
var trustedRoot []byte

type sigstoreSignerVerifier struct {
	identity string
	issuer   string
}

func newSigstoreSignerVerifierFromSSLibKey(key *signerverifier.SSLibKey) (*sigstoreSignerVerifier, error) {
	return &sigstoreSignerVerifier{identity: key.KeyVal.Identity, issuer: key.KeyVal.Issuer}, nil
}

func (s *sigstoreSignerVerifier) Sign(_ context.Context, _ []byte) ([]byte, error) {
	return nil, errNotImplemented
}

func (s *sigstoreSignerVerifier) Verify(ctx context.Context, data, sig []byte) error {
	// data is PAE encoded bytes for DSSE
	// sig is from the signature
	// cert must be fetched

	root, err := fulcioroots.Get()
	if err != nil {
		return errors.Join(ErrVerifyingSigstoreSignature, err)
	}
	intermediate, err := fulcioroots.GetIntermediates()
	if err != nil {
		return errors.Join(ErrVerifyingSigstoreSignature, err)
	}

	verifier, err := gitsignVerifier.NewCertVerifier(
		gitsignVerifier.WithRootPool(root),
		gitsignVerifier.WithIntermediatePool(intermediate),
	)
	if err != nil {
		return errors.Join(ErrVerifyingSigstoreSignature, err)
	}

	rekor, err := gitsignRekor.New(rekorServer)
	if err != nil {
		return errors.Join(ErrVerifyingSigstoreSignature, err)
	}

	ctPub, err := cosign.GetCTLogPubs(ctx)
	if err != nil {
		return errors.Join(ErrVerifyingSigstoreSignature, err)
	}

	verifiedCert, err := verifier.Verify(ctx, data, sig, true)
	if err != nil {
		return ErrIncorrectVerificationKey
	}

	checkOpts := &cosign.CheckOpts{
		RekorClient:       rekor.Rekor,
		RootCerts:         root,
		IntermediateCerts: intermediate,
		CTLogPubKeys:      ctPub,
		RekorPubKeys:      rekor.PublicKeys(),
		Identities: []cosign.Identity{{
			Issuer:  s.issuer,
			Subject: s.identity,
		}},
	}

	if _, err := cosign.ValidateAndUnpackCert(verifiedCert, checkOpts); err != nil {
		return ErrIncorrectVerificationKey
	}
	return nil
}

func (s *sigstoreSignerVerifier) KeyID() (string, error) {
	return fmt.Sprintf("%s::%s", s.identity, s.issuer), nil
}

func (s *sigstoreSignerVerifier) Public() crypto.PublicKey {
	return errNotImplemented
}

func verifySigstore(env *dsse.Envelope, sig dsse.Signature, issuer, identity string) error {
	sigContent := &bundle.Envelope{Envelope: env}

	block, _ := pem.Decode([]byte(sig.Cert))

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	verificationContent := &bundle.CertificateChain{Certificates: []*x509.Certificate{cert}}

	trustedMaterial, err := root.NewTrustedRootFromJSON(trustedRoot)
	if err != nil {
		return err
	}

	if err := sigstoreVerify.VerifySignature(sigContent, verificationContent, trustedMaterial); err != nil {
		return err
	}

	return nil
}
