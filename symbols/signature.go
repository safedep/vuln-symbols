package symbols

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// The identity of the signer. Only the build workflow of the main branch
// of safedep/vuln-symbols signs a manifest, with a keyless Sigstore
// certificate from its GitHub OIDC token.
const (
	SignerIssuer   = "https://token.actions.githubusercontent.com"
	SignerIdentity = "https://github.com/safedep/vuln-symbols/.github/workflows/build.yml@refs/heads/main"
)

// verifier checks the signature of a manifest. It returns the time of the
// signature that a transparency log or a timestamp authority proves.
type verifier interface {
	verify(manifest, signature []byte) (time.Time, error)
}

// sigstoreVerifier checks a Sigstore bundle against the public good
// Sigstore instance.
type sigstoreVerifier struct {
	identity verify.CertificateIdentity
	options  []verify.VerifierOption
	material func() (root.TrustedMaterial, error)
}

// cosign signs with a certificate that carries a certificate timestamp, and
// the transparency log entry or a timestamp authority gives the time of the
// signature.
var publicGoodOptions = []verify.VerifierOption{
	verify.WithSignedCertificateTimestamps(1),
	verify.WithTransparencyLog(1),
	verify.WithObserverTimestamps(1),
}

// newSigstoreVerifier reads the trusted root from a file when one is given.
// Else it reads the trusted root through TUF on first use, with the TUF
// cache under the cache directory. TUF can need the network to refresh
// its metadata, so a client with no network gives a trusted root file.
func newSigstoreVerifier(cacheDir, trustedRoot string) (*sigstoreVerifier, error) {
	id, err := verify.NewShortCertificateIdentity(SignerIssuer, "", SignerIdentity, "")
	if err != nil {
		return nil, err
	}
	var once sync.Once
	var material root.TrustedMaterial
	var materialErr error
	return &sigstoreVerifier{
		identity: id,
		options:  publicGoodOptions,
		material: func() (root.TrustedMaterial, error) {
			once.Do(func() {
				if trustedRoot != "" {
					material, materialErr = root.NewTrustedRootFromPath(trustedRoot)
					return
				}
				opts := tuf.DefaultOptions()
				if cacheDir != "" {
					opts.CachePath = filepath.Join(cacheDir, "sigstore-tuf")
				}
				material, materialErr = root.FetchTrustedRootWithOptions(opts)
			})
			return material, materialErr
		},
	}, nil
}

func (v *sigstoreVerifier) verify(manifest, signature []byte) (time.Time, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(signature); err != nil {
		return time.Time{}, fmt.Errorf("decode the signature: %w", err)
	}
	material, err := v.material()
	if err != nil {
		return time.Time{}, fmt.Errorf("read the Sigstore trusted root: %w", err)
	}
	return v.verifyEntity(material, &b, manifest)
}

func (v *sigstoreVerifier) verifyEntity(material root.TrustedMaterial, e verify.SignedEntity, manifest []byte) (time.Time, error) {
	sv, err := verify.NewVerifier(material, v.options...)
	if err != nil {
		return time.Time{}, err
	}
	policy := verify.NewPolicy(verify.WithArtifact(bytes.NewReader(manifest)), verify.WithCertificateIdentity(v.identity))
	res, err := sv.Verify(e, policy)
	if err != nil {
		return time.Time{}, fmt.Errorf("verify the signature: %w", err)
	}
	var signed time.Time
	for _, ts := range res.VerifiedTimestamps {
		if ts.Timestamp.After(signed) {
			signed = ts.Timestamp
		}
	}
	if signed.IsZero() {
		return time.Time{}, errors.New("verify the signature: no verified time")
	}
	return signed.UTC(), nil
}
