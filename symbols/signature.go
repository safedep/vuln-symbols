package symbols

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sync"

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

// verifier checks the signature of a manifest.
type verifier interface {
	verify(manifest, signature []byte) error
}

// sigstoreVerifier checks a Sigstore bundle against the public good
// Sigstore instance. It reads the trusted root through TUF on first use,
// and keeps the TUF cache under the cache directory of the client.
type sigstoreVerifier struct {
	identity verify.CertificateIdentity
	options  []verify.VerifierOption
	material func() (root.TrustedMaterial, error)
}

// cosign signs with a certificate that carries a certificate timestamp, and
// the transparency log entry gives the time of the signature.
var publicGoodOptions = []verify.VerifierOption{
	verify.WithSignedCertificateTimestamps(1),
	verify.WithTransparencyLog(1),
	verify.WithObserverTimestamps(1),
}

func newSigstoreVerifier(cacheDir string, offline bool) (*sigstoreVerifier, error) {
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
				opts := tuf.DefaultOptions()
				if cacheDir != "" {
					opts.CachePath = filepath.Join(cacheDir, "sigstore-tuf")
				}
				// An offline client reads the trusted root from the TUF
				// cache of an earlier online run.
				opts.ForceCache = offline
				material, materialErr = root.FetchTrustedRootWithOptions(opts)
			})
			return material, materialErr
		},
	}, nil
}

func (v *sigstoreVerifier) verify(manifest, signature []byte) error {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(signature); err != nil {
		return fmt.Errorf("decode the signature: %w", err)
	}
	material, err := v.material()
	if err != nil {
		return fmt.Errorf("read the Sigstore trusted root: %w", err)
	}
	return v.verifyEntity(material, &b, manifest)
}

func (v *sigstoreVerifier) verifyEntity(material root.TrustedMaterial, e verify.SignedEntity, manifest []byte) error {
	sv, err := verify.NewVerifier(material, v.options...)
	if err != nil {
		return err
	}
	policy := verify.NewPolicy(verify.WithArtifact(bytes.NewReader(manifest)), verify.WithCertificateIdentity(v.identity))
	if _, err := sv.Verify(e, policy); err != nil {
		return fmt.Errorf("verify the signature: %w", err)
	}
	return nil
}
