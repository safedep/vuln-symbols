package symbols

import (
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignatureNeedsTheBuildWorkflow(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	require.NoError(t, err)
	v, err := newSigstoreVerifier("", "")
	require.NoError(t, err)
	// The virtual Sigstore issues no certificate timestamp. The production
	// options also need one.
	v.options = []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}

	manifest := []byte(`{"format":1}`)
	for _, tc := range []struct {
		name, identity, issuer string
		artifact               []byte
		ok                     bool
	}{
		{"the build workflow of main", SignerIdentity, SignerIssuer, manifest, true},
		{"another workflow", "https://github.com/safedep/vuln-symbols/.github/workflows/ci.yml@refs/heads/main", SignerIssuer, manifest, false},
		{"another branch", "https://github.com/safedep/vuln-symbols/.github/workflows/build.yml@refs/heads/feature", SignerIssuer, manifest, false},
		{"a fork", "https://github.com/someone/vuln-symbols/.github/workflows/build.yml@refs/heads/main", SignerIssuer, manifest, false},
		{"another issuer", SignerIdentity, "https://accounts.example.com", manifest, false},
		{"another manifest", SignerIdentity, SignerIssuer, []byte(`{"format":2}`), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entity, err := vs.Sign(tc.identity, tc.issuer, tc.artifact)
			require.NoError(t, err)
			signed, err := v.verifyEntity(vs, entity, manifest)
			if tc.ok {
				assert.NoError(t, err)
				assert.False(t, signed.IsZero(), "a valid signature has a verified time")
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestPublicGoodOptionsNeedEveryProof(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	require.NoError(t, err)
	v, err := newSigstoreVerifier("", "")
	require.NoError(t, err)
	entity, err := vs.Sign(SignerIdentity, SignerIssuer, []byte("m"))
	require.NoError(t, err)
	_, err = v.verifyEntity(vs, entity, []byte("m"))
	assert.Error(t, err, "a signature with no certificate timestamp fails the production options")
}
