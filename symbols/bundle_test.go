package symbols_test

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	pb "github.com/safedep/dry/api/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vuln-symbols/internal/build"
	"github.com/safedep/vuln-symbols/internal/fixture"
	"github.com/safedep/vuln-symbols/internal/upstream"
	"github.com/safedep/vuln-symbols/symbols"
)

// testBuild makes a bundle with a Go record whose range has a backport,
// and a RustSec record of a crate with a dash in its name.
func testBuild(t *testing.T) build.Output {
	t.Helper()
	backport := fixture.GoAdvisory("GO-2026-0002", "example.com/acme/widget", "Decode")
	backport["aliases"] = []string{"CVE-2026-1111", "GHSA-wxyz-wxyz-wxyz"}
	backport["affected"].([]any)[0].(map[string]any)["ranges"] = []any{map[string]any{"type": "SEMVER", "events": []any{
		map[string]any{"introduced": "0"}, map[string]any{"fixed": "1.2.5"},
		map[string]any{"introduced": "1.3.0"}, map[string]any{"fixed": "1.3.2"},
	}}}
	o, err := build.Build([]build.Input{
		{Source: upstream.Go, Export: fixture.Zip(fixture.GoAdvisory("GO-2026-0001", "example.com/acme/widget", "Parse"), backport)},
		{Source: upstream.RustSec, Export: fixture.Zip(fixture.RustAdvisory("RUSTSEC-2026-0001", "acme-widget", "acme_widget::parse"))},
	})
	require.NoError(t, err)
	return o
}

func TestReadBundleChecksTheManifest(t *testing.T) {
	o := testBuild(t)
	b, err := symbols.ReadBundle(o.Manifest, o.Bundle)
	require.NoError(t, err)
	assert.Len(t, b.Records(), 3)
	assert.Equal(t, o.Manifest.Bundle.SHA256, b.Info().ID)

	bad := append([]byte(nil), o.Bundle...)
	bad[len(bad)/2] ^= 0xff
	_, err = symbols.ReadBundle(o.Manifest, bad)
	assert.ErrorContains(t, err, "SHA-256")

	_, err = symbols.ReadBundle(o.Manifest, o.Bundle[:len(o.Bundle)-1])
	assert.ErrorContains(t, err, "size")

	m := o.Manifest
	m.Bundle.Path = "../manifest.json"
	_, err = symbols.ReadBundle(m, o.Bundle)
	assert.ErrorContains(t, err, "bundle path")
}

func TestLookup(t *testing.T) {
	o := testBuild(t)
	b, err := symbols.ReadBundle(o.Manifest, o.Bundle)
	require.NoError(t, err)

	goPkg := func(v string) pb.PackageVersion {
		return pb.NewPackageVersionFromParts(packagev1.Ecosystem_ECOSYSTEM_GO, "example.com/acme/widget", v)
	}
	ids := func(as []symbols.Answer) []string {
		var out []string
		for _, a := range as {
			out = append(out, a.Record.ID)
		}
		return out
	}
	for _, tc := range []struct {
		name string
		q    symbols.Query
		want []string
	}{
		{"by an alias", symbols.Query{Package: goPkg("v1.2.0"), IDs: []string{"GHSA-wxyz-wxyz-wxyz"}}, []string{"GO-2026-0002"}},
		{"by the record id", symbols.Query{Package: goPkg("v1.1.0"), IDs: []string{"GO-2026-0001"}}, []string{"GO-2026-0001"}},
		{"every record of the version", symbols.Query{Package: goPkg("1.0.0")}, []string{"GO-2026-0001", "GO-2026-0002"}},
		{"a fixed version", symbols.Query{Package: goPkg("v1.2.5"), IDs: []string{"CVE-2026-1111"}}, nil},
		{"the second range of a backport", symbols.Query{Package: goPkg("v1.3.1"), IDs: []string{"CVE-2026-1111"}}, []string{"GO-2026-0002"}},
		{"between the two ranges", symbols.Query{Package: goPkg("v1.2.9"), IDs: []string{"CVE-2026-1111"}}, nil},
		{"a pseudo-version", symbols.Query{Package: goPkg("v0.0.0-20200101000000-abcdefabcdef"), IDs: []string{"GO-2026-0001"}}, []string{"GO-2026-0001"}},
		{"another advisory", symbols.Query{Package: goPkg("1.0.0"), IDs: []string{"CVE-2026-9999"}}, nil},
		{"another package", symbols.Query{Package: pb.NewPackageVersionFromParts(packagev1.Ecosystem_ECOSYSTEM_GO, "example.com/acme/other", "1.0.0")}, nil},
		{"a crate name in another spelling", symbols.Query{Package: pb.NewPackageVersionFromParts(packagev1.Ecosystem_ECOSYSTEM_CARGO, "acme_widget", "0.2.0")}, []string{"RUSTSEC-2026-0001"}},
		{"a version with no order", symbols.Query{Package: goPkg("not-a-version"), IDs: []string{"GO-2026-0001"}}, []string{"GO-2026-0001"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ids(b.Lookup(tc.q)))
		})
	}
}
