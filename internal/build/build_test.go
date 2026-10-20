package build

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vuln-symbols/internal/fixture"
	"github.com/safedep/vuln-symbols/internal/upstream"
	"github.com/safedep/vuln-symbols/symbols"
)

func inputs() []Input {
	goAdv := fixture.GoAdvisory("GO-2026-0002", "example.com/acme/widget", "Parse")
	goAdv["modified"] = "2026-03-04T05:06:07.123456789Z"
	return []Input{
		{Source: upstream.Go, Export: fixture.Zip(
			fixture.GoAdvisory("GO-2026-0001", "example.com/acme/widget", "Decode"),
			goAdv,
			fixture.GoAdvisory("GHSA-aaaa-bbbb-cccc", "example.com/acme/widget", "Decode"),
		)},
		{Source: upstream.RustSec, Export: fixture.Zip(fixture.RustAdvisory("RUSTSEC-2026-0001", "acme-widget", "acme_widget::parse"))},
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	a, err := Build(inputs())
	require.NoError(t, err)
	b, err := Build(inputs())
	require.NoError(t, err)
	assert.Equal(t, a.ManifestJSON, b.ManifestJSON)
	assert.Equal(t, a.Bundle, b.Bundle)
}

func TestBuildManifest(t *testing.T) {
	o, err := Build(inputs())
	require.NoError(t, err)
	m, err := symbols.ParseManifest(o.ManifestJSON)
	require.NoError(t, err)
	assert.Equal(t, 3, m.Records, "the build keeps only the advisories that the source owns")
	assert.Equal(t, "2026-03-04T05:06:07.123456789Z", m.AsOf.Format("2006-01-02T15:04:05.999999999Z07:00"), "as_of is the newest modified time of a record")
	require.Len(t, m.Sources, 2)
	assert.Equal(t, 2, m.Sources[0].Records)
	assert.Equal(t, 1, m.Sources[1].Records)

	b, err := symbols.ReadBundle(m, o.Bundle)
	require.NoError(t, err)
	var ids []string
	for _, r := range b.Records() {
		ids = append(ids, r.ID)
	}
	assert.Equal(t, []string{"GO-2026-0001", "GO-2026-0002", "RUSTSEC-2026-0001"}, ids, "the records are sorted by id")
}

func TestBuildFailsOnABadRecord(t *testing.T) {
	in := inputs()
	in[0].Export = fixture.Zip(fixture.GoAdvisory("GO-2026-0003", "example.com/acme/widget", "not a symbol"))
	_, err := Build(in)
	assert.ErrorContains(t, err, "V5")
}

func TestBuildWrite(t *testing.T) {
	o, err := Build(inputs())
	require.NoError(t, err)
	dir := t.TempDir()
	require.NoError(t, o.Write(dir))
	assert.FileExists(t, dir+"/manifest.json")
	assert.FileExists(t, dir+"/"+o.Manifest.Bundle.Path)
	assert.FileExists(t, dir+"/manifests/"+o.Manifest.Bundle.SHA256+".json")
}
