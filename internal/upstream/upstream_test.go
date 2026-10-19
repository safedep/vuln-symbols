package upstream

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vuln-symbols/internal/fixture"
	"github.com/safedep/vuln-symbols/symbols"
)

func TestConvertGo(t *testing.T) {
	adv := fixture.GoAdvisory("GO-2026-0001", "example.com/acme/widget", "Parse", "Decoder.Decode", "Parse")
	rec, ok, err := Convert(Go, adv.JSON())
	require.NoError(t, err)
	require.True(t, ok)

	assert.Equal(t, "GO-2026-0001", rec.ID)
	assert.Equal(t, symbols.SchemaVersion, rec.SchemaVersion)
	assert.Equal(t, "CC-BY-4.0", rec.DatabaseSpecific.License)
	assert.Equal(t, "https://pkg.go.dev/vuln/GO-2026-0001", rec.DatabaseSpecific.Source)
	require.Len(t, rec.Affected, 1)
	vs := rec.Affected[0].DatabaseSpecific.VulnSymbols
	assert.Equal(t, []string{symbols.MethodUpstream}, vs.Methods)
	assert.Equal(t, symbols.ReviewVerified, vs.Review.State)
	assert.Equal(t, symbols.CoverageExact, vs.Coverage)
	assert.Equal(t, []string{"example.com/acme/widget.Decoder.Decode", "example.com/acme/widget.Parse"}, rec.Affected[0].Names(), "the fix sites are sorted and unique")
}

func TestConvertRust(t *testing.T) {
	adv := fixture.RustAdvisory("RUSTSEC-2026-0001", "acme-widget", "acme_widget::Buf::insert", "acme_widget::parse")
	rec, ok, err := Convert(RustSec, adv.JSON())
	require.NoError(t, err)
	require.True(t, ok)
	assert.Empty(t, rec.Aliases, "a RustSec advisory can have no alias, and the record keeps the source id")
	assert.Equal(t, symbols.LanguageRust, rec.Affected[0].DatabaseSpecific.VulnSymbols.Language)
	assert.Equal(t, symbols.CoverageBroad, rec.Affected[0].DatabaseSpecific.VulnSymbols.Coverage, "RustSec does not promise a complete function list")
	assert.Equal(t, "CC0-1.0", rec.DatabaseSpecific.License)
	assert.Equal(t, []string{"acme_widget::Buf::insert", "acme_widget::parse"}, rec.Affected[0].Names())
}

func TestConvertSkips(t *testing.T) {
	withdrawn := fixture.GoAdvisory("GO-2026-0002", "example.com/acme/widget", "Parse")
	withdrawn["withdrawn"] = "2026-02-01T00:00:00Z"
	for _, tc := range []struct {
		name string
		src  Source
		adv  fixture.Advisory
	}{
		{"an advisory that another database owns", Go, fixture.GoAdvisory("GHSA-aaaa-bbbb-cccc", "example.com/acme/widget", "Parse")},
		{"a withdrawn advisory", Go, withdrawn},
		{"an advisory with no symbol", Go, fixture.GoAdvisory("GO-2026-0003", "example.com/acme/widget")},
		{"a RustSec advisory with no function", RustSec, fixture.RustAdvisory("RUSTSEC-2026-0002", "acme-widget")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ok, err := Convert(tc.src, tc.adv.JSON())
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
}

// An import with no symbol list affects the whole package. The entry must be
// broad, or a consumer could say "not called" for a call into the package.
func TestConvertWholePackageImportIsBroad(t *testing.T) {
	adv := fixture.GoAdvisory("GO-2026-0004", "example.com/acme/widget", "Parse")
	es := adv["affected"].([]any)[0].(map[string]any)["ecosystem_specific"].(map[string]any)
	es["imports"] = append(es["imports"].([]any), map[string]any{"path": "example.com/acme/widget/internal/codec"})
	rec, ok, err := Convert(Go, adv.JSON())
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, symbols.CoverageBroad, rec.Affected[0].DatabaseSpecific.VulnSymbols.Coverage)
}

func TestConvertManySymbolsIsBroad(t *testing.T) {
	var syms []string
	for i := range symbols.MaxExactFixSites + 1 {
		syms = append(syms, fmt.Sprintf("F%d", i))
	}
	rec, ok, err := Convert(Go, fixture.GoAdvisory("GO-2026-0005", "example.com/acme/widget", syms...).JSON())
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, symbols.CoverageBroad, rec.Affected[0].DatabaseSpecific.VulnSymbols.Coverage)
}

func TestConvertRejectsAnotherEcosystem(t *testing.T) {
	adv := fixture.GoAdvisory("GO-2026-0006", "example.com/acme/widget", "Parse")
	adv["affected"].([]any)[0].(map[string]any)["package"].(map[string]any)["ecosystem"] = "npm"
	_, _, err := Convert(Go, adv.JSON())
	assert.ErrorContains(t, err, `of ecosystem "npm"`)
}
