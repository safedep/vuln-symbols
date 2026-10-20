package verify

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vuln-symbols/symbols"
)

func upstreamRecord() symbols.Record {
	return symbols.Record{
		SchemaVersion:    symbols.SchemaVersion,
		ID:               "GO-2026-0001",
		Modified:         "2026-01-02T03:04:05Z",
		DatabaseSpecific: symbols.RecordDatabase{License: "CC-BY-4.0"},
		Affected: []symbols.Affected{{
			Package: symbols.Package{Ecosystem: "Go", Name: "example.com/acme/widget"},
			Ranges:  []symbols.Range{{Type: "SEMVER", Events: []symbols.Event{{Introduced: "0"}, {Fixed: "1.2.0"}}}},
			DatabaseSpecific: symbols.AffectedDatabase{VulnSymbols: symbols.VulnSymbols{
				Format:   symbols.Format,
				Language: symbols.LanguageGo,
				Methods:  []string{symbols.MethodUpstream},
				Coverage: symbols.CoverageExact,
				FixSites: []symbols.Symbol{{Name: "example.com/acme/widget.Parse"}},
				Review:   symbols.Review{State: symbols.ReviewVerified},
			}},
		}},
	}
}

func TestV0_ValidUpstreamRecord(t *testing.T) {
	require.NoError(t, V0(upstreamRecord()))
}

func TestV0_Rules(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(r *symbols.Record)
		want   string
	}{
		{"schema version", func(r *symbols.Record) { r.SchemaVersion = "1.0.0" }, "schema_version"},
		{"no license", func(r *symbols.Record) { r.DatabaseSpecific.License = "" }, "no license"},
		{"bad modified time", func(r *symbols.Record) { r.Modified = "yesterday" }, "RFC 3339"},
		{"unknown ecosystem", func(r *symbols.Record) { r.Affected[0].Package.Ecosystem = "Nope" }, "no known package"},
		{"two ranges", func(r *symbols.Record) { r.Affected[0].Ranges = append(r.Affected[0].Ranges, r.Affected[0].Ranges[0]) }, "2 ranges"},
		{"format", func(r *symbols.Record) { vs(r).Format = 2 }, "format 2"},
		{"language of another ecosystem", func(r *symbols.Record) { vs(r).Language = symbols.LanguageRust }, "does not fit"},
		{"unknown method", func(r *symbols.Record) { vs(r).Methods = []string{"guess"} }, "known methods"},
		{"duplicate method", func(r *symbols.Record) {
			vs(r).Methods = []string{symbols.MethodManual, symbols.MethodManual}
			vs(r).Review.State = symbols.ReviewReviewed
		}, "no duplicate"},
		{"upstream with another method", func(r *symbols.Record) {
			vs(r).Methods = []string{symbols.MethodUpstream, symbols.MethodManual}
		}, "combines upstream"},
		{"upstream that is not verified", func(r *symbols.Record) { vs(r).Review.State = symbols.ReviewReviewed }, "is upstream"},
		{"exact with no fix site", func(r *symbols.Record) { vs(r).FixSites = nil }, "is exact"},
		{"exact with too many fix sites", func(r *symbols.Record) {
			vs(r).FixSites = nil
			for i := range symbols.MaxExactFixSites + 1 {
				vs(r).FixSites = append(vs(r).FixSites, symbols.Symbol{Name: fmt.Sprintf("example.com/acme/widget.F%d", i)})
			}
		}, "is exact"},
		{"exact with an incomplete derivation", func(r *symbols.Record) {
			vs(r).EntrySymbols = &symbols.EntrySymbols{Complete: false}
		}, "is exact"},
		{"duplicate fix site", func(r *symbols.Record) { vs(r).FixSites = append(vs(r).FixSites, vs(r).FixSites[0]) }, "duplicate fix site"},
		{"community record with no alias", func(r *symbols.Record) {
			vs(r).Methods = []string{symbols.MethodPatchAnalysis}
			vs(r).Review.State = symbols.ReviewUnreviewed
		}, "aliases"},
		{"community record with another license", func(r *symbols.Record) {
			vs(r).Methods = []string{symbols.MethodPatchAnalysis}
			vs(r).Review.State = symbols.ReviewUnreviewed
			r.Aliases = []string{"GHSA-aaaa-bbbb-cccc"}
			r.DatabaseSpecific.License = "Apache-2.0"
		}, `license "Apache-2.0"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := upstreamRecord()
			tc.change(&r)
			assert.ErrorContains(t, V0(r), tc.want)
		})
	}
}

func vs(r *symbols.Record) *symbols.VulnSymbols { return &r.Affected[0].DatabaseSpecific.VulnSymbols }

func TestV5_Notation(t *testing.T) {
	for _, tc := range []struct {
		language, pkg, name string
		ok                  bool
	}{
		{symbols.LanguageGo, "example.com/acme/widget", "example.com/acme/widget.Parse", true},
		{symbols.LanguageGo, "example.com/acme/widget", "example.com/acme/widget.Decoder.Decode", true},
		{symbols.LanguageGo, "example.com/acme/widget", "example.com/acme/widget/codec.Decode", true},
		{symbols.LanguageGo, "example.com/acme/widget", "example.com/acme/widget/cmd/tool.init#2", true},
		{symbols.LanguageGo, "example.com/acme/widget/v2", "example.com/acme/widget/v2.Parse", true},
		{symbols.LanguageGo, "example.com/acme/yaml.v3", "example.com/acme/yaml.v3.Unmarshal", true},
		{symbols.LanguageGo, "stdlib", "net/http.Server.Serve", true},
		{symbols.LanguageGo, "stdlib", "fmt.Sprintf", true},
		{symbols.LanguageGo, "example.com/acme/widget", "example.com/acme/other.Parse", false},
		{symbols.LanguageGo, "example.com/acme/widget", "example.com/acme/widgets.Parse", false},
		{symbols.LanguageGo, "example.com/acme/widget", "example.com/acme/widget", false},
		{symbols.LanguageGo, "example.com/acme/widget", "example.com/acme/widget.A.B.C", false},
		{symbols.LanguageGo, "stdlib", "Sprintf", false},
		{symbols.LanguageRust, "acme-widget", "acme_widget::Buf::insert", true},
		{symbols.LanguageRust, "acme-widget", "acme_widget::Buf<T>::insert", true},
		{symbols.LanguageRust, "acme-widget", "insert", false},
		{symbols.LanguageRust, "acme-widget", "acme_widget::", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := upstreamRecord()
			r.Affected[0].Package.Name = tc.pkg
			vs(&r).Language = tc.language
			vs(&r).FixSites = []symbols.Symbol{{Name: tc.name}}
			if tc.ok {
				assert.NoError(t, V5(r))
			} else {
				assert.ErrorContains(t, V5(r), "V5")
			}
		})
	}
}
