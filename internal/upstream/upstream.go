// Package upstream turns an advisory of a database that already lists
// symbols into an upstream record of docs/spec/record.md.
package upstream

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/safedep/vuln-symbols/symbols"
)

// Source is one upstream database.
type Source struct {
	Name        string
	Ecosystem   string
	ExportURL   string
	IDPrefix    string
	Language    string
	License     string
	Attribution string
	// exact marks a source that promises a complete symbol list. RustSec
	// lists the affected functions with no such promise, so its entries are
	// broad, and no consumer says "not called" from them.
	exact bool
	// recordURL gives the page of one advisory.
	recordURL func(id string) string
	// names gives the symbols of one affected entry, and whether the
	// entry names its symbols in full.
	names func(es ecosystemSpecific) (names []string, complete bool)
}

// RecordURL returns the page of an advisory of the source.
func (s Source) RecordURL(id string) string { return s.recordURL(id) }

// Go is the Go vulnerability database.
var Go = Source{
	Name:        "Go vulnerability database",
	Ecosystem:   "Go",
	ExportURL:   "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip",
	IDPrefix:    "GO-",
	Language:    symbols.LanguageGo,
	License:     "CC-BY-4.0",
	Attribution: "Go vulnerability database (https://vuln.go.dev) by the Go Authors, licensed under CC-BY-4.0",
	exact:       true,
	recordURL:   func(id string) string { return "https://pkg.go.dev/vuln/" + id },
	names:       goNames,
}

// RustSec is the RustSec advisory database.
var RustSec = Source{
	Name:        "RustSec advisory database",
	Ecosystem:   "crates.io",
	ExportURL:   "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip",
	IDPrefix:    "RUSTSEC-",
	Language:    symbols.LanguageRust,
	License:     "CC0-1.0",
	Attribution: "RustSec advisory database (https://rustsec.org), dedicated to the public domain under CC0-1.0",
	recordURL:   func(id string) string { return "https://rustsec.org/advisories/" + id + ".html" },
	names:       rustNames,
}

// Sources lists the upstream databases in build order.
var Sources = []Source{Go, RustSec}

type advisory struct {
	ID         string              `json:"id"`
	Modified   string              `json:"modified"`
	Published  string              `json:"published"`
	Withdrawn  string              `json:"withdrawn"`
	Aliases    []string            `json:"aliases"`
	Summary    string              `json:"summary"`
	Affected   []affected          `json:"affected"`
	References []symbols.Reference `json:"references"`
}

type affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges            []symbols.Range   `json:"ranges"`
	EcosystemSpecific ecosystemSpecific `json:"ecosystem_specific"`
}

type ecosystemSpecific struct {
	Imports []struct {
		Path    string   `json:"path"`
		Symbols []string `json:"symbols"`
	} `json:"imports"`
	Affects struct {
		Functions []string `json:"functions"`
	} `json:"affects"`
}

// goNames joins each import path with its symbols, as the Go vulnerability
// database writes a symbol. An import with no symbol list affects the whole
// package, so the entry does not name its symbols in full.
func goNames(es ecosystemSpecific) ([]string, bool) {
	var names []string
	complete := true
	for _, imp := range es.Imports {
		if len(imp.Symbols) == 0 {
			complete = false
		}
		for _, s := range imp.Symbols {
			names = append(names, imp.Path+"."+s)
		}
	}
	return names, complete
}

func rustNames(es ecosystemSpecific) ([]string, bool) {
	return slices.Clone(es.Affects.Functions), true
}

// Convert reads one advisory of the source. It returns false for an
// advisory that the source does not own, that is withdrawn, or that lists
// no symbol.
func Convert(src Source, data []byte) (symbols.Record, bool, error) {
	var adv advisory
	if err := json.Unmarshal(data, &adv); err != nil {
		return symbols.Record{}, false, fmt.Errorf("decode advisory: %w", err)
	}
	if !strings.HasPrefix(adv.ID, src.IDPrefix) || adv.Withdrawn != "" {
		return symbols.Record{}, false, nil
	}
	rec := symbols.Record{
		SchemaVersion:    symbols.SchemaVersion,
		ID:               adv.ID,
		Modified:         adv.Modified,
		Published:        adv.Published,
		Aliases:          sortedUnique(adv.Aliases),
		Summary:          adv.Summary,
		References:       adv.References,
		DatabaseSpecific: symbols.RecordDatabase{License: src.License, Source: src.RecordURL(adv.ID)},
	}
	found := false
	for _, a := range adv.Affected {
		if a.Package.Ecosystem != src.Ecosystem {
			return symbols.Record{}, false, fmt.Errorf("%s: affected package %q is of ecosystem %q, not %q", adv.ID, a.Package.Name, a.Package.Ecosystem, src.Ecosystem)
		}
		names, complete := src.names(a.EcosystemSpecific)
		names = sortedUnique(names)
		found = found || len(names) > 0
		rec.Affected = append(rec.Affected, symbols.Affected{
			Package: symbols.Package{Ecosystem: a.Package.Ecosystem, Name: a.Package.Name},
			Ranges:  a.Ranges,
			DatabaseSpecific: symbols.AffectedDatabase{VulnSymbols: symbols.VulnSymbols{
				Format:   symbols.Format,
				Language: src.Language,
				Methods:  []string{symbols.MethodUpstream},
				Coverage: coverage(names, complete && src.exact),
				FixSites: toSymbols(names),
				Review:   symbols.Review{State: symbols.ReviewVerified},
			}},
		})
	}
	if !found {
		return symbols.Record{}, false, nil
	}
	return rec, true, nil
}

// coverage applies the rule of docs/spec/record.md to an upstream entry. An
// entry that does not name its symbols in full is broad, so no consumer
// says "not called" from it.
func coverage(names []string, complete bool) string {
	if !complete || len(names) == 0 || len(names) > symbols.MaxExactFixSites {
		return symbols.CoverageBroad
	}
	return symbols.CoverageExact
}

func toSymbols(names []string) []symbols.Symbol {
	out := make([]symbols.Symbol, len(names))
	for i, n := range names {
		out[i] = symbols.Symbol{Name: n}
	}
	return out
}

func sortedUnique(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}
