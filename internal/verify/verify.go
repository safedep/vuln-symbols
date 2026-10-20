// Package verify holds the checks of docs/spec/verification.md. Each check
// is deterministic and calls no model.
package verify

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	pb "github.com/safedep/dry/api/pb"
	"github.com/safedep/vuln-symbols/symbols"
)

// Error is a failed check of one record.
type Error struct {
	Check  string
	Record string
	Detail string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s: %s", e.Record, e.Check, e.Detail) }

// Upstream runs the checks that apply to an upstream record: V0 and V5.
func Upstream(r symbols.Record) error {
	return errors.Join(V0(r), V5(r))
}

// languages maps each OSV ecosystem that the database holds to the
// language of its symbols.
var languages = map[string]string{"Go": symbols.LanguageGo, "crates.io": symbols.LanguageRust}

var (
	methods  = []string{symbols.MethodUpstream, symbols.MethodPatchAnalysis, symbols.MethodManual}
	reviews  = []string{symbols.ReviewUnreviewed, symbols.ReviewReviewed, symbols.ReviewVerified}
	coverage = []string{symbols.CoverageExact, symbols.CoverageBroad}
)

// V0 checks that the record is an OSV document that keeps the rules of the
// extension.
func V0(r symbols.Record) error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, &Error{Check: "V0", Record: r.ID, Detail: fmt.Sprintf(format, args...)})
	}
	switch {
	case r.SchemaVersion != symbols.SchemaVersion:
		fail("schema_version %q is not %q", r.SchemaVersion, symbols.SchemaVersion)
	case r.ID == "":
		fail("the record has no id")
	case r.DatabaseSpecific.License == "":
		fail("the record names no license")
	case len(r.Affected) == 0:
		fail("the record has no affected entry")
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Modified); err != nil {
		fail("modified %q is not an RFC 3339 time", r.Modified)
	}
	upstream := false
	for i, a := range r.Affected {
		at := fmt.Sprintf("affected[%d]", i)
		vs := a.DatabaseSpecific.VulnSymbols
		if _, err := pb.EcosystemFromOSVName(a.Package.Ecosystem); err != nil || a.Package.Name == "" {
			fail("%s names no known package", at)
		}
		if len(a.Ranges) != 1 || len(a.Ranges[0].Events) == 0 {
			fail("%s has %d ranges, not one range with events", at, len(a.Ranges))
		}
		if vs.Format != symbols.Format {
			fail("%s format %d is not %d", at, vs.Format, symbols.Format)
		}
		if lang, ok := languages[a.Package.Ecosystem]; !ok || vs.Language != lang {
			fail("%s language %q does not fit ecosystem %q", at, vs.Language, a.Package.Ecosystem)
		}
		if len(vs.Methods) == 0 || slices.ContainsFunc(vs.Methods, func(m string) bool { return !slices.Contains(methods, m) }) || len(slices.Compact(slices.Sorted(slices.Values(vs.Methods)))) != len(vs.Methods) {
			fail("%s methods %v are not a list of known methods with no duplicate", at, vs.Methods)
		}
		if slices.Contains(vs.Methods, symbols.MethodUpstream) {
			upstream = true
			if len(vs.Methods) != 1 {
				fail("%s combines upstream with another method", at)
			}
			if vs.Review.State != symbols.ReviewVerified || len(vs.ChangedFunctions) > 0 || vs.Fix != nil {
				fail("%s is upstream, so it is verified and has no fix and no changed functions", at)
			}
		}
		if !slices.Contains(reviews, vs.Review.State) {
			fail("%s review state %q is unknown", at, vs.Review.State)
		}
		if !slices.Contains(coverage, vs.Coverage) {
			fail("%s coverage %q is unknown", at, vs.Coverage)
		}
		if mustBeBroad(vs) && vs.Coverage != symbols.CoverageBroad {
			fail("%s is exact, but it has %d fix sites or an incomplete derivation", at, len(vs.FixSites))
		}
		names := a.Names()
		if slices.Contains(names, "") || len(slices.Compact(slices.Sorted(slices.Values(names)))) != len(names) {
			fail("%s has an empty or a duplicate fix site", at)
		}
	}
	if !upstream && len(r.Aliases) == 0 {
		fail("a community record names at least one advisory in aliases")
	}
	if !upstream && r.DatabaseSpecific.License != symbols.CommunityLicense {
		fail("a community record has license %q, not %q", r.DatabaseSpecific.License, symbols.CommunityLicense)
	}
	return errors.Join(errs...)
}

// mustBeBroad applies the coverage rule of docs/spec/record.md.
func mustBeBroad(vs symbols.VulnSymbols) bool {
	return len(vs.FixSites) == 0 || len(vs.FixSites) > symbols.MaxExactFixSites || vs.EntrySymbols != nil && !vs.EntrySymbols.Complete
}

var (
	goIdent = `[A-Za-z_][A-Za-z0-9_]*`
	// The Go vulnerability database names the init functions of a package
	// init#1, init#2 and on.
	goSymbol = regexp.MustCompile(`^(init#[0-9]+|` + goIdent + `(\.` + goIdent + `)?)$`)
	rustPath = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(::[^:\s]+)+$`)
)

// V5 checks the notation of each symbol of the record.
func V5(r symbols.Record) error {
	var errs []error
	for i, a := range r.Affected {
		vs := a.DatabaseSpecific.VulnSymbols
		all := slices.Clone(vs.FixSites)
		if vs.EntrySymbols != nil {
			all = append(all, vs.EntrySymbols.Symbols...)
		}
		for _, s := range all {
			if !notation(vs.Language, a.Package.Name, s.Name) {
				errs = append(errs, &Error{Check: "V5", Record: r.ID, Detail: fmt.Sprintf("affected[%d] symbol %q does not follow the %s notation", i, s.Name, vs.Language)})
			}
		}
	}
	return errors.Join(errs...)
}

// notation checks one name.
func notation(language, pkg, name string) bool {
	switch language {
	case symbols.LanguageGo:
		return goNotation(pkg, name)
	case symbols.LanguageRust:
		return rustPath.MatchString(name)
	}
	return false
}

// goNotation checks an import path, a dot, and a function or a type and a
// method. The import path is the module path of the package or a path under
// it. The Go standard library has the modules stdlib and toolchain, and a
// package name of the standard library has no dot.
func goNotation(module, name string) bool {
	rest := name
	if module != "stdlib" && module != "toolchain" {
		var ok bool
		if rest, ok = strings.CutPrefix(name, module); !ok {
			return false
		}
		if sym, ok := strings.CutPrefix(rest, "."); ok {
			return goSymbol.MatchString(sym)
		}
		if !strings.HasPrefix(rest, "/") {
			return false
		}
	}
	_, sym, ok := strings.Cut(rest[strings.LastIndex(rest, "/")+1:], ".")
	return ok && goSymbol.MatchString(sym)
}
