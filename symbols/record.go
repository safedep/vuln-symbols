// Package symbols reads the records of the vuln-symbols database. A record
// is an OSV document with the extension of docs/spec/record.md. The package
// fetches, verifies and caches the signed bundle, and matches a package
// version to its records.
package symbols

// SchemaVersion is the OSV schema version that the records follow.
const SchemaVersion = "1.9.2"

// Format is the version of the vuln_symbols extension that this package
// reads and writes.
const Format = 1

// Record is one OSV document of the database.
type Record struct {
	SchemaVersion    string         `json:"schema_version"`
	ID               string         `json:"id"`
	Modified         string         `json:"modified"`
	Published        string         `json:"published,omitempty"`
	Aliases          []string       `json:"aliases,omitempty"`
	Summary          string         `json:"summary,omitempty"`
	Affected         []Affected     `json:"affected"`
	References       []Reference    `json:"references,omitempty"`
	DatabaseSpecific RecordDatabase `json:"database_specific"`
}

// RecordDatabase holds the fields of the database for the whole record.
type RecordDatabase struct {
	License string `json:"license"`
	Source  string `json:"source,omitempty"`
}

// Affected is one package of a record, with one range.
type Affected struct {
	Package          Package          `json:"package"`
	Ranges           []Range          `json:"ranges"`
	DatabaseSpecific AffectedDatabase `json:"database_specific"`
}

// Package names a package as its registry writes it. A consumer folds the
// name with its own identity rules.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// Range is an OSV range.
type Range struct {
	Type   string  `json:"type"`
	Repo   string  `json:"repo,omitempty"`
	Events []Event `json:"events"`
}

// Event is one event of an OSV range. Exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Reference is an OSV reference.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// AffectedDatabase holds the extension of one affected package.
type AffectedDatabase struct {
	VulnSymbols VulnSymbols `json:"vuln_symbols"`
}

// VulnSymbols is the extension of docs/spec/record.md.
type VulnSymbols struct {
	Format           int               `json:"format"`
	Language         string            `json:"language"`
	Methods          []string          `json:"methods"`
	Coverage         string            `json:"coverage"`
	AdvisoryModified map[string]string `json:"advisory_modified,omitempty"`
	Fix              *Fix              `json:"fix,omitempty"`
	FixSites         []Symbol          `json:"fix_sites"`
	ChangedFunctions []ChangedFunction `json:"changed_functions,omitempty"`
	EntrySymbols     *EntrySymbols     `json:"entry_symbols,omitempty"`
	Assist           []Assist          `json:"assist,omitempty"`
	Review           Review            `json:"review"`
}

// Symbol is a function or a method in the notation of its language. A later
// format can add fields. A consumer ignores a field that it does not know.
type Symbol struct {
	Name string `json:"name"`
}

// Fix is the fix that a community record reads.
type Fix struct {
	Kind    string   `json:"kind"`
	Repo    string   `json:"repo,omitempty"`
	Commits []string `json:"commits,omitempty"`
	From    string   `json:"from,omitempty"`
	To      string   `json:"to,omitempty"`
}

// ChangedFunction is the account of one function that the fix changed.
type ChangedFunction struct {
	Symbol  Symbol `json:"symbol"`
	File    string `json:"file"`
	Account string `json:"account"`
	Reason  string `json:"reason,omitempty"`
	Proof   string `json:"proof,omitempty"`
	Note    string `json:"note,omitempty"`
}

// EntrySymbols are the exported symbols from which the package call graph
// reaches a fix site. The tool derives them.
type EntrySymbols struct {
	Symbols  []Symbol `json:"symbols"`
	Complete bool     `json:"complete"`
	Tool     string   `json:"tool"`
}

// Assist names a tool and a model that helped to propose a record.
type Assist struct {
	Tool  string `json:"tool"`
	Model string `json:"model,omitempty"`
}

// Review is the review state of a record.
type Review struct {
	State     string   `json:"state"`
	Reviewers []string `json:"reviewers,omitempty"`
}

// The values of the extension fields.
const (
	MethodUpstream      = "upstream"
	MethodPatchAnalysis = "patch-analysis"
	MethodManual        = "manual"

	CoverageExact = "exact"
	CoverageBroad = "broad"

	ReviewUnreviewed = "unreviewed"
	ReviewReviewed   = "reviewed"
	ReviewVerified   = "verified"

	LanguageGo   = "go"
	LanguageRust = "rust"
)

// MaxExactFixSites is the largest number of fix sites of an exact record.
const MaxExactFixSites = 50

// Names returns the names of the fix sites of an affected package.
func (a Affected) Names() []string {
	out := make([]string, len(a.DatabaseSpecific.VulnSymbols.FixSites))
	for i, s := range a.DatabaseSpecific.VulnSymbols.FixSites {
		out[i] = s.Name
	}
	return out
}
