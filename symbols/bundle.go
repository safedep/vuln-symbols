package symbols

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	pb "github.com/safedep/dry/api/pb"
)

// Bundle is a verified set of records with an index by package.
type Bundle struct {
	manifest Manifest
	records  []Record
	byName   map[string][]int
}

// Query asks for the records of one package version. IDs is the alias set
// of the vulnerability, as GO-2024-0001, CVE-2024-0001 and GHSA-xxxx. An
// empty IDs asks for every record of the package version.
type Query struct {
	Package pb.PackageVersion
	IDs     []string
}

// Answer is one record that matches a query, with the affected entry of the
// queried package.
type Answer struct {
	Record   *Record
	Affected *Affected
}

// Info describes a bundle.
type Info struct {
	ID      string
	AsOf    string
	Records int
	Sources []Source
}

// ReadBundle reads a gzip file of JSON lines and checks it against the
// manifest. The manifest must come from a verified signature.
func ReadBundle(m Manifest, file []byte) (*Bundle, error) {
	if err := m.Check(); err != nil {
		return nil, err
	}
	if int64(len(file)) != m.Bundle.Size {
		return nil, fmt.Errorf("bundle size %d is not %d", len(file), m.Bundle.Size)
	}
	if got := hexSHA256(file); got != m.Bundle.SHA256 {
		return nil, fmt.Errorf("bundle SHA-256 %s is not %s", got, m.Bundle.SHA256)
	}
	zr, err := gzip.NewReader(bytes.NewReader(file))
	if err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	content, err := io.ReadAll(io.LimitReader(zr, 8*MaxBundleSize))
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	if got := hexSHA256(content); got != m.Bundle.ContentSHA256 {
		return nil, fmt.Errorf("bundle content SHA-256 %s is not %s", got, m.Bundle.ContentSHA256)
	}
	records, err := decodeLines(content)
	if err != nil {
		return nil, err
	}
	if len(records) != m.Records {
		return nil, fmt.Errorf("bundle holds %d records, the manifest says %d", len(records), m.Records)
	}
	return newBundle(m, records), nil
}

func decodeLines(content []byte) ([]Record, error) {
	var records []Record
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for line := 1; sc.Scan(); line++ {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("bundle line %d: %w", line, err)
		}
		records = append(records, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read bundle lines: %w", err)
	}
	return records, nil
}

func newBundle(m Manifest, records []Record) *Bundle {
	b := &Bundle{manifest: m, records: records, byName: map[string][]int{}}
	for i, r := range records {
		for _, a := range r.Affected {
			key, ok := nameKey(a.Package)
			if ok && !slices.Contains(b.byName[key], i) {
				b.byName[key] = append(b.byName[key], i)
			}
		}
	}
	return b
}

// nameKey folds the package of an affected entry with the identity rule of
// its ecosystem, as a consumer folds the package of a finding.
func nameKey(p Package) (string, bool) {
	eco, err := pb.EcosystemFromOSVName(p.Ecosystem)
	if err != nil {
		return "", false
	}
	return pb.NewPackageVersionFromParts(eco, p.Name, "").NameKey(), true
}

// Info returns the id, the time and the sources of the bundle. The id is
// the SHA-256 of the bundle file, the name of the bundle on the host and
// the value of a pin.
func (b *Bundle) Info() Info {
	return Info{ID: b.manifest.Bundle.SHA256, AsOf: b.manifest.AsOf.UTC().Format("2006-01-02T15:04:05Z"), Records: len(b.records), Sources: slices.Clone(b.manifest.Sources)}
}

// Records returns every record of the bundle.
func (b *Bundle) Records() []Record { return b.records }

// Lookup returns the records that match the query. A record matches when
// its id or one of its aliases is in the query IDs, when it names the
// package, and when the version is in the range of that entry.
func (b *Bundle) Lookup(q Query) []Answer {
	key := pb.NewPackageVersionFromParts(q.Package.Ecosystem(), q.Package.RawName(), "").NameKey()
	var out []Answer
	for _, i := range b.byName[key] {
		r := &b.records[i]
		if len(q.IDs) > 0 && !r.hasID(q.IDs) {
			continue
		}
		for j := range r.Affected {
			a := &r.Affected[j]
			if k, ok := nameKey(a.Package); ok && k == key && a.affects(q.Package) {
				out = append(out, Answer{Record: r, Affected: a})
			}
		}
	}
	return out
}

func (r *Record) hasID(ids []string) bool {
	return slices.ContainsFunc(ids, func(id string) bool { return id == r.ID || slices.Contains(r.Aliases, id) })
}

// affects reports whether the version is in a range of the entry, by the
// OSV rule for an ordered range. A version with no order, or a range that
// the ecosystem cannot order, matches. The query names an advisory that
// already affects the version, so a wrong match only adds symbols, and a
// missed match would hide them.
func (a *Affected) affects(v pb.PackageVersion) bool {
	if v.RawVersion() == "" || len(a.Ranges) == 0 {
		return true
	}
	for _, rg := range a.Ranges {
		if in, ok := rangeAffects(v, rg); !ok || in {
			return true
		}
	}
	return false
}

func rangeAffects(v pb.PackageVersion, rg Range) (affected, ordered bool) {
	if rg.Type != "SEMVER" && rg.Type != "ECOSYSTEM" {
		return false, false
	}
	eco := v.Ecosystem()
	cmp := func(other string) (int, bool) {
		c, err := pb.CompareVersions(eco, v.RawVersion(), other)
		return c, err == nil
	}
	for _, e := range sortedEvents(eco, rg.Events) {
		switch {
		case e.Introduced == "0":
			affected = true
		case e.Introduced != "":
			c, ok := cmp(e.Introduced)
			if !ok {
				return false, false
			}
			if c >= 0 {
				affected = true
			}
		case e.Fixed != "":
			c, ok := cmp(e.Fixed)
			if !ok {
				return false, false
			}
			if c >= 0 {
				affected = false
			}
		case e.LastAffected != "":
			c, ok := cmp(e.LastAffected)
			if !ok {
				return false, false
			}
			if c > 0 {
				affected = false
			}
		}
	}
	return affected, true
}

// sortedEvents orders the events by their version, as the OSV rule needs.
// An introduced event of 0 comes first. An event that the ecosystem cannot
// order keeps its place.
func sortedEvents(eco packagev1.Ecosystem, events []Event) []Event {
	out := slices.Clone(events)
	slices.SortStableFunc(out, func(x, y Event) int {
		vx, vy := x.version(), y.version()
		switch {
		case vx == vy:
			return 0
		case vx == "0":
			return -1
		case vy == "0":
			return 1
		}
		c, err := pb.CompareVersions(eco, vx, vy)
		if err != nil {
			return 0
		}
		return c
	})
	return out
}

func (e Event) version() string {
	for _, v := range []string{e.Introduced, e.Fixed, e.LastAffected, e.Limit} {
		if v != "" {
			return v
		}
	}
	return ""
}

func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
