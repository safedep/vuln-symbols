// Package fixture makes synthetic OSV exports for tests. Every package and
// advisory in it is made up.
package fixture

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
)

// Advisory is a synthetic OSV advisory.
type Advisory map[string]any

// GoAdvisory returns a Go advisory of one module with one import and its
// symbols.
func GoAdvisory(id, module string, symbols ...string) Advisory {
	return Advisory{
		"schema_version": "1.7.0",
		"id":             id,
		"modified":       "2026-01-02T03:04:05Z",
		"published":      "2026-01-01T00:00:00Z",
		"aliases":        []string{"CVE-0000-" + id[len(id)-4:]},
		"summary":        "Synthetic advisory",
		"affected": []any{map[string]any{
			"package": map[string]any{"ecosystem": "Go", "name": module},
			"ranges":  []any{map[string]any{"type": "SEMVER", "events": []any{map[string]any{"introduced": "0"}, map[string]any{"fixed": "1.2.0"}}}},
			"ecosystem_specific": map[string]any{"imports": []any{
				map[string]any{"path": module, "symbols": symbols},
			}},
		}},
	}
}

// RustAdvisory returns a RustSec advisory of one crate and its functions.
func RustAdvisory(id, crate string, functions ...string) Advisory {
	return Advisory{
		"schema_version": "1.7.0",
		"id":             id,
		"modified":       "2026-01-02T03:04:05Z",
		"published":      "2026-01-01T00:00:00Z",
		"summary":        "Synthetic advisory",
		"affected": []any{map[string]any{
			"package":            map[string]any{"ecosystem": "crates.io", "name": crate},
			"ranges":             []any{map[string]any{"type": "SEMVER", "events": []any{map[string]any{"introduced": "0.0.0-0"}, map[string]any{"fixed": "0.3.0"}}}},
			"ecosystem_specific": map[string]any{"affects": map[string]any{"functions": functions}},
		}},
	}
}

// JSON encodes the advisory.
func (a Advisory) JSON() []byte {
	b, err := json.Marshal(a)
	if err != nil {
		panic(err)
	}
	return b
}

// Zip packs advisories into an export, one file per id.
func Zip(advisories ...Advisory) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	ids := make([]string, 0, len(advisories))
	byID := map[string]Advisory{}
	for _, a := range advisories {
		id := fmt.Sprint(a["id"])
		ids = append(ids, id)
		byID[id] = a
	}
	// A zip in reverse order checks that a build sorts the entries.
	slices.Sort(ids)
	slices.Reverse(ids)
	for _, id := range ids {
		w, err := zw.Create(id + ".json")
		if err != nil {
			panic(err)
		}
		if _, err := w.Write(byID[id].JSON()); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
