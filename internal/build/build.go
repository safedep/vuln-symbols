// Package build makes the bundle and the manifest from the upstream
// exports. The same exports give the same bytes.
package build

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/safedep/vuln-symbols/internal/osvexport"
	"github.com/safedep/vuln-symbols/internal/upstream"
	"github.com/safedep/vuln-symbols/internal/verify"
	"github.com/safedep/vuln-symbols/symbols"
)

// Input is the export of one upstream database.
type Input struct {
	Source upstream.Source
	Export []byte
}

// Output is a built bundle. ManifestJSON is the exact byte form that the
// workflow signs.
type Output struct {
	Manifest     symbols.Manifest
	ManifestJSON []byte
	Bundle       []byte
}

// Build converts the exports, checks each record, and writes the bundle.
// A record that fails a check fails the build, so the live bundle stays.
func Build(inputs []Input) (Output, error) {
	var records []symbols.Record
	var sources []symbols.Source
	var errs []error
	for _, in := range inputs {
		entries, err := osvexport.Entries(in.Export)
		if err != nil {
			return Output{}, fmt.Errorf("%s: %w", in.Source.Name, err)
		}
		src := symbols.Source{
			Name:         in.Source.Name,
			Ecosystem:    in.Source.Ecosystem,
			URL:          in.Source.ExportURL,
			ExportSHA256: hexSHA256(in.Export),
			License:      in.Source.License,
			Attribution:  in.Source.Attribution,
		}
		for _, e := range entries {
			rec, ok, err := upstream.Convert(in.Source, e.Data)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", e.Name, err))
				continue
			}
			if !ok {
				continue
			}
			if err := verify.Upstream(rec); err != nil {
				errs = append(errs, err)
				continue
			}
			modified, err := time.Parse(time.RFC3339Nano, rec.Modified)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", rec.ID, err))
				continue
			}
			if modified.After(src.Modified) {
				src.Modified = modified.UTC()
			}
			src.Records++
			records = append(records, rec)
		}
		sources = append(sources, src)
	}
	if err := errors.Join(errs...); err != nil {
		return Output{}, err
	}
	slices.SortFunc(records, func(a, b symbols.Record) int { return strings.Compare(a.ID, b.ID) })
	for i := 1; i < len(records); i++ {
		if records[i].ID == records[i-1].ID {
			return Output{}, fmt.Errorf("two records have the id %s", records[i].ID)
		}
	}
	return pack(records, sources)
}

func pack(records []symbols.Record, sources []symbols.Source) (Output, error) {
	var content bytes.Buffer
	for _, r := range records {
		line, err := json.Marshal(r)
		if err != nil {
			return Output{}, fmt.Errorf("encode %s: %w", r.ID, err)
		}
		content.Write(line)
		content.WriteByte('\n')
	}
	// The gzip header holds no name and no time, so the file depends only on
	// the content.
	var file bytes.Buffer
	zw, err := gzip.NewWriterLevel(&file, gzip.BestCompression)
	if err != nil {
		return Output{}, err
	}
	if _, err := zw.Write(content.Bytes()); err != nil {
		return Output{}, err
	}
	if err := zw.Close(); err != nil {
		return Output{}, err
	}
	sum := hexSHA256(file.Bytes())
	m := symbols.Manifest{
		Format:  symbols.Format,
		Records: len(records),
		Bundle: symbols.BundleRef{
			Path:          "bundles/" + sum + ".jsonl.gz",
			Size:          int64(file.Len()),
			SHA256:        sum,
			ContentSHA256: hexSHA256(content.Bytes()),
		},
		Sources: sources,
	}
	for _, s := range sources {
		if s.Modified.After(m.AsOf) {
			m.AsOf = s.Modified
		}
	}
	if err := m.Check(); err != nil {
		return Output{}, err
	}
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Output{}, err
	}
	return Output{Manifest: m, ManifestJSON: append(mj, '\n'), Bundle: file.Bytes()}, nil
}

// Write puts the files of the host under dir: the bundle, the manifest of
// the bundle by its hash, and the manifest of the newest bundle. The
// workflow signs the manifest and writes the signature next to both copies.
func (o Output) Write(dir string) error {
	files := map[string][]byte{
		o.Manifest.Bundle.Path:                            o.Bundle,
		"manifests/" + o.Manifest.Bundle.SHA256 + ".json": o.ManifestJSON,
		symbols.ManifestFile:                              o.ManifestJSON,
	}
	for name, data := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
