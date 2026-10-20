// Package osvexport reads the zip export of one OSV ecosystem.
package osvexport

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"slices"
	"strings"
)

// The caps keep a bad export from filling the memory. The Go export is
// about 12 MB, and its largest file is far below a megabyte.
const (
	maxExportSize = 512 << 20
	maxFileSize   = 16 << 20
)

// Entry is one advisory file of an export.
type Entry struct {
	Name string
	Data []byte
}

// Fetch downloads an export.
func Fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxExportSize+1))
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	if len(data) > maxExportSize {
		return nil, fmt.Errorf("fetch %s: the export is larger than %d bytes", url, maxExportSize)
	}
	return data, nil
}

// Entries returns the JSON files of an export, sorted by name, so a build
// does not depend on the order of the zip.
func Entries(data []byte) ([]Entry, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open export: %w", err)
	}
	var out []Entry
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || path.Ext(f.Name) != ".json" || strings.Contains(f.Name, "/") {
			continue
		}
		if f.UncompressedSize64 > maxFileSize {
			return nil, fmt.Errorf("export file %s is larger than %d bytes", f.Name, maxFileSize)
		}
		b, err := readFile(f)
		if err != nil {
			return nil, err
		}
		out = append(out, Entry{Name: f.Name, Data: b})
	}
	slices.SortFunc(out, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func readFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("open export file %s: %w", f.Name, err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read export file %s: %w", f.Name, err)
	}
	if len(b) > maxFileSize {
		return nil, fmt.Errorf("export file %s is larger than %d bytes", f.Name, maxFileSize)
	}
	return b, nil
}
