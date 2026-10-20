package symbols

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"time"
)

// Manifest describes one bundle. The signature covers the manifest bytes,
// and the manifest holds the SHA-256 of the bundle, so one signature covers
// both.
type Manifest struct {
	Format  int       `json:"format"`
	AsOf    time.Time `json:"as_of"`
	Records int       `json:"records"`
	Bundle  BundleRef `json:"bundle"`
	Sources []Source  `json:"sources"`
}

// BundleRef locates the bundle file. Path is relative to the directory of
// the manifest. SHA256 is the hash of the file as stored, and ContentSHA256
// the hash of the uncompressed JSON lines.
type BundleRef struct {
	Path          string `json:"path"`
	Size          int64  `json:"size"`
	SHA256        string `json:"sha256"`
	ContentSHA256 string `json:"content_sha256"`
}

// Source is one upstream database of the bundle.
type Source struct {
	Name         string    `json:"name"`
	Ecosystem    string    `json:"ecosystem"`
	URL          string    `json:"url"`
	ExportSHA256 string    `json:"export_sha256"`
	Modified     time.Time `json:"modified"`
	Records      int       `json:"records"`
	License      string    `json:"license"`
	Attribution  string    `json:"attribution"`
}

// The file names of the layout. The bundle path comes from the manifest.
const (
	ManifestFile  = "manifest.json"
	SignatureFile = "manifest.sigstore.json"
)

// MaxBundleSize caps the size of a bundle file that a client reads. It
// keeps a bad host from filling the disk.
const MaxBundleSize = 64 << 20

var (
	sha256Hex  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	bundlePath = regexp.MustCompile(`^bundles/[0-9a-f]{64}\.jsonl\.gz$`)
)

// ParseManifest decodes and checks a manifest.
func ParseManifest(data []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	return m, m.Check()
}

// Check rejects a manifest that a client must not follow. The bundle path
// must stay under bundles/, so a manifest cannot point a client at another
// file of the host.
func (m Manifest) Check() error {
	switch {
	case m.Format != Format:
		return fmt.Errorf("manifest format %d is not %d", m.Format, Format)
	case m.AsOf.IsZero():
		return fmt.Errorf("manifest has no as_of time")
	case !sha256Hex.MatchString(m.Bundle.SHA256), !sha256Hex.MatchString(m.Bundle.ContentSHA256):
		return fmt.Errorf("manifest has a bad bundle hash")
	case m.Bundle.Path != path.Join("bundles", m.Bundle.SHA256+".jsonl.gz") || !bundlePath.MatchString(m.Bundle.Path):
		return fmt.Errorf("manifest bundle path %q is not bundles/<sha256>.jsonl.gz", m.Bundle.Path)
	case m.Bundle.Size <= 0 || m.Bundle.Size > MaxBundleSize:
		return fmt.Errorf("manifest bundle size %d is out of range", m.Bundle.Size)
	}
	return nil
}
