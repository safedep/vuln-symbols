package symbols

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultBaseURL is the public host of the bundle. The layout under it:
//
//	manifest.json                     names the newest bundle
//	manifest.sigstore.json            its signature
//	manifests/<sha256>.json           the manifest of each bundle, by bundle hash
//	manifests/<sha256>.sigstore.json  its signature
//	bundles/<sha256>.jsonl.gz         each bundle
//
// Only manifest.json and its signature change. The client reads the hash of
// the newest bundle from manifest.json, and then checks the signed pair under
// manifests/. It checks manifest.sigstore.json only for a bundle that comes
// back after a newer one. A breaking change of the format gets a new base
// path, as v2/.
const DefaultBaseURL = "https://vuln-data.safedep.io/v1/"

// DefaultMaxAge is how long a client waits before it asks the host again.
const DefaultMaxAge = 24 * time.Hour

const maxManifestSize = 1 << 20

// ErrNoBundle means the client has no verified bundle yet.
var ErrNoBundle = errors.New("no symbol bundle yet: update with network access, or use a local bundle")

// Client fetches, verifies and caches the bundle.
//
// The cache directory is trusted. Update writes a bundle there only after
// it checks the signature, and Load reads it back with a hash check and no
// network. A process that can write the cache directory can change the
// records, as it can change any other cache of its consumer. A consumer keeps
// the directory private to its user.
type Client struct {
	baseURL     string
	cacheDir    string
	localDir    string
	trustedRoot string
	pin         string
	offline     bool
	maxAge      time.Duration
	http        *http.Client
	verifier    verifier
	now         func() time.Time
}

// Option sets an option of a client.
type Option func(*Client)

// WithCacheDir sets the directory where the client keeps the bundle.
func WithCacheDir(dir string) Option { return func(c *Client) { c.cacheDir = dir } }

// WithLocalBundle reads the bundle from a directory with the layout of the
// host, as a mirror for a network with no access to the host. The client
// still checks the signature.
func WithLocalBundle(dir string) Option { return func(c *Client) { c.localDir = dir } }

// WithTrustedRoot reads the Sigstore trusted root from a file, in place of
// TUF. A client with no network and a local bundle needs it.
func WithTrustedRoot(path string) Option { return func(c *Client) { c.trustedRoot = path } }

// WithPin keeps the client on one bundle, by the SHA-256 of the bundle file.
func WithPin(id string) Option { return func(c *Client) { c.pin = id } }

// WithOffline stops every network call. The client reads the cache only.
func WithOffline() Option { return func(c *Client) { c.offline = true } }

// WithMaxAge sets how long the client waits before it asks the host again.
func WithMaxAge(d time.Duration) Option { return func(c *Client) { c.maxAge = d } }

// WithHTTPClient sets the HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithBaseURL sets another host, as a mirror. A mirror serves the signed
// files of the public host, because the client checks the signature
// against the build workflow.
func WithBaseURL(u string) Option { return func(c *Client) { c.baseURL = u } }

// New returns a client. It needs a cache directory, or a local bundle.
func New(opts ...Option) (*Client, error) {
	c := &Client{baseURL: DefaultBaseURL, maxAge: DefaultMaxAge, http: &http.Client{Timeout: 2 * time.Minute}, now: time.Now}
	for _, o := range opts {
		o(c)
	}
	if c.cacheDir == "" && c.localDir == "" {
		return nil, errors.New("a client needs a cache directory or a local bundle")
	}
	if c.pin != "" && !sha256Hex.MatchString(c.pin) {
		return nil, fmt.Errorf("pin %q is not a SHA-256", c.pin)
	}
	if !strings.HasSuffix(c.baseURL, "/") {
		c.baseURL += "/"
	}
	if c.verifier == nil {
		v, err := newSigstoreVerifier(c.cacheDir, c.trustedRoot)
		if err != nil {
			return nil, err
		}
		c.verifier = v
	}
	return c, nil
}

// Status says what an update did.
type Status struct {
	// Checked is true when the client asked the host.
	Checked bool
	// Changed is true when the client stored another bundle.
	Changed bool
}

type state struct {
	ETag      string    `json:"etag,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// signed records the verified signing time of the cached bundle.
type signed struct {
	Bundle   string    `json:"bundle_sha256"`
	SignedAt time.Time `json:"signed_at"`
}

const (
	stateFile  = "state.json"
	signedFile = "signed.json"
)

// Update asks the host for a newer bundle, at most once per max age. It
// stores a bundle only after it checks the signature, the hashes and the
// signing time. A bundle signed before the cached one is a rollback, and the
// client keeps the cached bundle.
func (c *Client) Update(ctx context.Context) (Status, error) {
	if c.offline || c.localDir != "" {
		return Status{}, nil
	}
	cur, curErr := c.cachedBundle()
	if c.pin != "" {
		if curErr == nil && cur.Bundle.SHA256 == c.pin {
			return Status{}, nil
		}
		changed, err := c.fetch(ctx, c.pin, nil)
		return Status{Checked: true, Changed: changed}, err
	}
	// With no cached bundle, the client asks at once and sends no ETag.
	st := state{}
	if curErr == nil {
		st = c.readState()
		if !st.CheckedAt.IsZero() && c.now().Sub(st.CheckedAt) < c.maxAge {
			return Status{}, nil
		}
	}
	mb, etag, notModified, err := c.get(ctx, ManifestFile, st.ETag, maxManifestSize)
	if err != nil {
		return Status{}, err
	}
	if notModified {
		return Status{Checked: true}, c.writeState(state{ETag: st.ETag, CheckedAt: c.now()})
	}
	// The newest manifest is not trusted. The client reads only the hash of
	// the bundle from it, and checks the signed pair of that hash.
	latest, err := ParseManifest(mb)
	if err != nil {
		return Status{}, err
	}
	changed := false
	if curErr != nil || latest.Bundle.SHA256 != cur.Bundle.SHA256 {
		if changed, err = c.fetch(ctx, latest.Bundle.SHA256, mb); err != nil {
			return Status{}, err
		}
	}
	return Status{Checked: true, Changed: changed}, c.writeState(state{ETag: etag, CheckedAt: c.now()})
}

// fetch reads, checks and stores the bundle of one hash. newest is the
// newest manifest of the host, when the hash comes from it.
func (c *Client) fetch(ctx context.Context, sha string, newest []byte) (bool, error) {
	mb, _, _, err := c.get(ctx, "manifests/"+sha+".json", "", maxManifestSize)
	if err != nil {
		return false, err
	}
	sig, _, _, err := c.get(ctx, "manifests/"+sha+".sigstore.json", "", maxManifestSize)
	if err != nil {
		return false, err
	}
	m, signedAt, err := c.verifyPair(mb, sig, sha)
	if err != nil {
		return false, err
	}
	if have, err := c.cachedBundle(); err == nil && have.Bundle.SHA256 == sha {
		return false, nil
	}
	cur, curErr := c.cachedManifest()
	if prev, ok := c.cachedSigned(cur, curErr); ok && c.pin == "" && signedAt.Before(prev.SignedAt) {
		rollback := fmt.Errorf("the host offers a bundle signed at %s, before the cached bundle of %s", signedAt.Format(time.RFC3339), prev.SignedAt.Format(time.RFC3339))
		// The host keeps the first signed pair of a bundle. When a bundle
		// comes back after a newer one, only the newest signature of the
		// host is newer than the cache.
		nsig, _, _, err := c.get(ctx, SignatureFile, "", maxManifestSize)
		if err != nil {
			return false, fmt.Errorf("%w, and the newest signature is not available: %w", rollback, err)
		}
		nm, nAt, err := c.verifyPair(newest, nsig, sha)
		if err != nil {
			return false, fmt.Errorf("%w, and the newest signature fails: %w", rollback, err)
		}
		if nAt.Before(prev.SignedAt) {
			return false, rollback
		}
		m, mb, sig, signedAt = nm, newest, nsig, nAt
	}
	file, _, _, err := c.get(ctx, m.Bundle.Path, "", m.Bundle.Size)
	if err != nil {
		return false, err
	}
	if _, err := ReadBundle(m, file); err != nil {
		return false, err
	}
	rec, err := json.Marshal(signed{Bundle: sha, SignedAt: signedAt})
	if err != nil {
		return false, err
	}
	// The manifest goes last, so a reader that runs at the same time sees
	// the old bundle or the new bundle, and never a manifest with no bundle.
	for _, f := range []struct {
		name string
		data []byte
	}{
		{filepath.FromSlash(m.Bundle.Path), file},
		{SignatureFile, sig},
		{signedFile, rec},
		{ManifestFile, mb},
	} {
		if err := writeAtomic(filepath.Join(c.cacheDir, f.name), f.data); err != nil {
			return false, err
		}
	}
	if curErr == nil && cur.Bundle.SHA256 != sha {
		if err := os.Remove(filepath.Join(c.cacheDir, filepath.FromSlash(cur.Bundle.Path))); err != nil && !errors.Is(err, os.ErrNotExist) {
			return true, fmt.Errorf("remove the old bundle: %w", err)
		}
	}
	return true, nil
}

// verifyPair checks the signature of a manifest and that the manifest names
// the expected bundle.
func (c *Client) verifyPair(mb, sig []byte, sha string) (Manifest, time.Time, error) {
	signedAt, err := c.verifier.verify(mb, sig)
	if err != nil {
		return Manifest{}, time.Time{}, err
	}
	m, err := ParseManifest(mb)
	if err != nil {
		return Manifest{}, time.Time{}, err
	}
	if m.Bundle.SHA256 != sha {
		return Manifest{}, time.Time{}, fmt.Errorf("the signed manifest names bundle %s, not %s", m.Bundle.SHA256, sha)
	}
	return m, signedAt, nil
}

// Load returns the verified bundle: the local bundle when the client has
// one, else the cached bundle.
func (c *Client) Load(ctx context.Context) (*Bundle, error) {
	if c.localDir != "" {
		return c.loadLocal()
	}
	m, err := c.cachedManifest()
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoBundle
	}
	if err != nil {
		return nil, err
	}
	file, err := os.ReadFile(filepath.Join(c.cacheDir, filepath.FromSlash(m.Bundle.Path)))
	if err != nil {
		return nil, fmt.Errorf("read the cached bundle: %w", err)
	}
	b, err := ReadBundle(m, file)
	if err != nil {
		return nil, err
	}
	if s, ok := c.cachedSigned(m, nil); ok {
		b.signedAt = s.SignedAt
	}
	return b, nil
}

func (c *Client) loadLocal() (*Bundle, error) {
	read := func(name string) ([]byte, error) {
		b, err := os.ReadFile(filepath.Join(c.localDir, filepath.FromSlash(name)))
		if err != nil {
			return nil, fmt.Errorf("read the local bundle: %w", err)
		}
		return b, nil
	}
	mb, err := read(ManifestFile)
	if err != nil {
		return nil, err
	}
	latest, err := ParseManifest(mb)
	if err != nil {
		return nil, err
	}
	sha := latest.Bundle.SHA256
	if c.pin != "" {
		sha = c.pin
	}
	pair, err := read("manifests/" + sha + ".json")
	if err != nil {
		return nil, err
	}
	sig, err := read("manifests/" + sha + ".sigstore.json")
	if err != nil {
		return nil, err
	}
	m, signedAt, err := c.verifyPair(pair, sig, sha)
	if err != nil {
		return nil, err
	}
	file, err := read(m.Bundle.Path)
	if err != nil {
		return nil, err
	}
	b, err := ReadBundle(m, file)
	if err != nil {
		return nil, err
	}
	b.signedAt = signedAt
	return b, nil
}

func (c *Client) cachedManifest() (Manifest, error) {
	mb, err := os.ReadFile(filepath.Join(c.cacheDir, ManifestFile))
	if err != nil {
		return Manifest{}, err
	}
	return ParseManifest(mb)
}

// cachedBundle returns the cached manifest when the bundle file is there
// with its hash. A lost or damaged bundle is no cache, so Update fetches it
// at once.
func (c *Client) cachedBundle() (Manifest, error) {
	m, err := c.cachedManifest()
	if err != nil {
		return Manifest{}, err
	}
	file, err := os.ReadFile(filepath.Join(c.cacheDir, filepath.FromSlash(m.Bundle.Path)))
	if err != nil {
		return Manifest{}, err
	}
	if hexSHA256(file) != m.Bundle.SHA256 {
		return Manifest{}, fmt.Errorf("the cached bundle %s is damaged", m.Bundle.SHA256)
	}
	return m, nil
}

// cachedSigned returns the signing time of the cached bundle. A record of
// another bundle is stale, as after a crash between two writes.
func (c *Client) cachedSigned(cur Manifest, curErr error) (signed, bool) {
	if curErr != nil {
		return signed{}, false
	}
	b, err := os.ReadFile(filepath.Join(c.cacheDir, signedFile))
	if err != nil {
		return signed{}, false
	}
	var s signed
	if json.Unmarshal(b, &s) != nil || s.Bundle != cur.Bundle.SHA256 {
		return signed{}, false
	}
	return s, true
}

func (c *Client) readState() state {
	var st state
	b, err := os.ReadFile(filepath.Join(c.cacheDir, stateFile))
	if err != nil {
		return st
	}
	// A state file that does not decode only makes the client ask the host
	// again.
	if json.Unmarshal(b, &st) != nil {
		return state{}
	}
	return st
}

func (c *Client) writeState(st state) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(c.cacheDir, stateFile), b)
}

// get reads one file of the host. With an etag, a 304 answer gives
// notModified.
func (c *Client) get(ctx context.Context, name, etag string, limit int64) (body []byte, newETag string, notModified bool, err error) {
	u, err := url.JoinPath(c.baseURL, name)
	if err != nil {
		return nil, "", false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", false, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("fetch %s: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, "", true, nil
	case http.StatusOK:
	default:
		return nil, "", false, fmt.Errorf("fetch %s: status %s", name, resp.Status)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, "", false, fmt.Errorf("fetch %s: %w", name, err)
	}
	if int64(len(body)) > limit {
		return nil, "", false, fmt.Errorf("fetch %s: the file is larger than %d bytes", name, limit)
	}
	return body, resp.Header.Get("ETag"), false, nil
}

// writeAtomic writes a file with a rename, after a sync, so a crash leaves
// the old file or the new file. The cache is private to its user.
func writeAtomic(name string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), filepath.Base(name)+".tmp*")
	if err != nil {
		return err
	}
	cleanup := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		return cleanup(err)
	}
	return os.Rename(tmp.Name(), name)
}
