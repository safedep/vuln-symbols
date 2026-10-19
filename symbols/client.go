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
//	manifest.json                  the manifest of the newest bundle
//	manifest.sigstore.json         its signature
//	manifests/<sha256>.json        the manifest of each bundle, by bundle hash
//	manifests/<sha256>.sigstore.json
//	bundles/<sha256>.jsonl.gz      each bundle, which never changes
//
// A breaking change of the format gets a new base path, as v2/.
const DefaultBaseURL = "https://vuln-data.safedep.io/v1/"

// DefaultMaxAge is how long a client waits before it asks the host again.
const DefaultMaxAge = 24 * time.Hour

const maxManifestSize = 1 << 20

// ErrNoBundle means the client has no verified bundle yet.
var ErrNoBundle = errors.New("no symbol bundle yet: update with network access, or use a local bundle")

// Client fetches, verifies and caches the bundle. Only a bundle whose
// manifest has a valid signature from the build workflow reaches the cache,
// so Load reads the cache with a hash check and no network.
type Client struct {
	baseURL  string
	cacheDir string
	localDir string
	pin      string
	offline  bool
	maxAge   time.Duration
	http     *http.Client
	verifier verifier
	now      func() time.Time
}

// Option sets an option of a client.
type Option func(*Client)

// WithCacheDir sets the directory where the client keeps the bundle.
func WithCacheDir(dir string) Option { return func(c *Client) { c.cacheDir = dir } }

// WithLocalBundle reads the bundle from a directory with the layout of the
// host, as a mirror for a network with no access to the host. The client
// still checks the signature.
func WithLocalBundle(dir string) Option { return func(c *Client) { c.localDir = dir } }

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
		v, err := newSigstoreVerifier(c.cacheDir, c.offline || c.localDir != "")
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

const stateFile = "state.json"

// Update asks the host for a newer bundle, at most once per max age. It
// stores a bundle only after it checks the signature, the hashes and the
// time. A manifest older than the cached one is a rollback, and the client
// keeps the cached bundle.
func (c *Client) Update(ctx context.Context) (Status, error) {
	if c.offline || c.localDir != "" {
		return Status{}, nil
	}
	if c.pin != "" {
		return c.updatePin(ctx)
	}
	st := c.readState()
	if !st.CheckedAt.IsZero() && c.now().Sub(st.CheckedAt) < c.maxAge {
		return Status{}, nil
	}
	mb, etag, notModified, err := c.get(ctx, ManifestFile, st.ETag, maxManifestSize)
	if err != nil {
		return Status{}, err
	}
	if notModified {
		return Status{Checked: true}, c.writeState(state{ETag: st.ETag, CheckedAt: c.now()})
	}
	sig, _, _, err := c.get(ctx, SignatureFile, "", maxManifestSize)
	if err != nil {
		return Status{}, err
	}
	changed, err := c.accept(ctx, mb, sig)
	if err != nil {
		return Status{}, err
	}
	return Status{Checked: true, Changed: changed}, c.writeState(state{ETag: etag, CheckedAt: c.now()})
}

func (c *Client) updatePin(ctx context.Context) (Status, error) {
	if m, err := c.cachedManifest(); err == nil && m.Bundle.SHA256 == c.pin {
		return Status{}, nil
	}
	mb, _, _, err := c.get(ctx, "manifests/"+c.pin+".json", "", maxManifestSize)
	if err != nil {
		return Status{}, err
	}
	sig, _, _, err := c.get(ctx, "manifests/"+c.pin+".sigstore.json", "", maxManifestSize)
	if err != nil {
		return Status{}, err
	}
	changed, err := c.accept(ctx, mb, sig)
	return Status{Checked: true, Changed: changed}, err
}

// accept checks a manifest and its bundle, and stores both.
func (c *Client) accept(ctx context.Context, mb, sig []byte) (bool, error) {
	if err := c.verifier.verify(mb, sig); err != nil {
		return false, err
	}
	m, err := ParseManifest(mb)
	if err != nil {
		return false, err
	}
	if c.pin != "" && m.Bundle.SHA256 != c.pin {
		return false, fmt.Errorf("the manifest names bundle %s, not the pinned %s", m.Bundle.SHA256, c.pin)
	}
	cur, curErr := c.cachedManifest()
	if curErr == nil && c.pin == "" && m.AsOf.Before(cur.AsOf) {
		return false, fmt.Errorf("the host offers a bundle of %s, older than the cached bundle of %s", m.AsOf.Format(time.RFC3339), cur.AsOf.Format(time.RFC3339))
	}
	if curErr == nil && m.Bundle.SHA256 == cur.Bundle.SHA256 {
		return false, nil
	}
	file, _, _, err := c.get(ctx, m.Bundle.Path, "", m.Bundle.Size)
	if err != nil {
		return false, err
	}
	if _, err := ReadBundle(m, file); err != nil {
		return false, err
	}
	// The bundle goes first and the manifest last, so a reader that runs
	// at the same time sees the old pair or the new pair.
	if err := writeAtomic(filepath.Join(c.cacheDir, filepath.FromSlash(m.Bundle.Path)), file); err != nil {
		return false, err
	}
	if err := writeAtomic(filepath.Join(c.cacheDir, SignatureFile), sig); err != nil {
		return false, err
	}
	if err := writeAtomic(filepath.Join(c.cacheDir, ManifestFile), mb); err != nil {
		return false, err
	}
	if curErr == nil {
		if err := os.Remove(filepath.Join(c.cacheDir, filepath.FromSlash(cur.Bundle.Path))); err != nil && !errors.Is(err, os.ErrNotExist) {
			return true, fmt.Errorf("remove the old bundle: %w", err)
		}
	}
	return true, nil
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
	return ReadBundle(m, file)
}

func (c *Client) loadLocal() (*Bundle, error) {
	mb, err := os.ReadFile(filepath.Join(c.localDir, ManifestFile))
	if err != nil {
		return nil, fmt.Errorf("read the local manifest: %w", err)
	}
	sig, err := os.ReadFile(filepath.Join(c.localDir, SignatureFile))
	if err != nil {
		return nil, fmt.Errorf("read the local signature: %w", err)
	}
	if err := c.verifier.verify(mb, sig); err != nil {
		return nil, err
	}
	m, err := ParseManifest(mb)
	if err != nil {
		return nil, err
	}
	file, err := os.ReadFile(filepath.Join(c.localDir, filepath.FromSlash(m.Bundle.Path)))
	if err != nil {
		return nil, fmt.Errorf("read the local bundle: %w", err)
	}
	return ReadBundle(m, file)
}

func (c *Client) cachedManifest() (Manifest, error) {
	mb, err := os.ReadFile(filepath.Join(c.cacheDir, ManifestFile))
	if err != nil {
		return Manifest{}, err
	}
	return ParseManifest(mb)
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

func writeAtomic(name string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), filepath.Base(name)+".tmp*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), name)
}
