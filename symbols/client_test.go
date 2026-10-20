package symbols_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vuln-symbols/internal/build"
	"github.com/safedep/vuln-symbols/internal/fixture"
	"github.com/safedep/vuln-symbols/internal/upstream"
	"github.com/safedep/vuln-symbols/symbols"
)

// host is a stub of the public host. It serves files by path, answers
// If-None-Match with 304, and counts the requests.
type host struct {
	mu       sync.Mutex
	files    map[string][]byte
	requests []string
	cached   string
}

func cachedSHA(h *host) string { return h.cached }

func (h *host) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	name := strings.TrimPrefix(r.URL.Path, "/v1/")
	h.requests = append(h.requests, name)
	data, ok := h.files[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	etag := `"` + hexSum(data) + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	_, _ = w.Write(data)
}

func (h *host) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.requests)
}

// publish puts a build on the host as the newest bundle, signed at a time,
// as the workflow does.
func (h *host) publish(o build.Output, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	sig := sign(o.ManifestJSON, at)
	h.files[o.Manifest.Bundle.Path] = o.Bundle
	h.files["manifests/"+o.Manifest.Bundle.SHA256+".json"] = o.ManifestJSON
	h.files["manifests/"+o.Manifest.Bundle.SHA256+".sigstore.json"] = sig
	h.files[symbols.ManifestFile] = o.ManifestJSON
	h.files[symbols.SignatureFile] = sig
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// sign and checkSignature stand for Sigstore. A signature names the
// SHA-256 of the manifest that it covers, and the time of the signature.
func sign(manifest []byte, at time.Time) []byte {
	return []byte("sig:" + hexSum(manifest) + ":" + at.UTC().Format(time.RFC3339))
}

func checkSignature(manifest, signature []byte) (time.Time, error) {
	parts := strings.SplitN(string(signature), ":", 3)
	if len(parts) != 3 || parts[1] != hexSum(manifest) {
		return time.Time{}, errors.New("bad signature")
	}
	return time.Parse(time.RFC3339, parts[2])
}

var (
	day1 = time.Date(2026, 4, 1, 3, 17, 0, 0, time.UTC)
	day2 = day1.Add(24 * time.Hour)
	day0 = day1.Add(-24 * time.Hour)
)

func buildAt(t *testing.T, modified string, functions ...string) build.Output {
	t.Helper()
	adv := fixture.RustAdvisory("RUSTSEC-2026-0001", "acme-widget", functions...)
	adv["modified"] = modified
	o, err := build.Build([]build.Input{
		{Source: upstream.Go, Export: fixture.Zip()},
		{Source: upstream.RustSec, Export: fixture.Zip(adv)},
	})
	require.NoError(t, err)
	return o
}

type env struct {
	host  *host
	url   string
	cache string
	now   time.Time
}

func newEnv(t *testing.T) *env {
	h := &host{files: map[string][]byte{}}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &env{host: h, url: srv.URL + "/v1/", cache: t.TempDir(), now: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)}
}

func (e *env) client(t *testing.T, opts ...symbols.Option) *symbols.Client {
	t.Helper()
	base := []symbols.Option{
		symbols.WithCacheDir(e.cache),
		symbols.WithBaseURL(e.url),
		symbols.WithTestVerifier(checkSignature),
		symbols.WithTestNow(func() time.Time { return e.now }),
	}
	c, err := symbols.New(append(base, opts...)...)
	require.NoError(t, err)
	return c
}

func TestClientUpdateAndLoad(t *testing.T) {
	e := newEnv(t)
	first := buildAt(t, "2026-04-01T00:00:00Z", "acme_widget::parse")
	e.host.publish(first, day1)
	c := e.client(t)

	_, err := c.Load(context.Background())
	require.ErrorIs(t, err, symbols.ErrNoBundle)

	st, err := c.Update(context.Background())
	require.NoError(t, err)
	assert.Equal(t, symbols.Status{Checked: true, Changed: true}, st)
	b, err := c.Load(context.Background())
	require.NoError(t, err)
	assert.Equal(t, first.Manifest.Bundle.SHA256, b.Info().ID)

	n := e.host.count()
	st, err = c.Update(context.Background())
	require.NoError(t, err)
	assert.Equal(t, symbols.Status{}, st)
	assert.Equal(t, n, e.host.count(), "a second update within the max age makes no request")

	e.now = e.now.Add(symbols.DefaultMaxAge + time.Minute)
	st, err = c.Update(context.Background())
	require.NoError(t, err)
	assert.Equal(t, symbols.Status{Checked: true}, st)
	assert.Equal(t, []string{symbols.ManifestFile}, e.host.requests[n:], "an unchanged manifest gives a 304 and no download")

	second := buildAt(t, "2026-04-20T00:00:00Z", "acme_widget::parse", "acme_widget::Buf::insert")
	e.host.publish(second, day2)
	e.now = e.now.Add(symbols.DefaultMaxAge + time.Minute)
	st, err = c.Update(context.Background())
	require.NoError(t, err)
	assert.Equal(t, symbols.Status{Checked: true, Changed: true}, st)
	b, err = c.Load(context.Background())
	require.NoError(t, err)
	assert.Equal(t, second.Manifest.Bundle.SHA256, b.Info().ID)
	assert.Equal(t, day2, b.Info().SignedAt)
	assert.NoFileExists(t, filepath.Join(e.cache, first.Manifest.Bundle.Path), "the client removes the old bundle")
}

// Each failure keeps the cached bundle, so a bad host never removes the
// symbols that a client already has.
func TestClientKeepsTheCachedBundle(t *testing.T) {
	newer := buildAt(t, "2026-04-20T00:00:00Z", "acme_widget::parse", "acme_widget::Buf::insert")
	for _, tc := range []struct {
		name   string
		attack func(h *host)
		want   string
	}{
		{"a bad signature", func(h *host) {
			h.publish(newer, day2)
			h.files["manifests/"+newer.Manifest.Bundle.SHA256+".sigstore.json"] = []byte("sig:forged")
		}, "bad signature"},
		{"a bundle that does not match the manifest", func(h *host) {
			h.publish(newer, day2)
			bad := append([]byte(nil), newer.Bundle...)
			bad[len(bad)/2] ^= 0xff
			h.files[newer.Manifest.Bundle.Path] = bad
		}, "SHA-256"},
		{"a bundle signed before the cached one", func(h *host) {
			h.publish(buildAt(t, "2026-04-20T00:00:00Z", "acme_widget::other"), day0)
		}, "before the cached bundle"},
		{"a manifest that names another bundle than its pair", func(h *host) {
			h.publish(newer, day2)
			h.files["manifests/"+newer.Manifest.Bundle.SHA256+".json"] = h.files["manifests/"+cachedSHA(h)+".json"]
			h.files["manifests/"+newer.Manifest.Bundle.SHA256+".sigstore.json"] = h.files["manifests/"+cachedSHA(h)+".sigstore.json"]
		}, "names bundle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			cached := buildAt(t, "2026-04-01T00:00:00Z", "acme_widget::parse")
			e.host.publish(cached, day1)
			e.host.cached = cached.Manifest.Bundle.SHA256
			c := e.client(t)
			_, err := c.Update(context.Background())
			require.NoError(t, err)

			tc.attack(e.host)
			e.now = e.now.Add(symbols.DefaultMaxAge + time.Minute)
			_, err = c.Update(context.Background())
			require.ErrorContains(t, err, tc.want)

			b, err := c.Load(context.Background())
			require.NoError(t, err)
			assert.Equal(t, cached.Manifest.Bundle.SHA256, b.Info().ID)
		})
	}
}

func TestClientOffline(t *testing.T) {
	e := newEnv(t)
	e.host.publish(buildAt(t, "2026-04-01T00:00:00Z", "acme_widget::parse"), day1)
	c := e.client(t, symbols.WithOffline())
	st, err := c.Update(context.Background())
	require.NoError(t, err)
	assert.Equal(t, symbols.Status{}, st)
	assert.Zero(t, e.host.count())
	_, err = c.Load(context.Background())
	assert.ErrorIs(t, err, symbols.ErrNoBundle)
}

func TestClientPin(t *testing.T) {
	e := newEnv(t)
	old := buildAt(t, "2026-04-01T00:00:00Z", "acme_widget::parse")
	e.host.publish(old, day1)
	e.host.publish(buildAt(t, "2026-04-20T00:00:00Z", "acme_widget::parse", "acme_widget::Buf::insert"), day2)

	c := e.client(t, symbols.WithPin(old.Manifest.Bundle.SHA256))
	_, err := c.Update(context.Background())
	require.NoError(t, err)
	b, err := c.Load(context.Background())
	require.NoError(t, err)
	assert.Equal(t, old.Manifest.Bundle.SHA256, b.Info().ID, "a pin keeps the client on its bundle when the host has a newer one")

	n := e.host.count()
	_, err = c.Update(context.Background())
	require.NoError(t, err)
	assert.Equal(t, n, e.host.count(), "a client that has its pinned bundle asks nothing")
}

func TestClientLocalBundle(t *testing.T) {
	o := buildAt(t, "2026-04-01T00:00:00Z", "acme_widget::parse")
	dir := t.TempDir()
	require.NoError(t, o.Write(dir))
	sigPath := filepath.Join(dir, "manifests", o.Manifest.Bundle.SHA256+".sigstore.json")
	require.NoError(t, os.WriteFile(sigPath, sign(o.ManifestJSON, day1), 0o644))

	c, err := symbols.New(symbols.WithLocalBundle(dir), symbols.WithTestVerifier(checkSignature))
	require.NoError(t, err)
	b, err := c.Load(context.Background())
	require.NoError(t, err)
	assert.Equal(t, o.Manifest.Bundle.SHA256, b.Info().ID)
	assert.Equal(t, day1, b.Info().SignedAt)

	require.NoError(t, os.WriteFile(sigPath, []byte("sig:forged"), 0o644))
	_, err = c.Load(context.Background())
	assert.ErrorContains(t, err, "bad signature", "a local bundle has its signature checked too")
}

func TestNewNeedsAPlace(t *testing.T) {
	_, err := symbols.New()
	assert.Error(t, err)
	_, err = symbols.New(symbols.WithCacheDir(t.TempDir()), symbols.WithPin("abc"))
	assert.ErrorContains(t, err, "SHA-256")
}

// The newest modified time of a record can go back, as when an advisory is
// withdrawn. The signing time decides, so the client takes the new bundle.
func TestClientTakesANewerSignatureWithAnOlderAsOf(t *testing.T) {
	e := newEnv(t)
	e.host.publish(buildAt(t, "2026-04-20T00:00:00Z", "acme_widget::parse"), day1)
	c := e.client(t)
	_, err := c.Update(context.Background())
	require.NoError(t, err)

	next := buildAt(t, "2026-04-10T00:00:00Z", "acme_widget::parse", "acme_widget::Buf::insert")
	e.host.publish(next, day2)
	e.now = e.now.Add(symbols.DefaultMaxAge + time.Minute)
	st, err := c.Update(context.Background())
	require.NoError(t, err)
	assert.True(t, st.Changed)
}

// A cache that lost its manifest asks the host at once, and does not wait
// for the max age.
func TestClientRefetchesALostManifest(t *testing.T) {
	e := newEnv(t)
	e.host.publish(buildAt(t, "2026-04-01T00:00:00Z", "acme_widget::parse"), day1)
	c := e.client(t)
	_, err := c.Update(context.Background())
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(e.cache, symbols.ManifestFile)))

	st, err := c.Update(context.Background())
	require.NoError(t, err)
	assert.True(t, st.Changed)
	_, err = c.Load(context.Background())
	assert.NoError(t, err)
}

// A lost or damaged bundle file is no cache. The client fetches it again at
// once, and does not wait for the max age or for a new bundle on the host.
func TestClientRefetchesALostBundle(t *testing.T) {
	o := buildAt(t, "2026-04-01T00:00:00Z", "acme_widget::parse")
	for _, tc := range []struct {
		name   string
		damage func(path string) error
		opts   []symbols.Option
	}{
		{"a deleted bundle", os.Remove, nil},
		{"a damaged bundle", func(path string) error { return os.WriteFile(path, []byte("damaged"), 0o600) }, nil},
		{"a deleted pinned bundle", os.Remove, []symbols.Option{symbols.WithPin(o.Manifest.Bundle.SHA256)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.host.publish(o, day1)
			c := e.client(t, tc.opts...)
			_, err := c.Update(context.Background())
			require.NoError(t, err)
			require.NoError(t, tc.damage(filepath.Join(e.cache, o.Manifest.Bundle.Path)))

			st, err := c.Update(context.Background())
			require.NoError(t, err)
			assert.True(t, st.Changed)
			b, err := c.Load(context.Background())
			require.NoError(t, err)
			assert.Equal(t, o.Manifest.Bundle.SHA256, b.Info().ID)
		})
	}
}

// A bundle can come back after a newer one, as when upstream removes a
// record and restores it. The host keeps the first signed pair of that
// bundle, and the newest signature on the host is the new one. The client
// takes the bundle with the newest signature.
func TestClientTakesABundleThatComesBack(t *testing.T) {
	e := newEnv(t)
	first := buildAt(t, "2026-04-01T00:00:00Z", "acme_widget::parse")
	e.host.publish(first, day0)
	second := buildAt(t, "2026-04-20T00:00:00Z", "acme_widget::parse", "acme_widget::Buf::insert")
	e.host.publish(second, day1)
	c := e.client(t)
	_, err := c.Update(context.Background())
	require.NoError(t, err)

	pair := e.host.files["manifests/"+first.Manifest.Bundle.SHA256+".sigstore.json"]
	e.host.publish(first, day2)
	e.host.files["manifests/"+first.Manifest.Bundle.SHA256+".sigstore.json"] = pair
	e.now = e.now.Add(symbols.DefaultMaxAge + time.Minute)
	st, err := c.Update(context.Background())
	require.NoError(t, err)
	assert.True(t, st.Changed)
	b, err := c.Load(context.Background())
	require.NoError(t, err)
	assert.Equal(t, first.Manifest.Bundle.SHA256, b.Info().ID)
	assert.Equal(t, day2, b.Info().SignedAt)
}
