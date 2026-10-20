package symbols

import "time"

// testVerifier lets a test decide the result of a signature check.
type testVerifier func(manifest, signature []byte) (time.Time, error)

func (f testVerifier) verify(manifest, signature []byte) (time.Time, error) {
	return f(manifest, signature)
}

// WithTestVerifier replaces the Sigstore check in a test.
func WithTestVerifier(f func(manifest, signature []byte) (time.Time, error)) Option {
	return func(c *Client) { c.verifier = testVerifier(f) }
}

// WithTestNow sets the clock of a client in a test.
func WithTestNow(now func() time.Time) Option { return func(c *Client) { c.now = now } }
