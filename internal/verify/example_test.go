package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vuln-symbols/symbols"
)

// The examples of the spec must pass the checks, so the spec and the code
// cannot drift apart.
func TestSpecExamplesPassTheChecks(t *testing.T) {
	files, err := filepath.Glob("../../docs/spec/examples/*.json")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			data, err := os.ReadFile(f)
			require.NoError(t, err)
			var r symbols.Record
			require.NoError(t, json.Unmarshal(data, &r))
			assert.NoError(t, V0(r))
			assert.NoError(t, V5(r))
		})
	}
}
