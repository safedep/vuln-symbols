package osvexport

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func zipOf(t *testing.T, files map[string]string, order ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range order {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(files[name]))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func TestEntriesKeepsTopLevelJSONInNameOrder(t *testing.T) {
	files := map[string]string{"B-2.json": "{}", "A-1.json": "{}", "notes.txt": "x", "dir/C-3.json": "{}"}
	entries, err := Entries(zipOf(t, files, "B-2.json", "notes.txt", "dir/C-3.json", "A-1.json"))
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}
	assert.Equal(t, []string{"A-1.json", "B-2.json"}, names)
}

func TestEntriesRejectsABadZip(t *testing.T) {
	_, err := Entries([]byte("not a zip"))
	assert.Error(t, err)
}
