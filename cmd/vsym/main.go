// Command vsym is the tool of the vuln-symbols database.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/safedep/vuln-symbols/internal/build"
	"github.com/safedep/vuln-symbols/internal/osvexport"
	"github.com/safedep/vuln-symbols/internal/upstream"
	"github.com/safedep/vuln-symbols/symbols"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "vsym:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vsym build -out <dir> [-export <ecosystem>=<zip>] | vsym check -dir <dir>")
	}
	switch args[0] {
	case "build":
		return runBuild(ctx, args[1:], out)
	case "check":
		return runCheck(ctx, args[1:], out)
	}
	return fmt.Errorf("unknown command %q. The commands are: build, check", args[0])
}

// exports maps an OSV ecosystem to a local zip, for a build with no
// network.
type exports map[string]string

func (e exports) String() string { return fmt.Sprint(map[string]string(e)) }

func (e exports) Set(v string) error {
	eco, file, ok := strings.Cut(v, "=")
	if !ok || eco == "" || file == "" {
		return fmt.Errorf("an export is <ecosystem>=<zip>, not %q", v)
	}
	e[eco] = file
	return nil
}

func runBuild(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	dir := fs.String("out", "", "directory for manifest.json and bundles/")
	local := exports{}
	fs.Var(local, "export", "local zip of an OSV ecosystem export, as Go=Go.zip (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("build needs -out")
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	var inputs []build.Input
	for _, src := range upstream.Sources {
		var data []byte
		var err error
		if file, ok := local[src.Ecosystem]; ok {
			data, err = os.ReadFile(file)
		} else {
			data, err = osvexport.Fetch(ctx, client, src.ExportURL)
		}
		if err != nil {
			return err
		}
		inputs = append(inputs, build.Input{Source: src, Export: data})
	}
	o, err := build.Build(inputs)
	if err != nil {
		return err
	}
	if err := o.Write(*dir); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "built %d records, bundle %s, %d bytes\n", o.Manifest.Records, o.Manifest.Bundle.SHA256, o.Manifest.Bundle.Size)
	return err
}

// runCheck reads a directory with the layout of the host through the
// client, as a consumer does. The workflow runs it on the signed build
// before it publishes, so the client code accepts what cosign wrote.
func runCheck(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	dir := fs.String("dir", "", "directory with the layout of the host")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("check needs -dir")
	}
	c, err := symbols.New(symbols.WithLocalBundle(*dir))
	if err != nil {
		return err
	}
	b, err := c.Load(ctx)
	if err != nil {
		return err
	}
	info := b.Info()
	_, err = fmt.Fprintf(out, "bundle %s: %d records, signed at %s\n", info.ID, info.Records, info.SignedAt.Format(time.RFC3339))
	return err
}
