# vuln-symbols

An open database of vulnerable functions for every ecosystem, in OSV format.

A reachability tool needs to know which functions of a package hold a vulnerability. With that, it
can tell "the project calls the vulnerable code" from "the project only installs the package".
Upstream databases list these functions for Go and for part of Rust. npm, PyPI and Maven advisories
list none.

This project:

- mirrors the symbols that upstream databases already hold
- takes community records where no upstream home exists
- gives contributors tooling to draft a record from a fix, with help from their own LLM if they want
- checks every record with deterministic verification, so a model cannot add a function that the
  fix did not change

## Status

Private, before the first alpha release. The record format and the verification rules are drafts:

- [docs/spec/record.md](docs/spec/record.md): the record, an OSV document with one extension
- [docs/spec/verification.md](docs/spec/verification.md): the checks, the accounting rule and the
  trust rules
- [docs/spec/bundle.md](docs/spec/bundle.md): the signed bundle that consumers download
- [docs/glossary.md](docs/glossary.md): the terms

## Use the records

```go
c, err := symbols.New(symbols.WithCacheDir(dir))
_, err = c.Update(ctx) // at most once a day, checks the signature
b, err := c.Load(ctx)
answers := b.Lookup(symbols.Query{Package: pv, IDs: []string{"GO-2024-1234", "CVE-2024-0001"}})
```

`pv` is a `dry/api/pb` `PackageVersion`. Each answer holds the record and the affected entry, with the
fix sites of the package.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Agents read [AGENTS.md](AGENTS.md).

## License

The code is licensed under Apache-2.0. See [LICENSE](LICENSE). The license of the community records
is not decided yet. Upstream records keep the license of their source.
