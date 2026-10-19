# The record format

Status: draft. The format changes freely until the first alpha release.

A record is an [OSV](https://ossf.github.io/osv-schema/) document. It uses the OSV fields for
everything that OSV already covers, and adds one object for what OSV does not cover. A consumer that
knows OSV and ignores the extension still reads a valid advisory.

## Why an extension

OSV has no field for vulnerable symbols that is the same for every ecosystem.

- The Go vulnerability database writes symbols in `affected[].ecosystem_specific.imports[].symbols`.
- RustSec writes them in `affected[].ecosystem_specific.affects.functions`.
- npm, PyPI and Maven advisories have no symbol field.

OSV also has no field for the evidence that a symbol is right. This project needs that evidence,
because verification reads it.

The extension lives at `affected[].database_specific.vuln_symbols`, one per affected package. OSV
defines `database_specific` as a free object that each database owns, with no fixed fields. OSV
defines nothing inside it. `vuln_symbols` and every field in it belong to this project. If OSV
adds a common symbol field later, the record moves to it, and the extension keeps only the evidence.

## Top-level fields

| Field | Rule |
| --- | --- |
| `schema_version` | The OSV schema version that the tool validates against. It is 1.9.2 now. |
| `id` | The id of the record in this database: `VSYM-<year>-<number>`. The prefix is provisional until it is registered with OSV. |
| `aliases` | The advisory ids: `GHSA-…`, `CVE-…`, `GO-…`, `RUSTSEC-…`. At least one. |
| `modified`, `published` | RFC 3339 times, as OSV requires. |
| `summary` | Optional. One line. |
| `affected` | One entry per package. See below. |
| `references` | The fix commits as `FIX` references. Other references are optional. |
| `credits` | The people who proposed and reviewed the record, with the OSV credit types. A proposer is `ANALYST`. |
| `database_specific.license` | The license of the record. An upstream record keeps the license of its source. |

## `affected[]`

| Field | Rule |
| --- | --- |
| `package.ecosystem` | The OSV ecosystem name, as `Go`, `crates.io`, `npm` or `PyPI`. |
| `package.name` | The name as the registry writes it. The record does not fold the name. A consumer folds it with its own identity rules. |
| `ranges` | Exactly one range. It must sit inside a range of the advisory. An advisory with a backport gives one `affected` entry per range, each with its own `fix`. |
| `database_specific.vuln_symbols` | The extension. See below. |

## `vuln_symbols`

```json
{
  "format": 1,
  "language": "go",
  "methods": ["patch-analysis"],
  "coverage": "exact",
  "fix": { "kind": "commit", "repo": "https://example.com/acme/widget", "commits": ["0123abc…"] },
  "fix_sites": [{ "name": "example.com/acme/widget/parse.readHeader" }],
  "changed_functions": [
    { "symbol": { "name": "example.com/acme/widget/parse.readHeader" }, "file": "parse/header.go", "account": "fix-site" },
    { "symbol": { "name": "example.com/acme/widget/parse.TestReadHeader" }, "file": "parse/header_test.go", "account": "excluded", "reason": "test", "proof": "tool" }
  ],
  "entry_symbols": {
    "symbols": [{ "name": "example.com/acme/widget/parse.Decode" }],
    "complete": true,
    "tool": "vsym 0.1.0"
  },
  "assist": [
    { "tool": "vsym 0.1.0", "model": "<model name>" },
    { "tool": "vsym 0.1.0", "model": "<other model name>" }
  ],
  "review": { "state": "reviewed", "reviewers": ["<github handle>"] }
}
```

| Field | Rule |
| --- | --- |
| `format` | The version of this extension. It starts at 1. |
| `language` | The language of the symbols: `go`, `rust`, `javascript`, `python`, `java`. |
| `methods` | How the record found its fix sites. A list of one or more of `upstream`, `patch-analysis` and `manual`, with no duplicate. A record can combine methods. `upstream` is never combined, because the builder makes an upstream record alone. A later format can add methods. |
| `coverage` | `exact` or `broad`. A record is `broad` when `entry_symbols.complete` is false, when it names no fix site, or when it has more than 50 fix sites. |
| `advisory_modified` | A map from each id in `aliases` to the `modified` time of the advisory that `vsym candidates` read. Verification fails when the advisory changed later. |
| `fix` | The fix that the record reads, for the one range of the entry. A commit must be one that the advisory names. With no named commit, the fix is a `release-diff`. `kind` is `commit`, with `repo` and `commits`, or `release-diff`, with `from` and `to` versions. A record with `release-diff` has a much longer list of changed functions, and a reviewer must read more. |
| `fix_sites` | The fix sites, as symbol objects. For a community record they are exactly the changed functions whose `account` is `fix-site`. For an upstream record they are the symbols of the source. The Go vulnerability database lists the fix sites and their exported callers together, so an upstream Go record also holds callers. |
| `changed_functions` | The account of every function that the fix changed. Required for a community record. Absent for an upstream record. |
| `changed_functions[].symbol` | The changed function, as a symbol object. |
| `changed_functions[].account` | `fix-site` or `excluded`. |
| `changed_functions[].reason` | For an exclusion. Proved by the tool: `test`, `comment-only`, `added`, `outside-package`. Judged: `generated`, `refactor`, `logging`, `other`. |
| `changed_functions[].proof` | `tool` when `verify` proves the exclusion. `judgment` when a person or a model decided. A proved reason must have `proof: tool`. |
| `changed_functions[].note` | Required when `proof` is `judgment`. One or two sentences for the reviewer. |
| `entry_symbols` | Derived by the tool. Never written by hand. `symbols` holds symbol objects. `complete` is false when the derivation hit an unresolved call. |
| `assist` | Optional. A list of the tools and the models that helped `propose`. Each entry has `tool`, the name and the version of the tool, and an optional `model`. A harness that uses several models gives one entry per model. Any tool can write an entry, not only `vsym`. It is provenance, not trust. |
| `review` | The review state and the reviewers. |

## Symbol objects

A record writes each symbol as an object. Symbol objects appear in `fix_sites`, in
`changed_functions[].symbol` and in `entry_symbols.symbols`.

```json
{ "name": "golang.org/x/net/html.render1" }
```

| Field | Rule |
| --- | --- |
| `name` | Required. The symbol in the notation of its language. See the next section. |

A later format can add fields to the object, as a canonical form or the kind of the symbol. A new
field never changes the meaning of `name`. A consumer ignores a field that it does not know. Two
symbols are the same when their `name` values are the same.

## Symbol notation

The `name` of a symbol uses the notation of its language and its upstream database, so a person can
read it and a tool can map it to any call-graph key.

| Language | Notation | Example |
| --- | --- | --- |
| Go | `<import path>.<Func>` or `<import path>.<Type>.<Method>`, as the Go vulnerability database writes them | `golang.org/x/net/html.render1` |
| Rust | The path as RustSec writes it | `smallvec::SmallVec::insert_many` |
| JavaScript, Python, Java | Open. The first tool that supports the language defines the notation in this section, with examples, in the same pull request. | |

The builder maps each symbol to the key form of a consumer. The record never stores a consumer key.

## Upstream records

The builder makes an upstream record from a source that already lists symbols. It sets `methods` to
`["upstream"]`, `review.state` to `verified` and `fix_sites` to the source symbols. It derives
`entry_symbols` the same way as for a community record. An upstream record is not a file in
`records/`. It exists only in the bundle.

When a community record and an upstream record cover the same advisory and package, the upstream
record wins. The build compares the names in the union of `fix_sites` and `entry_symbols` of the two records, because an upstream Go record lists fix sites and callers together. A difference fails the build, and a maintainer reads it.

## Open questions

- The record id prefix and its registration with OSV.
- Whether OSV accepts a source that adds data to advisories that another database owns.
- The license of community records. See the Licenses section of `AGENTS.md`.
- Whether the advisory ids go in `aliases` or in `upstream`. OSV defines `aliases` as the same
  vulnerability in other databases, and osv.dev groups records by alias. That can merge a record into
  the group of its advisory. The OSV field `upstream` lists the upstream vulnerabilities that an entry
  refers to, and can be the better home.
