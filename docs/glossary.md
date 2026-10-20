# Glossary

One word for one concept. Use these terms in code, docs and records. When a change adds a concept,
add it here in the same pull request.

| Term | Meaning |
| --- | --- |
| **record** | One OSV document in this database. It covers one advisory and the packages it affects. |
| **advisory** | The upstream vulnerability report that a record adds symbols to, as `GHSA-…`, `CVE-…`, `GO-…` or `RUSTSEC-…`. A record lists the advisory ids in `aliases`. |
| **symbol** | A function or a method. A record writes it as a symbol object, with its `name` in the native notation of its language. See "Symbol objects" in [spec/record.md](spec/record.md). |
| **fix** | The code change that removes the vulnerability: one or more fix commits, or the difference between the last affected release and the first fixed release. |
| **changed function** | A function whose parsed code the fix changed, or that the fix added or removed. The tool lists them. A person or a model never adds one. |
| **fix site** | A changed function that holds the vulnerable code. It can be internal to the package. |
| **exclusion** | A changed function that is not a fix site, with a reason. |
| **account** | The role of one changed function in a record: fix site or exclusion. Every changed function has exactly one account. |
| **proved exclusion** | An exclusion that the tool proves with no judgment, as a test file, a comment-only change or a function that the fix added. |
| **judged exclusion** | An exclusion that needs judgment, as a refactor with no change of behavior. A reviewer reads each one. |
| **entry symbol** | An exported symbol of the package from which the package call graph reaches a fix site. The tool derives the entry symbols. |
| **derivation** | The run of the tool that computes the entry symbols. It is complete when it hit no unresolved call. |
| **coverage** | `exact` when the record names the fix sites and the derivation is complete. `broad` otherwise. |
| **review state** | `unreviewed`, `reviewed` (one maintainer) or `verified` (two maintainers, or an upstream source). |
| **upstream record** | A record that the builder makes from an upstream database that already lists symbols, as the Go vulnerability database or RustSec. It is not a file in `records/`. |
| **community record** | A record in `records/`, which a contributor proposed and a maintainer merged. |
| **bundle** | The built file of every record that a consumer downloads, with its manifest and signature. See [spec/bundle.md](spec/bundle.md). |
| **manifest** | The signed description of one bundle: its hashes, its time and its sources. |
| **pin** | A client setting that keeps the client on one bundle, by the SHA-256 of the bundle file. |
| **verify** | The deterministic check of a record. It never calls a model. |
| **propose** | The workflow that drafts a record from a fix. A model can help here, and only here. |
